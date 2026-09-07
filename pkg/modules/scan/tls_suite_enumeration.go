package scan

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Cipher-suite and version enumeration on the observation channel
//
// The negotiated suite says what this client and this server agreed on once.
// It does not say what else the server would have agreed to, and that is the
// question a cipher-suite finding actually asks. Answering it needs the server
// to be asked repeatedly, which is why enumeration is a separate pass with a
// budget of its own rather than something the ordinary probe does for free.
//
// The method is elimination, not one handshake per candidate. Offer everything,
// see what the server picks, drop that one, offer the rest, repeat until the
// server refuses. That costs k+1 dials where k is what the *server* supports --
// typically 5 to 12 -- instead of one per suite the client implements. Each
// dial is also cut short at the server's first flight, so no key exchange is
// performed and the cost is about one round trip.
//
// What this can and cannot establish, stated here because getting it wrong is
// how a cipher check ends up measuring the scanner instead of the estate: the
// result is the intersection of what the server supports with what crypto/tls
// can offer at all. A suite Go does not implement cannot be asked about and
// will never appear, however loudly a server advertises it. OfferedSuites
// records the size of that askable set so the answer can be read with its own
// limit attached.
const (
	// defaultTLSEnumerationDialBudget bounds a single service. Elimination on a
	// real server ends well inside this; the budget exists for the server that
	// answers differently every time, or renegotiates, and would otherwise walk
	// the loop forever.
	defaultTLSEnumerationDialBudget = 40
	defaultTLSEnumerationTimeBudget = 5 * time.Second
	tlsEnumerationDialTimeout       = 2 * time.Second
)

// errTLSEnumerationServerHello aborts a handshake once the server has said what
// it chose. Returning it from VerifyConnection is how crypto/tls is asked to
// stop after the server's flight: the negotiated version and suite are already
// known there, and nothing past that point is needed.
var errTLSEnumerationServerHello = errors.New("tls_enumeration_server_hello")

// TLSEnumeration is what the server accepts, with the accounting that says how
// completely the question was answered. Truncated is never silent: a partial
// answer that does not say it is partial reads as a complete one.
type TLSEnumeration struct {
	CipherSuites    []string `json:"cipher_suites,omitempty"`
	TLSVersions     []string `json:"tls_versions,omitempty"`
	OfferedSuites   int      `json:"offered_suites"`
	Dials           int      `json:"dials"`
	Truncated       bool     `json:"truncated"`
	TruncatedReason string   `json:"truncated_reason,omitempty"`
}

type tlsEnumerationBudget struct {
	dials    int
	maxDials int
	deadline time.Time
	stopped  string
}

// take accounts for one dial and reports whether it may happen. Once a budget
// stops, it stays stopped and remembers why.
func (b *tlsEnumerationBudget) take() bool {
	if b.stopped != "" {
		return false
	}
	if b.dials >= b.maxDials {
		b.stopped = "dial_budget"
		return false
	}
	if !time.Now().Before(b.deadline) {
		b.stopped = "time_budget"
		return false
	}
	b.dials++
	return true
}

func enumerateTLS(ctx context.Context, target string, hostname string, port int, opts TLSProbeOptions) *TLSEnumeration {
	offer := tlsObservationCipherSuiteIDs()
	budget := &tlsEnumerationBudget{
		maxDials: defaultTLSEnumerationDialBudget,
		deadline: time.Now().Add(defaultTLSEnumerationTimeBudget),
	}

	enumeration := &TLSEnumeration{OfferedSuites: len(offer)}
	enumeration.CipherSuites = enumerateTLSCipherSuites(ctx, target, hostname, port, offer, budget, opts)
	enumeration.TLSVersions = enumerateTLSVersions(ctx, target, hostname, port, offer, budget, opts)
	enumeration.Dials = budget.dials
	enumeration.Truncated = budget.stopped != ""
	enumeration.TruncatedReason = budget.stopped

	log.Debug().
		Str("module", tlsNativeProbeModuleName).
		Str("target", target).
		Int("port", port).
		Int("suites", len(enumeration.CipherSuites)).
		Int("versions", len(enumeration.TLSVersions)).
		Int("dials", enumeration.Dials).
		Bool("truncated", enumeration.Truncated).
		Msg("TLS enumeration finished")

	if len(enumeration.CipherSuites) == 0 && len(enumeration.TLSVersions) == 0 && !enumeration.Truncated {
		return nil
	}
	return enumeration
}

// enumerateTLSCipherSuites walks the elimination.
//
// The ceiling is held at TLS 1.2 throughout, and that is not a preference. In
// crypto/tls, Config.CipherSuites governs TLS 1.0-1.2 only; a connection that
// lands on TLS 1.3 ignores the offer entirely and reports a TLS 1.3 suite that
// was never in it. Removing that suite from the offer would remove nothing, and
// the loop would ask the same question forever. TLS 1.3's three suites are
// fixed by RFC 8446 and always offered, so there is nothing to enumerate there
// in any case.
func enumerateTLSCipherSuites(
	ctx context.Context,
	target string,
	hostname string,
	port int,
	offer []uint16,
	budget *tlsEnumerationBudget,
	opts TLSProbeOptions,
) []string {
	remaining := append([]uint16(nil), offer...)
	accepted := make([]string, 0, len(remaining))

	for len(remaining) > 0 {
		if !budget.take() {
			return accepted
		}
		suite, _, err := dialTLSForServerHello(ctx, target, hostname, port, remaining, tls.VersionTLS12, opts)
		if err != nil {
			return accepted
		}

		shorter := removeTLSCipherSuite(remaining, suite)
		if len(shorter) == len(remaining) {
			// The server chose something it was not offered. Nothing can be
			// eliminated, so the walk cannot make progress; stop and say so
			// rather than spending the whole budget discovering it.
			budget.stopped = "unexpected_suite"
			return accepted
		}
		remaining = shorter
		accepted = append(accepted, tls.CipherSuiteName(suite))
	}
	return accepted
}

// enumerateTLSVersions is the same elimination applied to the version.
//
// Each dial reports the highest version at or below the ceiling that the server
// will accept, so stepping the ceiling to just under each answer walks down the
// versions it supports and skips the ones it does not -- a server that speaks
// 1.2 and 1.0 but not 1.1 is read correctly, because the dial capped at 1.1
// comes back with 1.0.
func enumerateTLSVersions(
	ctx context.Context,
	target string,
	hostname string,
	port int,
	offer []uint16,
	budget *tlsEnumerationBudget,
	opts TLSProbeOptions,
) []string {
	versions := make([]string, 0, 4)
	ceiling := uint16(tls.VersionTLS13)

	for {
		if !budget.take() {
			return versions
		}
		_, negotiated, err := dialTLSForServerHello(ctx, target, hostname, port, offer, ceiling, opts)
		if err != nil {
			return versions
		}
		versions = append(versions, tlsVersionString(negotiated))
		if negotiated <= tls.VersionTLS10 {
			return versions
		}
		ceiling = negotiated - 1
	}
}

// dialTLSForServerHello offers exactly `offer` under `maxVersion` and returns
// what the server chose, without completing the handshake.
func dialTLSForServerHello(
	ctx context.Context,
	target string,
	hostname string,
	port int,
	offer []uint16,
	maxVersion uint16,
	opts TLSProbeOptions,
) (uint16, uint16, error) {
	connectTimeout := opts.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = tlsEnumerationDialTimeout
	}

	var suite, version uint16
	config := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // Observation only; no trust decision is made here.
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         maxVersion,
		CipherSuites:       offer,
		VerifyConnection: func(state tls.ConnectionState) error {
			suite, version = state.CipherSuite, state.Version
			return errTLSEnumerationServerHello
		},
	}
	hostname = strings.TrimSpace(hostname)
	if hostname != "" && net.ParseIP(hostname) == nil {
		config.ServerName = hostname
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: connectTimeout},
		Config:    config,
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target, strconv.Itoa(port)))
	if err != nil {
		if errors.Is(err, errTLSEnumerationServerHello) {
			return suite, version, nil
		}
		return 0, 0, err
	}
	// Not expected: VerifyConnection always stops the handshake. Close rather
	// than leak the connection if crypto/tls ever changes underneath this.
	_ = conn.Close()
	return suite, version, nil
}

func removeTLSCipherSuite(ids []uint16, remove uint16) []uint16 {
	out := make([]uint16, 0, len(ids))
	for _, id := range ids {
		if id != remove {
			out = append(out, id)
		}
	}
	return out
}
