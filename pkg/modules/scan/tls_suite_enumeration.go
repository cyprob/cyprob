package scan

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/rs/zerolog/log"
)

// Cipher-suite and version enumeration on the observation channel
//
// The negotiated suite says what this client and this server agreed on once. It
// does not say what else the server would have accepted, and that is the
// question a cipher-suite finding actually asks. Answering it means asking the
// server repeatedly, which is why enumeration is a separate pass with a budget
// of its own rather than something the ordinary probe does for free.
//
// The method is elimination, not one handshake per candidate. Offer everything,
// see what the server picks, drop that one, offer the rest, repeat until the
// server refuses. That costs k+1 dials where k is what the *server* supports --
// typically 5 to 20 -- instead of one per candidate. Each dial is cut short
// after the server's first flight, so no key exchange is performed.
//
// The offer comes from IANA's registry and not from crypto/tls, and that is the
// whole point of the raw ClientHello. crypto/tls implements 25 of the 356
// assigned suites; the two checks this work exists for name 89 and 196 suites,
// of which a Go client can reach 3 in either case. An enumerator built on a Go
// client would reproduce the zero that had those checks withdrawn, because the
// limit is the instrument and not the matcher.
//
// What it still cannot establish is written down rather than left to be
// discovered: it measures the responder rather than the host, so a load
// balancer across unlike backends yields a union no machine actually offers; it
// measures a TLS terminator rather than an origin; it cannot report preference
// order, because the walk's discovery order is an artifact of the offers the
// walk itself generated and one deletion can flip a server's whole ranking; and
// selection is not usability, since nothing past the ServerHello is verified.
const (
	// defaultTLSEnumerationDialBudget bounds a single service. A version walk
	// is four dials, each suite walk is k+1, and each walk pays one dial for
	// its end-of-walk control -- comfortably inside this for any real server.
	// The budget is here for the server that answers differently every time.
	defaultTLSEnumerationDialBudget = 64
	defaultTLSEnumerationTimeBudget = 15 * time.Second
	tlsEnumerationDialTimeout       = 2 * time.Second

	tlsEnumerationMethodRawHello = "raw_client_hello"
)

// TLSEnumeration is what the server accepts, with the accounting that says how
// completely the question was answered. Truncated is never silent: a partial
// answer that does not say it is partial reads as a complete one.
type TLSEnumeration struct {
	CipherSuites []string `json:"cipher_suites,omitempty"`
	TLSVersions  []string `json:"tls_versions,omitempty"`
	// Method names the instrument. It exists because OfferedSuites means
	// something different depending on it -- "what our TLS stack implements"
	// against "what this ClientHello listed" -- and a number whose meaning
	// depends on an undeclared fact is a number that will be misread.
	Method string `json:"method,omitempty"`
	// OfferedSuites is how many candidates were asked about, so a result can be
	// read with its own ceiling attached.
	OfferedSuites int `json:"offered_suites"`
	Dials         int `json:"dials"`
	// Anomalies record a server doing something the protocol forbids -- naming
	// a suite it was not offered, selecting a signaling value, answering in
	// the wrong version namespace. These are findings, not parse noise.
	Anomalies       []string `json:"anomalies,omitempty"`
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

// stop records the first reason a walk ended abnormally and keeps it.
func (b *tlsEnumerationBudget) stop(reason string) {
	if b.stopped == "" {
		b.stopped = reason
	}
}

type tlsEnumerator struct {
	target    string
	hostname  string
	port      int
	opts      TLSProbeOptions
	budget    *tlsEnumerationBudget
	anomalies []string
}

func (e *tlsEnumerator) notef(format string, args ...any) {
	entry := fmt.Sprintf(format, args...)
	for _, existing := range e.anomalies {
		if existing == entry {
			return
		}
	}
	e.anomalies = append(e.anomalies, entry)
}

func enumerateTLS(ctx context.Context, target string, hostname string, port int, opts TLSProbeOptions) *TLSEnumeration {
	enumerator := &tlsEnumerator{
		target:   target,
		hostname: hostname,
		port:     port,
		opts:     opts,
		budget: &tlsEnumerationBudget{
			maxDials: defaultTLSEnumerationDialBudget,
			deadline: time.Now().Add(defaultTLSEnumerationTimeBudget),
		},
	}

	versions := enumerator.enumerateVersions(ctx)

	suites := make([]string, 0, 32)
	offered := 0
	if legacy := highestLegacyVersion(versions); legacy != 0 {
		offered += len(tlsRegistryLegacySuiteIDs)
		suites = append(suites, enumerator.enumerateSuites(ctx, tlsRegistryLegacySuiteIDs, legacy)...)
	}
	if versionSupported(versions, 0x0304) {
		offered += len(tlsRegistryTLS13SuiteIDs)
		suites = append(suites, enumerator.enumerateSuites(ctx, tlsRegistryTLS13SuiteIDs, 0x0304)...)
	}

	// Sorted, because the order a walk happens to discover suites in is an
	// artifact of the offers it generated and must not be read as preference.
	sort.Strings(suites)

	enumeration := &TLSEnumeration{
		CipherSuites:    suites,
		TLSVersions:     versionNames(versions),
		Method:          tlsEnumerationMethodRawHello,
		OfferedSuites:   offered,
		Dials:           enumerator.budget.dials,
		Anomalies:       enumerator.anomalies,
		Truncated:       enumerator.budget.stopped != "",
		TruncatedReason: enumerator.budget.stopped,
	}

	log.Debug().
		Str("module", tlsNativeProbeModuleName).
		Str("target", target).
		Int("port", port).
		Int("suites", len(enumeration.CipherSuites)).
		Int("versions", len(enumeration.TLSVersions)).
		Int("dials", enumeration.Dials).
		Int("anomalies", len(enumeration.Anomalies)).
		Bool("truncated", enumeration.Truncated).
		Msg("TLS enumeration finished")

	// Always a block once the walk has run. Enumeration is only attempted for a
	// service the probe already reached, so "nothing was learned" is itself an
	// observation -- the service answered a handshake and then refused to be
	// asked anything. A nil here would erase that, and a branch that only fires
	// when the caller's own precondition is violated is a branch no test can
	// reach honestly. Enumeration stays nil exactly when it was not attempted.
	return enumeration
}

// enumerateVersions asks about each version separately rather than walking a
// ceiling down. There are only four, so one pinned dial each answers exactly
// and needs no inference: a server that speaks 1.2 and 1.0 but not 1.1 is read
// correctly without the ceiling arithmetic having to be right about it.
func (e *tlsEnumerator) enumerateVersions(ctx context.Context) []uint16 {
	supported := make([]uint16, 0, 4)
	for _, version := range []uint16{0x0304, 0x0303, 0x0302, 0x0301} {
		if !e.budget.take() {
			return supported
		}
		offer := tlsRegistryLegacySuiteIDs
		if version == 0x0304 {
			offer = tlsRegistryTLS13SuiteIDs
		}
		outcome := dialRawTLSForServerHello(ctx, e.target, e.hostname, e.port, offer, version, e.opts)
		switch {
		case outcome.Err != nil && outcome.Transport == "not_tls":
			e.budget.stop("not_tls")
			return supported
		case outcome.Err != nil:
			// A transport failure says nothing about the version. It must never
			// be written down as "unsupported", and it makes the answer partial.
			e.budget.stop("transport_failure")
			return supported
		case outcome.Flight.Kind == rawFlightServerHello:
			if outcome.Flight.Version != version {
				// The server answered in a version we did not pin. That is its
				// fault, not an observation about the version we asked about.
				e.notef("version_mismatch:asked_0x%04X_got_0x%04X", version, outcome.Flight.Version)
				continue
			}
			supported = append(supported, version)
			if outcome.Flight.DowngradeCanary != "" {
				e.notef("downgrade_canary:%s", outcome.Flight.DowngradeCanary)
			}
		case outcome.Flight.Kind == rawFlightRefused, outcome.Flight.Kind == rawFlightVersionRefus:
			// A genuine "no": either no shared suite in that version, or the
			// version itself refused.
		default:
			// probe_rejected: our hello was wrong for this server. Recording it
			// as "version unsupported" would delete a supported version.
			e.notef("probe_rejected:version_0x%04X_alert_%d", version, outcome.Flight.AlertDescription)
		}
	}
	return supported
}

// enumerateSuites walks one namespace with the version pinned, so the server
// cannot move between the disjoint TLS 1.3 and pre-1.3 suite spaces mid-walk.
func (e *tlsEnumerator) enumerateSuites(ctx context.Context, offer []uint16, version uint16) []string {
	remaining := append([]uint16(nil), offer...)
	accepted := make([]string, 0, 16)
	var acceptedIDs []uint16

	for len(remaining) > 0 {
		if !e.budget.take() {
			return accepted
		}
		outcome := dialRawTLSForServerHello(ctx, e.target, e.hostname, e.port, remaining, version, e.opts)
		if outcome.Err != nil {
			e.budget.stop("transport_failure")
			return accepted
		}
		if outcome.Flight.Kind != rawFlightServerHello {
			if outcome.Flight.Kind == rawFlightRefused {
				// The candidate end of the walk -- but only the control can say
				// whether the server ran out of suites or ran out of patience.
				return e.confirmWalkEnd(ctx, accepted, acceptedIDs, version)
			}
			e.budget.stop("probe_rejected")
			e.notef("probe_rejected:suites_0x%04X_alert_%d", version, outcome.Flight.AlertDescription)
			return accepted
		}

		suite := outcome.Flight.CipherSuite
		if !tlsSuiteIsOfferable(suite) {
			e.notef("pseudo_suite_selected:0x%04X", suite)
			e.budget.stop("pseudo_suite_selected")
			return accepted
		}
		if inTLS13Namespace(suite) != (version == 0x0304) {
			e.notef("namespace_mismatch:0x%04X_under_0x%04X", suite, version)
			e.budget.stop("namespace_mismatch")
			return accepted
		}
		// There is deliberately no separate "already selected this one" guard.
		// An accepted suite is removed from the offer, so a repeat selection is
		// necessarily a selection of something not offered, and the check below
		// catches it. A second guard here would be unreachable code with a
		// plausible comment -- which is exactly the defect a reviewer found in
		// the previous version of this walk, where a guard could be deleted
		// without a single test noticing.
		shorter := removeTLSCipherSuite(remaining, suite)
		if len(shorter) == len(remaining) {
			// The server named something it was never offered. Nothing can be
			// eliminated, so the walk cannot progress -- and the answer so far
			// is not trustworthy either.
			e.notef("unexpected_suite:0x%04X", suite)
			e.budget.stop("unexpected_suite")
			return accepted
		}
		remaining = shorter
		acceptedIDs = append(acceptedIDs, suite)
		accepted = append(accepted, tlsSuiteName(suite))
		if outcome.Flight.ViaHelloRetry {
			e.notef("via_hello_retry:0x%04X", suite)
		}
	}
	// The offer was consumed without a refusal. That is a complete answer, and
	// the one exit that must not set Truncated.
	return accepted
}

// confirmWalkEnd spends one dial re-offering a suite the server already
// accepted. A rate limiter's cutoff and an honest exhaustion send the same
// alert 40 on the same connection number, and this is the only thing that tells
// them apart: if the server will still accept a suite it accepted a moment ago,
// the refusal that ended the walk was about the suites.
func (e *tlsEnumerator) confirmWalkEnd(ctx context.Context, accepted []string, acceptedIDs []uint16, version uint16) []string {
	if len(acceptedIDs) == 0 {
		// Nothing was ever accepted, so there is nothing to re-offer. The
		// refusal is all we have and the walk learned nothing either way.
		return accepted
	}
	if !e.budget.take() {
		return accepted
	}
	control := []uint16{acceptedIDs[0]}
	outcome := dialRawTLSForServerHello(ctx, e.target, e.hostname, e.port, control, version, e.opts)
	if outcome.Err != nil || outcome.Flight.Kind != rawFlightServerHello || outcome.Flight.CipherSuite != control[0] {
		e.notef("control_failed:0x%04X", control[0])
		e.budget.stop("control_failed")
	}
	return accepted
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

func inTLS13Namespace(id uint16) bool { return id>>8 == 0x13 }

// tlsSuiteName resolves an arbitrary two-byte ID. The hex fallback matches
// crypto/tls's own format exactly, so an unknown suite renders identically
// whichever side produced it -- and the numeric form is always available, since
// a bare hex string in a field a plugin pattern matches against is a check that
// reports zero and reads as clean.
func tlsSuiteName(id uint16) string {
	if name, ok := tlsRegistrySuiteNames[id]; ok {
		return name
	}
	if tlsSuiteIsGREASE(id) {
		return fmt.Sprintf("GREASE (0x%04X)", id)
	}
	return fmt.Sprintf("0x%04X", id)
}

func versionSupported(versions []uint16, want uint16) bool {
	for _, v := range versions {
		if v == want {
			return true
		}
	}
	return false
}

// highestLegacyVersion picks the version to pin the pre-1.3 suite walk to. The
// highest is used because a server may offer more suites at a higher version,
// and a walk pinned low would report a subset as the whole answer.
func highestLegacyVersion(versions []uint16) uint16 {
	best := uint16(0)
	for _, v := range versions {
		if v != 0x0304 && v > best {
			best = v
		}
	}
	return best
}

func versionNames(versions []uint16) []string {
	names := make([]string, 0, len(versions))
	for _, v := range versions {
		names = append(names, tlsVersionString(v))
	}
	return names
}
