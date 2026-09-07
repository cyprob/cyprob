package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// cyprob#294. The walk asks an untrusted server the same question repeatedly,
// so most of what matters here is what it does when the server does not play
// along -- and every one of those cases needs a server that can send arbitrary
// bytes, which is why these tests do not use crypto/tls on either side.

// --- harness -------------------------------------------------------------

type rawTestServer struct {
	mu          sync.Mutex
	hellos      []parsedTestClientHello
	connections atomic.Int32
}

func (s *rawTestServer) record(hello parsedTestClientHello) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hellos = append(s.hellos, hello)
}

func (s *rawTestServer) captured() []parsedTestClientHello {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]parsedTestClientHello(nil), s.hellos...)
}

// startRawTestServer answers with whatever the handler returns. A nil reply
// closes the connection without a word, which is itself a case the walk must
// classify.
func startRawTestServer(t *testing.T, handler func(hello parsedTestClientHello, connection int) []byte) (string, int, *rawTestServer, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &rawTestServer{}
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			index := int(server.connections.Add(1))
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				record, readErr := readOneTestRecord(conn)
				if readErr != nil {
					return
				}
				hello, parseErr := parseTestClientHello(record)
				if parseErr != nil {
					return
				}
				server.record(hello)
				if reply := handler(hello, index); reply != nil {
					_, _ = conn.Write(reply)
				}
			}()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, server, func() {
		_ = ln.Close()
		<-done
	}
}

func readOneTestRecord(conn net.Conn) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := readFullTest(conn, header); err != nil {
		return nil, err
	}
	length := int(header[3])<<8 | int(header[4])
	payload := make([]byte, length)
	if _, err := readFullTest(conn, payload); err != nil {
		return nil, err
	}
	record := make([]byte, 0, len(header)+len(payload))
	record = append(record, header...)
	return append(record, payload...), nil
}

func readFullTest(conn net.Conn, buf []byte) (int, error) {
	read := 0
	for read < len(buf) {
		n, err := conn.Read(buf[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

// serverPreferenceHandler picks the first suite on the server's own list that
// the client offered, which is what a real server does and what makes the
// walk's discovery order an artifact rather than a result.
func serverPreferenceHandler(t *testing.T, supported []uint16) func(parsedTestClientHello, int) []byte {
	return func(hello parsedTestClientHello, _ int) []byte {
		offered := map[uint16]struct{}{}
		for _, id := range hello.suites {
			offered[id] = struct{}{}
		}
		for _, id := range supported {
			if _, ok := offered[id]; !ok {
				continue
			}
			if (id>>8 == 0x13) != (hello.version == 0x0304) {
				continue // wrong namespace for the pinned version
			}
			spec := testServerHello{legacyVersion: 0x0303, suite: id}
			if hello.version == 0x0304 {
				spec.supportedVersion = 0x0304
			} else {
				spec.legacyVersion = hello.version
			}
			return testServerHelloRecord(t, spec)
		}
		return testAlertRecord(40)
	}
}

func enumerateForTest(t *testing.T, host string, port int) *TLSEnumeration {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return enumerateTLS(ctx, host, "", port, TLSProbeOptions{})
}

func suiteNameSet(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, name := range names {
		out[name] = true
	}
	return out
}

// --- the walk ------------------------------------------------------------

func TestEnumerateTLS_FindsExactlyTheServersSuites(t *testing.T) {
	t.Parallel()

	// Two of these are assigned suites that crypto/tls does not implement, which
	// is the whole reason the hello is hand-built: a Go client could never ask
	// about them, so an enumerator built on one returns a smaller answer.
	supported := []uint16{0xC02F, 0x0035, 0x0088, 0x0084}
	host, port, server, stop := startRawTestServer(t, serverPreferenceHandler(t, supported))
	defer stop()

	enumeration := enumerateForTest(t, host, port)
	if enumeration == nil {
		t.Fatal("enumeration returned nothing against a reachable server")
	}
	if enumeration.Method != tlsEnumerationMethodRawHello {
		t.Fatalf("method: %q", enumeration.Method)
	}

	got := suiteNameSet(enumeration.CipherSuites)
	for _, id := range supported {
		if !got[tlsSuiteName(id)] {
			t.Fatalf("0x%04X (%s) missing from %v", id, tlsSuiteName(id), enumeration.CipherSuites)
		}
	}
	if len(enumeration.CipherSuites) != len(supported) {
		t.Fatalf("expected exactly %d suites, got %v", len(supported), enumeration.CipherSuites)
	}
	// The proof that the ceiling moved: neither of these is in crypto/tls's 25.
	for _, id := range []uint16{0x0088, 0x0084} {
		if !got[tlsSuiteName(id)] {
			t.Fatalf("0x%04X is assigned but unimplemented by crypto/tls; it is the case this work exists for", id)
		}
	}

	if enumeration.Truncated {
		t.Fatalf("a completed walk must not be truncated: %s", enumeration.TruncatedReason)
	}
	// Elimination, not one dial per candidate: four versions + (k+1) + control.
	if enumeration.Dials > len(supported)+8 {
		t.Fatalf("%d dials for %d suites is not elimination", enumeration.Dials, len(supported))
	}
	if enumeration.Dials >= enumeration.OfferedSuites {
		t.Fatalf("%d dials against %d offered candidates is the naive walk", enumeration.Dials, enumeration.OfferedSuites)
	}
	if int(server.connections.Load()) != enumeration.Dials {
		t.Fatalf("server saw %d connections for %d declared dials", server.connections.Load(), enumeration.Dials)
	}
}

// The offer is the registry, not what our own TLS stack implements. That is the
// entire point of cyprob#294 and it is worth one assertion of its own.
func TestEnumerateTLS_OffersMoreThanCryptoTLSImplements(t *testing.T) {
	t.Parallel()

	host, port, server, stop := startRawTestServer(t, serverPreferenceHandler(t, []uint16{0x0035}))
	defer stop()

	if enumerateForTest(t, host, port) == nil {
		t.Fatal("enumeration returned nothing")
	}
	for _, hello := range server.captured() {
		if hello.version == 0x0304 {
			continue
		}
		if len(hello.suites) < 100 {
			continue // a later round of the walk, already eliminated down
		}
		if len(hello.suites) <= 25 {
			t.Fatalf("the offer was %d suites; crypto/tls implements 25, so this adds nothing", len(hello.suites))
		}
		return
	}
	t.Fatal("no full-size offer was ever sent")
}

// The guard the reviewer found had no test of its own, and could not have had
// one through crypto/tls: a Go client rejects an unoffered suite before the
// enumerator ever sees it, so the branch was unreachable rather than untested.
func TestEnumerateTLS_UnofferedSuiteStopsTheWalk(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startRawTestServer(t, func(hello parsedTestClientHello, _ int) []byte {
		if hello.version == 0x0304 {
			return testAlertRecord(40)
		}
		return testServerHelloRecord(t, testServerHello{legacyVersion: hello.version, suite: 0xFFFF})
	})
	defer stop()

	enumeration := enumerateForTest(t, host, port)
	if enumeration == nil {
		t.Fatal("enumeration returned nothing")
	}
	if enumeration.TruncatedReason != "unexpected_suite" {
		t.Fatalf("want unexpected_suite, got %q (dials %d)", enumeration.TruncatedReason, enumeration.Dials)
	}
	if enumeration.Dials >= defaultTLSEnumerationDialBudget {
		t.Fatalf("the walk should stop on the violation, not exhaust the budget: %d dials", enumeration.Dials)
	}
	for _, name := range enumeration.CipherSuites {
		if name == "0xFFFF" {
			t.Fatal("a suite the server was never offered must not be recorded as supported")
		}
	}
	if !hasAnomalyPrefix(enumeration.Anomalies, "unexpected_suite:") {
		t.Fatalf("the violation must be recorded: %v", enumeration.Anomalies)
	}
}

func TestEnumerateTLS_NonProgressingServerStopsTheWalk(t *testing.T) {
	t.Parallel()

	// Always the same suite, whatever is offered. Elimination cannot converge,
	// and the answer is not a list.
	host, port, _, stop := startRawTestServer(t, func(hello parsedTestClientHello, _ int) []byte {
		if hello.version == 0x0304 {
			return testAlertRecord(40)
		}
		for _, id := range hello.suites {
			if id == 0x0035 {
				return testServerHelloRecord(t, testServerHello{legacyVersion: hello.version, suite: 0x0035})
			}
		}
		return testServerHelloRecord(t, testServerHello{legacyVersion: hello.version, suite: 0x0035})
	})
	defer stop()

	enumeration := enumerateForTest(t, host, port)
	if enumeration == nil {
		t.Fatal("enumeration returned nothing")
	}
	// A suite that was already accepted has been removed from the offer, so
	// selecting it again is selecting something unoffered. One guard covers
	// both; a second would be unreachable code with a plausible comment.
	if enumeration.TruncatedReason != "unexpected_suite" {
		t.Fatalf("want unexpected_suite, got %q", enumeration.TruncatedReason)
	}
	if enumeration.Dials >= defaultTLSEnumerationDialBudget {
		t.Fatalf("a non-progressing server must be detected, not waited out: %d dials", enumeration.Dials)
	}
}

func TestEnumerateTLS_NamespaceMismatchStopsTheWalk(t *testing.T) {
	t.Parallel()

	// A TLS 1.3 suite offered under a pinned TLS 1.2: the two spaces are
	// disjoint and mixing them would file a suite under the wrong version.
	host, port, _, stop := startRawTestServer(t, func(hello parsedTestClientHello, _ int) []byte {
		if hello.version == 0x0304 {
			return testAlertRecord(40)
		}
		return testServerHelloRecord(t, testServerHello{legacyVersion: hello.version, suite: 0x1301})
	})
	defer stop()

	enumeration := enumerateForTest(t, host, port)
	if enumeration == nil {
		t.Fatal("enumeration returned nothing")
	}
	if enumeration.TruncatedReason != "namespace_mismatch" {
		t.Fatalf("want namespace_mismatch, got %q", enumeration.TruncatedReason)
	}
	if len(enumeration.CipherSuites) != 0 {
		t.Fatalf("nothing may be recorded from a mismatched namespace: %v", enumeration.CipherSuites)
	}
}

func TestEnumerateTLS_PseudoSuiteSelectionIsAnAnomaly(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startRawTestServer(t, func(hello parsedTestClientHello, _ int) []byte {
		if hello.version == 0x0304 {
			return testAlertRecord(40)
		}
		// TLS_EMPTY_RENEGOTIATION_INFO_SCSV is a signal, never a suite, and we
		// never offered it.
		return testServerHelloRecord(t, testServerHello{legacyVersion: hello.version, suite: 0x00FF})
	})
	defer stop()

	enumeration := enumerateForTest(t, host, port)
	if enumeration == nil {
		t.Fatal("enumeration returned nothing")
	}
	if enumeration.TruncatedReason != "pseudo_suite_selected" {
		t.Fatalf("want pseudo_suite_selected, got %q", enumeration.TruncatedReason)
	}
	for _, name := range enumeration.CipherSuites {
		if strings.Contains(name, "SCSV") {
			t.Fatal("a signaling value must never be recorded as a negotiated suite")
		}
	}
}

// The single highest-value defense, and it costs one dial: a rate limiter's
// cutoff sends the same alert 40, on the same connection, as an honest server
// that has run out of suites.
func TestEnumerateTLS_RateLimitedServerIsNotACompleteResult(t *testing.T) {
	t.Parallel()

	const cutoff = 7
	supported := []uint16{0xC02F, 0x0035, 0x0088, 0xC0FF, 0x009C}
	inner := serverPreferenceHandler(t, supported)
	host, port, _, stop := startRawTestServer(t, func(hello parsedTestClientHello, connection int) []byte {
		if connection > cutoff {
			return testAlertRecord(40) // byte-identical to an honest exhaustion
		}
		return inner(hello, connection)
	})
	defer stop()

	enumeration := enumerateForTest(t, host, port)
	if enumeration == nil {
		t.Fatal("enumeration returned nothing")
	}
	if !enumeration.Truncated || enumeration.TruncatedReason != "control_failed" {
		t.Fatalf("a rate-limited walk must be partial; got truncated=%v reason=%q suites=%v",
			enumeration.Truncated, enumeration.TruncatedReason, enumeration.CipherSuites)
	}
}

// The regression for the defense above: it must not label an honest walk
// partial, or it would be free to be right by always saying "incomplete".
func TestEnumerateTLS_HonestServerPassesTheControl(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startRawTestServer(t, serverPreferenceHandler(t, []uint16{0xC02F, 0x0035}))
	defer stop()

	enumeration := enumerateForTest(t, host, port)
	if enumeration == nil {
		t.Fatal("enumeration returned nothing")
	}
	if enumeration.Truncated {
		t.Fatalf("an honest walk must be complete, got %q", enumeration.TruncatedReason)
	}
	if len(enumeration.CipherSuites) != 2 {
		t.Fatalf("expected both suites, got %v", enumeration.CipherSuites)
	}
}

func TestEnumerateTLS_VersionsAreProbedIndividually(t *testing.T) {
	t.Parallel()

	// 1.2 and 1.0, but not 1.1: a ceiling walk has to infer this correctly,
	// while a pinned probe per version simply reads it.
	accepted := map[uint16]bool{0x0303: true, 0x0301: true}
	host, port, _, stop := startRawTestServer(t, func(hello parsedTestClientHello, _ int) []byte {
		if !accepted[hello.version] {
			return testAlertRecord(70) // protocol_version
		}
		return testServerHelloRecord(t, testServerHello{legacyVersion: hello.version, suite: 0x0035})
	})
	defer stop()

	enumeration := enumerateForTest(t, host, port)
	if enumeration == nil {
		t.Fatal("enumeration returned nothing")
	}
	want := map[string]bool{"TLS1.2": true, "TLS1.0": true}
	if len(enumeration.TLSVersions) != len(want) {
		t.Fatalf("expected TLS1.2 and TLS1.0 only, got %v", enumeration.TLSVersions)
	}
	for _, name := range enumeration.TLSVersions {
		if !want[name] {
			t.Fatalf("unexpected version %q in %v", name, enumeration.TLSVersions)
		}
	}
}

// A rejected probe says our hello was wrong. Recording it as a refusal would
// delete a supported suite from the answer and read as a clean result.
func TestEnumerateTLS_ProbeRejectionIsNotARefusal(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startRawTestServer(t, func(_ parsedTestClientHello, _ int) []byte {
		return testAlertRecord(112) // unrecognized_name
	})
	defer stop()

	enumeration := enumerateForTest(t, host, port)
	if enumeration == nil {
		t.Fatal("a probe-rejected service must still be reported")
	}
	if len(enumeration.TLSVersions) != 0 {
		t.Fatalf("an alert about our hello says nothing about versions: %v", enumeration.TLSVersions)
	}
	if !hasAnomalyPrefix(enumeration.Anomalies, "probe_rejected:") {
		t.Fatalf("the rejection must be recorded: %v", enumeration.Anomalies)
	}
}

// A transport failure can never be written down as a refusal, and it always
// makes the answer partial.
func TestEnumerateTLS_TransportFailureIsNotARefusal(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startRawTestServer(t, func(_ parsedTestClientHello, _ int) []byte {
		return nil // accept and close without a word
	})
	defer stop()

	enumeration := enumerateForTest(t, host, port)
	if enumeration == nil {
		t.Fatal("enumeration returned nothing")
	}
	if enumeration.TruncatedReason != "transport_failure" {
		t.Fatalf("want transport_failure, got %q", enumeration.TruncatedReason)
	}
	if len(enumeration.TLSVersions) != 0 || len(enumeration.CipherSuites) != 0 {
		t.Fatal("a server that never answered supports nothing we can claim")
	}
}

func TestEnumerateTLS_NonTLSServiceIsClassifiedNotWalked(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startRawTestServer(t, func(_ parsedTestClientHello, _ int) []byte {
		return []byte("SSH-2.0-OpenSSH_9.6\r\n")
	})
	defer stop()

	enumeration := enumerateForTest(t, host, port)
	if enumeration == nil {
		t.Fatal("enumeration returned nothing")
	}
	if enumeration.TruncatedReason != "not_tls" {
		t.Fatalf("want not_tls, got %q", enumeration.TruncatedReason)
	}
	if enumeration.Dials > 2 {
		t.Fatalf("a non-TLS service must be recognized at once, not walked: %d dials", enumeration.Dials)
	}
}

// The one exit that must leave Truncated false, and the one that never
// happened in the old tests because every server refused first.
func TestEnumerateTLS_ExhaustedOfferIsNotTruncated(t *testing.T) {
	t.Parallel()

	// A server accepting the whole offer would cost hundreds of dials, so this
	// exercises the same exit at the walk level with a tiny namespace: TLS 1.3
	// has seven candidates.
	host, port, _, stop := startRawTestServer(t, func(hello parsedTestClientHello, _ int) []byte {
		if hello.version != 0x0304 {
			return testAlertRecord(70)
		}
		if len(hello.suites) == 0 {
			return testAlertRecord(40)
		}
		return testServerHelloRecord(t, testServerHello{
			legacyVersion: 0x0303, supportedVersion: 0x0304, suite: hello.suites[0],
		})
	})
	defer stop()

	enumeration := enumerateForTest(t, host, port)
	if enumeration == nil {
		t.Fatal("enumeration returned nothing")
	}
	if enumeration.Truncated {
		t.Fatalf("consuming the offer is a complete answer, got %q", enumeration.TruncatedReason)
	}
	if len(enumeration.CipherSuites) != len(tlsRegistryTLS13SuiteIDs) {
		t.Fatalf("expected every TLS 1.3 candidate, got %v", enumeration.CipherSuites)
	}
}

// Both halves of the contract. The old test for this passed for the wrong
// reason: the nil it asserted came from the caller returning early, so it would
// still have passed had the enumerator returned an empty struct.
func TestEnumerateTLS_ReportsSilenceRatherThanClaimingNothing(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	enumeration := enumerateTLS(ctx, addr.IP.String(), "", addr.Port, TLSProbeOptions{})
	if enumeration == nil {
		t.Fatal("a walk that ran must report what it found, even when that is nothing")
	}
	if len(enumeration.CipherSuites) != 0 || len(enumeration.TLSVersions) != 0 {
		t.Fatalf("a service that never answered supports nothing we can claim: %+v", enumeration)
	}
	if !enumeration.Truncated || enumeration.TruncatedReason != "transport_failure" {
		t.Fatalf("silence must be recorded as partial, not as a clean empty result: %+v", enumeration)
	}
	// And the other half of the contract: nil means the walk never ran.
	if probeTLSDetails(ctx, addr.IP.String(), "", addr.Port, TLSProbeOptions{}).Enumeration != nil {
		t.Fatal("a service the probe never reached must carry no enumeration block at all")
	}
}

// Every hello in one walk must be identical outside the suite vector, or alert
// 40 cannot be attributed to the suites.
func TestEnumerateTLS_HoldsTheHelloConstantAcrossTheWalk(t *testing.T) {
	t.Parallel()

	host, port, server, stop := startRawTestServer(t, serverPreferenceHandler(t, []uint16{0xC02F, 0x0035, 0x009C}))
	defer stop()

	if enumerateForTest(t, host, port) == nil {
		t.Fatal("enumeration returned nothing")
	}

	byVersion := map[uint16]map[string]int{}
	for _, hello := range server.captured() {
		key := fmt.Sprintf("%v|%v|%q", hello.extensions[tlsExtSupportedGroups],
			hello.extensions[tlsExtSignatureAlgorithms], hello.sni)
		if byVersion[hello.version] == nil {
			byVersion[hello.version] = map[string]int{}
		}
		byVersion[hello.version][key]++
	}
	for version, shapes := range byVersion {
		if len(shapes) != 1 {
			t.Fatalf("version 0x%04X saw %d different hello shapes; a refusal cannot be attributed to the suites", version, len(shapes))
		}
	}
}

// --- units ---------------------------------------------------------------

func TestTLSEnumerationBudget(t *testing.T) {
	t.Parallel()

	spent := &tlsEnumerationBudget{maxDials: 1, deadline: time.Now().Add(time.Minute)}
	if !spent.take() {
		t.Fatal("the first dial must be allowed")
	}
	if spent.take() {
		t.Fatal("a dial past the cap must be refused")
	}
	if spent.stopped != "dial_budget" {
		t.Fatalf("expected dial_budget, got %q", spent.stopped)
	}

	expired := &tlsEnumerationBudget{maxDials: 100, deadline: time.Now().Add(-time.Second)}
	if expired.take() {
		t.Fatal("a dial past the deadline must be refused")
	}
	if expired.stopped != "time_budget" {
		t.Fatalf("expected time_budget, got %q", expired.stopped)
	}
	// A stopped budget keeps its first reason rather than being overwritten by
	// whatever is checked next.
	expired.stop("something_else")
	if expired.take() || expired.stopped != "time_budget" {
		t.Fatalf("a stopped budget must keep its original reason, got %q", expired.stopped)
	}
}

func TestRemoveTLSCipherSuite(t *testing.T) {
	t.Parallel()

	ids := []uint16{1, 2, 3}
	if got := removeTLSCipherSuite(ids, 2); len(got) != 2 || got[0] != 1 || got[1] != 3 {
		t.Fatalf("expected the named suite to be dropped, got %v", got)
	}
	// The condition the unoffered-suite guard tests for.
	if got := removeTLSCipherSuite(ids, 99); len(got) != len(ids) {
		t.Fatalf("removing an absent suite must leave the length unchanged, got %v", got)
	}
}

func TestTLSSuiteName(t *testing.T) {
	t.Parallel()

	if got := tlsSuiteName(0xC02F); got != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Fatalf("registry lookup: %q", got)
	}
	// Byte-identical to crypto/tls's own fallback, so an unknown suite renders
	// the same whichever side produced it.
	if got := tlsSuiteName(0xC0FF); got != "0xC0FF" {
		t.Fatalf("unknown suite: %q", got)
	}
	if got := tlsSuiteName(0x0A0A); !strings.HasPrefix(got, "GREASE") {
		t.Fatalf("GREASE must be named as such: %q", got)
	}
	// The registry must know the suites the withdrawn checks named and Go does
	// not implement -- that is the reason this table exists.
	for _, id := range []uint16{0x0088, 0x0084, 0xC013} {
		if strings.HasPrefix(tlsSuiteName(id), "0x") {
			t.Fatalf("0x%04X should be named by the registry, got %q", id, tlsSuiteName(id))
		}
	}
}

func TestTLSRegistryOffersAreClean(t *testing.T) {
	t.Parallel()

	if len(tlsRegistryLegacySuiteIDs) <= 25 {
		t.Fatalf("the legacy offer is %d suites; crypto/tls already implements 25", len(tlsRegistryLegacySuiteIDs))
	}
	for _, id := range tlsRegistryLegacySuiteIDs {
		if !tlsSuiteIsOfferable(id) {
			t.Fatalf("0x%04X must never be in an offer", id)
		}
		if id>>8 == 0x13 {
			t.Fatalf("0x%04X belongs to the TLS 1.3 namespace", id)
		}
	}
	for _, id := range tlsRegistryTLS13SuiteIDs {
		if id>>8 != 0x13 {
			t.Fatalf("0x%04X is not a TLS 1.3 suite", id)
		}
	}
	// Ascending, so an offer is reproducible and auditable.
	for i := 1; i < len(tlsRegistryLegacySuiteIDs); i++ {
		if tlsRegistryLegacySuiteIDs[i] <= tlsRegistryLegacySuiteIDs[i-1] {
			t.Fatalf("offer is not in ascending order at index %d", i)
		}
	}
}

func TestHighestLegacyVersion(t *testing.T) {
	t.Parallel()

	if got := highestLegacyVersion([]uint16{0x0304, 0x0301, 0x0303}); got != 0x0303 {
		t.Fatalf("want TLS 1.2, got 0x%04X", got)
	}
	if got := highestLegacyVersion([]uint16{0x0304}); got != 0 {
		t.Fatalf("TLS 1.3 alone leaves no legacy walk, got 0x%04X", got)
	}
	if got := highestLegacyVersion(nil); got != 0 {
		t.Fatalf("want 0, got 0x%04X", got)
	}
}

func hasAnomalyPrefix(anomalies []string, prefix string) bool {
	for _, entry := range anomalies {
		if strings.HasPrefix(entry, prefix) {
			return true
		}
	}
	return false
}

// --- guards that no earlier test forced to execute ------------------------
//
// Each of these covers a branch that would otherwise be dead code with a
// plausible comment: a reviewer already found one such guard in the crypto/tls
// enumerator that was not merely untested but unreachable, so its removal broke
// nothing. Every guard below is made to fire.

func TestEnumerateTLS_VersionMismatchIsNotRecordedAsSupport(t *testing.T) {
	t.Parallel()

	// Answers every pinned version with TLS 1.2. Only the 1.2 probe is an
	// honest answer; the rest are the server's fault and must not be counted.
	host, port, _, stop := startRawTestServer(t, func(hello parsedTestClientHello, _ int) []byte {
		if hello.version == 0x0304 {
			return testAlertRecord(40)
		}
		return testServerHelloRecord(t, testServerHello{legacyVersion: 0x0303, suite: 0x0035})
	})
	defer stop()

	enumeration := enumerateForTest(t, host, port)
	if enumeration == nil {
		t.Fatal("enumeration returned nothing")
	}
	for _, name := range enumeration.TLSVersions {
		if name == "TLS1.1" || name == "TLS1.0" {
			t.Fatalf("a server answering 1.2 to a 1.1 or 1.0 probe does not support them: %v", enumeration.TLSVersions)
		}
	}
	if !hasAnomalyPrefix(enumeration.Anomalies, "version_mismatch:") {
		t.Fatalf("the mismatch must be recorded: %v", enumeration.Anomalies)
	}
}

// Anomalies are a set, not a tally: a server that misbehaves the same way on
// every dial must not produce one entry per dial.
func TestEnumerateTLS_AnomaliesAreDeduplicated(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startRawTestServer(t, func(hello parsedTestClientHello, _ int) []byte {
		if hello.version == 0x0304 {
			return testAlertRecord(40)
		}
		return testServerHelloRecord(t, testServerHello{legacyVersion: 0x0303, suite: 0x0035})
	})
	defer stop()

	enumeration := enumerateForTest(t, host, port)
	if enumeration == nil {
		t.Fatal("enumeration returned nothing")
	}
	seen := map[string]int{}
	for _, entry := range enumeration.Anomalies {
		seen[entry]++
		if seen[entry] > 1 {
			t.Fatalf("anomaly %q recorded %d times", entry, seen[entry])
		}
	}
}

// The suite walk's own transport and probe-rejection exits, which the version
// walk's tests do not reach.
func TestEnumerateSuites_TransportFailureDuringTheWalk(t *testing.T) {
	t.Parallel()

	answers := []uint16{0x0035, 0xC02F}
	var dials atomic.Int32
	host, port, _, stop := startRawTestServer(t, func(hello parsedTestClientHello, _ int) []byte {
		index := int(dials.Add(1))
		if index > len(answers) {
			return nil // accept and close, mid-walk
		}
		return testServerHelloRecord(t, testServerHello{legacyVersion: hello.version, suite: answers[index-1]})
	})
	defer stop()

	enumerator := newTestEnumerator(host, port, 16)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	enumerator.enumerateSuites(ctx, []uint16{0x0035, 0xC02F, 0x009C}, 0x0303)
	if enumerator.budget.stopped != "transport_failure" {
		t.Fatalf("want transport_failure, got %q", enumerator.budget.stopped)
	}
}

func TestEnumerateSuites_ProbeRejectionDuringTheWalk(t *testing.T) {
	t.Parallel()

	var dials atomic.Int32
	host, port, _, stop := startRawTestServer(t, func(hello parsedTestClientHello, _ int) []byte {
		if int(dials.Add(1)) > 1 {
			return testAlertRecord(109) // missing_extension: our hello, not their suites
		}
		return testServerHelloRecord(t, testServerHello{legacyVersion: hello.version, suite: 0x0035})
	})
	defer stop()

	enumerator := newTestEnumerator(host, port, 16)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	accepted := enumerator.enumerateSuites(ctx, []uint16{0x0035, 0xC02F, 0x009C}, 0x0303)
	if enumerator.budget.stopped != "probe_rejected" {
		t.Fatalf("want probe_rejected, got %q", enumerator.budget.stopped)
	}
	if len(accepted) != 1 {
		t.Fatalf("only the suite actually selected may be kept, got %v", accepted)
	}
}

// Both walks must stop on the budget rather than run past it, and each must
// leave the reason behind.
func TestEnumerate_BudgetStopsBothWalks(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startRawTestServer(t, serverPreferenceHandler(t, []uint16{0x0035, 0xC02F, 0x009C, 0x0088}))
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	suiteWalk := newTestEnumerator(host, port, 2)
	suiteWalk.enumerateSuites(ctx, []uint16{0x0035, 0xC02F, 0x009C, 0x0088}, 0x0303)
	if suiteWalk.budget.stopped != "dial_budget" || suiteWalk.budget.dials != 2 {
		t.Fatalf("suite walk: stopped=%q dials=%d", suiteWalk.budget.stopped, suiteWalk.budget.dials)
	}

	versionWalk := newTestEnumerator(host, port, 1)
	versions := versionWalk.enumerateVersions(ctx)
	if versionWalk.budget.stopped != "dial_budget" {
		t.Fatalf("version walk: stopped=%q", versionWalk.budget.stopped)
	}
	if len(versions) > 1 {
		t.Fatalf("a one-dial budget cannot establish %d versions", len(versions))
	}
}

func newTestEnumerator(host string, port int, maxDials int) *tlsEnumerator {
	return &tlsEnumerator{
		target: host,
		port:   port,
		budget: &tlsEnumerationBudget{maxDials: maxDials, deadline: time.Now().Add(time.Minute)},
	}
}

func TestClassifyRawTransportError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err   error
		stage string
		want  string
	}{
		{nil, "read", ""},
		{errRawNotTLS, "read", "not_tls"},
		{fmt.Errorf("wrapped: %w", errRawMalformed), "read", "malformed"},
		{errRawDuplicateExtension, "read", "malformed"},
		{errRawNonAdvancingPeer, "read", "peer_exceeded_budget"},
		{errRawTooManyRecords, "read", "peer_exceeded_budget"},
		{io.EOF, "read", "eof_before_record"},
		{io.ErrUnexpectedEOF, "read", "eof_mid_record"},
		{context.DeadlineExceeded, "read", "read_deadline"},
		{errors.New("boom"), "connect", "connect_failed"},
		{errors.New("boom"), "write", "write_failed"},
	}
	for _, tc := range cases {
		if got := classifyRawTransportError(tc.err, tc.stage); got != tc.want {
			t.Fatalf("classify(%v, %s): want %q, got %q", tc.err, tc.stage, tc.want, got)
		}
	}
}

// Our own hello being wrong is a bug on this side and must never be recorded
// against the server as a refusal.
func TestDialRawTLS_HelloBuildFailureIsNotAServerVerdict(t *testing.T) {
	t.Parallel()

	outcome := dialRawTLSForServerHello(context.Background(), "127.0.0.1", "", 1, nil, 0x0303, TLSProbeOptions{})
	if outcome.Transport != "hello_build_failed" {
		t.Fatalf("want hello_build_failed, got %q", outcome.Transport)
	}
	if outcome.Flight.Kind != "" {
		t.Fatalf("no flight may be claimed, got %q", outcome.Flight.Kind)
	}
}
