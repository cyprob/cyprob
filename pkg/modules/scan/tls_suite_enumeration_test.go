package scan

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// cyprob#294. The negotiated suite says what this client and this server agreed
// on once; it says nothing about what else the server would have accepted, and
// that is the question a cipher-suite finding asks.

func TestEnumerateTLS_FindsExactlyTheServersSuitesByElimination(t *testing.T) {
	t.Parallel()

	offered := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_RC4_128_SHA,
	}
	host, port, srv, stop := startEnumerationTestServer(t, tls.VersionTLS12, tls.VersionTLS12, offered)
	defer stop()

	enumeration := enumerateTLS(context.Background(), host, "", port, TLSProbeOptions{})
	if enumeration == nil {
		t.Fatal("enumeration returned nothing against a reachable server")
	}

	want := make(map[string]bool, len(offered))
	for _, id := range offered {
		want[tls.CipherSuiteName(id)] = true
	}
	if len(enumeration.CipherSuites) != len(want) {
		t.Fatalf("expected %d suites, got %d: %v", len(want), len(enumeration.CipherSuites), enumeration.CipherSuites)
	}
	for _, name := range enumeration.CipherSuites {
		if !want[name] {
			t.Fatalf("enumerated a suite the server does not offer: %s", name)
		}
		delete(want, name)
	}

	// The cost is the point of elimination: k+1 dials for k suites, not one per
	// suite the client implements. Plus two for the version walk on a server
	// pinned to a single version.
	if enumeration.Dials != len(offered)+1+2 {
		t.Fatalf("expected %d dials (%d suites + 1 refusal + 2 version), got %d",
			len(offered)+3, len(offered), enumeration.Dials)
	}
	if enumeration.Dials >= enumeration.OfferedSuites {
		t.Fatalf("elimination cost %d dials against %d offerable suites — that is the naive walk",
			enumeration.Dials, enumeration.OfferedSuites)
	}
	if enumeration.Truncated {
		t.Fatalf("a complete walk must not be marked truncated: %s", enumeration.TruncatedReason)
	}

	// Every enumeration dial is cut at the server's first flight, so the server
	// never completes one. If any had completed, the walk would be paying for a
	// key exchange it has no use for.
	if srv.completed.Load() != 0 {
		t.Fatalf("%d enumeration handshakes ran to completion", srv.completed.Load())
	}
	if srv.accepted.Load() != int32(enumeration.Dials) {
		t.Fatalf("server saw %d connections for %d declared dials", srv.accepted.Load(), enumeration.Dials)
	}
}

func TestEnumerateTLS_WalksTheVersionsTheServerAccepts(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startEnumerationTestServer(t, tls.VersionTLS10, tls.VersionTLS12, nil)
	defer stop()

	enumeration := enumerateTLS(context.Background(), host, "", port, TLSProbeOptions{})
	if enumeration == nil {
		t.Fatal("enumeration returned nothing")
	}
	want := []string{"TLS1.2", "TLS1.1", "TLS1.0"}
	if len(enumeration.TLSVersions) != len(want) {
		t.Fatalf("expected %v, got %v", want, enumeration.TLSVersions)
	}
	for i, version := range want {
		if enumeration.TLSVersions[i] != version {
			t.Fatalf("expected %v, got %v", want, enumeration.TLSVersions)
		}
	}
}

// A TLS 1.3 server is where the naive loop never ends: Config.CipherSuites does
// not govern TLS 1.3, so the server picks a suite that was never in the offer,
// removing it eliminates nothing, and the walk asks the same question forever.
// The enumeration holds its ceiling at TLS 1.2 for exactly this reason.
func TestEnumerateTLS_TerminatesAgainstATLS13Server(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startEnumerationTestServer(t, tls.VersionTLS12, tls.VersionTLS13, nil)
	defer stop()

	done := make(chan *TLSEnumeration, 1)
	go func() {
		done <- enumerateTLS(context.Background(), host, "", port, TLSProbeOptions{})
	}()

	select {
	case enumeration := <-done:
		if enumeration == nil {
			t.Fatal("enumeration returned nothing")
		}
		if enumeration.TruncatedReason == "unexpected_suite" {
			t.Fatal("the walk hit a suite it never offered, so the TLS 1.2 ceiling is not being applied")
		}
		if enumeration.Dials >= defaultTLSEnumerationDialBudget {
			t.Fatalf("the walk only stopped because it ran out of budget: %d dials", enumeration.Dials)
		}
		for _, name := range enumeration.CipherSuites {
			if name == "TLS_AES_128_GCM_SHA256" || name == "TLS_AES_256_GCM_SHA384" || name == "TLS_CHACHA20_POLY1305_SHA256" {
				t.Fatalf("a TLS 1.3 suite cannot be enumerated through Config.CipherSuites: %s", name)
			}
		}
		// The version walk still sees 1.3, which is where that fact belongs.
		if len(enumeration.TLSVersions) == 0 || enumeration.TLSVersions[0] != "TLS1.3" {
			t.Fatalf("expected the version walk to report TLS1.3 first, got %v", enumeration.TLSVersions)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("enumeration did not terminate against a TLS 1.3 server")
	}
}

// A partial answer that does not say it is partial reads as a complete one.
func TestEnumerateTLSCipherSuites_TruncatesAgainstItsDialBudget(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startEnumerationTestServer(t, tls.VersionTLS12, tls.VersionTLS12, []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	})
	defer stop()

	budget := &tlsEnumerationBudget{maxDials: 2, deadline: time.Now().Add(time.Minute)}
	suites := enumerateTLSCipherSuites(context.Background(), host, "", port,
		tlsObservationCipherSuiteIDs(), budget, TLSProbeOptions{})

	if len(suites) != 2 {
		t.Fatalf("expected the walk to stop after 2 dials, got %d suites: %v", len(suites), suites)
	}
	if budget.stopped != "dial_budget" {
		t.Fatalf("expected the budget to record why it stopped, got %q", budget.stopped)
	}
}

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

	// A stopped budget stays stopped, and keeps the first reason rather than
	// being overwritten by whatever is checked next.
	if expired.take() || expired.stopped != "time_budget" {
		t.Fatalf("a stopped budget must stay stopped with its original reason, got %q", expired.stopped)
	}
}

// The guard behind TruncatedReason "unexpected_suite": if the server names
// something that was never offered, nothing can be removed and the walk cannot
// progress. This pins the condition the guard tests for.
func TestRemoveTLSCipherSuite(t *testing.T) {
	t.Parallel()

	ids := []uint16{1, 2, 3}
	if got := removeTLSCipherSuite(ids, 2); len(got) != 2 || got[0] != 1 || got[1] != 3 {
		t.Fatalf("expected the named suite to be dropped, got %v", got)
	}
	if got := removeTLSCipherSuite(ids, 99); len(got) != len(ids) {
		t.Fatalf("removing an absent suite must leave the length unchanged, got %v", got)
	}
}

// A service that was never reached must not be enumerated: there is nothing to
// ask and the budget would be spent discovering that.
func TestProbeTLSDetails_NoEnumerationWhenNothingAnswered(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	host, port := addr.IP.String(), addr.Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	result := probeTLSDetails(context.Background(), host, "", port, TLSProbeOptions{})
	if result.TLSProbe {
		t.Fatal("probe reported success against a closed port")
	}
	if result.Enumeration != nil {
		t.Fatalf("an unreachable service must not be enumerated: %+v", result.Enumeration)
	}
}

// The probe must actually run the enumeration, including for a service only
// the observation channel could reach -- which is the service most worth
// asking, and the one a failure-path-only trigger would have skipped.
func TestProbeTLSDetails_EnumeratesAServiceOnlyTheChannelCouldReach(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startEnumerationTestServer(t, tls.VersionTLS10, tls.VersionTLS10, nil)
	defer stop()

	result := probeTLSDetails(context.Background(), host, "", port, TLSProbeOptions{})
	if !result.TLSProbe {
		t.Fatalf("the channel did not reach a TLS 1.0-only server: %s", result.ProbeError)
	}
	if result.Enumeration == nil {
		t.Fatal("the probe did not enumerate a service it observed")
	}
	if len(result.Enumeration.CipherSuites) == 0 {
		t.Fatalf("expected the server's suites, got none: %+v", result.Enumeration)
	}
	if len(result.Enumeration.TLSVersions) != 1 || result.Enumeration.TLSVersions[0] != "TLS1.0" {
		t.Fatalf("expected exactly TLS1.0, got %v", result.Enumeration.TLSVersions)
	}
}

func TestProbeTLSDetails_EnumeratesAHealthyService(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startEnumerationTestServer(t, tls.VersionTLS12, tls.VersionTLS13, nil)
	defer stop()

	result := probeTLSDetails(context.Background(), host, "", port, TLSProbeOptions{})
	if !result.TLSProbe {
		t.Fatalf("probe failed against a healthy server: %s", result.ProbeError)
	}
	// Enumeration is not the channel: it asks its question of every service that
	// answered, because "what else would you accept" is exactly the question a
	// healthy server has an interesting answer to.
	if result.Enumeration == nil {
		t.Fatal("a healthy service must still be enumerated")
	}
	if len(result.Enumeration.CipherSuites) == 0 {
		t.Fatal("expected the healthy server's suites")
	}
}

type enumerationTestServer struct {
	accepted  atomic.Int32
	completed atomic.Int32
}

func startEnumerationTestServer(t *testing.T, minVersion, maxVersion uint16, suites []uint16) (string, int, *enumerationTestServer, func()) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(0xE17),
		Subject:               pkix.Name{CommonName: "enumerate.test"},
		DNSNames:              []string{"enumerate.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   minVersion,
		MaxVersion:   maxVersion,
	}
	if len(suites) > 0 {
		config.CipherSuites = suites
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := &enumerationTestServer{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			server.accepted.Add(1)
			go func() {
				if tlsConn, ok := conn.(*tls.Conn); ok {
					if tlsConn.HandshakeContext(context.Background()) == nil {
						server.completed.Add(1)
					}
				}
				_ = conn.Close()
			}()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, server, func() {
		_ = ln.Close()
		<-done
	}
}
