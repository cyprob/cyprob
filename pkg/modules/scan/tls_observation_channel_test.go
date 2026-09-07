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
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// cyprob#304 and cyprob#295. Two different servers were invisible for two
// different reasons -- one refuses the version, the other refuses the suites --
// and neither could be seen by lowering only one of the two.

func TestBuildTLSObservationStrategy(t *testing.T) {
	t.Parallel()

	strategy := buildTLSObservationStrategy("")
	if strategy.name != tlsObservationStrategyName {
		t.Fatalf("unexpected strategy name %q", strategy.name)
	}
	if !strategy.observation {
		t.Fatal("the channel's strategy must be marked as observation")
	}
	if strategy.useSNI {
		t.Fatal("an empty hostname must not be sent as SNI")
	}
	if strategy.forceTLS12 {
		t.Fatal("the channel must not lower the ceiling")
	}
	if buildTLSObservationStrategy("192.0.2.10").useSNI {
		t.Fatal("an IP literal must not be sent as SNI")
	}
	if !buildTLSObservationStrategy("weak.test").useSNI {
		t.Fatal("a real hostname must still be sent as SNI, so the right certificate is observed")
	}
}

func TestApplyTLSObservationConfig(t *testing.T) {
	t.Parallel()

	config := &tls.Config{MinVersion: tls.VersionTLS12} //nolint:gosec // exercising the widening
	applyTLSObservationConfig(config)

	if config.MinVersion != tls.VersionTLS10 {
		t.Fatalf("floor was not lowered: %#x", config.MinVersion)
	}
	if config.MaxVersion != 0 {
		t.Fatalf("the ceiling must be left alone, got %#x", config.MaxVersion)
	}
	if len(config.CipherSuites) != len(tls.CipherSuites())+len(tls.InsecureCipherSuites()) {
		t.Fatalf("expected every implemented suite, got %d", len(config.CipherSuites))
	}

	seen := make(map[uint16]bool, len(config.CipherSuites))
	for _, id := range config.CipherSuites {
		seen[id] = true
	}
	// Both halves matter: the insecure ones are the point, and the default ones
	// must survive so a server offering a mix still gets its best suite.
	for _, suite := range tls.InsecureCipherSuites() {
		if !seen[suite.ID] {
			t.Fatalf("insecure suite %s missing", suite.Name)
		}
	}
	for _, suite := range tls.CipherSuites() {
		if !seen[suite.ID] {
			t.Fatalf("default suite %s was dropped", suite.Name)
		}
	}
}

// The strategy that lowers the ceiling used to be called "tls12-fallback",
// which read as though it lowered the floor. Nothing keyed on the old name.
func TestBuildTLSProbeStrategies_CeilingStrategyIsNamedForWhatItDoes(t *testing.T) {
	t.Parallel()

	for _, strategy := range buildTLSProbeStrategies("mail.example.com") {
		if strategy.name == "tls12-fallback" {
			t.Fatal("the ceiling strategy must not be named as a fallback")
		}
		if strategy.forceTLS12 && strategy.name != "tls12-ceiling" {
			t.Fatalf("unexpected name for the ceiling strategy: %q", strategy.name)
		}
		if strategy.observation {
			t.Fatal("no ordinary strategy may carry the observation flag")
		}
	}
}

func TestProbeTLSDetails_ObservesAServerThatOnlySpeaksTLS10(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startPinnedTLSServer(t, tls.VersionTLS10, nil)
	defer stop()

	result := probeTLSDetails(context.Background(), host, "", port, TLSProbeOptions{})
	assertObservedOnlyByTheChannel(t, result)

	if result.TLSVersion != "TLS1.0" {
		t.Fatalf("expected TLS1.0 to be observed, got %q", result.TLSVersion)
	}
	// The consequence that made this worth doing: weak_protocol could not be
	// true from this probe before, whatever the estate looked like.
	if !result.WeakProtocol {
		t.Fatal("an observed TLS 1.0 negotiation must set weak_protocol")
	}
	if result.CertSubjectCN != "obsolete.test" || result.CertSHA256 == "" {
		t.Fatalf("the certificate the refused handshake used to cost is still missing: %q %q",
			result.CertSubjectCN, result.CertSHA256)
	}
	if result.CertSerial == "" {
		t.Fatal("the certificate serial must be read on the channel too")
	}
}

func TestProbeTLSDetails_ObservesAServerThatOnlyOffersInsecureSuites(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startPinnedTLSServer(t, tls.VersionTLS12, []uint16{tls.TLS_RSA_WITH_RC4_128_SHA})
	defer stop()

	result := probeTLSDetails(context.Background(), host, "", port, TLSProbeOptions{})
	assertObservedOnlyByTheChannel(t, result)

	if !strings.Contains(result.CipherSuite, "RC4") {
		t.Fatalf("expected an RC4 suite to be observed, got %q", result.CipherSuite)
	}
	if !result.WeakCipher {
		t.Fatal("an observed RC4 negotiation must set weak_cipher")
	}
	if result.CertSubjectCN != "obsolete.test" {
		t.Fatalf("certificate was not read: %q", result.CertSubjectCN)
	}
}

// Lowering only the floor does not reach a suite-refusing server, and widening
// only the suites does not reach a version-refusing one. This is why the
// channel does both, and the test pins that: each server above is unreachable
// under the ordinary strategies, which is asserted, not assumed.
func assertObservedOnlyByTheChannel(t *testing.T, result TLSServiceInfo) {
	t.Helper()

	if !result.TLSProbe {
		t.Fatalf("service was not observed at all: %s (%+v)", result.ProbeError, result.Attempts)
	}
	var ordinaryFailed, channelSucceeded bool
	for _, attempt := range result.Attempts {
		if attempt.Strategy == tlsObservationStrategyName {
			channelSucceeded = channelSucceeded || attempt.Success
			continue
		}
		if !attempt.Success {
			ordinaryFailed = true
		}
	}
	if !ordinaryFailed {
		t.Fatal("an ordinary strategy reached this server, so it does not reproduce the defect and the test proves nothing")
	}
	if !channelSucceeded {
		t.Fatalf("the observation channel did not complete a handshake: %+v", result.Attempts)
	}
}

// A service the strict strategies already read must not be dialed again. The
// assertion is on the server's own handshake count, so an extra dial cannot
// hide behind the recorded attempts.
func TestProbeTLSDetails_HealthyServiceIsNotDialledByTheChannel(t *testing.T) {
	t.Parallel()

	host, port, handshakes, stop := startPinnedTLSServer(t, 0, nil)
	defer stop()

	result := probeTLSDetails(context.Background(), host, "", port, TLSProbeOptions{})
	if !result.TLSProbe {
		t.Fatalf("probe failed against a healthy server: %s", result.ProbeError)
	}
	for _, attempt := range result.Attempts {
		if attempt.Strategy == tlsObservationStrategyName {
			t.Fatalf("the channel dialed a service that was already read: %+v", result.Attempts)
		}
	}
	if got := handshakes.Load(); got != int32(len(result.Attempts)) {
		t.Fatalf("server saw %d handshakes for %d recorded attempts — an unrecorded dial happened",
			got, len(result.Attempts))
	}
}

// The channel must not turn a genuine failure into a success, and its own
// failure has to be recorded rather than swallowed.
func TestProbeTLSDetails_ChannelFailureIsStillAFailure(t *testing.T) {
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
	if result.ProbeError == "" {
		t.Fatal("a failed probe must carry an error")
	}
	var sawChannel bool
	for _, attempt := range result.Attempts {
		if attempt.Strategy == tlsObservationStrategyName {
			sawChannel = true
			if attempt.Success {
				t.Fatal("the channel cannot succeed against a closed port")
			}
		}
	}
	if !sawChannel {
		t.Fatalf("the channel's own attempt must be recorded even when it fails: %+v", result.Attempts)
	}
}

// startPinnedTLSServer serves a self-signed certificate. A zero version and a
// nil suite list give an ordinary healthy server; pinning either restricts what
// it will negotiate.
func startPinnedTLSServer(t *testing.T, version uint16, suites []uint16) (string, int, *atomic.Int32, func()) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(0x0B501E),
		Subject:               pkix.Name{CommonName: "obsolete.test"},
		DNSNames:              []string{"obsolete.test"},
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
		MinVersion:   tls.VersionTLS12,
	}
	if version != 0 {
		config.MinVersion = version
		config.MaxVersion = version
		config.CipherSuites = tlsObservationCipherSuiteIDs()
	}
	if len(suites) > 0 {
		config.CipherSuites = suites
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var handshakes atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			handshakes.Add(1)
			go func() {
				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.HandshakeContext(context.Background())
				}
				_ = conn.Close()
			}()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, &handshakes, func() {
		_ = ln.Close()
		<-done
	}
}
