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

// cyprob#295: a server that negotiates nothing outside Go's insecure list
// refuses the default ClientHello, and the refused handshake costs the
// certificate, the negotiated version and the banner along with the ciphers.
// The host with the weakest TLS configuration was the one the scan learned
// least about.

func TestTLSWidenedCipherSuiteIDs(t *testing.T) {
	t.Parallel()

	ids := tlsWidenedCipherSuiteIDs()
	seen := make(map[uint16]bool, len(ids))
	for _, id := range ids {
		seen[id] = true
	}

	if len(ids) != len(tls.CipherSuites())+len(tls.InsecureCipherSuites()) {
		t.Fatalf("expected every secure and insecure suite, got %d", len(ids))
	}
	// The list has to keep the default suites, not replace them: the retry must
	// still be able to negotiate a normal suite against a server that offers a
	// mix.
	for _, suite := range tls.CipherSuites() {
		if !seen[suite.ID] {
			t.Fatalf("default suite %s is missing from the widened list", suite.Name)
		}
	}
	for _, suite := range tls.InsecureCipherSuites() {
		if !seen[suite.ID] {
			t.Fatalf("insecure suite %s is missing from the widened list", suite.Name)
		}
	}
}

func TestBuildTLSInsecureSuiteStrategy(t *testing.T) {
	t.Parallel()

	if s := buildTLSInsecureSuiteStrategy(""); !s.insecureSuites || s.useSNI || s.name != "tls-insecure-suites" {
		t.Fatalf("unexpected strategy for an empty hostname: %+v", s)
	}
	if s := buildTLSInsecureSuiteStrategy("192.0.2.10"); s.useSNI {
		t.Fatal("an IP literal must not be sent as SNI")
	}
	if s := buildTLSInsecureSuiteStrategy("weak.test"); !s.useSNI {
		t.Fatal("a real hostname must still be sent as SNI on the retry")
	}
}

// The positive control and the fix in one test: the ordinary strategies must be
// seen to fail against this server — otherwise the test proves nothing about
// the retry — and the retry must then complete a full observation.
func TestProbeTLSDetails_ReachesServerOfferingOnlyInsecureSuites(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startWeakTLSServer(t, []uint16{tls.TLS_RSA_WITH_RC4_128_SHA}, tls.VersionTLS12)
	defer stop()

	result := probeTLSDetails(context.Background(), host, "", port, TLSProbeOptions{})
	if !result.TLSProbe {
		t.Fatalf("probe did not complete a handshake: %s (attempts: %+v)", result.ProbeError, result.Attempts)
	}

	var ordinaryFailed, insecureSucceeded bool
	for _, attempt := range result.Attempts {
		if attempt.Strategy == "tls-insecure-suites" {
			if attempt.Success {
				insecureSucceeded = true
			}
			continue
		}
		if !attempt.Success {
			ordinaryFailed = true
		}
	}
	if !ordinaryFailed {
		t.Fatal("no ordinary strategy failed, so this server does not reproduce the defect and the test proves nothing")
	}
	if !insecureSucceeded {
		t.Fatalf("the insecure-suite retry did not succeed: %+v", result.Attempts)
	}

	if !strings.Contains(result.CipherSuite, "RC4") {
		t.Fatalf("expected an RC4 suite to be negotiated, got %q", result.CipherSuite)
	}
	if !result.WeakCipher {
		t.Fatal("a negotiated RC4 suite must still be reported as a weak cipher")
	}
	// The point of the change is everything else the refused handshake was
	// taking down with it.
	if result.CertSubjectCN != "weak.test" {
		t.Fatalf("certificate was not read: subject %q", result.CertSubjectCN)
	}
	if result.CertSHA256 == "" {
		t.Fatal("certificate fingerprint was not read")
	}
	if result.TLSVersion == "" {
		t.Fatal("negotiated version was not recorded")
	}
}

// A healthy service must not pay for the retry. Asserted on the server's own
// handshake count, not only on the attempt list, so an extra dial cannot hide.
func TestProbeTLSDetails_HealthyServiceDoesNotDialTheRetry(t *testing.T) {
	t.Parallel()

	host, port, handshakes, stop := startWeakTLSServer(t, nil, 0)
	defer stop()

	result := probeTLSDetails(context.Background(), host, "", port, TLSProbeOptions{})
	if !result.TLSProbe {
		t.Fatalf("probe failed against a healthy server: %s", result.ProbeError)
	}
	for _, attempt := range result.Attempts {
		if attempt.Strategy == "tls-insecure-suites" {
			t.Fatalf("the retry ran against a healthy service: %+v", result.Attempts)
		}
	}
	if got := handshakes.Load(); got != int32(len(result.Attempts)) {
		t.Fatalf("server saw %d handshakes for %d recorded attempts — an unrecorded dial happened", got, len(result.Attempts))
	}
}

// The retry must not turn a genuine failure into a success, and its own failure
// has to be visible rather than swallowed.
func TestProbeTLSDetails_RetryFailureIsStillReportedAsFailure(t *testing.T) {
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
	var sawRetry bool
	for _, attempt := range result.Attempts {
		if attempt.Strategy == "tls-insecure-suites" {
			sawRetry = true
			if attempt.Success {
				t.Fatal("the retry cannot succeed against a closed port")
			}
		}
	}
	if !sawRetry {
		t.Fatalf("the retry attempt must be recorded even when it fails: %+v", result.Attempts)
	}
}

// startWeakTLSServer serves a self-signed certificate. A nil suite list and a
// zero maxVersion give an ordinary healthy server; naming suites restricts what
// it will negotiate.
func startWeakTLSServer(t *testing.T, suites []uint16, maxVersion uint16) (string, int, *atomic.Int32, func()) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(0x5EC0DE),
		Subject:               pkix.Name{CommonName: "weak.test"},
		DNSNames:              []string{"weak.test"},
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
	if len(suites) > 0 {
		config.CipherSuites = suites
	}
	if maxVersion != 0 {
		config.MaxVersion = maxVersion
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
