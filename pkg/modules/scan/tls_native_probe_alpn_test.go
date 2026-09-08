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
	"strconv"
	"strings"
	"testing"
	"time"
)

// cyprob#306: TLSServiceInfo.ALPN had a JSON tag, a reader, a struct member and
// a report attribute, and could never hold a value — the probe read
// state.NegotiatedProtocol and never offered a protocol list, and Go leaves that
// empty unless the client advertises ALPN. "field, no producer".
//
// Offering it is not free, which is why the issue asked for a measurement rather
// than a one-line change. RFC 7301 lets a server that shares no application
// protocol abort with no_application_protocol, so a service the probe reads
// today can be lost by asking. Both directions are pinned here.

func TestProbeTLSDetails_ALPNIsNegotiatedAndReported(t *testing.T) {
	t.Parallel()

	host, port := startALPNServer(t, []string{"h2", "http/1.1"})
	result := probeTLSDetails(context.Background(), host, "", port, TLSProbeOptions{
		TotalTimeout:   3 * time.Second,
		ConnectTimeout: time.Second,
		IOTimeout:      time.Second,
	})

	if !result.TLSProbe {
		t.Fatalf("handshake did not complete: %s", result.ProbeError)
	}
	if result.ALPN != "h2" {
		t.Fatalf("ALPN: want h2, got %q", result.ALPN)
	}
}

// A server that does not configure ALPN at all is the common case, and it must
// still be read — with an honestly empty field rather than a guess.
func TestProbeTLSDetails_ServerWithoutALPNIsStillRead(t *testing.T) {
	t.Parallel()

	host, port := startALPNServer(t, nil)
	result := probeTLSDetails(context.Background(), host, "", port, TLSProbeOptions{
		TotalTimeout:   3 * time.Second,
		ConnectTimeout: time.Second,
		IOTimeout:      time.Second,
	})

	if !result.TLSProbe {
		t.Fatalf("handshake did not complete: %s", result.ProbeError)
	}
	if result.ALPN != "" {
		t.Fatalf("a server that negotiated no protocol must report none, got %q", result.ALPN)
	}
	if result.CipherSuite == "" || result.TLSVersion == "" {
		t.Fatal("the rest of the reading must be unaffected")
	}
}

// The measured hazard: a server configured with a protocol we do not offer
// refuses the handshake outright rather than negotiating nothing. The probe must
// not lose that service — it asks again without the question.
func TestProbeTLSDetails_ALPNRefusalDoesNotCostTheReading(t *testing.T) {
	t.Parallel()

	host, port := startALPNServer(t, []string{"imap"})

	// The hazard is real: offering ALPN to this server fails.
	direct, err := tls.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test server
		MinVersion:         tls.VersionTLS12,
		NextProtos:         tlsProbeALPNProtocols,
	})
	if err == nil {
		_ = direct.Close()
		t.Fatal("this server was supposed to refuse an ALPN offer it shares nothing with; the test proves nothing")
	}
	if !isALPNRefusal(err) {
		t.Fatalf("want a no_application_protocol refusal, got %v", err)
	}

	result := probeTLSDetails(context.Background(), host, "", port, TLSProbeOptions{
		TotalTimeout:   5 * time.Second,
		ConnectTimeout: time.Second,
		IOTimeout:      time.Second,
	})

	if !result.TLSProbe {
		t.Fatalf("the service must still be read after the ALPN offer was refused: %s", result.ProbeError)
	}
	if result.ALPN != "" {
		t.Fatalf("the retry offers nothing, so it can negotiate nothing, got %q", result.ALPN)
	}
	if result.CertSubjectCN != "alpn.test" {
		t.Fatalf("the certificate must be read on the retry, got %q", result.CertSubjectCN)
	}

	// Both dials stay in the record: the question that cost the handshake and
	// the one that did not.
	var refused, retried bool
	for _, attempt := range result.Attempts {
		if strings.HasSuffix(attempt.Strategy, "-no-alpn") {
			retried = true
			continue
		}
		if attempt.Error != "" {
			refused = true
		}
	}
	if !refused {
		t.Fatal("the ALPN-offering attempt must be recorded as failed")
	}
	if !retried {
		t.Fatalf("the retry must be recorded under its own strategy name, got %+v", result.Attempts)
	}
}

// The retry is for one refusal and not for failure in general. Without this the
// predicate can be widened to every error with the rest of the suite green, and
// every unreachable service would then be dialed twice per strategy — a
// footprint regression nothing would report.
func TestProbeTLSDetails_OrdinaryFailuresDoNotTriggerTheALPNRetry(t *testing.T) {
	t.Parallel()

	// Accepts and closes immediately: a handshake failure that has nothing to
	// do with application protocols.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	result := probeTLSDetails(context.Background(), addr.IP.String(), "", addr.Port, TLSProbeOptions{
		TotalTimeout:   3 * time.Second,
		ConnectTimeout: time.Second,
		IOTimeout:      500 * time.Millisecond,
	})

	if result.TLSProbe {
		t.Fatal("this server completes no handshake, so the test would prove nothing")
	}
	if len(result.Attempts) == 0 {
		t.Fatal("no attempt was recorded")
	}
	for _, attempt := range result.Attempts {
		if strings.HasSuffix(attempt.Strategy, "-no-alpn") {
			t.Fatalf("a failure that is not an ALPN refusal must not be retried, got %+v", result.Attempts)
		}
	}
}

// The observation channel exists to read services nothing else can, so it must
// never carry a question that can lose the answer.
func TestObservationStrategy_DoesNotOfferALPN(t *testing.T) {
	t.Parallel()

	if strategy := buildTLSObservationStrategy("example.test"); strategy.offerALPN {
		t.Fatal("the observation channel must not offer ALPN")
	}
	for _, strategy := range buildTLSProbeStrategies("example.test") {
		if !strategy.offerALPN {
			t.Fatalf("ordinary strategy %q must offer ALPN, or the field can never hold a value", strategy.name)
		}
	}
}

func startALPNServer(t *testing.T, serverProtocols []string) (string, int) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(0x0A1B2C),
		Subject:               pkix.Name{CommonName: "alpn.test"},
		DNSNames:              []string{"alpn.test"},
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

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   serverProtocols,
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.HandshakeContext(context.Background())
				}
				_ = conn.Close()
			}()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}
