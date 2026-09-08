package scan

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// cyprob#319: a certificate crypto/x509 refuses to parse kills the whole
// handshake, so the service was recorded as "handshake_failed" with nothing
// else -- indistinguishable from a service whose TLS is genuinely broken. The
// bar is not in tls.Config, so #307's deliberately wide observation channel
// fails on the same line as the strict strategies.
//
// It is also not one defect. Four non-conformances were measured, each with its
// own x509 error and each killing the handshake identically. All four are here,
// because a fix that only distinguishes the negative serial would leave three
// live cases reading as broken TLS.

type certParseCase struct {
	name       string
	mutate     func(*testing.T, []byte) []byte
	wantReason string
}

func certParseCases() []certParseCase {
	return []certParseCase{
		{
			name:       "negative serial",
			wantReason: "x509: negative serial number",
			// 0x1234 -> the two's complement of -0x1234 over the same width.
			mutate: swapExactlyOnce([]byte{0x02, 0x02, 0x12, 0x34}, []byte{0x02, 0x02, 0xED, 0xCC}),
		},
		{
			name:       "impossible month in notBefore",
			wantReason: "x509: malformed UTCTime",
			mutate:     swapExactlyOnce([]byte("260304050607Z"), []byte("261304050607Z")),
		},
		{
			name:       "BER boolean on a critical extension",
			wantReason: "x509: malformed extension critical field",
			// DER requires 0xFF for TRUE. Anchored on the keyUsage OID
			// 2.5.29.15, because "01 01 FF" alone appears on every critical
			// extension and the patch would land on whichever came first.
			mutate: swapExactlyOnce(
				[]byte{0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF},
				[]byte{0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0x01}),
		},
		{
			name:       "undefined certificate version",
			wantReason: "x509: invalid version",
			// [0] { INTEGER 2 } -> INTEGER 5. Anchored on the explicit tag, not
			// on "02 01 02", which occurs elsewhere in any certificate.
			mutate: swapExactlyOnce(
				[]byte{0xA0, 0x03, 0x02, 0x01, 0x02},
				[]byte{0xA0, 0x03, 0x02, 0x01, 0x05}),
		},
	}
}

// The whole point: the operator can tell our parser's refusal from a broken
// service, and can tell the four apart from each other.
func TestProbeTLSDetails_CertParseFamilyIsDistinguishable(t *testing.T) {
	t.Parallel()

	for _, tc := range certParseCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			host, port := startTLSServerWithUnparseableCert(t, tc.mutate, tc.wantReason)
			result := probeTLSDetails(context.Background(), host, "", port, TLSProbeOptions{
				TotalTimeout:   3 * time.Second,
				ConnectTimeout: time.Second,
				IOTimeout:      time.Second,
			})

			if result.TLSProbe {
				t.Fatal("no handshake completed, so nothing may claim one")
			}
			if result.ProbeError != "cert_parse_failed" {
				t.Fatalf("ProbeError: want cert_parse_failed, got %q", result.ProbeError)
			}
			// The reason, not just the code. Without this assertion three of
			// these four subtests would pass while collapsing onto one x509
			// rule.
			if result.CertParseError != tc.wantReason {
				t.Fatalf("CertParseError: want %q, got %q", tc.wantReason, result.CertParseError)
			}
			if len(result.Attempts) == 0 {
				t.Fatal("no attempt was recorded, so this test asserts nothing")
			}
			// Including the observation channel, which is the claim #307 made
			// and this issue contradicts: the wide channel refuses these too.
			sawObservation := false
			for _, attempt := range result.Attempts {
				if attempt.Error != "cert_parse_failed" {
					t.Fatalf("attempt %q: want cert_parse_failed, got %q", attempt.Strategy, attempt.Error)
				}
				if attempt.CertParseError != tc.wantReason {
					t.Fatalf("attempt %q reason: want %q, got %q", attempt.Strategy, tc.wantReason, attempt.CertParseError)
				}
				if attempt.Strategy == "tls-observation" {
					sawObservation = true
				}
			}
			if !sawObservation {
				t.Fatal("the observation channel must have run and must have failed too")
			}
		})
	}
}

// A probe that times out on one strategy and meets an unreadable certificate on
// the next must not report a certificate reason against the timeout. This is
// the misattribution the issue is about, one level down -- and it proves the
// priority ranking against a real mixed outcome rather than against a list.
func TestProbeTLSDetails_CertParseReasonBelongsToItsOwnAttempt(t *testing.T) {
	t.Parallel()

	tc := certParseCases()[0]
	host, port := startTLSServerWithUnparseableCert(t, tc.mutate, tc.wantReason, blackholeFirstConnection())

	result := probeTLSDetails(context.Background(), host, "", port, TLSProbeOptions{
		TotalTimeout:   6 * time.Second,
		ConnectTimeout: time.Second,
		IOTimeout:      300 * time.Millisecond,
	})

	if len(result.Attempts) < 2 {
		t.Fatalf("want a mixed outcome across at least two attempts, got %d", len(result.Attempts))
	}
	first := result.Attempts[0]
	if first.Error == "cert_parse_failed" {
		t.Fatalf("the first attempt was blackholed, so it cannot have read a certificate: %+v", first)
	}
	if first.CertParseError != "" {
		t.Fatalf("a non-certificate failure carries no certificate reason, got %q", first.CertParseError)
	}

	sawParse := false
	for _, attempt := range result.Attempts[1:] {
		if attempt.Error == "cert_parse_failed" {
			sawParse = true
			if attempt.CertParseError != tc.wantReason {
				t.Fatalf("attempt %q reason: want %q, got %q", attempt.Strategy, tc.wantReason, attempt.CertParseError)
			}
		}
	}
	if !sawParse {
		t.Fatal("no attempt met the unreadable certificate, so this test proves nothing")
	}

	// cert_parse_failed outranks timeout: it is the only code here backed by
	// bytes we received and identified.
	if result.ProbeError != "cert_parse_failed" {
		t.Fatalf("ProbeError: want cert_parse_failed, got %q", result.ProbeError)
	}
	if result.CertParseError != tc.wantReason {
		t.Fatalf("CertParseError: want %q, got %q", tc.wantReason, result.CertParseError)
	}
}

// A refusal the server sends is not a certificate we could not read. These
// three are real refusals -- nginx with ssl_verify_client on, alerts 42/48/45 --
// and misfiling them as a parse failure would invert the cyprob-ee#417 flag
// decision, which treats handshake_failed as evidence and an unknown code as
// none.
func TestClassifyTLSProbeError_ServerRefusalsAreNotParseFailures(t *testing.T) {
	t.Parallel()

	for _, text := range []string{
		"remote error: tls: bad certificate",
		"remote error: tls: unknown certificate authority",
		"remote error: tls: expired certificate",
		"remote error: tls: handshake failure",
	} {
		t.Run(text, func(t *testing.T) {
			t.Parallel()
			if got := classifyTLSProbeError(errorString(text)); got != "handshake_failed" {
				t.Fatalf("%q: want handshake_failed, got %q", text, got)
			}
		})
	}
}

func TestClassifyTLSProbeError_ParseFailuresAreTheirOwnCode(t *testing.T) {
	t.Parallel()

	for _, tc := range certParseCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := errorString("tls: failed to parse certificate from server: " + tc.wantReason)
			if got := classifyTLSProbeError(err); got != "cert_parse_failed" {
				t.Fatalf("want cert_parse_failed, got %q", got)
			}
			if got := certParseReason(err); got != tc.wantReason {
				t.Fatalf("reason: want %q, got %q", tc.wantReason, got)
			}
		})
	}
}

func TestPickTopTLSProbeError_CertParseOutranksTimeout(t *testing.T) {
	t.Parallel()

	for _, codes := range [][]string{
		{"timeout", "cert_parse_failed"},
		{"cert_parse_failed", "timeout"},
		{"probe_failed", "cert_parse_failed", "refused", "timeout"},
	} {
		if got := pickTopTLSProbeError(codes); got != "cert_parse_failed" {
			t.Fatalf("%v: want cert_parse_failed, got %q", codes, got)
		}
	}
}

// The reason only reaches a plugin or a JSONB query through this key, and
// extractNativeProbePayload copies map keys verbatim without ever exercising a
// struct tag.
func TestTLSProbeAttempt_CertParseErrorWireName(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(TLSProbeAttempt{Error: "cert_parse_failed", CertParseError: "x509: invalid version"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["cert_parse_error"] != "x509: invalid version" {
		t.Fatalf("the key is cert_parse_error; payload was %s", payload)
	}

	service, err := json.Marshal(TLSServiceInfo{ProbeError: "cert_parse_failed", CertParseError: "x509: invalid version"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(service, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["cert_parse_error"] != "x509: invalid version" {
		t.Fatalf("the service key is cert_parse_error; payload was %s", service)
	}

	// And absent when there is nothing to say, for the same reason
	// cyprob-ee#388 required of the timestamps.
	empty, err := json.Marshal(TLSProbeAttempt{Error: "timeout"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(empty), "cert_parse_error") {
		t.Fatalf("cert_parse_error must be absent on a non-certificate failure, got %s", empty)
	}
}

// swapExactlyOnce replaces a byte pattern in the DER, refusing to change its
// length and refusing to fire on anything but a unique match. A patch that
// shifts a length breaks the enclosing structure, and the certificate is then
// refused for a reason that has nothing to do with the field under test.
func swapExactlyOnce(old, replacement []byte) func(*testing.T, []byte) []byte {
	return func(t *testing.T, der []byte) []byte {
		t.Helper()
		if len(old) != len(replacement) {
			t.Fatalf("mutation changes length %d -> %d", len(old), len(replacement))
		}
		if n := bytes.Count(der, old); n != 1 {
			t.Fatalf("pattern %X occurs %d times in the certificate, want exactly 1", old, n)
		}
		return bytes.Replace(der, old, replacement, 1)
	}
}

type unparseableCertOption func(*unparseableCertServer)

type unparseableCertServer struct {
	blackholeFirst bool
}

// blackholeFirstConnection accepts the first connection and never answers it,
// so the first strategy times out and a later one meets the certificate.
func blackholeFirstConnection() unparseableCertOption {
	return func(s *unparseableCertServer) { s.blackholeFirst = true }
}

// startTLSServerWithUnparseableCert serves a certificate that crypto/x509
// refuses. The self-check asserts that ParseCertificate FAILS with the expected
// reason: a patch that did not land would otherwise leave a perfectly good
// certificate on the wire and every assertion below would be vacuous.
func startTLSServerWithUnparseableCert(
	t *testing.T,
	mutate func(*testing.T, []byte) []byte,
	wantReason string,
	options ...unparseableCertOption,
) (string, int) {
	t.Helper()

	settings := &unparseableCertServer{}
	for _, option := range options {
		option(settings)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234),
		Subject:      pkix.Name{CommonName: "unparseable.test"},
		DNSNames:     []string{"unparseable.test"},
		// Fixed rather than relative: the UTCTime mutation patches these bytes
		// by value, and "now" would move them.
		NotBefore:             time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
		NotAfter:              time.Date(2027, 3, 4, 5, 6, 7, 0, time.UTC),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	der = mutate(t, der)

	if _, err := x509.ParseCertificate(der); err == nil {
		t.Fatal("the mutation did not land: this certificate still parses, so the test would prove nothing")
	} else if err.Error() != wantReason {
		t.Fatalf("the mutation landed on the wrong rule: want %q, got %q", wantReason, err.Error())
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	config := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS10,
	}
	var accepted atomic.Int32
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			if settings.blackholeFirst && accepted.Add(1) == 1 {
				// Held open and never answered, then dropped well after the
				// client's IO deadline.
				go func() {
					time.Sleep(3 * time.Second)
					_ = conn.Close()
				}()
				continue
			}
			go func() {
				tlsConn := tls.Server(conn, config)
				_ = tlsConn.HandshakeContext(context.Background())
				_ = tlsConn.Close()
			}()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}
