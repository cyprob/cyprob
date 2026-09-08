package scan

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// cyprob#302: this encoding existed in three byte-identical copies — here, and
// twice in cyprob-ee — and dropped the sign in all three. It now lives once.

func TestFormatCertificateSerial(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		serial *big.Int
		want   string
	}{
		{"nil", nil, ""},
		{"zero renders as absent, not as 00", big.NewInt(0), ""},
		{"single byte", big.NewInt(1), "01"},
		{"multi byte, uppercase and colon separated", big.NewInt(0x0a1b2c), "0A:1B:2C"},
		{"leading zero byte is not carried", big.NewInt(0x00ff), "FF"},
		{"long serial keeps every byte", new(big.Int).SetBytes([]byte{
			0x4f, 0x9f, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef,
		}), "4F:9F:00:01:DE:AD:BE:EF"},
		{"negative serial keeps its sign", big.NewInt(-0x1234), "-12:34"},
		{"negative single byte", big.NewInt(-1), "-01"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := FormatCertificateSerial(tc.serial); got != tc.want {
				t.Fatalf("FormatCertificateSerial: want %q, got %q", tc.want, got)
			}
		})
	}
}

// Two serials differing only in sign must not render identically. This is the
// property the sign branch exists for, and it is the one a magnitude-only
// encoding breaks; asserting the strings separately would still pass if both
// sides were wrong in the same direction.
func TestFormatCertificateSerial_SignIsDistinguishing(t *testing.T) {
	t.Parallel()

	magnitude := new(big.Int).SetBytes([]byte{0x4f, 0x9f, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef})
	negated := new(big.Int).Neg(magnitude)

	if positive, negative := FormatCertificateSerial(magnitude), FormatCertificateSerial(negated); positive == negative {
		t.Fatalf("serials differing only in sign rendered identically: %q", positive)
	}
}

// The end-to-end direction, through a real handshake against a certificate that
// really carries a negative serial in its DER.
//
// Getting one is not straightforward, and the difficulty is itself the finding.
// x509.CreateCertificate refuses to mint a negative serial ("x509: serial
// number must be positive"), and since Go 1.23 ParseCertificate refuses to read
// one, which fails the entire handshake rather than just the serial:
//
//	tls: failed to parse certificate from server: x509: negative serial number
//
// Both cyprob and cyprob-ee build at go 1.25 with no godebug directive, so that
// rejection is the production default and no negative serial can reach
// FormatCertificateSerial through a handshake today. Enabling
// x509negativeserial is what makes this test able to exercise the branch at
// all — and, read the other way, what proves the branch is unreachable without
// it. See cyprob#319 for the reachable half of this: such a host is not
// scanned at all.
func TestProbeTLSDetails_NegativeSerialKeepsItsSign(t *testing.T) {
	t.Setenv("GODEBUG", "x509negativeserial=1")

	magnitude := []byte{0x4f, 0x9f, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef}
	host, port, stop := startTLSServerWithNegativeSerial(t, magnitude)
	defer stop()

	result := probeTLSDetails(context.Background(), host, "", port, TLSProbeOptions{})
	if !result.TLSProbe {
		t.Fatalf("handshake did not complete: %s", result.ProbeError)
	}
	if want := "-4F:9F:00:01:DE:AD:BE:EF"; result.CertSerial != want {
		t.Fatalf("CertSerial: want %q, got %q", want, result.CertSerial)
	}
}

// startTLSServerWithNegativeSerial mints a certificate carrying the positive
// serial, then rewrites that DER INTEGER in place as its two's complement over
// the same width — which is what a negative serial is on the wire. The
// signature no longer covers the tampered TBSCertificate, which does not matter
// here: the probe dials with InsecureSkipVerify, exactly as it does in the
// field.
func startTLSServerWithNegativeSerial(t *testing.T, magnitude []byte) (string, int, func()) {
	t.Helper()

	positive := new(big.Int).SetBytes(magnitude)
	width := uint(len(magnitude) * 8)
	twosComplement := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), width), positive)
	negated := twosComplement.Bytes()
	if len(negated) != len(magnitude) {
		t.Fatalf("two's complement changed width: %d vs %d bytes", len(negated), len(magnitude))
	}
	if negated[0] < 0x80 {
		t.Fatalf("two's complement %X does not have the sign bit set", negated)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          positive,
		Subject:               pkix.Name{CommonName: "negative-serial.test"},
		DNSNames:              []string{"negative-serial.test"},
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

	// DER INTEGER: tag 0x02, one length byte, then the value.
	before := append([]byte{0x02, byte(len(magnitude))}, magnitude...)
	after := append([]byte{0x02, byte(len(negated))}, negated...)
	if n := bytes.Count(der, before); n != 1 {
		t.Fatalf("serial %X appears %d times in the certificate, want exactly 1", magnitude, n)
	}
	der = bytes.Replace(der, before, after, 1)

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse patched certificate: %v", err)
	}
	if parsed.SerialNumber.Sign() >= 0 {
		t.Fatalf("patched certificate still carries a non-negative serial: %v", parsed.SerialNumber)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
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
	return addr.IP.String(), addr.Port, func() {
		_ = ln.Close()
		<-done
	}
}

// The production default, stated as a test so it is not rediscovered: without
// x509negativeserial, a negative serial does not reach the formatter — it fails
// the handshake, and the probe reports no certificate at all.
func TestProbeTLSDetails_NegativeSerialFailsTheHandshakeByDefault(t *testing.T) {
	magnitude := []byte{0x4f, 0x9f, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef}

	t.Setenv("GODEBUG", "x509negativeserial=1")
	host, port, stop := startTLSServerWithNegativeSerial(t, magnitude)
	defer stop()

	t.Setenv("GODEBUG", "")
	result := probeTLSDetails(context.Background(), host, "", port, TLSProbeOptions{})
	if result.TLSProbe {
		t.Fatalf("handshake completed against a negative serial; serial read as %q", result.CertSerial)
	}
	if result.CertSerial != "" {
		t.Fatalf("no certificate was read, so no serial may be reported, got %q", result.CertSerial)
	}
}
