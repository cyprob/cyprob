package scan

import (
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
	"testing"
	"time"
)

// cyprob#299: the TLS probe read seven certificate fields and never the serial,
// so cyprob-ee, which looks for it under "cert_serial", found it populated on 0
// of 99 TLS services while subject, issuer and expiry were populated on 40.

func TestFormatTLSCertSerial(t *testing.T) {
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
		// RFC 5280 requires a positive serial; certificates violating it exist,
		// and cyprob-ee renders them by magnitude, so this side must agree.
		{"negative serial is rendered by magnitude", big.NewInt(-0x1234), "12:34"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := formatTLSCertSerial(tc.serial); got != tc.want {
				t.Fatalf("formatTLSCertSerial: want %q, got %q", tc.want, got)
			}
		})
	}
}

// The end-to-end direction: a real handshake against a certificate with a known
// serial must put that serial on TLSServiceInfo, under the JSON key cyprob-ee
// reads. Asserting the wire key matters as much as the value — the consumer
// keys on "cert_serial", so a correctly extracted serial under any other name
// reproduces the same zero.
func TestProbeTLSDetails_EmitsCertificateSerial(t *testing.T) {
	t.Parallel()

	serial := new(big.Int).SetBytes([]byte{0x4f, 0x9f, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef})
	host, port, stop := startTLSServerWithSerial(t, serial)
	defer stop()

	result := probeTLSDetails(context.Background(), host, "", port, TLSProbeOptions{})
	if !result.TLSProbe {
		t.Fatalf("handshake did not complete: %s", result.ProbeError)
	}
	if result.CertSerial != "4F:9F:00:01:DE:AD:BE:EF" {
		t.Fatalf("CertSerial: want 4F:9F:00:01:DE:AD:BE:EF, got %q", result.CertSerial)
	}
	if result.CertSHA256 == "" {
		t.Fatal("CertSHA256 must still be read alongside the serial")
	}

	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["cert_serial"] != "4F:9F:00:01:DE:AD:BE:EF" {
		t.Fatalf("cyprob-ee reads the key \"cert_serial\"; payload carries %v", decoded["cert_serial"])
	}
}

// A probe that read no certificate must not put an empty serial on the wire,
// for the same reason cyprob-ee#388 required of the timestamps.
func TestTLSServiceInfo_AbsentSerialIsOmitted(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(TLSServiceInfo{TLSVersion: "TLS1.3"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(payload), "cert_serial") {
		t.Fatalf("cert_serial must be absent when no certificate was read, got %s", payload)
	}
}

func startTLSServerWithSerial(t *testing.T, serial *big.Int) (string, int, func()) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "serial.test"},
		DNSNames:              []string{"serial.test"},
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
