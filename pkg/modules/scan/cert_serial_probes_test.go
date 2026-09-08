package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// cyprob#303: six native probes read a certificate and feed one reader in
// cyprob-ee, which looks for the serial under "cert_serial"; five of them never
// emitted it. The serial now comes off engine.TLSObservation, which every one of
// them already fills, so the field has a single producer.

// The shared extraction, asserted against a certificate whose serial is known.
func TestExtractTLSObservation_CarriesTheCertificateSerial(t *testing.T) {
	t.Parallel()

	serial := new(big.Int).SetBytes([]byte{0x0b, 0x50, 0x1e, 0x00, 0x7f})
	leaf := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "obs.test"},
		Issuer:       pkix.Name{CommonName: "obs-ca.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	obs := extractTLSObservation(tls.ConnectionState{
		HandshakeComplete: true,
		Version:           tls.VersionTLS13,
		CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates:  []*x509.Certificate{leaf},
	})

	require.NotNil(t, obs)
	require.Equal(t, "0B:50:1E:00:7F", obs.CertSerial)
}

// A handshake that did not complete carries no certificate, so it must carry no
// serial either — the same rule cyprob-ee#388 established for the timestamps.
func TestExtractTLSObservation_NoHandshakeNoSerial(t *testing.T) {
	t.Parallel()

	require.Nil(t, extractTLSObservation(tls.ConnectionState{HandshakeComplete: false}))

	obs := extractTLSObservation(tls.ConnectionState{
		HandshakeComplete: true,
		Version:           tls.VersionTLS13,
	})
	require.NotNil(t, obs)
	require.Empty(t, obs.CertSerial, "no peer certificate was presented")
}

// Each of the five result structs has to put the serial on the wire under the
// key cyprob-ee reads. A correctly extracted serial under any other name
// reproduces the same empty column, so the key is asserted, not just the value.
func TestNativeProbeResults_SerializeCertSerialUnderTheKeyCyprobEEReads(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		value any
	}{
		{"rdp", RDPServiceInfo{CertSerial: testCertSerialFormatted}},
		{"smtp", SMTPServiceInfo{CertSerial: testCertSerialFormatted}},
		{"ftp", FTPServiceInfo{CertSerial: testCertSerialFormatted}},
		{"mysql", MySQLServiceInfo{CertSerial: testCertSerialFormatted}},
		{"winrm", WINRMServiceInfo{CertSerial: testCertSerialFormatted}},
		{"tls", TLSServiceInfo{CertSerial: testCertSerialFormatted}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			payload, err := json.Marshal(tc.value)
			require.NoError(t, err)

			var decoded map[string]any
			require.NoError(t, json.Unmarshal(payload, &decoded))
			require.Equal(t, testCertSerialFormatted, decoded["cert_serial"],
				"cyprob-ee reads cert_serial first; payload was %s", payload)
		})
	}
}

// And a probe that read no certificate must not put an empty serial on the wire.
func TestNativeProbeResults_AbsentCertSerialIsOmitted(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		value any
	}{
		{"rdp", RDPServiceInfo{}},
		{"smtp", SMTPServiceInfo{}},
		{"ftp", FTPServiceInfo{}},
		{"mysql", MySQLServiceInfo{}},
		{"winrm", WINRMServiceInfo{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			payload, err := json.Marshal(tc.value)
			require.NoError(t, err)

			var decoded map[string]any
			require.NoError(t, json.Unmarshal(payload, &decoded))
			_, present := decoded["cert_serial"]
			require.False(t, present, "cert_serial must be absent, got %s", payload)
		})
	}
}

// WinRM is the one of the five with no protocol-level TLS test server of its
// own. This drives the real HTTPS request path against a real handshake and
// asserts the serial the server actually presented, rather than a constant.
func TestExecuteWINRMRequest_HTTPSCarriesTheCertificateSerial(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/soap+xml; charset=UTF-8")
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <s:Body><wsmid:IdentifyResponse><wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor></wsmid:IdentifyResponse></s:Body>
</s:Envelope>`)
	}))
	defer server.Close()

	want := FormatCertificateSerial(server.Certificate().SerialNumber)
	require.NotEmpty(t, want, "the test server's certificate must carry a serial")

	host, port := httpTestTarget(t, server.URL)
	result, err := executeWINRMRequest(context.Background(), host, "winrm.tls.test", port, "https", WINRMProbeOptions{
		TotalTimeout:   2500 * time.Millisecond,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
	})
	require.NoError(t, err)
	require.NotNil(t, result.tlsObs)
	require.Equal(t, want, result.tlsObs.CertSerial)

	// And the step that used to drop it: the observation reaching the result.
	var info WINRMServiceInfo
	applyWINRMTLSObservation(&info, nil, result.tlsObs)
	require.Equal(t, want, info.CertSerial)
}
