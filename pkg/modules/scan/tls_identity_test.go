package scan

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeriveTLSCertIdentity_RecognizedAppliances(t *testing.T) {
	cases := []struct {
		name        string
		subjectCN   string
		issuerDN    string
		wantVendor  string
		wantProduct string
	}{
		{
			name:        "appliance names itself in the subject",
			subjectCN:   "FortiGate",
			issuerDN:    "CN=FortiGate,O=Fortinet Ltd.,C=US",
			wantVendor:  "Fortinet",
			wantProduct: "FortiGate",
		},
		{
			name:       "vendor only in the issuer organization",
			subjectCN:  "device.local",
			issuerDN:   "CN=UniFi,O=Ubiquiti Inc.,C=US",
			wantVendor: "Ubiquiti",
			// UniFi is matched before the generic ubiquiti marker.
			wantProduct: "UniFi",
		},
		{
			name:        "server management controller",
			subjectCN:   "iDRAC-ABC123",
			issuerDN:    "CN=iDRAC default certificate,O=Dell Inc.",
			wantVendor:  "Dell",
			wantProduct: "iDRAC",
		},
		{
			name:        "hypervisor management",
			subjectCN:   "vcenter.corp.local",
			issuerDN:    "CN=CA,O=VMware",
			wantVendor:  "VMware",
			wantProduct: "vCenter",
		},
		{
			name:        "case insensitive",
			subjectCN:   "PFSENSE-01",
			issuerDN:    "CN=pfSense-selfsigned",
			wantVendor:  "Netgate",
			wantProduct: "pfSense",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vendor, product := deriveTLSCertIdentity(tc.subjectCN, tc.issuerDN)
			require.Equal(t, tc.wantVendor, vendor)
			require.Equal(t, tc.wantProduct, product)
		})
	}
}

// A certificate CN is usually just a hostname. Deriving a vendor from an
// unrecognized one would invent identity, so nothing must be asserted.
func TestDeriveTLSCertIdentity_AssertsNothingWhenUnrecognized(t *testing.T) {
	cases := []struct{ subjectCN, issuerDN string }{
		{"www.example.com", "CN=R3,O=Let's Encrypt,C=US"},
		{"mail.acme.com.tr", "CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert Inc"},
		{"localhost", "CN=localhost"},
		{"", ""},
		{"   ", "  "},
	}
	for _, tc := range cases {
		vendor, product := deriveTLSCertIdentity(tc.subjectCN, tc.issuerDN)
		require.Emptyf(t, vendor, "must not invent a vendor for %q / %q", tc.subjectCN, tc.issuerDN)
		require.Empty(t, product)
	}
}

// Short markers must not match inside unrelated words. "ilo" occurs in "pilot",
// "silo" and "kilo"; a naive substring match labeled all of them HPE iLO.
func TestDeriveTLSCertIdentity_ShortMarkersDoNotMatchMidWord(t *testing.T) {
	for _, cn := range []string{"pilot.example.com", "silo-01.corp", "kilo.internal", "philology.edu"} {
		vendor, product := deriveTLSCertIdentity(cn, "CN=R3,O=Let's Encrypt")
		require.Emptyf(t, vendor, "%s must not be identified as a device", cn)
		require.Empty(t, product)
	}

	// The suffixed forms devices really use must still match.
	for _, cn := range []string{"ilo5-server", "ILO4", "iLO-ABC123"} {
		vendor, product := deriveTLSCertIdentity(cn, "")
		require.Equalf(t, "HPE", vendor, "%s should identify as HPE iLO", cn)
		require.Equal(t, "iLO", product)
	}
}

func TestDeriveTLSCertIdentity_PrefersMostSpecificMarker(t *testing.T) {
	// "fortigate" must win over the generic "fortinet" entry.
	vendor, product := deriveTLSCertIdentity("FortiGate-100F", "O=Fortinet")
	require.Equal(t, "Fortinet", vendor)
	require.Equal(t, "FortiGate", product)

	// A Fortinet cert with no product marker yields the vendor alone.
	vendor, product = deriveTLSCertIdentity("support", "O=Fortinet Ltd.")
	require.Equal(t, "Fortinet", vendor)
	require.Empty(t, product)
}
