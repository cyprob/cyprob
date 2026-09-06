package scan

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// cyprob-ee#388: a TLS probe that could not read a certificate used to serialize
// its zero time.Time as "0001-01-01T00:00:00Z", because encoding/json's
// omitempty does not omit a zero struct - only omitzero does. Downstream, that
// string parsed as a valid instant in year 1 and was compared against now, so a
// service whose certificate could not be read was reported as having an expired
// one. Measured on an appliance: two false "expired certificate" findings in
// five consecutive scans against a server presenting a certificate valid to 2027.
func TestTLSServiceInfo_ZeroCertificateTimestampsAreOmitted(t *testing.T) {
	payload, err := json.Marshal(TLSServiceInfo{TLSVersion: "TLS1.3"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	body := string(payload)
	for _, field := range []string{"cert_not_before", "cert_not_after"} {
		if strings.Contains(body, field) {
			t.Errorf("%s must be absent when the probe read no certificate, got %s", field, body)
		}
	}
	if strings.Contains(body, "0001-01-01") {
		t.Errorf("a zero timestamp must never reach the payload, got %s", body)
	}
}

// The opposite direction: a certificate the probe did read must still be carried,
// so the fix above cannot be satisfied by dropping the field altogether.
func TestTLSServiceInfo_RealCertificateTimestampsSurvive(t *testing.T) {
	notAfter := time.Date(2027, 9, 6, 21, 44, 4, 0, time.UTC)
	payload, err := json.Marshal(TLSServiceInfo{CertNotAfter: notAfter})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(payload), "2027-09-06T21:44:04Z") {
		t.Errorf("a certificate the probe read must be carried, got %s", string(payload))
	}
}
