package parse

import (
	"reflect"
	"testing"
)

// The positive cases are the exact product strings the estate produced, not
// invented ones: `select distinct service_product from asset_services where
// service_product ~* 'management|ilo|idrac|imm|bmc'` on 10.20.30.252,
// 2026-09-08.
func TestManagementControllerTags_ProductStringsSeenInTheField(t *testing.T) {
	cases := []struct {
		name    string
		product string
		vendor  string
		want    []string
	}{
		{"iLO, nine services on 443", "iLO", "HPE", []string{TagBMC, TagILO}},
		{"iDRAC, one service on 443", "iDRAC", "Dell", []string{TagBMC, TagIDRAC}},
		{"IMM2, two services on 5985/5986", "Integrated Management Module II (IMM2)", "", []string{TagBMC, TagIMM}},
		{"long HPE form from a certificate", "Integrated Lights-Out 5", "", []string{TagBMC, TagILO}},
		{"long Dell form", "Integrated Dell Remote Access Controller", "", []string{TagBMC, TagIDRAC}},
		{"vendor field alone carries it", "", "Lenovo XClarity Controller", []string{TagBMC}},
		{"generic self-description", "Baseboard Management Controller", "", []string{TagBMC}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := managementControllerTags(tc.product, tc.vendor)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("managementControllerTags(%q, %q) = %v, want %v", tc.product, tc.vendor, got, tc.want)
			}
		})
	}
}

// Both of these are on the same estate as the controllers above, and both are
// the reason the marker table is an allowlist rather than a keyword search.
func TestManagementControllerTags_DeliberateExclusions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		product string
	}{
		{"a storage array is not a controller", "SAN Volume Controller"},
		{"a CIM broker also ships on ESXi and on Linux", "SFCB (Small Footprint CIM Broker)"},
		{"an ordinary web server", "nginx"},
		{"empty identity asserts nothing", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := managementControllerTags(tc.product, ""); got != nil {
				t.Fatalf("managementControllerTags(%q) = %v, want nil", tc.product, got)
			}
		})
	}
}

// "ilo" is three characters and occurs inside ordinary words. A substring match
// would label all of these HPE controllers; the word-start rule is the only
// thing preventing it, so it is asserted here rather than assumed.
func TestManagementControllerTags_ShortMarkerDoesNotMatchInsideWords(t *testing.T) {
	for _, product := range []string{"pilot", "silo-01", "kilo", "Philology Server", "Immich"} {
		if got := managementControllerTags(product, ""); got != nil {
			t.Fatalf("managementControllerTags(%q) = %v, want nil", product, got)
		}
	}
}

// Every tag the bridge emits has to survive NormalizeTechTag, which is an
// allowlist: a tag absent from the canonical set is dropped silently, so the
// bridge would run, match, and change nothing. This is the failure the bridge
// was written to fix, one layer down.
func TestManagementControllerTags_AllEmittedTagsAreCanonical(t *testing.T) {
	for _, marker := range managementControllerMarkers {
		for _, tag := range marker.tags {
			if _, ok := NormalizeTechTag(tag); !ok {
				t.Fatalf("marker %q emits %q, which NormalizeTechTag drops", marker.marker, tag)
			}
		}
	}
}
