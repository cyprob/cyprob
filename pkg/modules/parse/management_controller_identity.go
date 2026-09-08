package parse

import (
	"strings"

	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
)

// managementControllerMarker maps a distinctive string in a service's product or
// vendor field to the routing tags for that controller.
type managementControllerMarker struct {
	// marker is matched case-insensitively at a word start against the product
	// and vendor fields.
	marker string
	tags   []string
}

// managementControllerMarkers is a curated allowlist for the same reason
// tlsCertIdentityMarkers is one: a product string is frequently just a service
// banner, and deriving "this is a management controller" from an unrecognized
// one would invent the most consequential fact on the asset.
//
// Ordered most-specific first, so the first hit is the most informative.
var managementControllerMarkers = []managementControllerMarker{
	// HPE. "integrated lights-out" is the long form certificates carry; "ilo"
	// is what the product field is normalized to. Both occur, so both are here
	// rather than relying on one of them being present.
	{"integrated lights-out", []string{TagBMC, TagILO}},
	{"ilo", []string{TagBMC, TagILO}},

	// Dell.
	{"integrated dell remote access", []string{TagBMC, TagIDRAC}},
	{"idrac", []string{TagBMC, TagIDRAC}},

	// IBM/Lenovo. The product field reads "Integrated Management Module II
	// (IMM2)" on the two services measured, so the long form is what matches
	// there; "imm2" is listed for the shortened form other paths produce.
	{"integrated management module", []string{TagBMC, TagIMM}},
	{"imm2", []string{TagBMC, TagIMM}},
	{"xclarity", []string{TagBMC}},

	// Cisco UCS, and the AMI firmware most white-box controllers ship.
	{"cimc", []string{TagBMC}},
	{"megarac", []string{TagBMC}},

	// The generic self-description, used by controllers that name no vendor.
	{"baseboard management controller", []string{TagBMC}},
}

// managementControllerTags returns the routing tags for a service whose product
// or vendor identifies it as a server management controller, and nil for
// everything else.
//
// Two exclusions are deliberate, and both were measured on the estate rather
// than reasoned about:
//
//   - "SFCB (Small Footprint CIM Broker)" is not matched. SFCB does run on the
//     controller at 192.168.0.43, but it is a general CIM broker that also ships
//     with ESXi and with sblim-sfcb on ordinary Linux hosts, so the string
//     establishes a CIM broker and not a controller. Three services carry it on
//     the measured estate and only two of them sit on a controller.
//   - No marker is a bare "controller". "SAN Volume Controller" — an IBM storage
//     array, seven services on the same estate — would match it, and a storage
//     array is a different asset class with a different blast radius.
func managementControllerTags(product, vendor string) []string {
	haystack := strings.ToLower(strings.TrimSpace(product) + " " + strings.TrimSpace(vendor))
	if strings.TrimSpace(haystack) == "" {
		return nil
	}
	for _, entry := range managementControllerMarkers {
		if scanpkg.ContainsMarkerAtWordStart(haystack, entry.marker) {
			return entry.tags
		}
	}
	return nil
}
