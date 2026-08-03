package scan

import "strings"

// tlsCertIdentityMarker maps a distinctive string found in a certificate's
// subject or issuer to the device it identifies.
//
// Appliances and management interfaces generate their own certificates and put
// the product name in them ("CN=FortiGate", "O=Ubiquiti Inc."), which makes the
// certificate a credential-free identity source for exactly the hosts that
// expose nothing else.
type tlsCertIdentityMarker struct {
	// marker is matched case-insensitively against the subject CN and issuer DN.
	marker  string
	vendor  string
	product string
}

// tlsCertIdentityMarkers is deliberately a curated allowlist rather than a
// heuristic: a certificate CN is very often just a hostname, so deriving a
// vendor from an unrecognized CN would invent one. Nothing is asserted unless a
// known marker matches.
var tlsCertIdentityMarkers = []tlsCertIdentityMarker{
	// Security appliances
	{"fortigate", "Fortinet", "FortiGate"},
	{"fortimanager", "Fortinet", "FortiManager"},
	{"fortianalyzer", "Fortinet", "FortiAnalyzer"},
	{"fortinet", "Fortinet", ""},
	{"palo alto", "Palo Alto Networks", ""},
	{"panorama", "Palo Alto Networks", "Panorama"},
	{"sonicwall", "SonicWall", ""},
	{"watchguard", "WatchGuard", ""},
	{"check point", "Check Point", ""},
	{"checkpoint", "Check Point", ""},
	{"sophos", "Sophos", ""},
	{"pfsense", "Netgate", "pfSense"},
	{"opnsense", "Deciso", "OPNsense"},

	// Network infrastructure
	{"unifi", "Ubiquiti", "UniFi"},
	{"ubiquiti", "Ubiquiti", ""},
	{"routeros", "MikroTik", "RouterOS"},
	{"mikrotik", "MikroTik", ""},
	{"cimc", "Cisco", "UCS CIMC"},
	{"cisco", "Cisco", ""},
	{"juniper", "Juniper Networks", ""},
	{"aruba", "HPE Aruba", ""},
	{"ruckus", "Ruckus", ""},
	{"zyxel", "Zyxel", ""},
	{"tp-link", "TP-Link", ""},
	{"netgear", "Netgear", ""},
	{"d-link", "D-Link", ""},
	{"big-ip", "F5", "BIG-IP"},
	{"netscaler", "Citrix", "NetScaler"},

	// Server management controllers
	{"idrac", "Dell", "iDRAC"},
	{"ilo", "HPE", "iLO"},
	{"integrated lights-out", "HPE", "iLO"},
	{"xclarity", "Lenovo", "XClarity"},
	{"supermicro", "Supermicro", ""},

	// Virtualization and storage
	{"vcenter", "VMware", "vCenter"},
	{"esxi", "VMware", "ESXi"},
	{"vmware", "VMware", ""},
	{"proxmox", "Proxmox", ""},
	{"synology", "Synology", ""},
	{"qnap", "QNAP", ""},
	{"truenas", "iXsystems", "TrueNAS"},

	// Cameras and other appliances
	{"hikvision", "Hikvision", ""},
	{"dahua", "Dahua", ""},
	{"axis communications", "Axis Communications", ""},
}

// deriveTLSCertIdentity extracts a device vendor and product from certificate
// identity fields. It returns empty strings when nothing recognizable matches,
// which is the common case for ordinary CA-issued web-server certificates.
func deriveTLSCertIdentity(subjectCN, issuerDN string) (vendor, product string) {
	haystack := strings.ToLower(strings.TrimSpace(subjectCN) + " " + strings.TrimSpace(issuerDN))
	if strings.TrimSpace(haystack) == "" {
		return "", ""
	}
	// Markers are ordered most-specific first ("fortigate" before "fortinet"),
	// so the first hit is the most informative one.
	for _, entry := range tlsCertIdentityMarkers {
		if containsMarkerAtWordStart(haystack, entry.marker) {
			return entry.vendor, entry.product
		}
	}
	return "", ""
}

// containsMarkerAtWordStart reports whether marker occurs at the start of a word.
//
// A plain substring match is unsafe for short markers: "ilo" appears inside
// "pilot", "silo" and "kilo", which would confidently mislabel an ordinary web
// server as an HPE iLO. Requiring a word start blocks that while still matching
// the suffixed forms devices actually use ("ilo5", "FortiGate-100F").
func containsMarkerAtWordStart(haystack, marker string) bool {
	if marker == "" {
		return false
	}
	for offset := 0; offset <= len(haystack)-len(marker); {
		index := strings.Index(haystack[offset:], marker)
		if index < 0 {
			return false
		}
		start := offset + index
		if start == 0 || !isMarkerWordChar(haystack[start-1]) {
			return true
		}
		offset = start + 1
	}
	return false
}

func isMarkerWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
