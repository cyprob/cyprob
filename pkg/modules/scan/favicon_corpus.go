package scan

// Favicon identity corpus.
//
// A favicon hash is a stable device fingerprint: the same hardware and firmware
// serve the same icon, so identical devices group together across a fleet even
// before anyone names them. Naming them is a corpus problem, and the corpus is
// grown from verified observations rather than guesswork.
//
// Entries assert "this hash IS this product", so a wrong entry mislabels every
// matching device in every scan — the same failure mode the SNMP PEN table, the
// TLS certificate markers and the MAC OUI table are all designed to avoid.
// Nothing is added from memory or from an unverified list.
//
// An entry is only added once a real device has been observed serving the icon
// AND its identity established independently — ideally from the device's own
// statement (a device-info endpoint, SNMP sysDescr, an mDNS TXT record), not
// from inference. `tools/seed_favicon.go` automates the mechanical half.
//
// The hash follows the Shodan convention (see favicon_hash.go), so publicly
// published favicon hashes are usable as candidates — but they still need
// confirming against a real device before being added here.
//
// Caveat worth knowing when reading a match: vendors commonly ship one icon
// across a product line, so a hash may identify the line rather than the exact
// model recorded. The vendor is the reliable half.
var faviconIdentityCorpus = map[int32]struct {
	vendor  string
	product string
}{
	// Verified 2026-08-03 on a live device: it served this icon and reported
	// FriendlyName "HUAWEI WiFi BE3" with DeviceIconType "router" from its own
	// unauthenticated /api/system/deviceinfo endpoint.
	1684467926: {vendor: "Huawei", product: "HUAWEI WiFi BE3"},
}

// LookupFaviconIdentity resolves a favicon hash to a device. An unknown hash
// returns nothing: the hash is still emitted by the probe and remains useful for
// grouping identical devices, so an empty result is a missing name, not a
// missing signal.
func LookupFaviconIdentity(hash int32) (vendor, product string) {
	if hash == 0 {
		return "", ""
	}
	entry, ok := faviconIdentityCorpus[hash]
	if !ok {
		return "", ""
	}
	return entry.vendor, entry.product
}

// FaviconCorpusSize reports how many device fingerprints are known, for
// diagnostics and tests.
func FaviconCorpusSize() int { return len(faviconIdentityCorpus) }
