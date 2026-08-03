package scan

// Favicon identity corpus.
//
// A favicon hash is a stable device fingerprint: the same hardware and firmware
// serve the same icon, so identical devices group together across a fleet even
// before anyone names them. Naming them is a corpus problem, and the corpus is
// grown from verified observations rather than guesswork.
//
// Deliberately empty at introduction. Entries assert "this hash IS this
// product", so a wrong entry mislabels every matching device in every scan —
// the same failure mode the SNMP PEN table, the TLS certificate markers and the
// MAC OUI table are all designed to avoid. Populating it from half-remembered
// values would poison exactly the signal it is meant to provide.
//
// To add an entry, verify the hash against the device itself:
//
//	curl -sS -o /tmp/f.ico http://<device>/favicon.ico
//	# then hash it with FaviconHash and record what the device actually is
//
// The hash follows the Shodan convention (see favicon_hash.go), so publicly
// published favicon hashes are directly usable as candidate entries — but they
// still need confirming against a real device before being added here.
var faviconIdentityCorpus = map[int32]struct {
	vendor  string
	product string
}{}

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
