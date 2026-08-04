package netutil

import (
	"net"
	"strings"
)

// ARPEntry pairs a neighbor IP with its link-layer address as reported by the
// host's ARP/neighbor table.
type ARPEntry struct {
	IP  string
	MAC string
}

// ARPTable returns the host's current ARP/neighbor table.
//
// This is a link-local signal: it only contains neighbors on directly attached
// segments, and only those the host has recently exchanged traffic with (a scan
// populates it as a side effect). Callers must treat an empty result as "no
// information", never as "no such host". Unsupported platforms return nil.
func ARPTable() []ARPEntry {
	entries := readARPTable()
	out := make([]ARPEntry, 0, len(entries))
	for _, entry := range entries {
		ip := strings.TrimSpace(entry.IP)
		mac := NormalizeMAC(entry.MAC)
		if ip == "" || mac == "" {
			continue
		}
		out = append(out, ARPEntry{IP: ip, MAC: mac})
	}
	return out
}

// ARPLookup returns the link-layer address for an IP, if the host knows it.
func ARPLookup(ip string) (string, bool) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "", false
	}
	for _, entry := range ARPTable() {
		if entry.IP == ip {
			return entry.MAC, true
		}
	}
	return "", false
}

// ARPLookupExclusive returns the link-layer address for an IP only when no
// other IP in the table shares it.
//
// A router doing proxy ARP answers for every address it fronts, so one MAC maps
// to many IPs. That MAC belongs to the router, not to the host being scanned:
// deriving a vendor from it mislabels the asset, and recording it as the asset's
// own address makes unrelated hosts look like one device to any correlation
// keyed on MAC. Callers that need the next hop rather than the device's own
// address should use ARPLookup.
func ARPLookupExclusive(ip string) (string, bool) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "", false
	}
	table := ARPTable()
	owners := make(map[string]int, len(table))
	for _, entry := range table {
		owners[entry.MAC]++
	}
	for _, entry := range table {
		if entry.IP == ip {
			if owners[entry.MAC] > 1 {
				return "", false
			}
			return entry.MAC, true
		}
	}
	return "", false
}

// NormalizeMAC canonicalizes a hardware address to lowercase colon-separated
// form, rejecting broadcast/all-zero placeholders that carry no identity.
func NormalizeMAC(mac string) string {
	mac = strings.TrimSpace(mac)
	if mac == "" {
		return ""
	}
	parsed, err := net.ParseMAC(padMACOctets(mac))
	if err != nil || len(parsed) != 6 {
		return ""
	}
	switch parsed.String() {
	case "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff":
		return ""
	}
	return parsed.String()
}

// padMACOctets zero-pads single-digit colon-separated octets.
//
// net.ParseMAC requires two hex digits per octet, but several common sources —
// BSD arp output, device web UIs, hand-entered inventory — drop the leading
// zero. Without this, a MAC like "0:11:32:43:c8:ff" would be silently discarded
// and the device left without a vendor.
func padMACOctets(mac string) string {
	if !strings.Contains(mac, ":") {
		return mac
	}
	parts := strings.Split(mac, ":")
	for i, part := range parts {
		if len(part) == 1 {
			parts[i] = "0" + part
		}
	}
	return strings.Join(parts, ":")
}

// IsLocallyAdministeredMAC reports whether the address has the
// locally-administered bit set, which marks randomized privacy MACs (common on
// phones and laptops). Such addresses carry no manufacturer information, so an
// OUI lookup against them is meaningless.
func IsLocallyAdministeredMAC(mac string) bool {
	parsed, err := net.ParseMAC(padMACOctets(strings.TrimSpace(mac)))
	if err != nil || len(parsed) == 0 {
		return false
	}
	return parsed[0]&0x02 != 0
}
