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

// NormalizeMAC canonicalizes a hardware address to lowercase colon-separated
// form, rejecting broadcast/all-zero placeholders that carry no identity.
func NormalizeMAC(mac string) string {
	mac = strings.TrimSpace(mac)
	if mac == "" {
		return ""
	}
	parsed, err := net.ParseMAC(mac)
	if err != nil || len(parsed) != 6 {
		return ""
	}
	switch parsed.String() {
	case "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff":
		return ""
	}
	return parsed.String()
}

// IsLocallyAdministeredMAC reports whether the address has the
// locally-administered bit set, which marks randomized privacy MACs (common on
// phones and laptops). Such addresses carry no manufacturer information, so an
// OUI lookup against them is meaningless.
func IsLocallyAdministeredMAC(mac string) bool {
	parsed, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(parsed) == 0 {
		return false
	}
	return parsed[0]&0x02 != 0
}
