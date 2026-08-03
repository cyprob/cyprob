// Package macvendor resolves a MAC address to its manufacturer using the IEEE
// OUI registry.
//
// On a local segment this is often the only vendor signal available: a device
// that exposes no SNMP, no banner and no management UI still has a
// manufacturer-assigned hardware address. The table is generated from the
// authoritative IEEE registry by gen_oui.go, never hand-maintained.
package macvendor

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"net"
	"strings"
	"sync"
)

//go:embed data/oui.txt.gz
var ouiTableGZ []byte

var (
	loadOnce sync.Once
	ouiTable map[string]string
)

// load decompresses the embedded table on first use, so scans that never
// resolve a MAC pay nothing.
func load() {
	table := make(map[string]string, 40000)
	reader, err := gzip.NewReader(bytes.NewReader(ouiTableGZ))
	if err != nil {
		ouiTable = table
		return
	}
	defer reader.Close() //nolint:errcheck // read-only best-effort cleanup

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		prefix, vendor, found := strings.Cut(scanner.Text(), "\t")
		if !found {
			continue
		}
		table[prefix] = vendor
	}
	ouiTable = table
}

// Lookup returns the manufacturer registered for a MAC address.
//
// It deliberately returns nothing for locally-administered addresses: those are
// randomized privacy MACs (common on phones and laptops) whose leading bytes are
// not a real OUI, so resolving them would invent a vendor.
func Lookup(mac string) (string, bool) {
	prefix, ok := ouiPrefix(mac)
	if !ok {
		return "", false
	}
	loadOnce.Do(load)
	vendor, found := ouiTable[prefix]
	if !found || vendor == "" {
		return "", false
	}
	return vendor, true
}

// ouiPrefix normalizes a MAC to its 6-hex-character OUI, rejecting addresses
// that cannot carry manufacturer information.
func ouiPrefix(mac string) (string, bool) {
	parsed, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(parsed) < 3 {
		return "", false
	}
	// Locally-administered (bit 1 of the first octet) => randomized, not an OUI.
	if parsed[0]&0x02 != 0 {
		return "", false
	}
	// Multicast/broadcast addresses are not device identities.
	if parsed[0]&0x01 != 0 {
		return "", false
	}
	var builder strings.Builder
	builder.Grow(6)
	const hexDigits = "0123456789ABCDEF"
	for _, octet := range parsed[:3] {
		builder.WriteByte(hexDigits[octet>>4])
		builder.WriteByte(hexDigits[octet&0x0f])
	}
	return builder.String(), true
}

// Size reports the number of loaded OUI prefixes (used by tests and diagnostics).
func Size() int {
	loadOnce.Do(load)
	return len(ouiTable)
}
