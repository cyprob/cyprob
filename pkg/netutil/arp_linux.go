//go:build linux

package netutil

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"
)

// procNetARP is the kernel's ARP cache. Reading it needs no privileges and no
// external command.
const procNetARP = "/proc/net/arp"

// readARPTable parses /proc/net/arp, whose columns are:
//
//	IP address  HW type  Flags  HW address  Mask  Device
func readARPTable() []ARPEntry {
	file, err := os.Open(procNetARP)
	if err != nil {
		return nil
	}
	defer file.Close() //nolint:errcheck // read-only best-effort cleanup

	var entries []ARPEntry
	scanner := bufio.NewScanner(file)
	for lineNumber := 0; scanner.Scan(); lineNumber++ {
		if lineNumber == 0 {
			continue // header row
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		// Flags 0x0 marks an incomplete entry with no usable hardware address.
		if fields[2] == "0x0" {
			continue
		}
		entries = append(entries, ARPEntry{IP: fields[0], MAC: fields[3]})
	}
	return entries
}

// procNetRoute is the kernel's IPv4 routing table.
const procNetRoute = "/proc/net/route"

// readDefaultGateways parses /proc/net/route for default routes. Its columns
// are Iface, Destination, Gateway, ... with addresses as little-endian hex.
func readDefaultGateways() []string {
	file, err := os.Open(procNetRoute)
	if err != nil {
		return nil
	}
	defer file.Close() //nolint:errcheck // read-only best-effort cleanup

	var gateways []string
	scanner := bufio.NewScanner(file)
	for lineNumber := 0; scanner.Scan(); lineNumber++ {
		if lineNumber == 0 {
			continue // header row
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		if ip := parseLittleEndianHexIP(fields[2]); ip != "" {
			gateways = append(gateways, ip)
		}
	}
	return gateways
}

// parseLittleEndianHexIP decodes the byte-reversed hex form the kernel uses.
func parseLittleEndianHexIP(hexValue string) string {
	value, err := strconv.ParseUint(hexValue, 16, 32)
	if err != nil {
		return ""
	}
	return net.IPv4(byte(value), byte(value>>8), byte(value>>16), byte(value>>24)).String()
}
