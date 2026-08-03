//go:build linux

package netutil

import (
	"bufio"
	"os"
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
