package netutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A MAC that several IPs share belongs to a router doing proxy ARP, not to any
// one of those hosts, so it must not be handed out as a device identity.
func TestARPLookupExclusive(t *testing.T) {
	table := ARPTable()
	if len(table) == 0 {
		t.Skip("no neighbor table entries available on this host")
	}
	owners := map[string][]string{}
	for _, entry := range table {
		owners[entry.MAC] = append(owners[entry.MAC], entry.IP)
	}
	for mac, ips := range owners {
		for _, ip := range ips {
			got, ok := ARPLookupExclusive(ip)
			if len(ips) > 1 {
				require.False(t, ok, "%s is shared by %v and must not identify a device", mac, ips)
				require.Empty(t, got)
				continue
			}
			require.True(t, ok)
			require.Equal(t, mac, got)
		}
	}
}

func TestPadMACOctets(t *testing.T) {
	// BSD arp output drops leading zeros; the address is still valid.
	require.Equal(t, "00:11:32:43:c8:ff", NormalizeMAC("0:11:32:43:c8:ff"))
	require.Equal(t, "5c:cf:7f:91:0d:ea", NormalizeMAC("5c:cf:7f:91:d:ea"))
	require.Equal(t, "08:55:31:e3:de:e7", NormalizeMAC("8:55:31:e3:de:e7"))
	// Already-padded and invalid input keep their existing behavior.
	require.Equal(t, "00:11:32:43:c8:ff", NormalizeMAC("00:11:32:43:c8:ff"))
	require.Empty(t, NormalizeMAC("not-a-mac"))
}
