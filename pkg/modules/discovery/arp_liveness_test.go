package discovery

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/netutil"
)

// appendARPConfirmedHosts must only ever add hosts, and only ones that were
// asked for. It is a supplement to ICMP, never a replacement, so it must not
// drop or reorder what the sweep already found.
func TestAppendARPConfirmedHosts(t *testing.T) {
	logger := zerolog.Nop()

	t.Run("keeps existing hosts and never removes any", func(t *testing.T) {
		live := []string{"192.0.2.1", "192.0.2.2"}
		got, _ := appendARPConfirmedHosts(live, []string{"192.0.2.1", "192.0.2.2"}, &logger)
		require.Subset(t, got, live, "hosts found by ICMP must survive")
	})

	t.Run("a host not in the target list is never added", func(t *testing.T) {
		// Whatever the local neighbor table holds, nothing outside the requested
		// targets may appear in the result.
		got, _ := appendARPConfirmedHosts(nil, []string{"198.51.100.77"}, &logger)
		for _, host := range got {
			require.Equal(t, "198.51.100.77", host,
				"only requested targets may be reported as live")
		}
	})

	t.Run("no targets means no additions", func(t *testing.T) {
		combined, arpConfirmed := appendARPConfirmedHosts(nil, nil, &logger)
		require.Empty(t, combined)
		require.Empty(t, arpConfirmed)
	})

	t.Run("a host is not reported twice", func(t *testing.T) {
		table := ARPTableForTest(t)
		if len(table) == 0 {
			t.Skip("no neighbor table entries available on this host")
		}
		first := table[0]
		got, _ := appendARPConfirmedHosts([]string{first}, []string{first}, &logger)
		count := 0
		for _, host := range got {
			if host == first {
				count++
			}
		}
		require.Equal(t, 1, count, "an ICMP-confirmed host must not be duplicated by ARP")
	})

	// The attribution split is the point of cyprob-ee#141: a caller must be able
	// to say how many hosts actually answered an echo request. Anything the
	// neighbor table supplied has to be reported separately, and only that.
	t.Run("what ARP supplied is reported separately, and is exactly the additions", func(t *testing.T) {
		table := ARPTableForTest(t)
		if len(table) == 0 {
			t.Skip("no neighbor table entries available on this host")
		}
		neighbor := table[0]

		combined, arpConfirmed := appendARPConfirmedHosts(nil, []string{neighbor}, &logger)

		require.Equal(t, []string{neighbor}, arpConfirmed,
			"a host that never answered ICMP must be attributed to ARP, not to ICMP")
		require.Equal(t, len(combined), len(arpConfirmed),
			"with no ICMP replies, every host in the result came from the neighbor table")
		require.Subset(t, combined, arpConfirmed,
			"the ARP-confirmed set must be a subset of the combined result, not a parallel list")
	})

	t.Run("a host that answered ICMP is never claimed by ARP", func(t *testing.T) {
		table := ARPTableForTest(t)
		if len(table) == 0 {
			t.Skip("no neighbor table entries available on this host")
		}
		answered := table[0]

		// Same host, but this time ICMP already found it.
		_, arpConfirmed := appendARPConfirmedHosts([]string{answered}, []string{answered}, &logger)

		require.Empty(t, arpConfirmed,
			"an echo reply must keep its attribution even when the host is also in the neighbor table")
	})
}

// ARPTableForTest exposes the local neighbor IPs so tests can use whatever the
// machine actually has, without asserting anything about a specific network.
func ARPTableForTest(t *testing.T) []string {
	t.Helper()
	var ips []string
	for _, entry := range netutil.ARPTable() {
		ips = append(ips, entry.IP)
	}
	return ips
}
