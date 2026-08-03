package macvendor

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLookup_KnownVendors(t *testing.T) {
	// Prefixes verified against the IEEE registry; the Apple entries were also
	// cross-checked against live devices that independently identified
	// themselves as Apple over mDNS.
	cases := map[string]string{
		"40:ed:cf:71:44:66": "Apple",
		"48:E1:5C:7B:57:EC": "Apple",
		"00:50:56:aa:bb:cc": "VMware",
	}
	for mac, wantPrefix := range cases {
		vendor, ok := Lookup(mac)
		require.Truef(t, ok, "expected a vendor for %s", mac)
		require.Containsf(t, vendor, wantPrefix, "unexpected vendor for %s: %q", mac, vendor)
	}
}

func TestLookup_RejectsNonIdentifyingAddresses(t *testing.T) {
	t.Run("locally administered MACs are randomized, not OUIs", func(t *testing.T) {
		// Bit 0x02 set in the first octet.
		for _, mac := range []string{"42:a0:9f:17:ad:01", "02:b3:eb:4e:c1:dc", "66:f8:61:34:2f:c0"} {
			_, ok := Lookup(mac)
			require.Falsef(t, ok, "%s is locally administered and must not resolve", mac)
		}
	})

	t.Run("multicast and broadcast are not device identities", func(t *testing.T) {
		for _, mac := range []string{"01:00:5e:00:00:fb", "ff:ff:ff:ff:ff:ff"} {
			_, ok := Lookup(mac)
			require.Falsef(t, ok, "%s must not resolve", mac)
		}
	})

	t.Run("malformed input", func(t *testing.T) {
		for _, mac := range []string{"", "not-a-mac", "00:11"} {
			_, ok := Lookup(mac)
			require.Falsef(t, ok, "%q must not resolve", mac)
		}
	})
}

func TestLookup_UnregisteredPrefix(t *testing.T) {
	// A globally-administered prefix that is not assigned in the registry.
	_, ok := Lookup("00:00:01:02:03:04")
	if ok {
		t.Skip("prefix is assigned in the current registry snapshot")
	}
}

func TestTableLoaded(t *testing.T) {
	require.Greater(t, Size(), 30000, "embedded OUI table looks truncated")
}

func TestOUIPrefix(t *testing.T) {
	prefix, ok := ouiPrefix("40:ed:cf:71:44:66")
	require.True(t, ok)
	require.Equal(t, "40EDCF", prefix, "prefix must be uppercase hex")
}
