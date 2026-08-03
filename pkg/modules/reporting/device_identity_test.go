package reporting

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/scan"
)

func TestDeviceProfileFromMDNS(t *testing.T) {
	t.Run("advertised identity becomes a device profile", func(t *testing.T) {
		device := deviceProfileFromMDNS(scan.MDNSServiceInfo{
			MDNSProbe: true, VendorHint: "Apple", ProductHint: "AppleTV14,1",
			Model: "AppleTV14,1", DeviceType: "media-device",
		})
		require.NotNil(t, device)
		require.Equal(t, "Apple", device.Vendor)
		require.Equal(t, "media-device", device.Type)
		require.Equal(t, "mdns", device.Source)
	})

	t.Run("no probe or no identity yields nothing", func(t *testing.T) {
		require.Nil(t, deviceProfileFromMDNS(scan.MDNSServiceInfo{MDNSProbe: false, Model: "x"}))
		require.Nil(t, deviceProfileFromMDNS(scan.MDNSServiceInfo{MDNSProbe: true}))
	})
}

func TestMergeDeviceProfile(t *testing.T) {
	t.Run("stronger source is never overwritten", func(t *testing.T) {
		base := &engine.DeviceProfile{Vendor: "Fortinet", Model: "FortiGate-100F", Source: "snmp"}
		merged := mergeDeviceProfile(base, &engine.DeviceProfile{Vendor: "Acme", Source: "mac_oui"})
		require.Equal(t, "Fortinet", merged.Vendor)
		require.Equal(t, "snmp", merged.Source, "a fallback that filled nothing must not claim credit")
	})

	t.Run("gaps are filled and the source is recorded", func(t *testing.T) {
		base := &engine.DeviceProfile{Model: "AppleTV14,1", Source: "mdns"}
		merged := mergeDeviceProfile(base, &engine.DeviceProfile{Vendor: "Apple", Source: "mac_oui"})
		require.Equal(t, "Apple", merged.Vendor)
		require.Equal(t, "mdns+mac_oui", merged.Source)
	})

	t.Run("nil handling", func(t *testing.T) {
		fallback := &engine.DeviceProfile{Vendor: "LG Innotek", Source: "mac_oui"}
		require.Equal(t, fallback, mergeDeviceProfile(nil, fallback))

		base := &engine.DeviceProfile{Vendor: "Apple", Source: "mdns"}
		require.Equal(t, base, mergeDeviceProfile(base, nil))
		require.Nil(t, mergeDeviceProfile(nil, nil))
	})

	t.Run("a source is not recorded twice", func(t *testing.T) {
		base := &engine.DeviceProfile{Vendor: "Apple", Source: "mac_oui"}
		merged := mergeDeviceProfile(base, &engine.DeviceProfile{Model: "Mac16,7", Source: "mac_oui"})
		require.Equal(t, "mac_oui", merged.Source)
	})
}

func TestFindMDNSDetails(t *testing.T) {
	items := []scan.MDNSServiceInfo{
		{Target: "192.0.2.1", Model: "A"},
		{Target: "192.0.2.2", Model: "B"},
	}
	found := findMDNSDetails(items, "192.0.2.2")
	require.NotNil(t, found)
	require.Equal(t, "B", found.Model)
	require.Nil(t, findMDNSDetails(items, "192.0.2.9"))
}
