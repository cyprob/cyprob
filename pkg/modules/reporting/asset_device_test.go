package reporting

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/modules/scan"
)

func TestDeviceProfileFromSNMP(t *testing.T) {
	t.Run("full identity", func(t *testing.T) {
		device := deviceProfileFromSNMP(scan.SNMPServiceInfo{
			SNMPProbe:   true,
			VendorHint:  "Fortinet",
			ProductHint: "Fortinet",
			DeviceType:  "firewall",
			Model:       "FortiGate-100F",
			Serial:      "FG100FT918000001",
		})
		require.NotNil(t, device)
		require.Equal(t, "Fortinet", device.Vendor)
		require.Equal(t, "firewall", device.Type)
		require.Equal(t, "FortiGate-100F", device.Model)
		require.Equal(t, "FG100FT918000001", device.Serial)
		require.Equal(t, "snmp", device.Source)
	})

	t.Run("no probe -> nil", func(t *testing.T) {
		require.Nil(t, deviceProfileFromSNMP(scan.SNMPServiceInfo{SNMPProbe: false, VendorHint: "Fortinet"}))
	})

	t.Run("no identity signal -> nil", func(t *testing.T) {
		require.Nil(t, deviceProfileFromSNMP(scan.SNMPServiceInfo{SNMPProbe: true, SysName: "host1"}))
	})

	t.Run("vendor-only still yields a device", func(t *testing.T) {
		device := deviceProfileFromSNMP(scan.SNMPServiceInfo{SNMPProbe: true, VendorHint: "APC", DeviceType: "ups"})
		require.NotNil(t, device)
		require.Equal(t, "APC", device.Vendor)
		require.Equal(t, "ups", device.Type)
		require.Empty(t, device.Model)
	})
}
