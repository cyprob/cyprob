package scan

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifySNMPDevice(t *testing.T) {
	cases := []struct {
		name   string
		descr  string
		vendor string
		want   string
	}{
		// description-driven (strongest signal)
		{"fortigate firewall", "FortiGate-100F v7.2.5", "Fortinet", deviceTypeFirewall},
		{"cisco asa firewall", "Cisco Adaptive Security Appliance Version 9.14", "Cisco", deviceTypeFirewall},
		{"palo alto", "Palo Alto Networks PA-3220 series firewall", "Palo Alto Networks", deviceTypeFirewall},
		{"f5 big-ip", "BIG-IP 15.1.0 Build 0.0.31 Final", "F5 Networks", deviceTypeLoadBalancer},
		{"aruba ap", "ArubaOS Wireless Access Point AP-315", "Aruba Networks", deviceTypeWirelessAP},
		{"hp printer", "HP ETHERNET MULTI-ENVIRONMENT, JETDIRECT, LaserJet", "Hewlett-Packard", deviceTypePrinter},
		{"apc ups descr", "APC Web/SNMP Management Card, Smart-UPS 1500", "APC", deviceTypeUPS},
		{"synology nas", "Linux DiskStation 4.4.180 Synology", "Synology", deviceTypeStorage},
		{"esxi hypervisor", "VMware ESXi 7.0.3 build-19193900", "VMware", deviceTypeHypervisor},
		{"cisco catalyst switch", "Cisco IOS Software, Catalyst 2960 Software", "Cisco", deviceTypeSwitch},
		{"cisco isr router", "Cisco IOS Software, ISR4331 Software", "Cisco", deviceTypeRouter},
		{"generic windows server", "Hardware: Intel64 Windows Version 10.0 (Build 17763) Server", "Microsoft", deviceTypeServer},

		// vendor fallback (uninformative description)
		{"fortinet vendor fallback", "device", "Fortinet", deviceTypeFirewall},
		{"lexmark vendor fallback", "network device", "Lexmark", deviceTypePrinter},
		{"eaton vendor fallback", "power device", "Eaton", deviceTypeUPS},

		// multi-category vendor with no descr signal -> unknown (no guess)
		{"cisco no signal -> unknown", "some device", "Cisco", ""},
		{"unknown vendor + descr -> unknown", "generic appliance", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, classifySNMPDevice(tc.descr, tc.vendor, ""))
		})
	}
}

// firewall description must win even when it also contains weaker words.
func TestClassifySNMPDevice_Precedence(t *testing.T) {
	// A firewall running Linux with routing features: firewall wins over
	// server/router.
	require.Equal(t, deviceTypeFirewall,
		classifySNMPDevice("Linux FortiGate router firewall appliance", "Fortinet", ""))
}
