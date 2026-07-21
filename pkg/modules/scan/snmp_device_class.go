package scan

import "strings"

// Device type/role categories emitted by classifySNMPDevice. Empty string means
// "unknown" — a wrong role is worse than none, so the classifier only commits
// when a signal is clear.
const (
	deviceTypeFirewall     = "firewall"
	deviceTypeLoadBalancer = "load-balancer"
	deviceTypeWirelessAP   = "wireless-ap"
	deviceTypePrinter      = "printer"
	deviceTypeUPS          = "ups"
	deviceTypeStorage      = "storage"
	deviceTypeHypervisor   = "hypervisor"
	deviceTypeSwitch       = "switch"
	deviceTypeRouter       = "router"
	deviceTypeServer       = "server"
)

// sysDescr keyword sets, checked most-specific-first. Appliance categories are
// checked before the generic switch/router/server buckets because an appliance
// description often also contains those weaker words.
var (
	firewallDescrKeywords     = []string{"firewall", "fortigate", "fortios", "palo alto", "pan-os", "cisco asa", "adaptive security appliance", "checkpoint", "check point", "sonicwall", "sophos", "watchguard", "netscreen", "pfsense"}
	loadBalancerDescrKeywords = []string{"big-ip", "big ip", "load balancer", "netscaler", "application delivery"}
	apDescrKeywords           = []string{"access point", "wireless", "wlan", "aironet", "unifi ap"}
	printerDescrKeywords      = []string{"printer", "laserjet", "officejet", "jetdirect", "imagerunner", "workcentre", "workcenter", "phaser", "bizhub", "imageclass", "mfp"}
	upsDescrKeywords          = []string{"smart-ups", "powerware", "ups ", "uninterruptible"}
	storageDescrKeywords      = []string{"diskstation", "rackstation", "data ontap", "storeonce", "isilon", "network attached storage", " nas ", "storage array"}
	hypervisorDescrKeywords   = []string{"esxi", "vmware esx", "vsphere", "hyper-v", "proxmox", "xenserver"}
	switchDescrKeywords       = []string{"switch", "catalyst", "procurve", "nexus", "powerconnect", "ex series", "ex4", "ex2", "aruba os-cx"}
	routerDescrKeywords       = []string{"router", "routeros", "mikrotik", " isr", " asr", "mx series", "vyos", "edgerouter", "integrated services"}
	serverDescrKeywords       = []string{"windows", "linux", "ubuntu", "debian", "centos", "red hat", "rhel", "server"}
)

// vendorDeviceRole maps PEN-derived vendors that make essentially one device
// category to that role, used only when the description is uninformative.
// Multi-category vendors (Cisco, Juniper, Huawei, ...) are intentionally absent:
// their role must come from the description, not the vendor.
var vendorDeviceRole = map[string]string{
	"Fortinet":           deviceTypeFirewall,
	"Palo Alto Networks": deviceTypeFirewall,
	"Check Point":        deviceTypeFirewall,
	"F5 Networks":        deviceTypeLoadBalancer,
	"Xerox":              deviceTypePrinter,
	"Lexmark":            deviceTypePrinter,
	"Canon":              deviceTypePrinter,
	"Brother":            deviceTypePrinter,
	"Ricoh":              deviceTypePrinter,
	"Kyocera":            deviceTypePrinter,
	"Epson":              deviceTypePrinter,
	"APC":                deviceTypeUPS,
	"Eaton":              deviceTypeUPS,
	"Synology":           deviceTypeStorage,
	"QNAP":               deviceTypeStorage,
	"NetApp":             deviceTypeStorage,
	"EMC":                deviceTypeStorage,
	"VMware":             deviceTypeHypervisor,
}

// classifySNMPDevice infers a coarse device type/role from the SNMP description
// and the (PEN-derived) vendor. Returns "" when no signal is clear.
func classifySNMPDevice(sysDescr, vendor, _ string) string {
	d := strings.ToLower(sysDescr)
	switch {
	case snmpDescrHasAny(d, firewallDescrKeywords):
		return deviceTypeFirewall
	case snmpDescrHasAny(d, loadBalancerDescrKeywords):
		return deviceTypeLoadBalancer
	case snmpDescrHasAny(d, apDescrKeywords):
		return deviceTypeWirelessAP
	case snmpDescrHasAny(d, printerDescrKeywords):
		return deviceTypePrinter
	case snmpDescrHasAny(d, upsDescrKeywords):
		return deviceTypeUPS
	case snmpDescrHasAny(d, storageDescrKeywords):
		return deviceTypeStorage
	case snmpDescrHasAny(d, hypervisorDescrKeywords):
		return deviceTypeHypervisor
	case snmpDescrHasAny(d, switchDescrKeywords):
		return deviceTypeSwitch
	case snmpDescrHasAny(d, routerDescrKeywords):
		return deviceTypeRouter
	case snmpDescrHasAny(d, serverDescrKeywords):
		return deviceTypeServer
	}
	if role, ok := vendorDeviceRole[strings.TrimSpace(vendor)]; ok {
		return role
	}
	return ""
}

func snmpDescrHasAny(lowerDescr string, keywords []string) bool {
	for _, kw := range keywords {
		if strings.Contains(lowerDescr, kw) {
			return true
		}
	}
	return false
}
