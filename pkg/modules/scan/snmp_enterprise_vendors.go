package scan

import (
	"regexp"
	"strings"
)

// snmpVendorInfo is a coarse manufacturer identity derived from an SNMP
// enterprise number. Product mirrors the vendor because the enterprise number
// identifies the maker, not the specific model (model resolution is a later
// layer via ENTITY-MIB / an OID->model catalog).
type snmpVendorInfo struct {
	vendor  string
	product string
}

// snmpEnterpriseNumberPattern captures the enterprise number: the arc directly
// after the IANA private-enterprise root 1.3.6.1.4.1.
var snmpEnterpriseNumberPattern = regexp.MustCompile(`^\.?1\.3\.6\.1\.4\.1\.(\d+)`)

// snmpEnterpriseVendors maps IANA Private Enterprise Numbers (the arc after
// 1.3.6.1.4.1) to a manufacturer. Seeded with the common infrastructure and
// device vendors seen in enterprise / finance networks; structured to expand
// toward the full IANA PEN registry. Only high-confidence assignments are
// included: a wrong vendor is worse than no vendor.
var snmpEnterpriseVendors = map[string]snmpVendorInfo{
	// Networking & security
	"9":     {vendor: "Cisco", product: "Cisco"},
	"2636":  {vendor: "Juniper Networks", product: "Juniper Networks"},
	"2620":  {vendor: "Check Point", product: "Check Point"},
	"3375":  {vendor: "F5 Networks", product: "F5 Networks"},
	"12356": {vendor: "Fortinet", product: "Fortinet"},
	"25461": {vendor: "Palo Alto Networks", product: "Palo Alto Networks"},
	"14988": {vendor: "MikroTik", product: "MikroTik"},
	"14823": {vendor: "Aruba Networks", product: "Aruba Networks"},
	"30065": {vendor: "Arista Networks", product: "Arista Networks"},
	"1588":  {vendor: "Brocade", product: "Brocade"},
	"1991":  {vendor: "Foundry Networks", product: "Foundry Networks"},
	"2011":  {vendor: "Huawei", product: "Huawei"},
	"41112": {vendor: "Ubiquiti Networks", product: "Ubiquiti Networks"},
	"4526":  {vendor: "Netgear", product: "Netgear"},
	"1916":  {vendor: "Extreme Networks", product: "Extreme Networks"},
	"6027":  {vendor: "Force10 Networks", product: "Force10 Networks"},
	"43":    {vendor: "3Com", product: "3Com"},
	"6486":  {vendor: "Alcatel-Lucent", product: "Alcatel-Lucent"},
	"25506": {vendor: "H3C", product: "H3C"},
	"25053": {vendor: "Ruckus Wireless", product: "Ruckus Wireless"},
	"193":   {vendor: "Ericsson", product: "Ericsson"},

	// Compute, storage, virtualization, OS
	"311":   {vendor: "Microsoft", product: "Microsoft"},
	"11":    {vendor: "Hewlett-Packard", product: "Hewlett-Packard"},
	"232":   {vendor: "Hewlett-Packard", product: "HP Server"},
	"674":   {vendor: "Dell", product: "Dell"},
	"6876":  {vendor: "VMware", product: "VMware"},
	"42":    {vendor: "Sun Microsystems", product: "Sun Microsystems"},
	"111":   {vendor: "Oracle", product: "Oracle"},
	"2":     {vendor: "IBM", product: "IBM"},
	"343":   {vendor: "Intel", product: "Intel"},
	"789":   {vendor: "NetApp", product: "NetApp"},
	"1139":  {vendor: "EMC", product: "EMC"},
	"6574":  {vendor: "Synology", product: "Synology"},
	"24681": {vendor: "QNAP", product: "QNAP"},
	"8072":  {vendor: "Net-SNMP Project", product: "Net-SNMP"},
	"2021":  {vendor: "Net-SNMP Project", product: "UCD-SNMP"},

	// Printers / imaging
	"253":  {vendor: "Xerox", product: "Xerox"},
	"641":  {vendor: "Lexmark", product: "Lexmark"},
	"1602": {vendor: "Canon", product: "Canon"},
	"2435": {vendor: "Brother", product: "Brother"},
	"367":  {vendor: "Ricoh", product: "Ricoh"},
	"1347": {vendor: "Kyocera", product: "Kyocera"},
	"1248": {vendor: "Epson", product: "Epson"},
	"236":  {vendor: "Samsung", product: "Samsung"},

	// Power / facilities
	"318": {vendor: "APC", product: "APC"},
	"534": {vendor: "Eaton", product: "Eaton"},
}

// lookupSNMPEnterprise resolves an sysObjectID to a manufacturer via its
// enterprise number. Returns ok=false when the OID is not under the private
// enterprise root or the number is not in the table.
func lookupSNMPEnterprise(sysObjectID string) (vendor, product string, ok bool) {
	m := snmpEnterpriseNumberPattern.FindStringSubmatch(strings.TrimSpace(sysObjectID))
	if m == nil {
		return "", "", false
	}
	info, found := snmpEnterpriseVendors[m[1]]
	if !found {
		return "", "", false
	}
	return info.vendor, info.product, true
}
