package scan

import (
	"context"
	"errors"
	"net"
	"strings"
)

// Device classes discovered via mDNS that the SNMP-oriented vocabulary in
// snmp_device_class.go does not cover.
const (
	deviceTypeMediaDevice = "media-device"
	deviceTypeMobile      = "mobile"
	deviceTypeWorkstation = "workstation"
	deviceTypeIoT         = "iot"
)

// Signal strength for a device-class decision, strongest first. The ranks exist
// because the alternative is the alphabet: every writer of ServiceTypes goes
// through appendUniqueSorted, so "the first service that matches" meant "the
// alphabetically first", and a printer that also does AirPlay was a media device
// because "_airplay" sorts before "_ipp" (cyprob#231).
const (
	// mdnsRankDedicated is a service only that kind of device offers. A host
	// advertising IPP is a printer; nothing else publishes it.
	mdnsRankDedicated = iota
	// mdnsRankModel is a stated hardware identifier. More specific than any
	// capability and less specific than a dedicated service, which is why the
	// model check sits between the two rather than after all of them.
	mdnsRankModel
	// mdnsRankCapability is a service a general-purpose computer also offers.
	// A Mac, an iPhone, a television and a speaker all advertise AirPlay, and a
	// Mac with file sharing on advertises SMB.
	mdnsRankCapability
	// mdnsRankAmbient is the weakest: a home-automation bridge says what
	// protocol it speaks and nothing about what it is.
	mdnsRankAmbient
)

type mdnsServiceSignal struct {
	deviceType string
	rank       int
}

// mdnsServiceDeviceTypes maps an advertised DNS-SD service type to the device
// class it implies and to how strongly it implies it.
//
// The storage services are deliberately capabilities rather than dedicated:
// _smb, _afpovertcp, _nfs and _adisk are what a Mac with file sharing enabled
// publishes, so reading them as "this is a NAS" is the same mistake AirPlay
// was. A NAS advertising only those is still classified storage, because
// nothing stronger competes.
var mdnsServiceDeviceTypes = map[string]mdnsServiceSignal{
	"_ipp._tcp":            {deviceTypePrinter, mdnsRankDedicated},
	"_ipps._tcp":           {deviceTypePrinter, mdnsRankDedicated},
	"_printer._tcp":        {deviceTypePrinter, mdnsRankDedicated},
	"_pdl-datastream._tcp": {deviceTypePrinter, mdnsRankDedicated},
	"_scanner._tcp":        {deviceTypePrinter, mdnsRankDedicated},
	// Android TV exposes its remote-control service even when the cast service
	// only answers multicast, so it is often the one signal a unicast probe gets.
	// Both are dedicated: no general-purpose computer publishes them.
	"_androidtvremote2._tcp": {deviceTypeMediaDevice, mdnsRankDedicated},
	"_androidtvremote._tcp":  {deviceTypeMediaDevice, mdnsRankDedicated},
	"_googlecast._tcp":       {deviceTypeMediaDevice, mdnsRankDedicated},

	"_airplay._tcp":         {deviceTypeMediaDevice, mdnsRankCapability},
	"_raop._tcp":            {deviceTypeMediaDevice, mdnsRankCapability},
	"_spotify-connect._tcp": {deviceTypeMediaDevice, mdnsRankCapability},
	"_afpovertcp._tcp":      {deviceTypeStorage, mdnsRankCapability},
	"_smb._tcp":             {deviceTypeStorage, mdnsRankCapability},
	"_nfs._tcp":             {deviceTypeStorage, mdnsRankCapability},
	"_adisk._tcp":           {deviceTypeStorage, mdnsRankCapability},

	"_hap._tcp":     {deviceTypeIoT, mdnsRankAmbient},
	"_matter._tcp":  {deviceTypeIoT, mdnsRankAmbient},
	"_matterc._udp": {deviceTypeIoT, mdnsRankAmbient},
}

// appleOnlyServiceTypes are DNS-SD services published only by Apple's own
// devices, so advertising one names the vendor even when no model record is
// available. AirPlay and RAOP are deliberately absent: both are licensed to
// third parties, and a Sony television advertising AirPlay is not an Apple
// device.
var appleOnlyServiceTypes = map[string]bool{
	"_companion-link._tcp": true,
	"_rdlink._tcp":         true,
	"_apple-mobdev2._tcp":  true,
}

// appleModelFamilies maps Apple hardware-identifier prefixes (e.g. "Mac16,7")
// to a device class. These identifier families are stable and self-describing.
var appleModelFamilies = []struct {
	prefix     string
	deviceType string
}{
	{"macbook", deviceTypeWorkstation},
	{"imac", deviceTypeWorkstation},
	{"macmini", deviceTypeWorkstation},
	{"macpro", deviceTypeWorkstation},
	{"macstudio", deviceTypeWorkstation},
	{"mac", deviceTypeWorkstation},
	{"iphone", deviceTypeMobile},
	{"ipad", deviceTypeMobile},
	{"ipod", deviceTypeMobile},
	{"watch", deviceTypeMobile},
	{"appletv", deviceTypeMediaDevice},
	{"audioaccessory", deviceTypeMediaDevice},
	{"homepod", deviceTypeMediaDevice},
	{"airport", deviceTypeWirelessAP},
}

// deriveMDNSIdentity turns the collected DNS-SD records into vendor / product /
// model / version / device-type hints. It only asserts what the records state:
// when a signal is absent the field is left empty rather than guessed.
func deriveMDNSIdentity(result *MDNSServiceInfo) {
	if result == nil {
		return
	}

	// Everything below is derived from TXTAttrs and ServiceTypes, so it is
	// cleared first and the function becomes a pure function of them. That
	// matters because it runs a second time after the unicast and multicast
	// records are merged: without the reset, a field guarded by "only if empty"
	// would keep a value derived from one transport while its siblings were
	// recomputed from both. Resetting here rather than at the call site means a
	// field added later cannot be left out of it.
	result.Model = ""
	result.VendorHint = ""
	result.ProductHint = ""
	result.VersionHint = ""
	result.DeviceType = ""

	// Model: several DNS-SD conventions carry it under different keys.
	// "model" (Apple AirPlay), "md" (HomeKit / Chromecast), "usb_MDL" and
	// "product" (printers).
	for _, key := range []string{"model", "md", "usb_mdl", "product", "ty"} {
		if value, ok := result.TXTAttrs[key]; ok && strings.TrimSpace(value) != "" {
			result.Model = strings.Trim(strings.TrimSpace(value), "()")
			break
		}
	}

	// OS / firmware version.
	for _, key := range []string{"osvers", "fw", "firmware", "vers", "srcvers"} {
		if value, ok := result.TXTAttrs[key]; ok && strings.TrimSpace(value) != "" {
			result.VersionHint = strings.TrimSpace(value)
			break
		}
	}

	// Vendor: explicit manufacturer keys first, then inference from the model.
	for _, key := range []string{"usb_mfg", "manufacturer", "mfg", "vendor"} {
		if value, ok := result.TXTAttrs[key]; ok && strings.TrimSpace(value) != "" {
			result.VendorHint = strings.TrimSpace(value)
			break
		}
	}
	if result.VendorHint == "" && isAppleModelIdentifier(result.Model) {
		result.VendorHint = "Apple"
	}
	// A host that states no model at all can still name its vendor by the
	// services it advertises. This is the only identity available for a device
	// with a randomized MAC that publishes no model record.
	if result.VendorHint == "" && advertisesAppleOnlyService(result.ServiceTypes) {
		result.VendorHint = "Apple"
	}

	result.DeviceType = deriveMDNSDeviceType(result)

	if result.ProductHint == "" && result.Model != "" {
		if result.VendorHint != "" && !strings.HasPrefix(strings.ToLower(result.Model), strings.ToLower(result.VendorHint)) {
			result.ProductHint = result.VendorHint + " " + result.Model
		} else {
			result.ProductHint = result.Model
		}
	}
}

// deriveMDNSDeviceType prefers the advertised service types (unambiguous) and
// falls back to the model identifier family.
// deriveMDNSDeviceType picks the strongest signal rather than the first one it
// meets. Ties inside a rank keep the order of the slice, which is sorted -- that
// residue is left deliberately, because the conflicts it would decide (a printer
// that also casts) are not things anyone has seen, and inventing a rule for them
// would be the same guess this function exists to stop making.
func deriveMDNSDeviceType(result *MDNSServiceInfo) string {
	best := ""
	bestRank := mdnsRankAmbient + 1

	for _, service := range result.ServiceTypes {
		signal, ok := mdnsServiceDeviceTypes[normalizeMDNSServiceType(service)]
		if !ok || signal.rank >= bestRank {
			continue
		}
		best, bestRank = signal.deviceType, signal.rank
	}

	// The model is one signal among them rather than a fallback consulted after
	// all of them: it beats a capability and loses to a dedicated service.
	if deviceType := appleModelDeviceType(result.Model); deviceType != "" && mdnsRankModel < bestRank {
		best, bestRank = deviceType, mdnsRankModel
	}

	return best
}

func advertisesAppleOnlyService(serviceTypes []string) bool {
	for _, service := range serviceTypes {
		if appleOnlyServiceTypes[normalizeMDNSServiceType(service)] {
			return true
		}
	}
	return false
}

// normalizeMDNSServiceType reduces an advertised type to its bare form:
// "_companion-link._tcp.local." -> "_companion-link._tcp".
func normalizeMDNSServiceType(service string) string {
	return strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(service)), "."), ".local")
}

func appleModelDeviceType(model string) string {
	normalized := strings.ToLower(strings.TrimSpace(model))
	if normalized == "" {
		return ""
	}
	for _, family := range appleModelFamilies {
		if strings.HasPrefix(normalized, family.prefix) {
			return family.deviceType
		}
	}
	return ""
}

// isAppleModelIdentifier reports whether the model looks like an Apple hardware
// identifier ("Mac16,7", "AppleTV14,1"): a known family prefix followed by the
// "<major>,<minor>" revision form.
func isAppleModelIdentifier(model string) bool {
	normalized := strings.ToLower(strings.TrimSpace(model))
	if normalized == "" || !strings.Contains(normalized, ",") {
		return false
	}
	for _, family := range appleModelFamilies {
		if strings.HasPrefix(normalized, family.prefix) {
			return true
		}
	}
	return false
}

func classifyMDNSError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, errMDNSNoResponse) || errors.Is(err, context.DeadlineExceeded) {
		return "no_response"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "no_response"
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(message, "refused"):
		return "refused"
	case strings.Contains(message, "timeout"), strings.Contains(message, "no response"):
		return "no_response"
	default:
		return "probe_failed"
	}
}
