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

// mdnsServiceDeviceTypes maps an advertised DNS-SD service type to the device
// class it implies. Service types are unambiguous, so they are the strongest
// signal available before looking at any model string.
var mdnsServiceDeviceTypes = map[string]string{
	"_ipp._tcp":            deviceTypePrinter,
	"_ipps._tcp":           deviceTypePrinter,
	"_printer._tcp":        deviceTypePrinter,
	"_pdl-datastream._tcp": deviceTypePrinter,
	"_scanner._tcp":        deviceTypePrinter,
	"_airplay._tcp":        deviceTypeMediaDevice,
	// Android TV exposes its remote-control service even when the cast service
	// only answers multicast, so it is often the one signal a unicast probe gets.
	"_androidtvremote2._tcp": deviceTypeMediaDevice,
	"_androidtvremote._tcp":  deviceTypeMediaDevice,
	"_raop._tcp":             deviceTypeMediaDevice,
	"_googlecast._tcp":       deviceTypeMediaDevice,
	"_spotify-connect._tcp":  deviceTypeMediaDevice,
	"_hap._tcp":              deviceTypeIoT,
	"_matter._tcp":           deviceTypeIoT,
	"_matterc._udp":          deviceTypeIoT,
	"_afpovertcp._tcp":       deviceTypeStorage,
	"_smb._tcp":              deviceTypeStorage,
	"_nfs._tcp":              deviceTypeStorage,
	"_adisk._tcp":            deviceTypeStorage,
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
func deriveMDNSDeviceType(result *MDNSServiceInfo) string {
	// Service types win: a host advertising _ipp is a printer regardless of how
	// its model string reads.
	for _, service := range result.ServiceTypes {
		key := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(service)), "."), ".local")
		if deviceType, ok := mdnsServiceDeviceTypes[key]; ok && deviceType != deviceTypeIoT {
			return deviceType
		}
	}

	if deviceType := appleModelDeviceType(result.Model); deviceType != "" {
		return deviceType
	}

	// IoT is the weakest of the service signals, so it only applies when
	// nothing more specific matched.
	for _, service := range result.ServiceTypes {
		key := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(service)), "."), ".local")
		if deviceType, ok := mdnsServiceDeviceTypes[key]; ok {
			return deviceType
		}
	}
	return ""
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
