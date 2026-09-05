package parse

import (
	"context"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
)

const mikrotikFTPGreeting = "220 Habib FTP server (MikroTik 6.49.10) ready"

func runNormalizer(t *testing.T, inputs map[string]any, target string, port int) ServiceIdentityInfo {
	t.Helper()

	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-telnet-vendor-word", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	out := make(chan engine.ModuleOutput, 16)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	for item := range out {
		candidate, ok := item.Data.(ServiceIdentityInfo)
		if !ok {
			continue
		}
		if candidate.Target == target && candidate.Port == port {
			return candidate
		}
	}
	t.Fatalf("no identity emitted for %s:%d", target, port)
	return ServiceIdentityInfo{}
}

// TestNormalizer_TelnetDoesNotRenameAnFTPService is the end of the chain
// cyprob-ee#100 describes. The telnet probe was dispatched to port 21 because
// the banner names a vendor, read the FTP greeting, and concluded nothing --
// so it must not name the service. Gating only the probe's verdict is not
// enough on its own: the ingest skip fires only when the banner is empty too,
// and here it is not.
func TestNormalizer_TelnetDoesNotRenameAnFTPService(t *testing.T) {
	identity := runNormalizer(t, map[string]any{
		"service.ftp.details": []any{scanpkg.FTPServiceInfo{
			Target: "192.168.0.41", Port: 21, FTPProbe: true, FTPProtocol: "ftp",
			Banner:       mikrotikFTPGreeting,
			SoftwareHint: "RouterOS", VendorHint: "MikroTik", VersionHint: "6.49.10",
		}},
		"service.telnet.details": []any{scanpkg.TelnetServiceInfo{
			Target: "192.168.0.41", Port: 21,
			TelnetProbe: false, IACDetected: false, ProbeError: "protocol_mismatch",
			Banner:      mikrotikFTPGreeting,
			ProductHint: "RouterOS Telnet", VendorHint: "MikroTik",
		}},
	}, "192.168.0.41", 21)

	if identity.ServiceName != "ftp" {
		t.Errorf("service_name = %q, want ftp", identity.ServiceName)
	}
	if identity.Product == "RouterOS Telnet" {
		t.Errorf("product = %q: a probe that concluded nothing must not supply the product", identity.Product)
	}
	for _, tag := range identity.TechTags {
		if tag == TagTelnet {
			t.Errorf("tech_tags carry %q for a service no probe identified as telnet: %v", TagTelnet, identity.TechTags)
		}
	}
	if identity.Banner != mikrotikFTPGreeting {
		t.Errorf("banner = %q: the bytes were really read and should survive", identity.Banner)
	}
}

// TestNormalizer_RouterOSVersionReachesTheServiceRecord is the point of the FTP
// pattern: a version-gated plugin needs a version on the service, and this
// greeting is the only unauthenticated place one is published.
//
// Scope, because the name promises more than one package can prove: the hints
// are supplied here, so this covers the normalizer plumbing only. That the
// greeting actually yields them is asserted in package scan, by
// TestFTPHints_ReadsRouterOSVersionFromTheGreeting.
func TestNormalizer_RouterOSVersionReachesTheServiceRecord(t *testing.T) {
	identity := runNormalizer(t, map[string]any{
		"service.ftp.details": []any{scanpkg.FTPServiceInfo{
			Target: "192.168.0.41", Port: 21, FTPProbe: true, FTPProtocol: "ftp",
			Banner:       mikrotikFTPGreeting,
			SoftwareHint: "RouterOS", VendorHint: "MikroTik", VersionHint: "6.49.10",
		}},
		"service.telnet.details": []any{scanpkg.TelnetServiceInfo{
			Target: "192.168.0.41", Port: 21,
			TelnetProbe: false, IACDetected: false, ProbeError: "protocol_mismatch",
			Banner:      mikrotikFTPGreeting,
			ProductHint: "RouterOS Telnet", VendorHint: "MikroTik",
		}},
	}, "192.168.0.41", 21)

	if identity.Version != "6.49.10" {
		t.Errorf("version = %q, want 6.49.10", identity.Version)
	}
	if identity.Product != "RouterOS" {
		t.Errorf("product = %q, want RouterOS", identity.Product)
	}
	if identity.Vendor != "MikroTik" {
		t.Errorf("vendor = %q, want MikroTik", identity.Vendor)
	}
}

// TestNormalizer_GenuineTelnetIsStillIdentified guards the other direction: the
// gate must not cost us real telnet services. This is the loss the change could
// cause, so it is asserted rather than assumed.
func TestNormalizer_GenuineTelnetIsStillIdentified(t *testing.T) {
	identity := runNormalizer(t, map[string]any{
		"service.telnet.details": []any{scanpkg.TelnetServiceInfo{
			Target: "192.168.0.41", Port: 23,
			TelnetProbe: true, IACDetected: true, TelnetProtocol: "telnet",
			Banner:      "\r\nlogin: ",
			ProductHint: "RouterOS Telnet", VendorHint: "MikroTik",
		}},
	}, "192.168.0.41", 23)

	if identity.ServiceName != "telnet" {
		t.Errorf("service_name = %q, want telnet", identity.ServiceName)
	}
	if identity.Product != "RouterOS Telnet" {
		t.Errorf("product = %q, want RouterOS Telnet", identity.Product)
	}
}
