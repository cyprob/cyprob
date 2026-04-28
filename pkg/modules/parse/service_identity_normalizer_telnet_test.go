package parse

import (
	"context"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
)

func TestServiceIdentityNormalizer_TelnetFallbackIdentity(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-telnet", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.telnet.details": []any{
			scanpkg.TelnetServiceInfo{
				Target:         "198.51.100.170",
				Port:           23,
				TelnetProbe:    true,
				TelnetProtocol: "telnet",
				Banner:         "BusyBox telnetd login:",
				ProductHint:    "BusyBox telnetd",
				VendorHint:     "BusyBox",
			},
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	var identity ServiceIdentityInfo
	found := false
	for item := range out {
		candidate, ok := item.Data.(ServiceIdentityInfo)
		if !ok {
			continue
		}
		if candidate.Target == "198.51.100.170" && candidate.Port == 23 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected telnet identity output")
	}
	if identity.ServiceName != "telnet" {
		t.Fatalf("expected service_name=telnet, got %q", identity.ServiceName)
	}
	if identity.Product != "BusyBox telnetd" || identity.Vendor != "BusyBox" {
		t.Fatalf("unexpected telnet identity fields: product=%q vendor=%q", identity.Product, identity.Vendor)
	}
	if identity.FieldSources["service_name"] != sourceTelnetNative {
		t.Fatalf("expected telnet native source, got %+v", identity.FieldSources)
	}
	if !hasTag(identity.TechTags, TagTelnet) {
		t.Fatalf("expected telnet tech tag, got %+v", identity.TechTags)
	}
}
