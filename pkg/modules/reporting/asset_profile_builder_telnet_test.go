package reporting

import (
	"context"
	"testing"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"github.com/cyprob/cyprob/pkg/modules/parse"
	"github.com/cyprob/cyprob/pkg/modules/scan"
)

func TestAssetProfileBuilder_Execute_EmitTelnetDetails(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("test-telnet-profile", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	target := "192.0.2.77"
	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{23}},
		},
		"service.telnet.details": []any{
			scan.TelnetServiceInfo{
				Target:             target,
				Port:               23,
				TelnetProbe:        true,
				TelnetProtocol:     "telnet",
				Banner:             "BusyBox telnetd login:",
				IACDetected:        true,
				NegotiationOptions: []string{"do-suppress-go-ahead", "will-echo"},
				ProductHint:        "BusyBox telnetd",
				VendorHint:         "BusyBox",
			},
		},
		"service.identity.details": []any{
			parse.ServiceIdentityInfo{
				Target:      target,
				Port:        23,
				ServiceName: "telnet",
				Product:     "BusyBox telnetd",
				Vendor:      "BusyBox",
				TechTags:    []string{"telnet"},
			},
		},
	}

	outCh := make(chan engine.ModuleOutput, 1)
	if err := module.Execute(context.Background(), inputs, outCh); err != nil {
		t.Fatalf("execute: %v", err)
	}

	select {
	case out := <-outCh:
		profiles, ok := out.Data.([]engine.AssetProfile)
		if !ok {
			t.Fatalf("expected []engine.AssetProfile, got %T", out.Data)
		}
		if len(profiles) != 1 {
			t.Fatalf("expected 1 profile, got %d", len(profiles))
		}
		ports := profiles[0].OpenPorts[target]
		if len(ports) != 1 {
			t.Fatalf("expected 1 open port entry, got %d", len(ports))
		}
		port := ports[0]
		if port.Service.Name != "telnet" || port.Service.Product != "BusyBox telnetd" {
			t.Fatalf("unexpected service identity: %+v", port.Service)
		}
		if port.Service.ParsedAttributes["telnet_protocol"] != "telnet" {
			t.Fatalf("expected telnet_protocol, got %v", port.Service.ParsedAttributes["telnet_protocol"])
		}
		if port.Service.ParsedAttributes["telnet_iac_detected"] != true {
			t.Fatalf("expected telnet_iac_detected=true, got %v", port.Service.ParsedAttributes["telnet_iac_detected"])
		}
		if port.Service.ParsedAttributes["telnet_vendor_hint"] != "BusyBox" {
			t.Fatalf("expected telnet_vendor_hint, got %v", port.Service.ParsedAttributes["telnet_vendor_hint"])
		}
	case <-time.After(time.Second):
		t.Fatal("no output emitted")
	}
}
