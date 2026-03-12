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

func TestAssetProfileBuilder_Execute_OpenUDPPortsSeedSNMPProfile(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("test-snmp-udp-seed", map[string]any{}); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	target := "192.0.2.80"
	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.live_hosts": []any{
			discovery.ICMPPingDiscoveryResult{LiveHosts: []string{}},
		},
		"discovery.open_udp_ports": []any{
			discovery.UDPPortDiscoveryResult{Target: target, OpenPorts: []int{161}},
		},
		"service.snmp.details": []any{
			scan.SNMPServiceInfo{
				Target:        target,
				Port:          161,
				SNMPProbe:     true,
				SNMPVersion:   "SNMPv2c",
				Community:     "public",
				SysDescr:      "Net-SNMP 5.9",
				SysName:       "edge-snmp",
				SysObjectID:   ".1.3.6.1.4.1.8072.3.2.10",
				ProductHint:   "Net-SNMP",
				VendorHint:    "Net-SNMP Project",
				VersionHint:   "5.9",
				WeakCommunity: true,
			},
		},
		"service.identity.details": []any{
			parse.ServiceIdentityInfo{
				Target:      target,
				Port:        161,
				ServiceName: "snmp",
				Product:     "Net-SNMP",
				Vendor:      "Net-SNMP Project",
				Version:     "5.9",
				TechTags:    []string{"snmp"},
			},
		},
	}

	outCh := make(chan engine.ModuleOutput, 1)
	err := module.Execute(context.Background(), inputs, outCh)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
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
		profile := profiles[0]
		ports := profile.OpenPorts[target]
		if len(ports) != 1 {
			t.Fatalf("expected 1 open port entry, got %d", len(ports))
		}
		port := ports[0]
		if port.Protocol != "udp" || port.PortNumber != 161 {
			t.Fatalf("expected udp/161, got %s/%d", port.Protocol, port.PortNumber)
		}
		if port.Service.Name != "snmp" || port.Service.Product != "Net-SNMP" || port.Service.Version != "5.9" {
			t.Fatalf("unexpected service identity: %+v", port.Service)
		}
		if port.Service.ParsedAttributes["snmp_version"] != "SNMPv2c" {
			t.Fatalf("expected snmp_version parsed attribute")
		}
		if port.Service.ParsedAttributes["snmp_weak_community"] != true {
			t.Fatalf("expected snmp_weak_community=true")
		}
		if _, leaked := port.Service.ParsedAttributes["community"]; leaked {
			t.Fatalf("raw community leaked into parsed attributes")
		}
		if _, leaked := port.Service.ParsedAttributes["snmp.community"]; leaked {
			t.Fatalf("raw community leaked into parsed attributes")
		}
	case <-time.After(time.Second):
		t.Fatal("no output emitted")
	}
}
