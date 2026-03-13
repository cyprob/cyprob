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

func TestAssetProfileBuilder_Execute_EmitDNSDetailsForTCPAndUDP(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("test-dns-asset-profile", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	target := "192.0.2.53"
	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.live_hosts": []any{
			discovery.ICMPPingDiscoveryResult{LiveHosts: []string{}},
		},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{53}},
		},
		"discovery.open_udp_ports": []any{
			discovery.UDPPortDiscoveryResult{Target: target, OpenPorts: []int{53}},
		},
		"service.dns.details": []any{
			scan.DNSServiceInfo{
				Target:               target,
				Port:                 53,
				Transport:            "udp",
				DNSProbe:             true,
				NSQueryResponded:     true,
				VersionBindResponded: true,
				VersionBindSupported: true,
				ResponseCode:         "NOERROR",
				RecursionAvailable:   true,
				NSRecords:            []string{"a.root-servers.net."},
				VersionBind:          "BIND 9.16.23",
				ProductHint:          "BIND",
				VendorHint:           "ISC",
				VersionHint:          "9.16.23",
			},
			scan.DNSServiceInfo{
				Target:               target,
				Port:                 53,
				Transport:            "tcp",
				DNSProbe:             true,
				NSQueryResponded:     true,
				VersionBindResponded: true,
				VersionBindSupported: false,
				ResponseCode:         "REFUSED",
			},
		},
		"service.identity.details": []any{
			parse.ServiceIdentityInfo{
				Target:      target,
				Port:        53,
				ServiceName: "dns",
				Product:     "BIND",
				Vendor:      "ISC",
				Version:     "9.16.23",
				Protocol:    "udp",
				TechTags:    []string{"dns"},
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
		if len(ports) != 2 {
			t.Fatalf("expected tcp+udp profiles, got %d", len(ports))
		}

		var tcpPort, udpPort *engine.PortProfile
		for i := range ports {
			switch ports[i].Protocol {
			case "tcp":
				tcpPort = &ports[i]
			case "udp":
				udpPort = &ports[i]
			}
		}
		if tcpPort == nil || udpPort == nil {
			t.Fatalf("expected both tcp and udp port profiles, got %+v", ports)
		}
		if tcpPort.Service.ParsedAttributes["dns_transport"] != "tcp" {
			t.Fatalf("expected tcp dns transport attr, got %+v", tcpPort.Service.ParsedAttributes)
		}
		if udpPort.Service.ParsedAttributes["dns_transport"] != "udp" {
			t.Fatalf("expected udp dns transport attr, got %+v", udpPort.Service.ParsedAttributes)
		}
		if udpPort.Service.ParsedAttributes["dns_version_bind"] != "BIND 9.16.23" {
			t.Fatalf("expected udp version.bind attr, got %+v", udpPort.Service.ParsedAttributes)
		}
		if _, leaked := udpPort.Service.ParsedAttributes["dns_body"]; leaked {
			t.Fatalf("raw dns body leaked into parsed attributes")
		}
	case <-time.After(time.Second):
		t.Fatal("no output emitted")
	}
}
