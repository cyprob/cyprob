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

func TestAssetProfileBuilder_Execute_EmitMySQLDetails(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("test-mysql-profile", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	target := "192.0.2.91"
	notAfter := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{3306}},
		},
		"service.mysql.details": []any{
			scan.MySQLServiceInfo{
				Target:          target,
				Port:            3306,
				MySQLProbe:      true,
				GreetingKind:    "handshake",
				ProtocolVersion: 10,
				ServerVersion:   "8.0.36-MySQL Community Server",
				ConnectionID:    1234,
				CapabilityFlags: 0x00000800,
				StatusFlags:     2,
				CharacterSet:    33,
				AuthPluginName:  "caching_sha2_password",
				TLSSupported:    true,
				TLSEnabled:      true,
				TLSVersion:      "TLS1.3",
				TLSCipherSuite:  "TLS_AES_128_GCM_SHA256",
				CertSubjectCN:   "mysql.example.test",
				CertIssuer:      "CN=mysql.example.test",
				CertNotAfter:    notAfter,
				ProductHint:     "MySQL",
				VendorHint:      "Oracle",
				VersionHint:     "8.0.36-MySQL",
			},
		},
		"service.identity.details": []any{
			parse.ServiceIdentityInfo{
				Target:      target,
				Port:        3306,
				ServiceName: "mysql",
				Product:     "MySQL",
				Vendor:      "Oracle",
				Version:     "8.0.36-MySQL",
				TechTags:    []string{"mysql"},
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
		if port.Protocol != "tcp" || port.PortNumber != 3306 {
			t.Fatalf("expected tcp/3306, got %s/%d", port.Protocol, port.PortNumber)
		}
		if port.Service.Name != "mysql" || port.Service.Product != "MySQL" || port.Service.Version != "8.0.36-MySQL" {
			t.Fatalf("unexpected service identity: %+v", port.Service)
		}
		if !port.Service.IsTLS {
			t.Fatalf("expected service to be marked TLS")
		}
		if port.Service.ParsedAttributes["mysql_protocol_version"] != 10 {
			t.Fatalf("expected mysql_protocol_version=10, got %v", port.Service.ParsedAttributes["mysql_protocol_version"])
		}
		if port.Service.ParsedAttributes["mysql_server_version"] != "8.0.36-MySQL Community Server" {
			t.Fatalf("expected mysql_server_version, got %v", port.Service.ParsedAttributes["mysql_server_version"])
		}
		if port.Service.ParsedAttributes["mysql_auth_plugin_name"] != "caching_sha2_password" {
			t.Fatalf("expected mysql_auth_plugin_name, got %v", port.Service.ParsedAttributes["mysql_auth_plugin_name"])
		}
		if port.Service.ParsedAttributes["mysql_tls_version"] != "TLS1.3" {
			t.Fatalf("expected mysql_tls_version, got %v", port.Service.ParsedAttributes["mysql_tls_version"])
		}
		if port.Service.ParsedAttributes["mysql_cert_subject_cn"] != "mysql.example.test" {
			t.Fatalf("expected mysql_cert_subject_cn, got %v", port.Service.ParsedAttributes["mysql_cert_subject_cn"])
		}
	case <-time.After(time.Second):
		t.Fatal("no output emitted")
	}
}
