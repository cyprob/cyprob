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

func TestAssetProfileBuilder_Execute_EmitFTPDetails(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("test-ftp-profile", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	target := "192.0.2.90"
	notAfter := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{990}},
		},
		"service.ftp.details": []any{
			scan.FTPServiceInfo{
				Target:           target,
				Port:             990,
				FTPProbe:         true,
				FTPProtocol:      "ftps",
				Banner:           "220 FileZilla Server 1.9.4 ready",
				GreetingCode:     220,
				Features:         []string{"UTF8", "MDTM"},
				TLSEnabled:       true,
				TLSVersion:       "TLS1.3",
				TLSCipherSuite:   "TLS_AES_128_GCM_SHA256",
				CertSubjectCN:    "ftp.example.test",
				CertIssuer:       "CN=ftp.example.test",
				CertNotAfter:     notAfter,
				CertIsSelfSigned: true,
				SystemHint:       "UNIX Type: L8",
				SoftwareHint:     "FileZilla Server",
				VendorHint:       "FileZilla Project",
				VersionHint:      "1.9.4",
			},
		},
		"service.identity.details": []any{
			parse.ServiceIdentityInfo{
				Target:      target,
				Port:        990,
				ServiceName: "ftps",
				Product:     "FileZilla Server",
				Vendor:      "FileZilla Project",
				Version:     "1.9.4",
				TechTags:    []string{"ftp", "tls"},
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
		if port.Protocol != "tcp" || port.PortNumber != 990 {
			t.Fatalf("expected tcp/990, got %s/%d", port.Protocol, port.PortNumber)
		}
		if port.Service.Name != "ftps" || port.Service.Product != "FileZilla Server" || port.Service.Version != "1.9.4" {
			t.Fatalf("unexpected service identity: %+v", port.Service)
		}
		if !port.Service.IsTLS {
			t.Fatalf("expected service to be marked TLS")
		}
		if port.Service.ParsedAttributes["ftp_protocol"] != "ftps" {
			t.Fatalf("expected ftp_protocol=ftps, got %v", port.Service.ParsedAttributes["ftp_protocol"])
		}
		if port.Service.ParsedAttributes["ftp_tls_version"] != "TLS1.3" {
			t.Fatalf("expected ftp_tls_version TLS1.3, got %v", port.Service.ParsedAttributes["ftp_tls_version"])
		}
		if port.Service.ParsedAttributes["ftp_cert_subject_cn"] != "ftp.example.test" {
			t.Fatalf("expected ftp_cert_subject_cn, got %v", port.Service.ParsedAttributes["ftp_cert_subject_cn"])
		}
		if port.Service.ParsedAttributes["ftp_system_hint"] != "UNIX Type: L8" {
			t.Fatalf("expected ftp_system_hint, got %v", port.Service.ParsedAttributes["ftp_system_hint"])
		}
	case <-time.After(time.Second):
		t.Fatal("no output emitted")
	}
}
