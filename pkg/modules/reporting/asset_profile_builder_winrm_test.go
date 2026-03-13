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

func TestAssetProfileBuilder_Execute_EmitWINRMDetails(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("test-winrm-profile", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	target := "192.0.2.185"
	notAfter := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{5986}},
		},
		"service.winrm.details": []any{
			scan.WINRMServiceInfo{
				Target:               target,
				Port:                 5986,
				WINRMProbe:           true,
				WINRMTransport:       "https",
				HTTPStatusCode:       200,
				ServerHeader:         "Microsoft-HTTPAPI/2.0",
				ContentType:          "application/soap+xml; charset=UTF-8",
				AuthSchemes:          []string{"Negotiate", "NTLM"},
				IdentifySupported:    true,
				ServiceHint:          "WinRM",
				WSMANProtocolVersion: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
				ProductVendor:        "Microsoft Corporation",
				ProductVersion:       "OS: 10.0.20348 SP: 0.0 Stack: 3.0",
				TLSEnabled:           true,
				TLSVersion:           "TLS1.3",
				TLSCipherSuite:       "TLS_AES_128_GCM_SHA256",
				CertSubjectCN:        "winrm.example.test",
				CertIssuer:           "CN=winrm.example.test",
				CertNotAfter:         notAfter,
				CertIsSelfSigned:     true,
			},
		},
		"service.identity.details": []any{
			parse.ServiceIdentityInfo{
				Target:      target,
				Port:        5986,
				ServiceName: "winrm",
				Product:     "WinRM",
				Vendor:      "Microsoft",
				Version:     "OS: 10.0.20348 SP: 0.0 Stack: 3.0",
				TechTags:    []string{"winrm", "wsman", "tls"},
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
		if port.Protocol != "tcp" || port.PortNumber != 5986 {
			t.Fatalf("expected tcp/5986, got %s/%d", port.Protocol, port.PortNumber)
		}
		if port.Service.Name != "winrm" || port.Service.Product != "WinRM" || port.Service.Version != "OS: 10.0.20348 SP: 0.0 Stack: 3.0" {
			t.Fatalf("unexpected service identity: %+v", port.Service)
		}
		if !port.Service.IsTLS {
			t.Fatalf("expected service to be marked TLS")
		}
		if port.Service.ParsedAttributes["winrm_transport"] != "https" {
			t.Fatalf("expected winrm_transport=https, got %v", port.Service.ParsedAttributes["winrm_transport"])
		}
		if port.Service.ParsedAttributes["winrm_http_status_code"] != 200 {
			t.Fatalf("expected winrm_http_status_code=200, got %v", port.Service.ParsedAttributes["winrm_http_status_code"])
		}
		if port.Service.ParsedAttributes["winrm_service_hint"] != "WinRM" {
			t.Fatalf("expected winrm_service_hint, got %v", port.Service.ParsedAttributes["winrm_service_hint"])
		}
		if port.Service.ParsedAttributes["winrm_product_vendor"] != "Microsoft Corporation" {
			t.Fatalf("expected winrm_product_vendor, got %v", port.Service.ParsedAttributes["winrm_product_vendor"])
		}
		if _, ok := port.Service.ParsedAttributes["winrm_body"]; ok {
			t.Fatalf("did not expect raw SOAP body in parsed attributes")
		}
	case <-time.After(time.Second):
		t.Fatal("no output emitted")
	}
}
