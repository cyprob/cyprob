package reporting

import (
	"context"
	"testing"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"github.com/cyprob/cyprob/pkg/modules/evaluation"
	"github.com/cyprob/cyprob/pkg/modules/parse"
	"github.com/cyprob/cyprob/pkg/modules/scan"
)

func TestAssetProfileBuilderUsesFingerprintForNonDefaultPort(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init(assetProfileBuilderModuleTypeName, map[string]any{}); err != nil {
		t.Fatalf("init module failed: %v", err)
	}

	target := "192.0.2.10"
	port := 20022

	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{port}},
		},
		"service.banner.tcp": []any{
			scan.BannerGrabResult{IP: target, Port: port, Banner: "SSH-2.0-OpenSSH_8.9p1"},
		},
		"service.fingerprint.details": []any{
			parse.FingerprintParsedInfo{Target: target, Port: port, Protocol: "ssh", Product: "OpenSSH", Version: "8.9p1", Confidence: 0.92},
		},
	}

	outputChan := make(chan engine.ModuleOutput, 1)
	if err := module.Execute(context.Background(), inputs, outputChan); err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	select {
	case out := <-outputChan:
		profiles, ok := out.Data.([]engine.AssetProfile)
		if !ok {
			t.Fatalf("expected []engine.AssetProfile, got %T", out.Data)
		}
		if len(profiles) == 0 {
			t.Fatalf("no asset profiles returned")
		}
		profile := profiles[0]
		ports := profile.OpenPorts[target]
		if len(ports) == 0 {
			t.Fatalf("expected open port entry")
		}
		service := ports[0].Service
		if service.Name != "ssh" {
			t.Fatalf("expected service name ssh, got %s", service.Name)
		}
		if service.Product != "OpenSSH" {
			t.Fatalf("expected product OpenSSH, got %s", service.Product)
		}
		if service.Version != "8.9p1" {
			t.Fatalf("expected version 8.9p1, got %s", service.Version)
		}
	case <-time.After(time.Second):
		t.Fatal("no output emitted")
	}
}

func TestAssetProfileBuilderModuleFactory_ReturnsModule(t *testing.T) {
	t.Parallel()

	mod := AssetProfileBuilderModuleFactory()
	if mod == nil {
		t.Fatal("factory returned nil module")
	}

	meta := mod.Metadata()
	if meta.Name != assetProfileBuilderModuleTypeName {
		t.Fatalf("expected module name %q, got %q", assetProfileBuilderModuleTypeName, meta.Name)
	}
}

func TestAssetProfileBuilderModuleFactory_InitExecuteProducesAssetProfilesKey(t *testing.T) {
	t.Parallel()

	mod := AssetProfileBuilderModuleFactory()
	if err := mod.Init("factory-instance", map[string]any{}); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if mod.Metadata().ID != "factory-instance" {
		t.Fatalf("expected meta.ID set to %q, got %q", "factory-instance", mod.Metadata().ID)
	}

	outCh := make(chan engine.ModuleOutput, 1)
	if err := mod.Execute(context.Background(), map[string]any{}, outCh); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	select {
	case out := <-outCh:
		if out.DataKey != "asset.profiles" {
			t.Fatalf("unexpected data key: %s", out.DataKey)
		}
		if _, ok := out.Data.([]engine.AssetProfile); !ok {
			t.Fatalf("expected data type []engine.AssetProfile, got %T", out.Data)
		}
	case <-time.After(time.Second):
		t.Fatal("no output emitted")
	}
}

func TestAssetProfileBuilderMapsVulnerabilitiesToPort(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init(assetProfileBuilderModuleTypeName, map[string]any{}); err != nil {
		t.Fatalf("init module failed: %v", err)
	}

	target := "192.0.2.30"
	port := 8080

	vuln := evaluation.VulnerabilityResult{
		Target:      target,
		Port:        port,
		Plugin:      "test-plugin",
		Message:     "remote code execution",
		Severity:    "medium",
		CVE:         []string{"CVE-2025-1234"},
		Remediation: "update package",
		Reference:   "http://example.com/vuln",
	}

	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{port}},
		},
		"evaluation.vulnerabilities": []any{vuln},
	}

	outCh := make(chan engine.ModuleOutput, 1)
	if err := module.Execute(context.Background(), inputs, outCh); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	select {
	case out := <-outCh:
		profiles, ok := out.Data.([]engine.AssetProfile)
		if !ok {
			t.Fatalf("expected []engine.AssetProfile, got %T", out.Data)
		}
		if len(profiles) == 0 {
			t.Fatalf("no asset profiles returned")
		}
		profile := profiles[0]
		ports := profile.OpenPorts[target]
		if len(ports) == 0 {
			t.Fatalf("expected open port entry")
		}
		if profile.TotalVulnerabilities != 1 {
			t.Fatalf("expected TotalVulnerabilities 1, got %d", profile.TotalVulnerabilities)
		}
		vulns := ports[0].Vulnerabilities
		if len(vulns) != 1 {
			t.Fatalf("expected 1 vulnerability on port, got %d", len(vulns))
		}
		if vulns[0].Summary != vuln.Message {
			t.Fatalf("expected vulnerability summary %q, got %q", vuln.Message, vulns[0].Summary)
		}
		if vulns[0].SourceModule != vuln.Plugin {
			t.Fatalf("expected vulnerability source %q, got %q", vuln.Plugin, vulns[0].SourceModule)
		}
		if vulns[0].ID != "CVE-2025-1234" {
			t.Fatalf("expected vulnerability ID %q, got %q", "CVE-2025-1234", vulns[0].ID)
		}
	case <-time.After(time.Second):
		t.Fatal("no output emitted")
	}
}

func TestAssetProfileBuilder_Execute_EmptyInputs(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("test-empty", map[string]any{}); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	outCh := make(chan engine.ModuleOutput, 1)
	err := module.Execute(context.Background(), map[string]any{}, outCh)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	select {
	case out := <-outCh:
		profiles, ok := out.Data.([]engine.AssetProfile)
		if !ok {
			t.Fatalf("expected []engine.AssetProfile, got %T", out.Data)
		}
		if len(profiles) != 0 {
			t.Fatalf("expected 0 profiles, got %d", len(profiles))
		}
	case <-time.After(time.Second):
		t.Fatal("no output emitted")
	}
}

func TestAssetProfileBuilder_Execute_InitialTargetsOnly(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("test-initial", map[string]any{}); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	targets := []string{"192.0.2.1", "192.0.2.2"}
	inputs := map[string]any{
		"config.targets": targets,
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
		if len(profiles) != len(targets) {
			t.Fatalf("expected %d profiles, got %d", len(targets), len(profiles))
		}
		for _, p := range profiles {
			if p.IsAlive {
				t.Errorf("expected IsAlive=false for %s", p.Target)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("no output emitted")
	}
}

func TestAssetProfileBuilder_Execute_LiveHostsAndOpenPorts(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("test-live", map[string]any{}); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	target := "192.0.2.5"
	port := 443
	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.live_hosts": []any{
			discovery.ICMPPingDiscoveryResult{LiveHosts: []string{target}},
		},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{port}},
		},
		"service.banner.tcp": []any{
			scan.BannerGrabResult{IP: target, Port: port, Banner: "HTTPS Service", IsTLS: true},
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
		if !profile.IsAlive {
			t.Errorf("expected IsAlive=true for %s", profile.Target)
		}
		ports := profile.OpenPorts[target]
		if len(ports) != 1 {
			t.Fatalf("expected 1 open port, got %d", len(ports))
		}
		if ports[0].PortNumber != port {
			t.Errorf("expected port %d, got %d", port, ports[0].PortNumber)
		}
		if ports[0].Service.RawBanner != "HTTPS Service" {
			t.Errorf("expected banner 'HTTPS Service', got %q", ports[0].Service.RawBanner)
		}
		if !ports[0].Service.IsTLS {
			t.Errorf("expected IsTLS=true")
		}
	case <-time.After(time.Second):
		t.Fatal("no output emitted")
	}
}

func TestAssetProfileBuilder_Execute_HTTPAndSSHDetails(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("test-details", map[string]any{}); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	target := "192.0.2.10"
	httpPort := 80
	sshPort := 22

	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{httpPort, sshPort}},
		},
		"service.http.details": []any{
			parse.HTTPParsedInfo{
				Target:        target,
				Port:          httpPort,
				ServerProduct: "nginx",
				ServerVersion: "1.21.0",
				StatusCode:    200,
				HTTPVersion:   "1.1",
				HTMLTitle:     "Welcome",
				ContentType:   "text/html",
				Headers:       map[string]string{"Server": "nginx"},
			},
		},
		"service.ssh.details": []any{
			parse.SSHParsedInfo{
				Target:          target,
				Port:            sshPort,
				ProtocolName:    "ssh",
				Software:        "OpenSSH",
				SoftwareVersion: "8.9p1",
				SSHVersion:      "2.0",
				VersionInfo:     "OpenSSH_8.9p1 Debian-3",
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
		if len(profiles) == 0 {
			t.Fatalf("no asset profiles returned")
		}
		profile := profiles[0]
		ports := profile.OpenPorts[target]
		if len(ports) != 2 {
			t.Fatalf("expected 2 open ports, got %d", len(ports))
		}
		var httpFound, sshFound bool
		for _, p := range ports {
			if p.PortNumber == httpPort {
				httpFound = true
				if p.Service.Name != "http" {
					t.Errorf("expected service name http, got %s", p.Service.Name)
				}
				if p.Service.Product != "nginx" {
					t.Errorf("expected product nginx, got %s", p.Service.Product)
				}
				if p.Service.Version != "1.21.0" {
					t.Errorf("expected version 1.21.0, got %s", p.Service.Version)
				}
				if p.Service.ParsedAttributes["http_status_code"] != 200 {
					t.Errorf("expected status code 200, got %v", p.Service.ParsedAttributes["http_status_code"])
				}
			}
			if p.PortNumber == sshPort {
				sshFound = true
				if p.Service.Name != "ssh" {
					t.Errorf("expected service name ssh, got %s", p.Service.Name)
				}
				if p.Service.Product != "OpenSSH" {
					t.Errorf("expected product OpenSSH, got %s", p.Service.Product)
				}
				if p.Service.Version != "8.9p1" {
					t.Errorf("expected version 8.9p1, got %s", p.Service.Version)
				}
				if p.Service.ParsedAttributes["ssh_protocol_version"] != "2.0" {
					t.Errorf("expected ssh_protocol_version 2.0, got %v", p.Service.ParsedAttributes["ssh_protocol_version"])
				}
			}
		}
		if !httpFound {
			t.Error("HTTP port not found in profile")
		}
		if !sshFound {
			t.Error("SSH port not found in profile")
		}
	case <-time.After(time.Second):
		t.Fatal("no output emitted")
	}
}

func TestAssetProfileBuilder_Execute_FingerprintOverridesBanner(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("test-fp", map[string]any{}); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	target := "192.0.2.20"
	port := 8081

	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{port}},
		},
		"service.banner.tcp": []any{
			scan.BannerGrabResult{IP: target, Port: port, Banner: "SomeBanner"},
		},
		"service.fingerprint.details": []any{
			parse.FingerprintParsedInfo{
				Target:      target,
				Port:        port,
				Protocol:    "customproto",
				Product:     "CustomProduct",
				Version:     "2.3.4",
				Confidence:  0.99,
				CPE:         "cpe:/a:custom:product:2.3.4",
				Vendor:      "CustomVendor",
				Description: "Custom service",
				SourceProbe: "fp-probe",
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
		if len(profiles) == 0 {
			t.Fatalf("no asset profiles returned")
		}
		profile := profiles[0]
		ports := profile.OpenPorts[target]
		if len(ports) == 0 {
			t.Fatalf("expected open port entry")
		}
		service := ports[0].Service
		if service.Name != "customproto" {
			t.Errorf("expected service name customproto, got %s", service.Name)
		}
		if service.Product != "CustomProduct" {
			t.Errorf("expected product CustomProduct, got %s", service.Product)
		}
		if service.Version != "2.3.4" {
			t.Errorf("expected version 2.3.4, got %s", service.Version)
		}
		if service.ParsedAttributes["cpe"] != "cpe:/a:custom:product:2.3.4" {
			t.Errorf("expected cpe attribute, got %v", service.ParsedAttributes["cpe"])
		}
		if service.ParsedAttributes["vendor"] != "CustomVendor" {
			t.Errorf("expected vendor attribute, got %v", service.ParsedAttributes["vendor"])
		}
		if service.ParsedAttributes["fingerprint_primary_description"] != "Custom service" {
			t.Errorf("expected fingerprint_primary_description, got %v", service.ParsedAttributes["fingerprint_primary_description"])
		}
		if service.ParsedAttributes["fingerprint_primary_probe"] != "fp-probe" {
			t.Errorf("expected fingerprint_primary_probe, got %v", service.ParsedAttributes["fingerprint_primary_probe"])
		}
		if service.ParsedAttributes["fingerprint_confidence"] != 0.99 {
			t.Errorf("expected fingerprint_confidence 0.99, got %v", service.ParsedAttributes["fingerprint_confidence"])
		}
	case <-time.After(time.Second):
		t.Fatal("no output emitted")
	}
}
