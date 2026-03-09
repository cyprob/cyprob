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

func TestAssetProfileBuilder_UsesCanonicalServiceIdentity(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("identity-builder", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	target := "192.0.2.60"
	port := 445

	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{port}},
		},
		"service.banner.tcp": []any{
			scan.BannerGrabResult{IP: target, Port: port, Banner: "legacy"},
		},
		"service.fingerprint.details": []any{
			parse.FingerprintParsedInfo{
				Target:     target,
				Port:       port,
				Protocol:   "microsoft-ds",
				Product:    "legacy smb",
				Vendor:     "legacy",
				Version:    "1.0",
				Confidence: 0.8,
			},
		},
		"service.identity.details": []any{
			parse.ServiceIdentityInfo{
				Target:       target,
				Port:         port,
				ServiceName:  "smb",
				Product:      "windows smb server",
				Vendor:       "microsoft",
				Version:      "10.0.26100",
				CPE:          "cpe:2.3:a:microsoft:windows_smb_server:10.0.26100:*:*:*:*:*:*:*",
				HostnameHint: "win-host.local",
				TechTags:     []string{"smb"},
				FieldSources: map[string]string{"product": "smb_native_enum"},
			},
		},
	}

	out := make(chan engine.ModuleOutput, 1)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}

	result := <-out
	profiles, ok := result.Data.([]engine.AssetProfile)
	if !ok {
		t.Fatalf("expected []engine.AssetProfile, got %T", result.Data)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}

	ports := profiles[0].OpenPorts[target]
	if len(ports) != 1 {
		t.Fatalf("expected 1 open port entry, got %d", len(ports))
	}

	service := ports[0].Service
	if service.Product != "windows smb server" {
		t.Fatalf("expected canonical product, got %q", service.Product)
	}
	if service.Version != "10.0.26100" {
		t.Fatalf("expected canonical version, got %q", service.Version)
	}
	if vendor, _ := service.ParsedAttributes["vendor"].(string); vendor != "microsoft" {
		t.Fatalf("expected canonical vendor attribute, got %q", vendor)
	}
	if cpe, _ := service.ParsedAttributes["cpe"].(string); cpe == "" {
		t.Fatalf("expected canonical cpe in parsed attributes")
	}
	if len(profiles[0].Hostnames) == 0 || profiles[0].Hostnames[0] != "win-host.local" {
		t.Fatalf("expected hostname hint promoted to asset hostnames, got %+v", profiles[0].Hostnames)
	}
}

func TestAssetProfileBuilder_MapsRDPDetailsToParsedAttributes(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("rdp-builder", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	target := "192.0.2.61"
	port := 3389
	nla := true
	tls := true

	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{port}},
		},
		"service.rdp.details": []any{
			scan.RDPServiceInfo{
				Target:           target,
				Port:             port,
				RDPProbe:         true,
				RDPDetected:      "x224-confirm",
				SelectedProtocol: "hybrid",
				NLACapable:       &nla,
				TLSCapable:       &tls,
				NegFailureCode:   "",
				Error:            "",
			},
		},
	}

	out := make(chan engine.ModuleOutput, 1)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}

	result := <-out
	profiles, ok := result.Data.([]engine.AssetProfile)
	if !ok {
		t.Fatalf("expected []engine.AssetProfile, got %T", result.Data)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}

	ports := profiles[0].OpenPorts[target]
	if len(ports) != 1 {
		t.Fatalf("expected 1 open port entry, got %d", len(ports))
	}

	attrs := ports[0].Service.ParsedAttributes
	if attrs["rdp_detected"] != "x224-confirm" {
		t.Fatalf("expected rdp_detected=x224-confirm, got %v", attrs["rdp_detected"])
	}
	if attrs["rdp_selected_protocol"] != "hybrid" {
		t.Fatalf("expected rdp_selected_protocol=hybrid, got %v", attrs["rdp_selected_protocol"])
	}
	if got, ok := attrs["rdp_nla_capable"].(bool); !ok || !got {
		t.Fatalf("expected rdp_nla_capable=true, got %v", attrs["rdp_nla_capable"])
	}
	if got, ok := attrs["rdp_tls_capable"].(bool); !ok || !got {
		t.Fatalf("expected rdp_tls_capable=true, got %v", attrs["rdp_tls_capable"])
	}
}

func TestAssetProfileBuilder_MapsTLSDetailsToParsedAttributes(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("tls-builder", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	target := "192.0.2.62"
	port := 443
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)

	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{port}},
		},
		"service.tls.details": []any{
			scan.TLSServiceInfo{
				Target:           target,
				Port:             port,
				TLSProbe:         true,
				TLSVersion:       "TLS1.2",
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				ALPN:             "h2",
				SNIServerName:    "example.test",
				CertSubjectCN:    "example.test",
				CertIssuer:       "CN=example-ca",
				CertDNSNames:     []string{"example.test", "www.example.test"},
				CertNotBefore:    notBefore,
				CertNotAfter:     notAfter,
				CertIsExpired:    false,
				CertIsSelfSigned: true,
				CertSHA256:       "deadbeef",
				WeakProtocol:     false,
				WeakCipher:       false,
				HostnameMismatch: false,
				CertExpiringSoon: true,
				ProbeError:       "",
			},
		},
	}

	out := make(chan engine.ModuleOutput, 1)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}

	result := <-out
	profiles, ok := result.Data.([]engine.AssetProfile)
	if !ok {
		t.Fatalf("expected []engine.AssetProfile, got %T", result.Data)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}

	ports := profiles[0].OpenPorts[target]
	if len(ports) != 1 {
		t.Fatalf("expected 1 open port entry, got %d", len(ports))
	}

	service := ports[0].Service
	attrs := service.ParsedAttributes
	if !service.IsTLS {
		t.Fatalf("expected service.IsTLS=true")
	}
	if attrs["tls_version"] != "TLS1.2" {
		t.Fatalf("expected tls_version=TLS1.2, got %v", attrs["tls_version"])
	}
	if attrs["tls_cipher_suite"] != "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" {
		t.Fatalf("expected tls_cipher_suite mapped, got %v", attrs["tls_cipher_suite"])
	}
	if attrs["tls_alpn"] != "h2" {
		t.Fatalf("expected tls_alpn=h2, got %v", attrs["tls_alpn"])
	}
	if attrs["tls_sni_server_name"] != "example.test" {
		t.Fatalf("expected tls_sni_server_name=example.test, got %v", attrs["tls_sni_server_name"])
	}
	if attrs["tls_cert_subject_cn"] != "example.test" {
		t.Fatalf("expected tls_cert_subject_cn mapped, got %v", attrs["tls_cert_subject_cn"])
	}
	if attrs["tls_cert_issuer"] != "CN=example-ca" {
		t.Fatalf("expected tls_cert_issuer mapped, got %v", attrs["tls_cert_issuer"])
	}
	dnsNames, ok := attrs["tls_cert_dns_names"].([]string)
	if !ok || len(dnsNames) != 2 {
		t.Fatalf("expected tls_cert_dns_names as []string, got %#v", attrs["tls_cert_dns_names"])
	}
	if _, ok := attrs["tls_cert_not_before"].(time.Time); !ok {
		t.Fatalf("expected tls_cert_not_before as time.Time, got %T", attrs["tls_cert_not_before"])
	}
	if _, ok := attrs["tls_cert_not_after"].(time.Time); !ok {
		t.Fatalf("expected tls_cert_not_after as time.Time, got %T", attrs["tls_cert_not_after"])
	}
	if got, ok := attrs["tls_cert_is_self_signed"].(bool); !ok || !got {
		t.Fatalf("expected tls_cert_is_self_signed=true, got %v", attrs["tls_cert_is_self_signed"])
	}
	if got, ok := attrs["tls_cert_expiring_soon"].(bool); !ok || !got {
		t.Fatalf("expected tls_cert_expiring_soon=true, got %v", attrs["tls_cert_expiring_soon"])
	}
}

func TestAssetProfileBuilder_MapsTLSProbeError(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("tls-builder-error", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	target := "192.0.2.63"
	port := 443

	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{port}},
		},
		"service.tls.details": []any{
			scan.TLSServiceInfo{
				Target:     target,
				Port:       port,
				TLSProbe:   false,
				ProbeError: "handshake_failed",
			},
		},
	}

	out := make(chan engine.ModuleOutput, 1)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}

	result := <-out
	profiles, ok := result.Data.([]engine.AssetProfile)
	if !ok {
		t.Fatalf("expected []engine.AssetProfile, got %T", result.Data)
	}
	attrs := profiles[0].OpenPorts[target][0].Service.ParsedAttributes
	if attrs["tls_probe_error"] != "handshake_failed" {
		t.Fatalf("expected tls_probe_error=handshake_failed, got %v", attrs["tls_probe_error"])
	}
}

func TestAssetProfileBuilder_MapsRPCDetailsToParsedAttributes(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("rpc-builder", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	target := "192.0.2.64"
	port := 135

	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{port}},
		},
		"service.rpc.details": []any{
			scan.RPCServiceInfo{
				Target:            target,
				Port:              port,
				RPCProbe:          true,
				AnonymousBind:     true,
				IsServerListening: true,
				PrincipalName:     "NT AUTHORITY\\SYSTEM",
				InterfaceCount:    4,
				InterfaceUUIDs:    []string{"uuid-1", "uuid-2"},
				NamedPipes:        []string{"\\\\PIPE\\\\eventlog"},
				InternalIPs:       []string{"192.168.0.10"},
				RPCStats:          []int{12625, 0, 22, 21},
				ProbeError:        "",
			},
		},
	}

	out := make(chan engine.ModuleOutput, 1)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}

	result := <-out
	profiles, ok := result.Data.([]engine.AssetProfile)
	if !ok {
		t.Fatalf("expected []engine.AssetProfile, got %T", result.Data)
	}

	attrs := profiles[0].OpenPorts[target][0].Service.ParsedAttributes
	if got, ok := attrs["rpc_probe"].(bool); !ok || !got {
		t.Fatalf("expected rpc_probe=true, got %v", attrs["rpc_probe"])
	}
	if got, ok := attrs["rpc_anonymous_bind"].(bool); !ok || !got {
		t.Fatalf("expected rpc_anonymous_bind=true, got %v", attrs["rpc_anonymous_bind"])
	}
	if attrs["rpc_principal_name"] != "NT AUTHORITY\\SYSTEM" {
		t.Fatalf("expected rpc_principal_name mapped, got %v", attrs["rpc_principal_name"])
	}
	if attrs["rpc_interface_count"] != 4 {
		t.Fatalf("expected rpc_interface_count=4, got %v", attrs["rpc_interface_count"])
	}
}

func TestAssetProfileBuilder_MapsRPCProbeError(t *testing.T) {
	module := newAssetProfileBuilderModule()
	if err := module.Init("rpc-builder-error", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	target := "192.0.2.65"
	port := 49152

	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{port}},
		},
		"service.rpc.details": []any{
			scan.RPCServiceInfo{
				Target:     target,
				Port:       port,
				RPCProbe:   false,
				ProbeError: "timeout",
			},
		},
	}

	out := make(chan engine.ModuleOutput, 1)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}

	result := <-out
	profiles, ok := result.Data.([]engine.AssetProfile)
	if !ok {
		t.Fatalf("expected []engine.AssetProfile, got %T", result.Data)
	}
	attrs := profiles[0].OpenPorts[target][0].Service.ParsedAttributes
	if attrs["rpc_probe_error"] != "timeout" {
		t.Fatalf("expected rpc_probe_error=timeout, got %v", attrs["rpc_probe_error"])
	}
}
