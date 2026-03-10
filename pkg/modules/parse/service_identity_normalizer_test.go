package parse

import (
	"context"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
)

func TestServiceIdentityNormalizer_SMBPrecedenceOverFingerprint(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.banner.tcp": []any{
			scanpkg.BannerGrabResult{
				IP:       "203.0.113.10",
				Port:     445,
				Protocol: "tcp",
				Banner:   "",
			},
		},
		"service.fingerprint.details": []any{
			FingerprintParsedInfo{
				Target:     "203.0.113.10",
				Port:       445,
				Protocol:   "microsoft-ds",
				Product:    "legacy smb",
				Vendor:     "legacy vendor",
				Version:    "1.0",
				CPE:        "cpe:2.3:a:legacy:smb:1.0:*:*:*:*:*:*:*",
				Confidence: 0.80,
			},
		},
		"service.tech.tags": []any{
			TechTagResult{
				Target: "203.0.113.10",
				Port:   445,
				Tags:   []string{"smb"},
			},
		},
		"service.smb.details": []any{
			scanpkg.SMBServiceInfo{
				Target:         "203.0.113.10",
				Port:           445,
				Product:        "windows smb server",
				Vendor:         "microsoft",
				ProductVersion: "10.0.26100",
				HostHints: scanpkg.SMBHostHints{
					NBComputer:  "NB-HOST",
					TargetName:  "TARGET-HOST",
					DNSComputer: "dns-host.example.local",
				},
				OSHints: scanpkg.SMBOSHints{
					Family:  "windows",
					Name:    "Windows",
					Version: "Windows 11 / Server 2025 Build 26100",
				},
			},
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	var identities []ServiceIdentityInfo
	for item := range out {
		identity, ok := item.Data.(ServiceIdentityInfo)
		if !ok {
			continue
		}
		identities = append(identities, identity)
	}

	if len(identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(identities))
	}

	identity := identities[0]
	if identity.Product != "windows smb server" {
		t.Fatalf("expected SMB native product, got %q", identity.Product)
	}
	if identity.Vendor != "microsoft" {
		t.Fatalf("expected SMB native vendor, got %q", identity.Vendor)
	}
	if identity.Version != "10.0.26100" {
		t.Fatalf("expected SMB native version, got %q", identity.Version)
	}
	if identity.CPE != "cpe:2.3:a:legacy:smb:1.0:*:*:*:*:*:*:*" {
		t.Fatalf("expected fingerprint cpe, got %q", identity.CPE)
	}
	if identity.HostnameHint != "dns-host.example.local" {
		t.Fatalf("expected dns hostname hint precedence, got %q", identity.HostnameHint)
	}
	if identity.FieldSources["product"] != sourceSMBNative {
		t.Fatalf("expected product source %q, got %q", sourceSMBNative, identity.FieldSources["product"])
	}
}

func TestChooseHostnameHintPriority(t *testing.T) {
	hints := scanpkg.SMBHostHints{
		NBComputer:  "NB-COMPUTER",
		TargetName:  "TARGET-NAME",
		DNSComputer: "DNS-COMPUTER",
	}
	if got := chooseHostnameHint(hints); got != "DNS-COMPUTER" {
		t.Fatalf("expected DNS priority, got %q", got)
	}

	hints.DNSComputer = ""
	if got := chooseHostnameHint(hints); got != "TARGET-NAME" {
		t.Fatalf("expected target_name fallback, got %q", got)
	}

	hints.TargetName = ""
	if got := chooseHostnameHint(hints); got != "NB-COMPUTER" {
		t.Fatalf("expected nb_computer fallback, got %q", got)
	}
}

func TestServiceIdentityNormalizer_RDPPrecedenceAndFallbackProduct(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-rdp", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.fingerprint.details": []any{
			FingerprintParsedInfo{
				Target:     "198.51.100.20",
				Port:       3389,
				Protocol:   "ms-wbt-server",
				Product:    "Microsoft Terminal Services",
				Confidence: 0.80,
			},
		},
		"service.rdp.details": []any{
			scanpkg.RDPServiceInfo{
				Target:           "198.51.100.20",
				Port:             3389,
				RDPProbe:         true,
				RDPDetected:      "x224-confirm",
				SelectedProtocol: "hybrid",
			},
			scanpkg.RDPServiceInfo{
				Target:      "198.51.100.21",
				Port:        3389,
				RDPProbe:    true,
				RDPDetected: "tpkt",
			},
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	results := map[string]ServiceIdentityInfo{}
	for item := range out {
		identity, ok := item.Data.(ServiceIdentityInfo)
		if !ok {
			continue
		}
		results[identity.Target] = identity
	}

	first, ok := results["198.51.100.20"]
	if !ok {
		t.Fatalf("expected identity for 198.51.100.20")
	}
	if first.ServiceName != "rdp" {
		t.Fatalf("expected service name rdp, got %q", first.ServiceName)
	}
	if first.FieldSources["service_name"] != sourceRDPNative {
		t.Fatalf("expected service_name source %q, got %q", sourceRDPNative, first.FieldSources["service_name"])
	}
	// Fingerprint product should stay authoritative.
	if first.Product != "Microsoft Terminal Services" {
		t.Fatalf("expected fingerprint product preserved, got %q", first.Product)
	}
	if !hasTag(first.TechTags, "rdp") {
		t.Fatalf("expected rdp tech tag in canonical output")
	}

	second, ok := results["198.51.100.21"]
	if !ok {
		t.Fatalf("expected identity for 198.51.100.21")
	}
	if second.Product != "RDP" {
		t.Fatalf("expected RDP fallback product, got %q", second.Product)
	}
	if second.FieldSources["product"] != sourceRDPNative {
		t.Fatalf("expected fallback product source %q, got %q", sourceRDPNative, second.FieldSources["product"])
	}
	if second.FieldConfidence["product"] != 0.70 {
		t.Fatalf("expected fallback product confidence 0.70, got %f", second.FieldConfidence["product"])
	}
}

func TestServiceIdentityNormalizer_RDPSMBCorrelation_FillsVendorVersionAndProduct(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-rdp-smb-correlation", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.rdp.details": []any{
			scanpkg.RDPServiceInfo{
				Target:      "203.0.113.55",
				Port:        3389,
				RDPProbe:    true,
				RDPDetected: "x224-confirm",
			},
		},
		"service.smb.details": []any{
			scanpkg.SMBServiceInfo{
				Target:         "203.0.113.55",
				Port:           445,
				Product:        "Microsoft Windows SMB",
				Vendor:         "microsoft",
				ProductVersion: "6.3",
			},
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	results := map[string]ServiceIdentityInfo{}
	for item := range out {
		identity, ok := item.Data.(ServiceIdentityInfo)
		if !ok {
			continue
		}
		results[identityKey(identity.Target, identity.Port)] = identity
	}

	rdpIdentity, ok := results[identityKey("203.0.113.55", 3389)]
	if !ok {
		t.Fatalf("expected identity for 203.0.113.55:3389")
	}
	if rdpIdentity.Port != 3389 {
		t.Fatalf("expected rdp identity on port 3389, got %d", rdpIdentity.Port)
	}
	if rdpIdentity.Vendor != "microsoft" {
		t.Fatalf("expected vendor from smb correlation, got %q", rdpIdentity.Vendor)
	}
	if rdpIdentity.Version != "6.3" {
		t.Fatalf("expected version from smb correlation, got %q", rdpIdentity.Version)
	}
	if rdpIdentity.Product != "Microsoft Remote Desktop Services (RDP)" {
		t.Fatalf("expected microsoft rdp product, got %q", rdpIdentity.Product)
	}
	if rdpIdentity.CPE != "" {
		t.Fatalf("expected empty cpe for correlation path, got %q", rdpIdentity.CPE)
	}
	if rdpIdentity.FieldSources["vendor"] != sourceSMBCorrelation {
		t.Fatalf("expected vendor source %q, got %q", sourceSMBCorrelation, rdpIdentity.FieldSources["vendor"])
	}
	if rdpIdentity.FieldSources["version"] != sourceSMBCorrelation {
		t.Fatalf("expected version source %q, got %q", sourceSMBCorrelation, rdpIdentity.FieldSources["version"])
	}
	if rdpIdentity.FieldConfidence["vendor"] != 0.60 || rdpIdentity.FieldConfidence["version"] != 0.60 {
		t.Fatalf("expected vendor/version confidence 0.60, got vendor=%f version=%f",
			rdpIdentity.FieldConfidence["vendor"],
			rdpIdentity.FieldConfidence["version"],
		)
	}
}

func TestServiceIdentityNormalizer_RPCFallbackIdentity(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-rpc", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.rpc.details": []any{
			scanpkg.RPCServiceInfo{
				Target:         "203.0.113.100",
				Port:           135,
				RPCProbe:       true,
				PrincipalName:  "NT AUTHORITY\\SYSTEM",
				InterfaceUUIDs: []string{"uuid-1"},
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
		casted, ok := item.Data.(ServiceIdentityInfo)
		if !ok {
			continue
		}
		if casted.Target == "203.0.113.100" && casted.Port == 135 {
			identity = casted
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("expected rpc identity output")
	}
	if identity.ServiceName != "msrpc" {
		t.Fatalf("expected service_name=msrpc, got %q", identity.ServiceName)
	}
	if identity.Product != "Microsoft RPC Endpoint Mapper" {
		t.Fatalf("expected RPC product fallback, got %q", identity.Product)
	}
	if identity.Vendor != "microsoft" {
		t.Fatalf("expected rpc vendor fallback, got %q", identity.Vendor)
	}
	if identity.FieldSources["product"] != sourceRPCNative {
		t.Fatalf("expected product source %q, got %q", sourceRPCNative, identity.FieldSources["product"])
	}
	if !hasTag(identity.TechTags, TagRPC) || !hasTag(identity.TechTags, TagMSRPC) {
		t.Fatalf("expected rpc/msrpc tech tags, got %+v", identity.TechTags)
	}
}

func TestServiceIdentityNormalizer_RPCDoesNotOverwriteFingerprint(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-rpc-fingerprint", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.fingerprint.details": []any{
			FingerprintParsedInfo{
				Target:     "203.0.113.101",
				Port:       49152,
				Protocol:   "rpc",
				Product:    "Custom RPC Product",
				Vendor:     "acme",
				Version:    "9.9",
				Confidence: 0.90,
			},
		},
		"service.rpc.details": []any{
			scanpkg.RPCServiceInfo{
				Target:         "203.0.113.101",
				Port:           49152,
				RPCProbe:       true,
				PrincipalName:  "host/example",
				InterfaceUUIDs: []string{"uuid-2"},
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
		casted, ok := item.Data.(ServiceIdentityInfo)
		if !ok {
			continue
		}
		if casted.Target == "203.0.113.101" && casted.Port == 49152 {
			identity = casted
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected identity output")
	}

	if identity.Product != "Custom RPC Product" {
		t.Fatalf("expected fingerprint product preserved, got %q", identity.Product)
	}
	if identity.Vendor != "acme" {
		t.Fatalf("expected fingerprint vendor preserved, got %q", identity.Vendor)
	}
	if identity.Version != "9.9" {
		t.Fatalf("expected fingerprint version preserved, got %q", identity.Version)
	}
	if identity.FieldSources["product"] != sourceFingerprint {
		t.Fatalf("expected product source %q, got %q", sourceFingerprint, identity.FieldSources["product"])
	}
}

func TestServiceIdentityNormalizer_RDPSMBCorrelation_DoesNotOverwriteFingerprint(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-rdp-no-overwrite", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.fingerprint.details": []any{
			FingerprintParsedInfo{
				Target:     "203.0.113.56",
				Port:       3389,
				Protocol:   "ms-wbt-server",
				Product:    "Microsoft Terminal Services",
				Vendor:     "microsoft",
				Version:    "10.0",
				Confidence: 0.85,
			},
		},
		"service.rdp.details": []any{
			scanpkg.RDPServiceInfo{
				Target:      "203.0.113.56",
				Port:        3389,
				RDPProbe:    true,
				RDPDetected: "x224-confirm",
			},
		},
		"service.smb.details": []any{
			scanpkg.SMBServiceInfo{
				Target:         "203.0.113.56",
				Port:           445,
				Vendor:         "microsoft",
				ProductVersion: "6.3",
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
		if candidate.Target == "203.0.113.56" && candidate.Port == 3389 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected identity for 203.0.113.56:3389")
	}
	if identity.Product != "Microsoft Terminal Services" {
		t.Fatalf("expected fingerprint product preserved, got %q", identity.Product)
	}
	if identity.Version != "10.0" {
		t.Fatalf("expected fingerprint version preserved, got %q", identity.Version)
	}
	if identity.FieldSources["version"] != sourceFingerprint {
		t.Fatalf("expected fingerprint version source, got %q", identity.FieldSources["version"])
	}
}

func TestServiceIdentityNormalizer_RDPSMBCorrelation_TargetIsolation(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-rdp-target-isolation", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.rdp.details": []any{
			scanpkg.RDPServiceInfo{
				Target:      "203.0.113.57",
				Port:        3389,
				RDPProbe:    true,
				RDPDetected: "tpkt",
			},
		},
		"service.smb.details": []any{
			scanpkg.SMBServiceInfo{
				Target:         "203.0.113.99",
				Port:           445,
				Vendor:         "microsoft",
				ProductVersion: "6.3",
			},
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	var identity ServiceIdentityInfo
	for item := range out {
		candidate, ok := item.Data.(ServiceIdentityInfo)
		if !ok {
			continue
		}
		if candidate.Target == "203.0.113.57" && candidate.Port == 3389 {
			identity = candidate
			break
		}
	}
	if identity.Vendor != "" || identity.Version != "" {
		t.Fatalf("expected no cross-target smb correlation, got vendor=%q version=%q", identity.Vendor, identity.Version)
	}
	if identity.Product != "RDP" {
		t.Fatalf("expected fallback RDP product, got %q", identity.Product)
	}
}

func TestPickBestSMBForCorrelation_PriorityAndDeterminism(t *testing.T) {
	yes := true
	no := false

	best, ok := pickBestSMBForCorrelation([]scanpkg.SMBServiceInfo{
		{
			Target:          "203.0.113.88",
			Port:            139,
			Vendor:          "microsoft",
			ProductVersion:  "10.0",
			SigningRequired: &yes,
		},
		{
			Target:          "203.0.113.88",
			Port:            445,
			Vendor:          "microsoft",
			ProductVersion:  "",
			SigningRequired: &no,
		},
		{
			Target:         "203.0.113.88",
			Port:           445,
			Vendor:         "microsoft",
			ProductVersion: "6.3",
		},
	})
	if !ok {
		t.Fatalf("expected best smb candidate")
	}
	if best.Port != 445 {
		t.Fatalf("expected port 445 priority, got %d", best.Port)
	}
	if best.ProductVersion != "6.3" {
		t.Fatalf("expected vendor+version preferred on same port, got %q", best.ProductVersion)
	}
}

func TestServiceIdentityNormalizer_TLSFallbackServiceNameAndTags(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-tls-fallback", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.banner.tcp": []any{
			scanpkg.BannerGrabResult{
				IP:       "198.51.100.90",
				Port:     443,
				Protocol: "tcp",
			},
		},
		"service.tls.details": []any{
			scanpkg.TLSServiceInfo{
				Target:      "198.51.100.90",
				Port:        443,
				TLSProbe:    true,
				TLSVersion:  "TLS1.2",
				CipherSuite: "TLS_AES_128_GCM_SHA256",
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
		if candidate.Target == "198.51.100.90" && candidate.Port == 443 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected identity for tls target")
	}
	if identity.ServiceName != "https" {
		t.Fatalf("expected service_name=https fallback from tls, got %q", identity.ServiceName)
	}
	if identity.FieldSources["service_name"] != sourceTLSNative {
		t.Fatalf("expected tls source for service_name, got %q", identity.FieldSources["service_name"])
	}
	if !hasTag(identity.TechTags, TagTLS) || !hasTag(identity.TechTags, TagHTTPS) {
		t.Fatalf("expected tls and https tags in canonical output, got %+v", identity.TechTags)
	}
	if identity.Product != "" || identity.Vendor != "" || identity.Version != "" || identity.CPE != "" {
		t.Fatalf("expected no product/vendor/version/cpe from tls fallback, got %+v", identity)
	}
}

func TestServiceIdentityNormalizer_TLSDoesNotOverwriteFingerprint(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-tls-no-overwrite", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.fingerprint.details": []any{
			FingerprintParsedInfo{
				Target:     "198.51.100.91",
				Port:       443,
				Protocol:   "http",
				Product:    "nginx",
				Vendor:     "f5",
				Version:    "1.25.4",
				CPE:        "cpe:2.3:a:f5:nginx:1.25.4:*:*:*:*:*:*:*",
				Confidence: 0.90,
			},
		},
		"service.tls.details": []any{
			scanpkg.TLSServiceInfo{
				Target:      "198.51.100.91",
				Port:        443,
				TLSProbe:    true,
				TLSVersion:  "TLS1.3",
				CipherSuite: "TLS_AES_256_GCM_SHA384",
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
		if candidate.Target == "198.51.100.91" && candidate.Port == 443 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected identity for tls+fingerprint target")
	}
	if identity.ServiceName != "http" {
		t.Fatalf("expected fingerprint service name preserved, got %q", identity.ServiceName)
	}
	if identity.Product != "nginx" {
		t.Fatalf("expected fingerprint product preserved, got %q", identity.Product)
	}
	if identity.Vendor != "f5" || identity.Version != "1.25.4" {
		t.Fatalf("expected fingerprint vendor/version preserved, got vendor=%q version=%q", identity.Vendor, identity.Version)
	}
	if identity.CPE == "" {
		t.Fatalf("expected fingerprint cpe preserved")
	}
	if identity.FieldSources["service_name"] != sourceFingerprint {
		t.Fatalf("expected fingerprint source to remain for service_name, got %q", identity.FieldSources["service_name"])
	}
	if !hasTag(identity.TechTags, TagTLS) || !hasTag(identity.TechTags, TagHTTPS) {
		t.Fatalf("expected tls tags appended even with fingerprint identity, got %+v", identity.TechTags)
	}
}

func TestServiceIdentityNormalizer_SSHFallbackIdentity(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-ssh", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.ssh.details": []any{
			scanpkg.SSHServiceInfo{
				Target:      "198.51.100.110",
				Port:        22,
				SSHProbe:    true,
				SSHBanner:   "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.8",
				SSHProtocol: "2.0",
				SSHSoftware: "OpenSSH",
				SSHVersion:  "9.6p1",
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
		if candidate.Target == "198.51.100.110" && candidate.Port == 22 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ssh identity output")
	}
	if identity.ServiceName != "ssh" {
		t.Fatalf("expected service_name=ssh, got %q", identity.ServiceName)
	}
	if identity.Product != "OpenSSH" {
		t.Fatalf("expected product OpenSSH, got %q", identity.Product)
	}
	if identity.Version != "9.6p1" {
		t.Fatalf("expected version 9.6p1, got %q", identity.Version)
	}
	if identity.FieldSources["service_name"] != sourceSSHNative {
		t.Fatalf("expected ssh native source, got %q", identity.FieldSources["service_name"])
	}
	if !hasTag(identity.TechTags, "ssh") {
		t.Fatalf("expected ssh tech tag, got %+v", identity.TechTags)
	}
}

func TestServiceIdentityNormalizer_SSHDoesNotOverwriteFingerprint(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-ssh-no-overwrite", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.fingerprint.details": []any{
			FingerprintParsedInfo{
				Target:     "198.51.100.111",
				Port:       22,
				Protocol:   "ssh",
				Product:    "OpenSSH",
				Vendor:     "openbsd",
				Version:    "9.9p2",
				Confidence: 0.90,
			},
		},
		"service.ssh.details": []any{
			scanpkg.SSHServiceInfo{
				Target:      "198.51.100.111",
				Port:        22,
				SSHProbe:    true,
				SSHBanner:   "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.8",
				SSHProtocol: "2.0",
				SSHSoftware: "OpenSSH",
				SSHVersion:  "9.6p1",
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
		if candidate.Target == "198.51.100.111" && candidate.Port == 22 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ssh identity output")
	}
	if identity.Product != "OpenSSH" || identity.Version != "9.9p2" {
		t.Fatalf("expected fingerprint product/version preserved, got product=%q version=%q", identity.Product, identity.Version)
	}
	if identity.Vendor != "openbsd" {
		t.Fatalf("expected fingerprint vendor preserved, got %q", identity.Vendor)
	}
	if identity.FieldSources["version"] != sourceFingerprint {
		t.Fatalf("expected fingerprint version source, got %q", identity.FieldSources["version"])
	}
}
