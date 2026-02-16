package parse

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/fingerprint"
	"github.com/cyprob/cyprob/pkg/modules/scan"
)

// --- MOCK RESOLVER ---

type mockResolver struct {
	resolveFn func(ctx context.Context, input fingerprint.Input) (fingerprint.Result, error)
}

func (m mockResolver) Resolve(ctx context.Context, input fingerprint.Input) (fingerprint.Result, error) {
	return m.resolveFn(ctx, input)
}

// --- TESTS ---

func TestFingerprintParserModule_Execute_FullCoverage(t *testing.T) {
	// Arrange
	originalGetResolver := getResolver
	defer func() { getResolver = originalGetResolver }()

	calledInputs := []fingerprint.Input{}

	getResolver = func() fingerprint.Resolver {
		return mockResolver{
			resolveFn: func(ctx context.Context, input fingerprint.Input) (fingerprint.Result, error) {
				calledInputs = append(calledInputs, input)

				switch {
				case strings.Contains(input.Banner, "error"):
					return fingerprint.Result{}, errors.New("resolver error")
				case strings.Contains(input.Banner, "unknown"):
					return fingerprint.Result{}, nil
				default:
					return fingerprint.Result{
						Product:     "TestProduct",
						Vendor:      "TestVendor",
						Version:     "1.0",
						CPE:         "cpe:/a:test:product:1.0",
						Confidence:  0.9,
						Description: "Test Description",
					}, nil
				}
			},
		}
	}

	m := newFingerprintParserModule()
	_ = m.Init("test-instance", nil)

	banner := scan.BannerGrabResult{
		IP:       "127.0.0.1",
		Port:     22,
		Protocol: "tcp",
		Banner:   "SSH-2.0-OpenSSH_8.9",
		Evidence: []engine.ProbeObservation{
			{Response: "HTTP/1.1 200 OK\r\nServer: nginx", Protocol: "http", ProbeID: "probe1"},
			{Response: "error-banner", Protocol: "http", ProbeID: "probe2"},
			{Response: "unknown-banner", Protocol: "ftp", ProbeID: "probe3"},
			{Response: "HTTP/1.1 200 OK\r\nServer: nginx", Protocol: "http", ProbeID: "probe1"}, // duplicate
		},
	}

	inputs := map[string]any{
		"service.banner.tcp": []any{banner},
	}
	outputChan := make(chan engine.ModuleOutput, 10)
	ctx, cancel := context.WithCancel(context.Background())

	// Act
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel() // ctx.Done() branch
	}()

	err := m.Execute(ctx, inputs, outputChan)

	// Assert
	if err != nil && err != context.Canceled {
		t.Fatalf("unexpected error: %v", err)
	}

	close(outputChan)

	count := 0
	for out := range outputChan {
		parsed, ok := out.Data.(FingerprintParsedInfo)
		if !ok {
			t.Errorf("output type mismatch: %T", out.Data)
			continue
		}
		if parsed.Product != "TestProduct" {
			t.Errorf("unexpected product: %v", parsed.Product)
		}
		count++
	}

	if count == 0 {
		t.Error("expected at least one parsed fingerprint result")
	}
}

func TestFingerprintParserModule_Execute_NoInputKey(t *testing.T) {
	m := newFingerprintParserModule()
	out := make(chan engine.ModuleOutput)
	defer close(out)

	err := m.Execute(context.Background(), map[string]any{}, out)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestFingerprintParserModule_Execute_InvalidType(t *testing.T) {
	m := newFingerprintParserModule()
	out := make(chan engine.ModuleOutput)
	defer close(out)

	err := m.Execute(context.Background(), map[string]any{
		"service.banner.tcp": "not-a-list",
	}, out)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestFingerprintParserModule_Execute_InvalidElementType(t *testing.T) {
	m := newFingerprintParserModule()
	out := make(chan engine.ModuleOutput)
	defer close(out)

	err := m.Execute(context.Background(), map[string]any{
		"service.banner.tcp": []any{"not-banner"},
	}, out)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestFingerprintParserModule_fingerprintProtocolHint_AllBranches(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0":                    "ssh",
		"HTTP/1.1 200 OK":            "http",
		"Server: nginx":              "http",
		"EHLO smtp.gmail.com":        "smtp",
		"ftp ready":                  "ftp",
		"MySQL server version 8.0.1": "mysql",
		"unknown banner":             "",
	}

	for banner, want := range cases {
		got := fingerprintProtocolHint(0, banner)
		if got != want {
			t.Errorf("banner %q => got %q, want %q", banner, got, want)
		}
	}
}

func TestFingerprintParserModule_gatherBannerCandidates(t *testing.T) {
	banner := scan.BannerGrabResult{
		Banner:   "HTTP/1.1 200 OK",
		Protocol: "tcp",
		Evidence: []engine.ProbeObservation{
			{Response: "SSH-2.0-OpenSSH_8.9", Protocol: "", ProbeID: "probe1"},
			{Response: "HTTP/1.1 200 OK", Protocol: "http", ProbeID: "tcp-passive"},
			{Response: "   ", Protocol: "http", ProbeID: "probe2"}, // boş response skip
		},
	}

	candidates := gatherBannerCandidates(banner)
	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}

	if candidates[0].ProbeID != "probe1" {
		t.Errorf("expected first ProbeID 'probe1', got %s", candidates[0].ProbeID)
	}
	if candidates[1].ProbeID != "tcp-passive" {
		t.Errorf("expected passive probe candidate to be last, got %s", candidates[1].ProbeID)
	}
	if candidates[0].Protocol != "tcp" {
		t.Errorf("expected inherited protocol 'tcp', got %s", candidates[0].Protocol)
	}
}

func TestFingerprintParserModule_AttributionPrefersActiveProbe(t *testing.T) {
	originalGetResolver := getResolver
	defer func() { getResolver = originalGetResolver }()

	getResolver = func() fingerprint.Resolver {
		return mockResolver{
			resolveFn: func(ctx context.Context, input fingerprint.Input) (fingerprint.Result, error) {
				if strings.Contains(strings.ToLower(input.Banner), "microsoft-httpapi/2.0") {
					return fingerprint.Result{
						Product:    "WinRM",
						Vendor:     "Microsoft",
						Confidence: 0.9,
					}, nil
				}
				return fingerprint.Result{}, errors.New("no match")
			},
		}
	}

	m := newFingerprintParserModule()
	_ = m.Init("attr-test", nil)

	banner := scan.BannerGrabResult{
		IP:       "10.0.0.10",
		Port:     80,
		Protocol: "tcp",
		Banner:   "HTTP/1.1 400 Bad Request\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n",
		Evidence: []engine.ProbeObservation{
			{
				ProbeID:  "tcp-passive",
				Protocol: "tcp",
				Response: "HTTP/1.1 400 Bad Request\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n",
			},
			{
				ProbeID:  "http-get",
				Protocol: "http",
				Response: "HTTP/1.1 400 Bad Request\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n",
			},
		},
	}

	outputChan := make(chan engine.ModuleOutput, 8)
	err := m.Execute(context.Background(), map[string]any{
		"service.banner.tcp": []any{banner},
	}, outputChan)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(outputChan)

	found := false
	for out := range outputChan {
		fp, ok := out.Data.(FingerprintParsedInfo)
		if !ok {
			continue
		}
		found = true
		if fp.SourceProbe != "http-get" {
			t.Fatalf("expected source_probe http-get, got %q", fp.SourceProbe)
		}
	}
	if !found {
		t.Fatal("expected at least one fingerprint output")
	}
}

func TestFingerprintParserModule_Metadata(t *testing.T) {
	m := newFingerprintParserModule()
	meta := m.Metadata()

	if meta.ID != fingerprintParserModuleID {
		t.Errorf("unexpected ID: %v", meta.ID)
	}
	if meta.Name != fingerprintParserModuleName {
		t.Errorf("unexpected Name: %v", meta.Name)
	}
	if len(meta.Consumes) == 0 || len(meta.Produces) == 0 {
		t.Error("expected consumes/produces metadata to be set")
	}
}

func TestFingerprintParserModule_Init(t *testing.T) {
	m := newFingerprintParserModule()
	err := m.Init("test-id", nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if m.meta.ID != "test-id" {
		t.Errorf("expected meta.ID = 'test-id', got %s", m.meta.ID)
	}
}

func TestFingerprintParserModule_fingerprintParserModuleFactory(t *testing.T) {
	mod := fingerprintParserModuleFactory()
	if mod == nil {
		t.Fatal("expected non-nil module")
	}
	meta := mod.Metadata()
	if meta.Name != fingerprintParserModuleName {
		t.Errorf("unexpected factory module name: %s", meta.Name)
	}
}

func TestDetectProtocolFromPort(t *testing.T) {
	tests := []struct {
		name     string
		port     int
		expected string
	}{
		// Databases
		{"MySQL standard port", 3306, "mysql"},
		{"PostgreSQL standard port", 5432, "postgresql"},
		{"Redis standard port", 6379, "redis"},
		{"MongoDB standard port", 27017, "mongodb"},

		// Network Services
		{"SSH standard port", 22, "ssh"},
		{"FTP standard port", 21, "ftp"},
		{"SMTP standard port", 25, "smtp"},
		{"SMTP submission port", 587, "smtp"},

		// Mail Protocols (Phase 1.6)
		{"POP3 standard port", 110, "pop3"},
		{"POP3S secure port", 995, "pop3"},
		{"IMAP standard port", 143, "imap"},
		{"IMAPS secure port", 993, "imap"},

		// Enterprise/Messaging (Phase 1.6)
		{"DNS standard port", 53, "dns"},
		{"LDAP standard port", 389, "ldap"},
		{"LDAPS secure port", 636, "ldap"},
		{"LDAP global catalog", 3268, "ldap"},
		{"LDAP global catalog SSL", 3269, "ldap"},
		{"RabbitMQ standard port", 5672, "rabbitmq"},
		{"RabbitMQ secure port", 5671, "rabbitmq"},
		{"Kafka standard port", 9092, "kafka"},
		{"Kafka secure port", 9093, "kafka"},
		{"Elasticsearch HTTP port", 9200, "elasticsearch"},
		{"Elasticsearch transport port", 9300, "elasticsearch"},
		{"SNMP standard port", 161, "snmp"},
		{"SNMP trap port", 162, "snmp"},
		{"msrpc", 135, "msrpc"},
		{"netbios", 139, "netbios"},
		{"smb", 445, "smb"},
		{"rpc", 111, "rpc"},

		// Unknown ports
		{"Unknown port 1234", 1234, ""},
		{"Unknown port 8080", 8080, ""},
		{"Unknown port 12345", 12345, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectProtocolFromPort(tt.port)
			if result != tt.expected {
				t.Errorf("detectProtocolFromPort(%d) = %q, want %q", tt.port, result, tt.expected)
			}
		})
	}
}

func TestDetectProtocolFromBanner(t *testing.T) {
	tests := []struct {
		name     string
		banner   string
		expected string
	}{
		// SSH - expects lowercase (called after ToLower in fingerprintProtocolHint)
		{"SSH banner", "ssh-2.0-openssh_8.9", "ssh"},
		{"SSH banner lowercase", "ssh-2.0-openssh", "ssh"},

		// HTTP
		{"HTTP version", "http/1.1 200 ok", "http"},
		{"HTTP server header", "server: nginx/1.18.0", "http"},
		{"HTTP lowercase", "http/2.0 404 not found", "http"},

		// SMTP
		{"SMTP greeting", "220 smtp.gmail.com esmtp", "smtp"},
		{"SMTP command", "smtp ready", "smtp"},

		// FTP
		{"FTP banner", "220 ftp server ready", "ftp"},
		{"FTP welcome", "welcome to ftp service", "ftp"},

		// MySQL/MariaDB
		{"MySQL banner", "mysql server 8.0.43", "mysql"},
		{"MariaDB banner", "mariadb 10.5.8", "mysql"},
		{"MySQL lowercase", "5.7.33-mysql community server", "mysql"},

		// Unknown
		{"Empty banner", "", ""},
		{"Unknown protocol", "unknown service banner", ""},
		{"Random text", "hello world", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectProtocolFromBanner(tt.banner)
			if result != tt.expected {
				t.Errorf("detectProtocolFromBanner(%q) = %q, want %q", tt.banner, result, tt.expected)
			}
		})
	}
}

func TestFingerprintProtocolHint_Integration(t *testing.T) {
	tests := []struct {
		name     string
		port     int
		banner   string
		expected string
	}{
		// Banner detection takes priority
		{"SSH banner on non-standard port", 2222, "SSH-2.0-OpenSSH_8.9", "ssh"},
		{"HTTP banner on non-standard port", 8080, "HTTP/1.1 200 OK", "http"},
		{"MySQL banner on non-standard port", 3210, "MySQL Server 8.0.43", "mysql"},

		// Port fallback when banner doesn't match
		{"Standard MySQL port with unknown banner", 3306, "unknown banner", "mysql"},
		{"Standard SSH port with unknown banner", 22, "welcome", "ssh"},
		{"Standard IMAP port with unknown banner", 143, "ready", "imap"},

		// Phase 1.6 protocols
		{"IMAPS port detection", 993, "unknown", "imap"},
		{"POP3S port detection", 995, "unknown", "pop3"},
		{"LDAP port detection", 389, "unknown", "ldap"},
		{"Kafka port detection", 9092, "unknown", "kafka"},

		// Unknown combinations
		{"Unknown port unknown banner", 12345, "unknown service", ""},
		{"Non-standard port no match", 8888, "random text", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fingerprintProtocolHint(tt.port, tt.banner)
			if result != tt.expected {
				t.Errorf("fingerprintProtocolHint(%d, %q) = %q, want %q",
					tt.port, tt.banner, result, tt.expected)
			}
		})
	}
}

// TestFingerprintParserModule_TLSMetadataEmission tests that TLS metadata
// is properly emitted as individual data keys to DataContext.
// Phase 1.8: Verify TLS plugins can consume TLS metadata.
func TestFingerprintParserModule_TLSMetadataEmission(t *testing.T) {
	// Arrange
	originalGetResolver := getResolver
	defer func() { getResolver = originalGetResolver }()

	getResolver = func() fingerprint.Resolver {
		return mockResolver{
			resolveFn: func(ctx context.Context, input fingerprint.Input) (fingerprint.Result, error) {
				return fingerprint.Result{
					Product:    "nginx",
					Version:    "1.18.0",
					Confidence: 0.95,
				}, nil
			},
		}
	}

	m := newFingerprintParserModule()
	_ = m.Init("test-tls", nil)

	// Create banner with TLS metadata
	notBefore := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)

	banner := scan.BannerGrabResult{
		IP:       "192.168.1.100",
		Port:     443,
		Protocol: "tcp",
		Banner:   "HTTP/1.1 200 OK",
		Evidence: []engine.ProbeObservation{
			{
				Response: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
				Protocol: "https",
				ProbeID:  "https-probe",
				IsTLS:    true,
				TLS: &engine.TLSObservation{
					Version:        "TLS1.3",
					CipherSuite:    "TLS_AES_128_GCM_SHA256",
					ServerName:     "example.com",
					PeerCommonName: "example.com",
					PeerDNSNames:   []string{"example.com", "www.example.com"},
					Issuer:         "CN=Let's Encrypt Authority X3",
					NotBefore:      notBefore,
					NotAfter:       notAfter,
					IsExpired:      false,
					IsSelfSigned:   false,
				},
			},
		},
	}

	inputs := map[string]any{
		"service.banner.tcp": []any{banner},
	}
	outputChan := make(chan engine.ModuleOutput, 20)
	ctx := context.Background()

	// Act
	err := m.Execute(ctx, inputs, outputChan)
	close(outputChan)

	// Assert
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Collect all outputs
	outputs := make(map[string][]engine.ModuleOutput)
	for out := range outputChan {
		outputs[out.DataKey] = append(outputs[out.DataKey], out)
	}

	// Verify TLS protocol-level keys are emitted
	if len(outputs["tls.version"]) == 0 {
		t.Error("Expected tls.version to be emitted")
	} else if outputs["tls.version"][0].Data != "TLS1.3" {
		t.Errorf("tls.version = %v, want TLS1.3", outputs["tls.version"][0].Data)
	}

	if len(outputs["tls.cipher_suite"]) == 0 {
		t.Error("Expected tls.cipher_suite to be emitted")
	} else if outputs["tls.cipher_suite"][0].Data != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("tls.cipher_suite = %v, want TLS_AES_128_GCM_SHA256", outputs["tls.cipher_suite"][0].Data)
	}

	if len(outputs["tls.server_name"]) == 0 {
		t.Error("Expected tls.server_name to be emitted")
	} else if outputs["tls.server_name"][0].Data != "example.com" {
		t.Errorf("tls.server_name = %v, want example.com", outputs["tls.server_name"][0].Data)
	}

	// Verify TLS certificate-level keys are emitted
	if len(outputs["tls.certificate.issuer"]) == 0 {
		t.Error("Expected tls.certificate.issuer to be emitted")
	} else if outputs["tls.certificate.issuer"][0].Data != "CN=Let's Encrypt Authority X3" {
		t.Errorf("tls.certificate.issuer = %v, want CN=Let's Encrypt Authority X3", outputs["tls.certificate.issuer"][0].Data)
	}

	if len(outputs["tls.certificate.common_name"]) == 0 {
		t.Error("Expected tls.certificate.common_name to be emitted")
	} else if outputs["tls.certificate.common_name"][0].Data != "example.com" {
		t.Errorf("tls.certificate.common_name = %v, want example.com", outputs["tls.certificate.common_name"][0].Data)
	}

	if len(outputs["tls.certificate.dns_names"]) == 0 {
		t.Error("Expected tls.certificate.dns_names to be emitted")
	}

	if len(outputs["tls.certificate.not_before"]) == 0 {
		t.Error("Expected tls.certificate.not_before to be emitted")
	} else if !outputs["tls.certificate.not_before"][0].Data.(time.Time).Equal(notBefore) {
		t.Errorf("tls.certificate.not_before = %v, want %v", outputs["tls.certificate.not_before"][0].Data, notBefore)
	}

	if len(outputs["tls.certificate.not_after"]) == 0 {
		t.Error("Expected tls.certificate.not_after to be emitted")
	} else if !outputs["tls.certificate.not_after"][0].Data.(time.Time).Equal(notAfter) {
		t.Errorf("tls.certificate.not_after = %v, want %v", outputs["tls.certificate.not_after"][0].Data, notAfter)
	}

	// Verify boolean flags (always emitted)
	if len(outputs["tls.certificate.is_expired"]) == 0 {
		t.Error("Expected tls.certificate.is_expired to be emitted")
	} else if outputs["tls.certificate.is_expired"][0].Data != false {
		t.Errorf("tls.certificate.is_expired = %v, want false", outputs["tls.certificate.is_expired"][0].Data)
	}

	if len(outputs["tls.certificate.is_self_signed"]) == 0 {
		t.Error("Expected tls.certificate.is_self_signed to be emitted")
	} else if outputs["tls.certificate.is_self_signed"][0].Data != false {
		t.Errorf("tls.certificate.is_self_signed = %v, want false", outputs["tls.certificate.is_self_signed"][0].Data)
	}

	// Verify target is set correctly for all TLS keys
	for key, outs := range outputs {
		if strings.HasPrefix(key, "tls.") {
			if len(outs) > 0 && outs[0].Target != "192.168.1.100" {
				t.Errorf("TLS key %s has wrong target: %v, want 192.168.1.100", key, outs[0].Target)
			}
		}
	}
}

// TestFingerprintParserModule_NoTLSMetadata tests that no TLS keys are emitted
// when TLS metadata is not present.
func TestFingerprintParserModule_NoTLSMetadata(t *testing.T) {
	// Arrange
	originalGetResolver := getResolver
	defer func() { getResolver = originalGetResolver }()

	getResolver = func() fingerprint.Resolver {
		return mockResolver{
			resolveFn: func(ctx context.Context, input fingerprint.Input) (fingerprint.Result, error) {
				return fingerprint.Result{
					Product:    "OpenSSH",
					Version:    "8.9",
					Confidence: 0.95,
				}, nil
			},
		}
	}

	m := newFingerprintParserModule()
	_ = m.Init("test-no-tls", nil)

	// Create banner WITHOUT TLS metadata
	banner := scan.BannerGrabResult{
		IP:       "192.168.1.200",
		Port:     22,
		Protocol: "tcp",
		Banner:   "SSH-2.0-OpenSSH_8.9",
		Evidence: []engine.ProbeObservation{
			{
				Response: "SSH-2.0-OpenSSH_8.9p1",
				Protocol: "ssh",
				ProbeID:  "ssh-probe",
				IsTLS:    false,
				TLS:      nil, // No TLS metadata
			},
		},
	}

	inputs := map[string]any{
		"service.banner.tcp": []any{banner},
	}
	outputChan := make(chan engine.ModuleOutput, 20)
	ctx := context.Background()

	// Act
	err := m.Execute(ctx, inputs, outputChan)
	close(outputChan)

	// Assert
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// Collect all outputs
	outputs := make(map[string][]engine.ModuleOutput)
	for out := range outputChan {
		outputs[out.DataKey] = append(outputs[out.DataKey], out)
	}

	// Verify NO TLS keys are emitted
	tlsKeys := []string{
		"tls.version", "tls.cipher_suite", "tls.server_name",
		"tls.certificate.issuer", "tls.certificate.common_name",
		"tls.certificate.dns_names", "tls.certificate.not_before",
		"tls.certificate.not_after", "tls.certificate.is_expired",
		"tls.certificate.is_self_signed",
	}

	for _, key := range tlsKeys {
		if len(outputs[key]) > 0 {
			t.Errorf("TLS key %s should not be emitted when TLS metadata is nil", key)
		}
	}

	// Verify fingerprint data is still emitted
	if len(outputs["service.fingerprint.details"]) == 0 {
		t.Error("Expected service.fingerprint.details to be emitted")
	}
}
