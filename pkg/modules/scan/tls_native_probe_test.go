package scan

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

func TestTLSNativeProbeModule_ExecuteFiltersCandidates(t *testing.T) {
	originalProbe := probeTLSDetailsFunc
	defer func() { probeTLSDetailsFunc = originalProbe }()

	calls := 0
	probeTLSDetailsFunc = func(ctx context.Context, target, hostname string, port int, opts TLSProbeOptions) TLSServiceInfo {
		calls++
		return TLSServiceInfo{
			Target:      target,
			Port:        port,
			TLSProbe:    true,
			TLSVersion:  "TLS1.2",
			CipherSuite: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		}
	}

	module := newTLSNativeProbeModule()
	if err := module.Init("test-tls-native", map[string]any{
		"extra_ports": []int{10443},
	}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{
				Target:    "198.51.100.10",
				Hostname:  "example.com",
				OpenPorts: []int{443, 3389, 10443},
			},
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	var outputs []TLSServiceInfo
	for item := range out {
		tlsInfo, ok := item.Data.(TLSServiceInfo)
		if !ok {
			continue
		}
		outputs = append(outputs, tlsInfo)
	}

	if calls != 2 {
		t.Fatalf("expected 2 probe calls (443 + 10443), got %d", calls)
	}
	if len(outputs) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(outputs))
	}
}

func TestTLSNativeProbeModule_ExecuteUsesOriginalTargetFallback(t *testing.T) {
	originalProbe := probeTLSDetailsFunc
	defer func() { probeTLSDetailsFunc = originalProbe }()

	var capturedHostname string
	probeTLSDetailsFunc = func(ctx context.Context, target, hostname string, port int, opts TLSProbeOptions) TLSServiceInfo {
		capturedHostname = hostname
		return TLSServiceInfo{Target: target, Port: port, TLSProbe: true}
	}

	module := newTLSNativeProbeModule()
	if err := module.Init("test-tls-native", nil); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{
				Target:    "198.51.100.10",
				OpenPorts: []int{443},
			},
		},
		"config.original_cli_targets": []string{"mail.netkedi.com"},
	}

	out := make(chan engine.ModuleOutput, 2)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if capturedHostname != "mail.netkedi.com" {
		t.Fatalf("expected fallback hostname mail.netkedi.com, got %q", capturedHostname)
	}
}

func TestTLSNativeProbeModule_ExecutePrefersOpenPortHostname(t *testing.T) {
	originalProbe := probeTLSDetailsFunc
	defer func() { probeTLSDetailsFunc = originalProbe }()

	var capturedHostname string
	probeTLSDetailsFunc = func(ctx context.Context, target, hostname string, port int, opts TLSProbeOptions) TLSServiceInfo {
		capturedHostname = hostname
		return TLSServiceInfo{Target: target, Port: port, TLSProbe: true}
	}

	module := newTLSNativeProbeModule()
	if err := module.Init("test-tls-native", nil); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{
				Target:    "198.51.100.10",
				Hostname:  "service.netkedi.com",
				OpenPorts: []int{443},
			},
		},
		"config.original_cli_targets": []string{"mail.netkedi.com"},
	}

	out := make(chan engine.ModuleOutput, 2)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if capturedHostname != "service.netkedi.com" {
		t.Fatalf("expected discovery hostname service.netkedi.com, got %q", capturedHostname)
	}
}

func TestTLSNativeProbeModule_ExecuteSkipsUnsafeFallbacks(t *testing.T) {
	originalProbe := probeTLSDetailsFunc
	defer func() { probeTLSDetailsFunc = originalProbe }()

	var capturedHostnames []string
	probeTLSDetailsFunc = func(ctx context.Context, target, hostname string, port int, opts TLSProbeOptions) TLSServiceInfo {
		capturedHostnames = append(capturedHostnames, hostname)
		return TLSServiceInfo{Target: target, Port: port, TLSProbe: true}
	}

	module := newTLSNativeProbeModule()
	if err := module.Init("test-tls-native", nil); err != nil {
		t.Fatalf("init: %v", err)
	}

	tests := []struct {
		name           string
		originalInputs any
	}{
		{name: "multi target", originalInputs: []string{"a.example", "b.example"}},
		{name: "ip only", originalInputs: []string{"198.51.100.10"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capturedHostnames = capturedHostnames[:0]
			inputs := map[string]any{
				"discovery.open_tcp_ports": []any{
					discovery.TCPPortDiscoveryResult{
						Target:    "198.51.100.10",
						OpenPorts: []int{443},
					},
				},
				"config.original_cli_targets": tt.originalInputs,
			}

			out := make(chan engine.ModuleOutput, 2)
			if err := module.Execute(context.Background(), inputs, out); err != nil {
				t.Fatalf("execute: %v", err)
			}
			if len(capturedHostnames) != 1 {
				t.Fatalf("expected 1 captured hostname, got %d", len(capturedHostnames))
			}
			if capturedHostnames[0] != "" {
				t.Fatalf("expected empty hostname for %s fallback, got %q", tt.name, capturedHostnames[0])
			}
		})
	}
}

func TestBuildTLSProbeStrategies(t *testing.T) {
	withHostname := buildTLSProbeStrategies("mail.example.com")
	if len(withHostname) != 3 {
		t.Fatalf("expected 3 strategies with hostname, got %d", len(withHostname))
	}
	if withHostname[0].name != "tls-sni" {
		t.Fatalf("expected first strategy tls-sni, got %q", withHostname[0].name)
	}

	withoutHostname := buildTLSProbeStrategies("")
	if len(withoutHostname) != 2 {
		t.Fatalf("expected 2 strategies without hostname, got %d", len(withoutHostname))
	}
}

func TestClassifyTLSProbeError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "timeout", err: errors.New("i/o timeout"), want: "timeout"},
		{name: "refused", err: errors.New("connection refused"), want: "refused"},
		{name: "short", err: errors.New("short_tls_response"), want: "short_response"},
		{name: "handshake", err: errors.New("remote error: tls: handshake failure"), want: "handshake_failed"},
		{name: "generic", err: errors.New("unexpected"), want: "probe_failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyTLSProbeError(tt.err); got != tt.want {
				t.Fatalf("classifyTLSProbeError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPickTopTLSProbeErrorPriority(t *testing.T) {
	codes := []string{"probe_failed", "short_response", "timeout"}
	if got := pickTopTLSProbeError(codes); got != "timeout" {
		t.Fatalf("expected timeout priority, got %q", got)
	}
}

func TestTLSWeakSecuritySignals(t *testing.T) {
	if !isWeakTLSVersion("TLS1.0") {
		t.Fatalf("expected TLS1.0 to be weak")
	}
	if isWeakTLSVersion("TLS1.3") {
		t.Fatalf("expected TLS1.3 to be strong")
	}

	if !isWeakCipher("TLS_RSA_WITH_3DES_EDE_CBC_SHA") {
		t.Fatalf("expected 3DES cipher to be weak")
	}
	if isWeakCipher("TLS_AES_128_GCM_SHA256") {
		t.Fatalf("expected modern cipher to be strong")
	}
}

func TestIsCertExpiringSoon(t *testing.T) {
	now := time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC)
	if !isCertExpiringSoon(now.Add(10*24*time.Hour), now) {
		t.Fatalf("expected cert expiring in 10 days to be expiring soon")
	}
	if isCertExpiringSoon(now.Add(90*24*time.Hour), now) {
		t.Fatalf("expected cert expiring in 90 days to not be expiring soon")
	}
}
