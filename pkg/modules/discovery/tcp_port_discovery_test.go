package discovery

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/vulntor/vulntor/pkg/engine"
)

func TestTCPPortDiscoveryModule_Metadata(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	meta := module.Metadata()

	if meta.Name != "tcp-port-discovery" {
		t.Errorf("expected Name 'tcp-port-discovery', got '%s'", meta.Name)
	}
	if meta.Version == "" {
		t.Error("expected non-empty Version")
	}
	if meta.Description == "" {
		t.Error("expected non-empty Description")
	}
	if meta.Type != engine.DiscoveryModuleType {
		t.Errorf("expected Type '%s', got '%s'", engine.DiscoveryModuleType, meta.Type)
	}
	if meta.Author == "" {
		t.Error("expected non-empty Author")
	}
	if len(meta.Tags) == 0 {
		t.Error("expected non-empty Tags")
	}

	var gotKeys []string
	for _, e := range meta.Produces {
		gotKeys = append(gotKeys, e.Key)
	}

	if !reflect.DeepEqual(gotKeys, []string{"discovery.open_tcp_ports"}) {
		t.Errorf("expected Produces ['discovery.open_tcp_ports'], got %v", meta.Produces)
	}
	if len(meta.ConfigSchema) == 0 {
		t.Error("expected non-empty ConfigSchema")
	}
}

func TestNewTCPPortDiscoveryModule_Defaults(t *testing.T) {
	module := newTCPPortDiscoveryModule()

	// Check metadata fields
	meta := module.meta
	if meta.Name != "tcp-port-discovery" {
		t.Errorf("expected Name 'tcp-port-discovery', got '%s'", meta.Name)
	}
	if meta.Version != "0.1.0" {
		t.Errorf("expected Version '0.1.0', got '%s'", meta.Version)
	}
	if meta.Description == "" {
		t.Error("expected non-empty Description")
	}
	if meta.Type != engine.DiscoveryModuleType {
		t.Errorf("expected Type '%s', got '%s'", engine.DiscoveryModuleType, meta.Type)
	}
	if meta.Author != "Vulntor Team" {
		t.Errorf("expected Author 'Vulntor Team', got '%s'", meta.Author)
	}
	if len(meta.Tags) == 0 {
		t.Error("expected non-empty Tags")
	}

	for _, produce := range meta.Produces {
		if !reflect.DeepEqual(produce.Key, "discovery.open_tcp_ports") {
			t.Errorf("expected Produces discovery.open_tcp_ports, got %v", produce.Key)
		}
	}

	gotConsumeKeys := []string{}

	for _, consume := range meta.Consumes {
		if consume.IsOptional == false {
			gotConsumeKeys = append(gotConsumeKeys, consume.Key)
		}
	}

	if !reflect.DeepEqual(gotConsumeKeys, []string{"discovery.live_hosts"}) {
		t.Errorf("expected Consumes ['config.targets', 'discovery.live_hosts'], got %v", gotConsumeKeys)
	}

	if len(meta.ConfigSchema) == 0 {
		t.Error("expected non-empty ConfigSchema")
	}
	// Check config defaults
	cfg := module.config
	if !reflect.DeepEqual(cfg.Ports, []string{"1-1024"}) {
		t.Errorf("expected Ports ['1-1024'], got %v", cfg.Ports)
	}
	if cfg.Timeout != defaultTCPPortDiscoveryTimeout {
		t.Errorf("expected Timeout %v, got %v", defaultTCPPortDiscoveryTimeout, cfg.Timeout)
	}
	if cfg.Concurrency != defaultTCPConcurrency {
		t.Errorf("expected Concurrency %d, got %d", defaultTCPConcurrency, cfg.Concurrency)
	}
	if len(cfg.Targets) != 0 {
		t.Errorf("expected Targets to be empty by default, got %v", cfg.Targets)
	}
}

func TestTCPPortDiscoveryModule_Init(t *testing.T) {
	tests := []struct {
		name       string
		input      map[string]any
		wantConfig TCPPortDiscoveryConfig
	}{
		{
			name:  "empty config uses defaults",
			input: map[string]any{},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:     nil,
				Ports:       []string{"1-1024"},
				Timeout:     defaultTCPPortDiscoveryTimeout,
				Concurrency: defaultTCPConcurrency,
			},
		},
		{
			name: "set targets and ports",
			input: map[string]any{
				"targets": []string{"127.0.0.1", "192.168.1.1"},
				"ports":   []string{"22", "80-81"},
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:     []string{"127.0.0.1", "192.168.1.1"},
				Ports:       []string{"22", "80-81"},
				Timeout:     defaultTCPPortDiscoveryTimeout,
				Concurrency: defaultTCPConcurrency,
			},
		},
		{
			name: "set timeout and concurrency",
			input: map[string]any{
				"timeout":     "2s",
				"concurrency": 50,
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:     nil,
				Ports:       []string{"1-1024"},
				Timeout:     2 * time.Second,
				Concurrency: 50,
			},
		},
		{
			name: "invalid timeout falls back to default",
			input: map[string]any{
				"timeout": "notaduration",
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:     nil,
				Ports:       []string{"1-1024"},
				Timeout:     defaultTCPPortDiscoveryTimeout,
				Concurrency: defaultTCPConcurrency,
			},
		},
		{
			name: "concurrency less than 1 falls back to default",
			input: map[string]any{
				"concurrency": 0,
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:     nil,
				Ports:       []string{"1-1024"},
				Timeout:     defaultTCPPortDiscoveryTimeout,
				Concurrency: defaultTCPConcurrency,
			},
		},
		{
			name: "empty ports falls back to default",
			input: map[string]any{
				"ports": []string{""},
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:     nil,
				Ports:       []string{"1-1024"},
				Timeout:     defaultTCPPortDiscoveryTimeout,
				Concurrency: defaultTCPConcurrency,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module := newTCPPortDiscoveryModule()
			err := module.Init("instanceId", tt.input)
			if err != nil {
				t.Errorf("Init() returned error: %v", err)
			}
			got := module.config

			if !reflect.DeepEqual(got.Targets, tt.wantConfig.Targets) {
				t.Errorf("Targets: got %v, want %v", got.Targets, tt.wantConfig.Targets)
			}
			if !reflect.DeepEqual(got.Ports, tt.wantConfig.Ports) {
				t.Errorf("Ports: got %v, want %v", got.Ports, tt.wantConfig.Ports)
			}
			if got.Timeout != tt.wantConfig.Timeout {
				t.Errorf("Timeout: got %v, want %v", got.Timeout, tt.wantConfig.Timeout)
			}
			if got.Concurrency != tt.wantConfig.Concurrency {
				t.Errorf("Concurrency: got %v, want %v", got.Concurrency, tt.wantConfig.Concurrency)
			}
		})
	}
}

func TestTCPPortDiscoveryModule_Execute_NoTargets(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	module.meta.ID = "test-instance"
	module.config.Ports = []string{"80"}
	ctx := context.Background()
	outputs := make(chan engine.ModuleOutput, 1)

	// No targets in config or input
	err := module.Execute(ctx, map[string]any{}, outputs)
	if err == nil {
		t.Error("expected error when no targets are specified")
	}
	select {
	case out := <-outputs:
		if out.Error == nil {
			t.Error("expected output error when no targets are specified")
		}
	default:
		t.Error("expected output to be sent")
	}
}

func TestTCPPortDiscoveryModule_Execute_InvalidPorts(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	module.meta.ID = "test-instance"
	module.config.Targets = []string{"127.0.0.1"}
	module.config.Ports = []string{"notaport"}
	ctx := context.Background()
	outputs := make(chan engine.ModuleOutput, 1)

	err := module.Execute(ctx, map[string]any{}, outputs)
	if err == nil {
		t.Error("expected error for invalid port configuration")
	}
	select {
	case out := <-outputs:
		if out.Error == nil {
			t.Error("expected output error for invalid port configuration")
		}
	default:
		t.Error("expected output to be sent")
	}
}

func TestTCPPortDiscoveryModule_Execute_EmptyTargetsAfterExpansion(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	module.meta.ID = "test-instance"
	module.config.Targets = []string{}
	module.config.Ports = []string{"80"}
	ctx := context.Background()
	outputs := make(chan engine.ModuleOutput, 1)

	err := module.Execute(ctx, map[string]any{}, outputs)
	if err == nil {
		t.Error("expected error when no targets are specified")
	}
	select {
	case out := <-outputs:
		if out.Error == nil {
			t.Error("expected output error when no targets are specified")
		}
	default:
		t.Error("expected output to be sent")
	}
}

func TestTCPPortDiscoveryModule_Execute_EmptyPortsAfterParsing(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	module.meta.ID = "test-instance"
	module.config.Targets = []string{"127.0.0.1"}
	module.config.Ports = []string{""}
	ctx := context.Background()
	outputs := make(chan engine.ModuleOutput, 1)

	err := module.Execute(ctx, map[string]any{}, outputs)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	select {
	case out := <-outputs:
		results, ok := out.Data.([]TCPPortDiscoveryResult)
		if !ok {
			t.Errorf("expected []TCPPortDiscoveryResult, got %T", out.Data)
		}
		if len(results) != 0 {
			t.Errorf("expected empty results, got %v", results)
		}
	default:
		t.Error("expected output to be sent")
	}
}

func TestTCPPortDiscoveryModule_Execute_SuccessLocalhost(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	module.meta.ID = "test-instance"
	module.config.Targets = []string{"127.0.0.1"}
	module.config.Ports = []string{"22", "65535"} // 22 is often closed, 65535 almost always closed
	module.config.Timeout = 200 * time.Millisecond
	ctx := context.Background()
	outputs := make(chan engine.ModuleOutput, 10)

	err := module.Execute(ctx, map[string]any{}, outputs)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	close(outputs)
	// We can't guarantee any port is open, but we can check that outputs are valid
	for out := range outputs {
		result, ok := out.Data.(TCPPortDiscoveryResult)
		if !ok {
			t.Errorf("expected TCPPortDiscoveryResult, got %T", out.Data)
		}
		if result.Target != "127.0.0.1" {
			t.Errorf("expected target 127.0.0.1, got %s", result.Target)
		}
		// OpenPorts may be empty or not, depending on the environment
	}
}

func TestTCPPortDiscoveryModule_Execute_ContextCancelled(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	module.meta.ID = "test-instance"
	module.config.Targets = []string{"127.0.0.1"}
	module.config.Ports = []string{"1-100"}
	module.config.Concurrency = 1
	module.config.Timeout = 1 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	outputs := make(chan engine.ModuleOutput, 10)

	// Cancel context immediately
	cancel()
	err := module.Execute(ctx, map[string]any{}, outputs)
	if err != nil && err != context.Canceled {
		t.Errorf("expected context.Canceled or nil, got %v", err)
	}
	// No outputs expected, but should not panic or deadlock
}

func TestBuildHostnameByIPMap(t *testing.T) {
	originalLookup := lookupHost
	t.Cleanup(func() { lookupHost = originalLookup })

	lookupHost = func(host string) ([]string, error) {
		switch host {
		case "app.example":
			return []string{"10.0.0.10", "10.0.0.11"}, nil
		case "db.example":
			return []string{"10.0.0.10"}, nil
		default:
			return nil, context.DeadlineExceeded
		}
	}

	m := buildHostnameByIPMap([]string{
		"app.example",
		"db.example",
		"10.0.0.20",
		"10.0.0.0/24",
		"10.0.1.1-10.0.1.5",
	})

	// First hostname wins for same IP to keep deterministic behavior.
	if got := m["10.0.0.10"]; got != "app.example" {
		t.Fatalf("ip 10.0.0.10 hostname = %q, want app.example", got)
	}
	if got := m["10.0.0.11"]; got != "app.example" {
		t.Fatalf("ip 10.0.0.11 hostname = %q, want app.example", got)
	}
	if _, ok := m["10.0.0.20"]; ok {
		t.Fatalf("expected raw IP target not to be treated as hostname source")
	}
}
