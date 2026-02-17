package discovery

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
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
				Targets:         nil,
				Ports:           []string{"1-1024"},
				Timeout:         defaultTCPPortDiscoveryTimeout,
				Concurrency:     defaultTCPConcurrency,
				StopOnFirstOpen: false,
			},
		},
		{
			name: "set targets and ports",
			input: map[string]any{
				"targets": []string{"127.0.0.1", "192.168.1.1"},
				"ports":   []string{"22", "80-81"},
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:         []string{"127.0.0.1", "192.168.1.1"},
				Ports:           []string{"22", "80-81"},
				Timeout:         defaultTCPPortDiscoveryTimeout,
				Concurrency:     defaultTCPConcurrency,
				StopOnFirstOpen: false,
			},
		},
		{
			name: "set timeout and concurrency",
			input: map[string]any{
				"timeout":     "2s",
				"concurrency": 50,
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:         nil,
				Ports:           []string{"1-1024"},
				Timeout:         2 * time.Second,
				Concurrency:     50,
				StopOnFirstOpen: false,
			},
		},
		{
			name: "invalid timeout falls back to default",
			input: map[string]any{
				"timeout": "notaduration",
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:         nil,
				Ports:           []string{"1-1024"},
				Timeout:         defaultTCPPortDiscoveryTimeout,
				Concurrency:     defaultTCPConcurrency,
				StopOnFirstOpen: false,
			},
		},
		{
			name: "concurrency less than 1 falls back to default",
			input: map[string]any{
				"concurrency": 0,
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:         nil,
				Ports:           []string{"1-1024"},
				Timeout:         defaultTCPPortDiscoveryTimeout,
				Concurrency:     defaultTCPConcurrency,
				StopOnFirstOpen: false,
			},
		},
		{
			name: "empty ports falls back to default",
			input: map[string]any{
				"ports": []string{""},
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:         nil,
				Ports:           []string{"1-1024"},
				Timeout:         defaultTCPPortDiscoveryTimeout,
				Concurrency:     defaultTCPConcurrency,
				StopOnFirstOpen: false,
			},
		},
		{
			name: "set stop_on_first_open",
			input: map[string]any{
				"stop_on_first_open": true,
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:         nil,
				Ports:           []string{"1-1024"},
				Timeout:         defaultTCPPortDiscoveryTimeout,
				Concurrency:     defaultTCPConcurrency,
				StopOnFirstOpen: true,
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
			if got.StopOnFirstOpen != tt.wantConfig.StopOnFirstOpen {
				t.Errorf("StopOnFirstOpen: got %v, want %v", got.StopOnFirstOpen, tt.wantConfig.StopOnFirstOpen)
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

func TestTCPPortDiscoveryModule_StopOnFirstOpenPerTarget(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	module.meta.ID = "test-instance"
	module.config.Targets = []string{"198.51.100.10", "198.51.100.11"}
	module.config.Ports = []string{"101", "102", "103", "104"}
	module.config.Timeout = 20 * time.Millisecond
	module.config.Concurrency = 8
	module.config.StopOnFirstOpen = true

	originalDial := dialTimeout
	t.Cleanup(func() { dialTimeout = originalDial })

	var mu sync.Mutex
	attemptsByIP := make(map[string]int)
	dialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}

		mu.Lock()
		attemptsByIP[host]++
		mu.Unlock()

		if host == "198.51.100.10" && port == 101 {
			c1, c2 := net.Pipe()
			_ = c2.Close()
			return c1, nil
		}
		return nil, errors.New("closed")
	}

	outputs := make(chan engine.ModuleOutput, 8)
	err := module.Execute(context.Background(), map[string]any{}, outputs)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	close(outputs)

	// Target-1 should stop after first open, target-2 should continue all probes.
	if got := attemptsByIP["198.51.100.10"]; got != 1 {
		t.Fatalf("target 198.51.100.10 attempts = %d, want 1", got)
	}
	if got := attemptsByIP["198.51.100.11"]; got != 4 {
		t.Fatalf("target 198.51.100.11 attempts = %d, want 4", got)
	}
}

func TestTCPPortDiscoveryModule_StopOnFirstOpenDisabledScansAll(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	module.meta.ID = "test-instance"
	module.config.Targets = []string{"198.51.100.20"}
	module.config.Ports = []string{"201", "202", "203", "204"}
	module.config.Timeout = 20 * time.Millisecond
	module.config.Concurrency = 8
	module.config.StopOnFirstOpen = false

	originalDial := dialTimeout
	t.Cleanup(func() { dialTimeout = originalDial })

	var mu sync.Mutex
	attempts := 0
	dialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if host != "198.51.100.20" {
			return nil, errors.New("unknown host")
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}

		mu.Lock()
		attempts++
		mu.Unlock()

		if port == 201 {
			c1, c2 := net.Pipe()
			_ = c2.Close()
			return c1, nil
		}
		return nil, errors.New("closed")
	}

	outputs := make(chan engine.ModuleOutput, 8)
	err := module.Execute(context.Background(), map[string]any{}, outputs)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	close(outputs)

	if attempts != 4 {
		t.Fatalf("attempt count = %d, want 4", attempts)
	}
}
