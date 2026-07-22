package discovery

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type timeoutTestError struct{}

func (timeoutTestError) Error() string   { return "i/o timeout" }
func (timeoutTestError) Timeout() bool   { return true }
func (timeoutTestError) Temporary() bool { return true }

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

	if len(gotConsumeKeys) != 0 {
		t.Errorf("expected all consumes optional by default, got required keys %v", gotConsumeKeys)
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

func TestTCPPortDiscoveryModule_Execute_UsesLiveHostsListInput(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	host, portString, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	module := newTCPPortDiscoveryModule()
	if err := module.Init("test-live-hosts-list", map[string]any{
		"ports":   []string{portString},
		"timeout": "200ms",
	}); err != nil {
		t.Fatalf("init: %v", err)
	}

	outputs := make(chan engine.ModuleOutput, 4)
	err = module.Execute(context.Background(), map[string]any{
		"config.targets": []string{"198.51.100.50"},
		"discovery.live_hosts": []any{
			ICMPPingDiscoveryResult{LiveHosts: []string{host}},
		},
	}, outputs)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(outputs)

	found := false
	port, _ := strconv.Atoi(portString)
	for out := range outputs {
		result, ok := out.Data.(TCPPortDiscoveryResult)
		if !ok {
			continue
		}
		if result.Target == host && reflect.DeepEqual(result.OpenPorts, []int{port}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected live host result for %s:%d", host, port)
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
				Targets:                 nil,
				Ports:                   []string{"1-1024"},
				Timeout:                 defaultTCPPortDiscoveryTimeout,
				Concurrency:             defaultTCPConcurrency,
				Retries:                 0,
				StopOnFirstOpen:         false,
				VerificationPassEnabled: true,
			},
		},
		{
			name: "set targets and ports",
			input: map[string]any{
				"targets": []string{"127.0.0.1", "192.168.1.1"},
				"ports":   []string{"22", "80-81"},
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:                 []string{"127.0.0.1", "192.168.1.1"},
				Ports:                   []string{"22", "80-81"},
				Timeout:                 defaultTCPPortDiscoveryTimeout,
				Concurrency:             defaultTCPConcurrency,
				Retries:                 0,
				StopOnFirstOpen:         false,
				VerificationPassEnabled: true,
			},
		},
		{
			name: "set timeout and concurrency",
			input: map[string]any{
				"timeout":     "2s",
				"concurrency": 50,
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:                 nil,
				Ports:                   []string{"1-1024"},
				Timeout:                 2 * time.Second,
				Concurrency:             50,
				Retries:                 0,
				StopOnFirstOpen:         false,
				VerificationPassEnabled: true,
			},
		},
		{
			name: "set port timeout overrides",
			input: map[string]any{
				"port_timeout_overrides": map[string]any{
					"135": "8s",
					"139": "8s",
					"bad": "9s",
					"445": "0s",
				},
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets: nil,
				Ports:   []string{"1-1024"},
				Timeout: defaultTCPPortDiscoveryTimeout,
				PortTimeoutOverrides: map[int]time.Duration{
					135: 8 * time.Second,
					139: 8 * time.Second,
				},
				Concurrency:             defaultTCPConcurrency,
				Retries:                 0,
				StopOnFirstOpen:         false,
				VerificationPassEnabled: true,
			},
		},
		{
			name: "set retries",
			input: map[string]any{
				"retries": 1,
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:                 nil,
				Ports:                   []string{"1-1024"},
				Timeout:                 defaultTCPPortDiscoveryTimeout,
				Concurrency:             defaultTCPConcurrency,
				Retries:                 1,
				StopOnFirstOpen:         false,
				VerificationPassEnabled: true,
			},
		},
		{
			name: "invalid timeout falls back to default",
			input: map[string]any{
				"timeout": "notaduration",
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:                 nil,
				Ports:                   []string{"1-1024"},
				Timeout:                 defaultTCPPortDiscoveryTimeout,
				Concurrency:             defaultTCPConcurrency,
				Retries:                 0,
				StopOnFirstOpen:         false,
				VerificationPassEnabled: true,
			},
		},
		{
			name: "concurrency less than 1 falls back to default",
			input: map[string]any{
				"concurrency": 0,
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:                 nil,
				Ports:                   []string{"1-1024"},
				Timeout:                 defaultTCPPortDiscoveryTimeout,
				Concurrency:             defaultTCPConcurrency,
				Retries:                 0,
				StopOnFirstOpen:         false,
				VerificationPassEnabled: true,
			},
		},
		{
			name: "empty ports falls back to default",
			input: map[string]any{
				"ports": []string{""},
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:                 nil,
				Ports:                   []string{"1-1024"},
				Timeout:                 defaultTCPPortDiscoveryTimeout,
				Concurrency:             defaultTCPConcurrency,
				StopOnFirstOpen:         false,
				VerificationPassEnabled: true,
			},
		},
		{
			name: "set stop_on_first_open",
			input: map[string]any{
				"stop_on_first_open": true,
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:                 nil,
				Ports:                   []string{"1-1024"},
				Timeout:                 defaultTCPPortDiscoveryTimeout,
				Concurrency:             defaultTCPConcurrency,
				StopOnFirstOpen:         true,
				VerificationPassEnabled: true,
			},
		},
		{
			name: "set verification_pass_enabled",
			input: map[string]any{
				"verification_pass_enabled": false,
			},
			wantConfig: TCPPortDiscoveryConfig{
				Targets:                 nil,
				Ports:                   []string{"1-1024"},
				Timeout:                 defaultTCPPortDiscoveryTimeout,
				Concurrency:             defaultTCPConcurrency,
				StopOnFirstOpen:         false,
				VerificationPassEnabled: false,
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
			if !reflect.DeepEqual(got.PortTimeoutOverrides, tt.wantConfig.PortTimeoutOverrides) {
				t.Errorf("PortTimeoutOverrides: got %v, want %v", got.PortTimeoutOverrides, tt.wantConfig.PortTimeoutOverrides)
			}
			if got.Concurrency != tt.wantConfig.Concurrency {
				t.Errorf("Concurrency: got %v, want %v", got.Concurrency, tt.wantConfig.Concurrency)
			}
			if got.StopOnFirstOpen != tt.wantConfig.StopOnFirstOpen {
				t.Errorf("StopOnFirstOpen: got %v, want %v", got.StopOnFirstOpen, tt.wantConfig.StopOnFirstOpen)
			}
			if got.VerificationPassEnabled != tt.wantConfig.VerificationPassEnabled {
				t.Errorf("VerificationPassEnabled: got %v, want %v", got.VerificationPassEnabled, tt.wantConfig.VerificationPassEnabled)
			}
		})
	}
}

func TestTCPPortDiscoveryModule_DialWithRetries(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	module.config.Timeout = 10 * time.Millisecond
	module.config.Retries = 1

	originalDial := dialTimeout
	defer func() { dialTimeout = originalDial }()

	attempts := 0
	dialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		attempts++
		if attempts == 1 {
			return nil, errors.New("temporary timeout")
		}
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}

	conn, err := module.dialWithRetries(context.Background(), "127.0.0.1:80", 80, module.config.Timeout)
	if conn != nil {
		_ = conn.Close()
	}

	if err != nil {
		t.Fatalf("expected retry to succeed, got error: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 dial attempts, got %d", attempts)
	}
}

func TestTCPPortDiscoveryModule_DialWithRetriesUsesPortTimeoutOverride(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	module.config.Timeout = time.Second
	module.config.PortTimeoutOverrides = map[int]time.Duration{
		445: 8 * time.Second,
	}

	originalDial := dialTimeout
	t.Cleanup(func() { dialTimeout = originalDial })

	var gotTimeout time.Duration
	dialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		gotTimeout = timeout
		return nil, timeoutTestError{}
	}

	_, err := module.dialWithRetries(context.Background(), "127.0.0.1:445", 445, module.config.Timeout)
	require.Error(t, err)
	require.Equal(t, 8*time.Second, gotTimeout)
}

func TestTCPPortDiscoveryModule_ScanTargetPortsAll_AppliesPortTimeoutOverrideOnlyToMatchingPort(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	module.config.Timeout = time.Second
	module.config.Retries = 0
	module.config.VerificationPassEnabled = false
	module.config.PortTimeoutOverrides = map[int]time.Duration{
		445: 8 * time.Second,
	}

	originalDial := dialTimeout
	t.Cleanup(func() { dialTimeout = originalDial })

	var timeoutsMu sync.Mutex
	timeouts := make(map[string]time.Duration)
	dialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		timeoutsMu.Lock()
		timeouts[address] = timeout
		timeoutsMu.Unlock()
		return nil, timeoutTestError{}
	}

	openPortsByTarget := make(map[string][]int)
	timedOutPortsByTarget := make(map[string][]int)
	refusedPortsByTarget := make(map[string][]int)
	otherErrorPortsByTarget := make(map[string][]int)
	var mapMutex sync.Mutex

	module.scanTargetPortsAll(
		context.Background(),
		"127.0.0.1",
		[]int{80, 445},
		make(chan struct{}, 2),
		&mapMutex,
		openPortsByTarget,
		timedOutPortsByTarget,
		refusedPortsByTarget,
		otherErrorPortsByTarget,
	)

	timeoutsMu.Lock()
	defer timeoutsMu.Unlock()
	require.Equal(t, time.Second, timeouts["127.0.0.1:80"])
	require.Equal(t, 8*time.Second, timeouts["127.0.0.1:445"])
}

func TestTCPPortDiscoveryModule_ScanTargetPortsAll_TwoPhaseSweepRecoversSlowOpen(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	module.config.Timeout = 1 * time.Second
	module.config.SweepTimeout = 200 * time.Millisecond
	module.config.Retries = 0
	module.config.VerificationPassEnabled = false // a sweep implies its own verification

	originalDial := dialTimeout
	t.Cleanup(func() { dialTimeout = originalDial })

	var mu sync.Mutex
	dialCount := make(map[int]int)
	dialTimeout = func(_ string, address string, timeout time.Duration) (net.Conn, error) {
		_, portStr, _ := net.SplitHostPort(address)
		port, _ := strconv.Atoi(portStr)
		mu.Lock()
		dialCount[port]++
		mu.Unlock()

		switch port {
		case 80: // open immediately on the sweep
			c1, c2 := net.Pipe()
			_ = c2.Close()
			return c1, nil
		case 8080: // slow-open: times out on the short sweep, opens at the full timeout
			if timeout <= module.config.SweepTimeout {
				return nil, timeoutTestError{}
			}
			c1, c2 := net.Pipe()
			_ = c2.Close()
			return c1, nil
		default: // 81: refused -> definitively closed, must not be re-probed
			return nil, syscall.ECONNREFUSED
		}
	}

	openPortsByTarget := make(map[string][]int)
	timedOutPortsByTarget := make(map[string][]int)
	refusedPortsByTarget := make(map[string][]int)
	otherErrorPortsByTarget := make(map[string][]int)
	var mapMutex sync.Mutex

	module.scanTargetPortsAll(
		context.Background(),
		"127.0.0.1",
		[]int{80, 81, 8080},
		make(chan struct{}, 8),
		&mapMutex,
		openPortsByTarget,
		timedOutPortsByTarget,
		refusedPortsByTarget,
		otherErrorPortsByTarget,
	)

	require.ElementsMatch(t, []int{80, 8080}, openPortsByTarget["127.0.0.1"],
		"slow-open 8080 must be recovered by the full-timeout verification pass")
	require.Equal(t, []int{81}, refusedPortsByTarget["127.0.0.1"])
	require.Empty(t, timedOutPortsByTarget["127.0.0.1"],
		"8080 must move from timed-out to open after verification")

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, dialCount[80], "open port dialed once (sweep)")
	require.Equal(t, 1, dialCount[81], "refused port must NOT be re-verified")
	require.Equal(t, 2, dialCount[8080], "slow-open dialed twice: sweep (timeout) + verification (open)")
}

func TestTCPPortDiscoveryModule_ScanTargetPortsAll_TargetedSecondPassRecoversMissedPort(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	module.config.Timeout = 10 * time.Millisecond
	module.config.Retries = 0
	module.config.VerificationPassEnabled = true

	originalDial := dialTimeout
	defer func() { dialTimeout = originalDial }()

	var attemptsMu sync.Mutex
	attempts := make(map[string]int)

	dialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		attemptsMu.Lock()
		attempts[address]++
		attempt := attempts[address]
		attemptsMu.Unlock()

		if strings.HasSuffix(address, ":80") && attempt == 1 {
			return nil, timeoutTestError{}
		}

		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}

	openPortsByTarget := make(map[string][]int)
	timedOutPortsByTarget := make(map[string][]int)
	refusedPortsByTarget := make(map[string][]int)
	otherErrorPortsByTarget := make(map[string][]int)
	var mapMutex sync.Mutex

	ipPorts := module.scanTargetPortsAll(
		context.Background(),
		"127.0.0.1",
		[]int{80, 443},
		make(chan struct{}, 4),
		&mapMutex,
		openPortsByTarget,
		timedOutPortsByTarget,
		refusedPortsByTarget,
		otherErrorPortsByTarget,
	)

	assert.Equal(t, []int{80, 443}, ipPorts)
	assert.Equal(t, []int{80, 443}, openPortsByTarget["127.0.0.1"])
	assert.Empty(t, timedOutPortsByTarget["127.0.0.1"])
	assert.Empty(t, refusedPortsByTarget["127.0.0.1"])
	assert.Empty(t, otherErrorPortsByTarget["127.0.0.1"])

	attemptsMu.Lock()
	assert.Equal(t, 2, attempts["127.0.0.1:80"])
	assert.Equal(t, 1, attempts["127.0.0.1:443"])
	attemptsMu.Unlock()
}

func TestTCPPortDiscoveryModule_ScanTargetPortsAll_VerificationPassDisabledLeavesMiss(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	module.config.Timeout = 10 * time.Millisecond
	module.config.Retries = 0
	module.config.VerificationPassEnabled = false

	originalDial := dialTimeout
	defer func() { dialTimeout = originalDial }()

	var attemptsMu sync.Mutex
	attempts := make(map[string]int)

	dialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		attemptsMu.Lock()
		attempts[address]++
		attempt := attempts[address]
		attemptsMu.Unlock()

		if strings.HasSuffix(address, ":80") && attempt == 1 {
			return nil, timeoutTestError{}
		}

		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}

	openPortsByTarget := make(map[string][]int)
	timedOutPortsByTarget := make(map[string][]int)
	refusedPortsByTarget := make(map[string][]int)
	otherErrorPortsByTarget := make(map[string][]int)
	var mapMutex sync.Mutex

	ipPorts := module.scanTargetPortsAll(
		context.Background(),
		"127.0.0.1",
		[]int{80, 443},
		make(chan struct{}, 4),
		&mapMutex,
		openPortsByTarget,
		timedOutPortsByTarget,
		refusedPortsByTarget,
		otherErrorPortsByTarget,
	)

	assert.Equal(t, []int{443}, ipPorts)
	assert.Equal(t, []int{443}, openPortsByTarget["127.0.0.1"])
	assert.Equal(t, []int{80}, timedOutPortsByTarget["127.0.0.1"])
	assert.Empty(t, refusedPortsByTarget["127.0.0.1"])
	assert.Empty(t, otherErrorPortsByTarget["127.0.0.1"])

	attemptsMu.Lock()
	assert.Equal(t, 1, attempts["127.0.0.1:80"])
	assert.Equal(t, 1, attempts["127.0.0.1:443"])
	attemptsMu.Unlock()
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
	module.config.VerificationPassEnabled = false

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

func TestTCPPortDiscoveryModule_Execute_ReportsTimedOutPorts(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	module.meta.ID = "test-timeout-instance"
	module.config.Targets = []string{"198.51.100.30"}
	module.config.Ports = []string{"301", "302", "303"}
	module.config.Timeout = 20 * time.Millisecond
	module.config.Concurrency = 3

	originalDial := dialTimeout
	t.Cleanup(func() { dialTimeout = originalDial })

	dialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		_, portStr, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}

		switch port {
		case 301:
			c1, c2 := net.Pipe()
			_ = c2.Close()
			return c1, nil
		case 302:
			return nil, timeoutTestError{}
		default:
			return nil, errors.New("closed")
		}
	}

	outputs := make(chan engine.ModuleOutput, 8)
	err := module.Execute(context.Background(), map[string]any{}, outputs)
	require.NoError(t, err)
	close(outputs)

	found := false
	for out := range outputs {
		result, ok := out.Data.(TCPPortDiscoveryResult)
		if !ok || result.Target != "198.51.100.30" {
			continue
		}
		assert.Equal(t, []int{301}, result.OpenPorts)
		assert.Equal(t, []int{302}, result.TimedOutPorts)
		found = true
	}

	assert.True(t, found, "expected timeout-aware TCP discovery result")
}

func TestTCPPortDiscoveryModule_Execute_ReportsRefusedAndOtherErrorPorts(t *testing.T) {
	module := newTCPPortDiscoveryModule()
	module.meta.ID = "test-negative-instance"
	module.config.Targets = []string{"198.51.100.31"}
	module.config.Ports = []string{"401", "402", "403"}
	module.config.Timeout = 20 * time.Millisecond
	module.config.Concurrency = 3

	originalDial := dialTimeout
	t.Cleanup(func() { dialTimeout = originalDial })

	dialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		_, portStr, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}

		switch port {
		case 401:
			return nil, syscall.ECONNREFUSED
		case 402:
			return nil, errors.New("other socket failure")
		default:
			c1, c2 := net.Pipe()
			_ = c2.Close()
			return c1, nil
		}
	}

	outputs := make(chan engine.ModuleOutput, 8)
	err := module.Execute(context.Background(), map[string]any{}, outputs)
	require.NoError(t, err)
	close(outputs)

	found := false
	for out := range outputs {
		result, ok := out.Data.(TCPPortDiscoveryResult)
		if !ok || result.Target != "198.51.100.31" {
			continue
		}
		assert.Equal(t, []int{403}, result.OpenPorts)
		assert.Equal(t, []int{401}, result.RefusedPorts)
		assert.Equal(t, []int{402}, result.OtherErrorPorts)
		assert.Empty(t, result.TimedOutPorts)
		found = true
	}

	assert.True(t, found, "expected refused/other-aware TCP discovery result")
}
