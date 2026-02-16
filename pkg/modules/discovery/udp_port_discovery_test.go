// pkg/modules/discovery/udp_port_discovery_test.go
package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/engine"
)

func TestUDPPortDiscoveryModule_Metadata(t *testing.T) {
	module := newUDPPortDiscoveryModule()
	meta := module.Metadata()

	assert.Equal(t, udpPortDiscoveryModuleTypeName, meta.Name)
	assert.Equal(t, engine.DiscoveryModuleType, meta.Type)
	assert.NotEmpty(t, meta.Produces)
	assert.Equal(t, "discovery.open_udp_ports", meta.Produces[0].Key)
}

func TestUDPPortDiscoveryModule_Init(t *testing.T) {
	tests := []struct {
		name      string
		config    map[string]any
		expectErr bool
		checkFunc func(*testing.T, *UDPPortDiscoveryModule)
	}{
		{
			name:      "default config",
			config:    map[string]any{},
			expectErr: false,
			checkFunc: func(t *testing.T, m *UDPPortDiscoveryModule) {
				assert.Equal(t, defaultUDPPortDiscoveryTimeout, m.config.Timeout)
				assert.Equal(t, defaultUDPConcurrency, m.config.Concurrency)
				assert.Equal(t, defaultUDPMaxRetries, m.config.MaxRetries)
			},
		},
		{
			name: "custom timeout",
			config: map[string]any{
				"timeout": "3s",
			},
			expectErr: false,
			checkFunc: func(t *testing.T, m *UDPPortDiscoveryModule) {
				assert.Equal(t, 3*time.Second, m.config.Timeout)
			},
		},
		{
			name: "custom ports",
			config: map[string]any{
				"ports": []string{"53", "123", "161"},
			},
			expectErr: false,
			checkFunc: func(t *testing.T, m *UDPPortDiscoveryModule) {
				assert.Equal(t, []string{"53", "123", "161"}, m.config.Ports)
			},
		},
		{
			name: "custom concurrency",
			config: map[string]any{
				"concurrency": 10,
			},
			expectErr: false,
			checkFunc: func(t *testing.T, m *UDPPortDiscoveryModule) {
				assert.Equal(t, 10, m.config.Concurrency)
			},
		},
		{
			name: "invalid concurrency falls back to default",
			config: map[string]any{
				"concurrency": -5,
			},
			expectErr: false,
			checkFunc: func(t *testing.T, m *UDPPortDiscoveryModule) {
				assert.Equal(t, defaultUDPConcurrency, m.config.Concurrency)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module := newUDPPortDiscoveryModule()
			err := module.Init("test-instance", tt.config)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.checkFunc != nil {
					tt.checkFunc(t, module)
				}
			}
		})
	}
}

func TestUDPPortDiscoveryModule_Execute_NoTargets(t *testing.T) {
	module := newUDPPortDiscoveryModule()
	err := module.Init("test-instance", map[string]any{})
	require.NoError(t, err)

	ctx := context.Background()
	outputChan := make(chan engine.ModuleOutput, 10)

	inputs := map[string]any{} // No targets

	err = module.Execute(ctx, inputs, outputChan)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no targets specified")
}

func TestUDPPortDiscoveryModule_Execute_EmptyTargets(t *testing.T) {
	module := newUDPPortDiscoveryModule()
	err := module.Init("test-instance", map[string]any{})
	require.NoError(t, err)

	ctx := context.Background()
	outputChan := make(chan engine.ModuleOutput, 10)

	// Provide empty targets through inputs (not config)
	inputs := map[string]any{
		"config.targets": []string{}, // Empty targets - should trigger "no targets specified" error
	}

	err = module.Execute(ctx, inputs, outputChan)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no targets specified")
}

func TestUDPPortDiscoveryModule_Execute_Localhost(t *testing.T) {
	// This test requires local UDP services running (e.g., systemd-resolved on port 53)
	// Skip if not available
	if testing.Short() {
		t.Skip("Skipping localhost UDP test in short mode")
	}

	module := newUDPPortDiscoveryModule()
	err := module.Init("test-instance", map[string]any{
		"targets": []string{"127.0.0.1"},
		"ports":   []string{"53"}, // DNS (usually available on Linux with systemd-resolved)
		"timeout": "1s",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	outputChan := make(chan engine.ModuleOutput, 10)

	inputs := map[string]any{}

	go func() {
		err := module.Execute(ctx, inputs, outputChan)
		assert.NoError(t, err)
		close(outputChan) // Signal completion
	}()

	// Collect outputs
	var results []engine.ModuleOutput
	done := make(chan bool)
	go func() {
		for output := range outputChan {
			results = append(results, output)
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("Test timeout")
	}

	// Verify results
	if len(results) > 0 {
		for _, result := range results {
			assert.NoError(t, result.Error)
			assert.Equal(t, "discovery.open_udp_ports", result.DataKey)

			if udpResult, ok := result.Data.(UDPPortDiscoveryResult); ok {
				t.Logf("UDP scan result for %s: Open=%v, Filtered=%v", udpResult.Target, udpResult.OpenPorts, udpResult.FilteredPorts)
			}
		}
	} else {
		t.Log("No open UDP ports found (expected on systems without DNS/SNMP/NTP services)")
	}
}

func TestUDPPortDiscoveryModule_Execute_ContextCancellation(t *testing.T) {
	module := newUDPPortDiscoveryModule()
	err := module.Init("test-instance", map[string]any{
		"targets": []string{"10.0.0.1"}, // Non-routable IP (slow timeout)
		"ports":   []string{"53,161,123"},
		"timeout": "5s",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	outputChan := make(chan engine.ModuleOutput, 10)

	inputs := map[string]any{}

	// Cancel context after 100ms
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	err = module.Execute(ctx, inputs, outputChan)
	// Execution should complete (no error on cancellation)
	assert.NoError(t, err)
}

func TestGetDefaultUDPPayloads(t *testing.T) {
	payloads := getDefaultUDPPayloads()

	// Check common ports have payloads
	assert.Contains(t, payloads, 53, "DNS payload should exist")
	assert.Contains(t, payloads, 161, "SNMP payload should exist")
	assert.Contains(t, payloads, 123, "NTP payload should exist")
	assert.Contains(t, payloads, 514, "Syslog payload should exist")
	assert.Contains(t, payloads, 1900, "UPnP SSDP payload should exist")

	// Verify payload sizes
	assert.NotEmpty(t, payloads[53], "DNS payload should not be empty")
	assert.NotEmpty(t, payloads[161], "SNMP payload should not be empty")
}

func TestUDPPortDiscoveryModule_Factory(t *testing.T) {
	module := UDPPortDiscoveryModuleFactory()
	assert.NotNil(t, module)
	assert.Implements(t, (*engine.Module)(nil), module)
}
