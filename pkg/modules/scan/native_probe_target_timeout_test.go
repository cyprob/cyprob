package scan

import (
	"context"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"github.com/stretchr/testify/require"
)

// drainOutputs empties a module's output channel so Execute cannot block on it.
func drainOutputs(out chan engine.ModuleOutput) {
	close(out)
	for range out {
	}
}

// The per-target timeout must be released by the code that created it, for
// every target including the last one (cyprob#269). Capturing the contexts the
// loop hands to the probe is the only way to see it: the module returns results,
// not contexts.
func TestFTPNativeProbe_ReleasesEveryTargetTimeout(t *testing.T) {
	original := probeFTPDetailsFunc
	defer func() { probeFTPDetailsFunc = original }()

	var seen []context.Context
	probeFTPDetailsFunc = func(ctx context.Context, target string, hostname string, port int, protocolHint string, opts FTPProbeOptions) FTPServiceInfo {
		seen = append(seen, ctx)
		return FTPServiceInfo{Target: target, Port: port, FTPProbe: true}
	}

	module := newFTPNativeProbeModule()
	require.NoError(t, module.Init("test-ftp-native", map[string]any{"total_timeout": "2500ms"}))

	out := make(chan engine.ModuleOutput, 8)
	require.NoError(t, module.Execute(context.Background(), map[string]any{
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: "198.51.100.60", OpenPorts: []int{21}},
			discovery.TCPPortDiscoveryResult{Target: "198.51.100.61", OpenPorts: []int{21}},
		},
	}, out))
	drainOutputs(out)

	require.Len(t, seen, 2, "one context per target")
	for i, ctx := range seen {
		_, hasDeadline := ctx.Deadline()
		require.True(t, hasDeadline, "context %d carries the per-target timeout", i)
		require.Error(t, ctx.Err(), "context %d must be released before Execute returns", i)
	}
}

// Same property, second module, because the four native probes share this loop
// shape verbatim and a fix applied to one of them proves nothing about the rest.
func TestWINRMNativeProbe_ReleasesEveryTargetTimeout(t *testing.T) {
	original := probeWINRMDetailsFunc
	defer func() { probeWINRMDetailsFunc = original }()

	var seen []context.Context
	probeWINRMDetailsFunc = func(ctx context.Context, target string, hostname string, port int, opts WINRMProbeOptions) WINRMServiceInfo {
		seen = append(seen, ctx)
		return WINRMServiceInfo{Target: target, Port: port, WINRMProbe: true}
	}

	module := newWINRMNativeProbeModule()
	require.NoError(t, module.Init("test-winrm-native", map[string]any{"total_timeout": "2500ms"}))

	out := make(chan engine.ModuleOutput, 8)
	require.NoError(t, module.Execute(context.Background(), map[string]any{
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: "198.51.100.60", OpenPorts: []int{5985}},
			discovery.TCPPortDiscoveryResult{Target: "198.51.100.61", OpenPorts: []int{5985}},
		},
	}, out))
	drainOutputs(out)

	require.Len(t, seen, 2, "one context per target")
	for i, ctx := range seen {
		require.Error(t, ctx.Err(), "context %d must be released before Execute returns", i)
	}
}
