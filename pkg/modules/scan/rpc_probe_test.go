package scan

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

func TestRPCEpmapperProbeModule_ExecuteFiltersCandidates(t *testing.T) {
	originalProbe := probeRPCEpmapperDetailsFunc
	defer func() { probeRPCEpmapperDetailsFunc = originalProbe }()

	calls := 0
	probeRPCEpmapperDetailsFunc = func(ctx context.Context, target string, port int, opts RPCEpmapperProbeOptions) RPCEpmapperInfo {
		calls++
		return RPCEpmapperInfo{Target: target, Port: port, RPCProbe: true}
	}

	module := newRPCEpmapperProbeModule()
	if err := module.Init("test-rpc-epmapper", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: "198.51.100.10", OpenPorts: []int{135, 443}},
			discovery.TCPPortDiscoveryResult{Target: "198.51.100.11", OpenPorts: []int{445}},
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	var outputs []RPCEpmapperInfo
	for item := range out {
		result, ok := item.Data.(RPCEpmapperInfo)
		if !ok {
			continue
		}
		outputs = append(outputs, result)
	}

	if calls != 1 {
		t.Fatalf("expected 1 probe call, got %d", calls)
	}
	if len(outputs) != 1 {
		t.Fatalf("expected 1 output, got %d", len(outputs))
	}
	if outputs[0].Target != "198.51.100.10" || outputs[0].Port != 135 {
		t.Fatalf("unexpected output target/port: %+v", outputs[0])
	}
}

func TestRPCFollowupProbeModule_ExecuteUsesBoundedDynamicPorts(t *testing.T) {
	originalProbe := probeRPCFollowupDetailsFunc
	defer func() { probeRPCFollowupDetailsFunc = originalProbe }()

	probedPorts := make([]int, 0, 4)
	probeRPCFollowupDetailsFunc = func(ctx context.Context, target string, port int, derivedFromPort int, opts RPCFollowupProbeOptions) RPCServiceInfo {
		probedPorts = append(probedPorts, port)
		return RPCServiceInfo{
			Target:          target,
			Port:            port,
			DerivedFromPort: derivedFromPort,
			RPCProbe:        true,
		}
	}

	module := newRPCFollowupProbeModule()
	if err := module.Init("test-rpc-followup", map[string]any{"max_dynamic_ports": 1}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.rpc.epmapper": []any{
			RPCEpmapperInfo{
				Target:        "198.51.100.20",
				Port:          135,
				RPCProbe:      true,
				AnonymousBind: true,
				DynamicEndpoints: []RPCDynamicEndpoint{
					{Port: 49153, InterfaceCount: 2},
					{Port: 49152, InterfaceCount: 6},
				},
				DynamicPorts: []int{49154},
			},
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	var outputs []RPCServiceInfo
	for item := range out {
		result, ok := item.Data.(RPCServiceInfo)
		if !ok {
			continue
		}
		outputs = append(outputs, result)
	}

	if len(probedPorts) != 1 {
		t.Fatalf("expected 1 probed dynamic port, got %d", len(probedPorts))
	}
	if probedPorts[0] != 49152 {
		t.Fatalf("expected highest-priority dynamic port 49152, got %d", probedPorts[0])
	}
	if len(outputs) != 2 {
		t.Fatalf("expected 2 outputs (base+followup), got %d", len(outputs))
	}
}

func TestSelectRPCDynamicPorts_Deterministic(t *testing.T) {
	entries := []RPCEpmapperInfo{
		{
			Target: "198.51.100.30",
			Port:   135,
			DynamicEndpoints: []RPCDynamicEndpoint{
				{Port: 49160, InterfaceCount: 2},
				{Port: 49161, InterfaceCount: 2},
				{Port: 49162, InterfaceCount: 3},
			},
		},
	}

	selected := selectRPCDynamicPorts(entries, 2, true)
	if len(selected) != 2 {
		t.Fatalf("expected 2 selected ports, got %d", len(selected))
	}
	ports := []int{selected[0].port, selected[1].port}
	if !slices.Equal(ports, []int{49162, 49160}) {
		t.Fatalf("unexpected deterministic selection order: %+v", ports)
	}
}

func TestClassifyRPCProbeError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "timeout", err: errors.New("i/o timeout"), want: "timeout"},
		{name: "refused", err: errors.New("connection refused"), want: "refused"},
		{name: "bind", err: errors.New("bind_failed: unexpected"), want: "bind_failed"},
		{name: "lookup", err: errors.New("lookup_failed"), want: "lookup_failed"},
		{name: "mgmt", err: errors.New("mgmt_failed"), want: "mgmt_failed"},
		{name: "budget", err: errors.New("budget_exceeded"), want: "budget_exceeded"},
		{name: "generic", err: errors.New("unexpected"), want: "probe_failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyRPCProbeError(tt.err); got != tt.want {
				t.Fatalf("classifyRPCProbeError() = %q, want %q", got, tt.want)
			}
		})
	}
}
