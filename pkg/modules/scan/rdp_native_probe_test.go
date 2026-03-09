package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

func TestRDPNativeProbeModule_ExecuteFiltersCandidates(t *testing.T) {
	originalProbe := probeRDPDetailsFunc
	defer func() { probeRDPDetailsFunc = originalProbe }()

	calls := 0
	probeRDPDetailsFunc = func(ctx context.Context, target string, port int, opts RDPProbeOptions) RDPServiceInfo {
		calls++
		return RDPServiceInfo{
			Target:      target,
			Port:        port,
			RDPProbe:    true,
			RDPDetected: "x224-confirm",
		}
	}

	module := newRDPNativeProbeModule()
	if err := module.Init("test-rdp-native", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: "198.51.100.10", OpenPorts: []int{3389, 22}},
		},
		"service.banner.tcp": []any{
			BannerGrabResult{IP: "198.51.100.10", Port: 3390, Protocol: "rdp"},
			BannerGrabResult{IP: "198.51.100.10", Port: 3390, Protocol: "rdp"}, // duplicate
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	var outputs []RDPServiceInfo
	for item := range out {
		rdp, ok := item.Data.(RDPServiceInfo)
		if !ok {
			continue
		}
		outputs = append(outputs, rdp)
	}

	if calls != 2 {
		t.Fatalf("expected 2 probe calls, got %d", calls)
	}
	if len(outputs) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(outputs))
	}
}

func TestDetectRDPResponseKind(t *testing.T) {
	x224Confirm := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xD0, 0x00}
	tpktOnly := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0x70, 0x00}
	invalid := []byte{0x16, 0x03, 0x01}

	if got := detectRDPResponseKind(x224Confirm); got != "x224-confirm" {
		t.Fatalf("expected x224-confirm, got %q", got)
	}
	if got := detectRDPResponseKind(tpktOnly); got != "tpkt" {
		t.Fatalf("expected tpkt, got %q", got)
	}
	if got := detectRDPResponseKind(invalid); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestParseRDPNegotiationMetadata(t *testing.T) {
	// X.224 confirm + RDP Negotiation Response (selected protocol = HYBRID/0x02).
	response := []byte{
		0x03, 0x00, 0x00, 0x13,
		0x0e, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00,
		0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	selectedProtocol, hasSelected, nlaCapable, tlsCapable, negFailureCode := parseRDPNegotiationMetadata(response)
	if selectedProtocol != "hybrid" {
		t.Fatalf("expected selected protocol hybrid, got %q", selectedProtocol)
	}
	if !hasSelected {
		t.Fatalf("expected hasSelected=true")
	}
	if !nlaCapable || !tlsCapable {
		t.Fatalf("expected nla/tls capable true, got nla=%t tls=%t", nlaCapable, tlsCapable)
	}
	if negFailureCode != "" {
		t.Fatalf("expected empty neg failure code, got %q", negFailureCode)
	}

	// X.224 confirm + RDP Negotiation Failure (HYBRID_REQUIRED_BY_SERVER/0x05).
	failure := []byte{
		0x03, 0x00, 0x00, 0x13,
		0x0e, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00,
		0x03, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00,
	}

	selectedProtocol, hasSelected, nlaCapable, tlsCapable, negFailureCode = parseRDPNegotiationMetadata(failure)
	if selectedProtocol != "" {
		t.Fatalf("expected empty selected protocol, got %q", selectedProtocol)
	}
	if hasSelected {
		t.Fatalf("expected hasSelected=false")
	}
	if nlaCapable || tlsCapable {
		t.Fatalf("expected nla/tls capable false on failure")
	}
	if negFailureCode != "hybrid_required_by_server" {
		t.Fatalf("expected hybrid_required_by_server, got %q", negFailureCode)
	}
}

func TestClassifyRDPProbeError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "timeout", err: errors.New("i/o timeout"), want: "timeout"},
		{name: "refused", err: errors.New("connection refused"), want: "refused"},
		{name: "short", err: errors.New("short_rdp_response"), want: "short_response"},
		{name: "unknown", err: errors.New("unknown_rdp_response"), want: "unknown_response"},
		{name: "generic", err: errors.New("unexpected"), want: "probe_failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyRDPProbeError(tt.err); got != tt.want {
				t.Fatalf("classifyRDPProbeError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPickTopRDPProbeErrorPriority(t *testing.T) {
	codes := []string{"probe_failed", "short_response", "timeout"}
	if got := pickTopRDPProbeError(codes); got != "timeout" {
		t.Fatalf("expected timeout priority, got %q", got)
	}
}
