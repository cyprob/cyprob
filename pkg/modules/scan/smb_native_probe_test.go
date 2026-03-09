package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
)

func TestSMBNativeProbeModule_ExecuteFiltersCandidates(t *testing.T) {
	originalProbe := probeSMBDetailsFunc
	defer func() { probeSMBDetailsFunc = originalProbe }()

	calls := 0
	probeSMBDetailsFunc = func(ctx context.Context, target string, port int, opts SMBProbeOptions) SMBServiceInfo {
		calls++
		return SMBServiceInfo{
			Target:          target,
			Port:            port,
			ProtocolVersion: "smb3",
		}
	}

	module := newSMBNativeProbeModule()
	if err := module.Init("test-smb-native", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.banner.tcp": []any{
			BannerGrabResult{IP: "198.51.100.10", Port: 80, Protocol: "tcp"},
			BannerGrabResult{IP: "198.51.100.10", Port: 445, Protocol: "tcp"},
			BannerGrabResult{IP: "198.51.100.10", Port: 445, Protocol: "tcp"}, // duplicate candidate
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	var outputs []SMBServiceInfo
	for item := range out {
		smb, ok := item.Data.(SMBServiceInfo)
		if !ok {
			continue
		}
		outputs = append(outputs, smb)
	}

	if calls != 1 {
		t.Fatalf("expected 1 probe call, got %d", calls)
	}
	if len(outputs) != 1 {
		t.Fatalf("expected 1 output, got %d", len(outputs))
	}
	if outputs[0].Target != "198.51.100.10" || outputs[0].Port != 445 {
		t.Fatalf("unexpected output target/port: %+v", outputs[0])
	}
}

func TestClassifySMBProbeError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "timeout", err: errors.New("i/o timeout"), want: "timeout"},
		{name: "refused", err: errors.New("connection refused"), want: "refused"},
		{name: "short", err: errors.New("short_negotiate_response"), want: "short_response"},
		{name: "generic", err: errors.New("unexpected"), want: "probe_failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifySMBProbeError(tt.err); got != tt.want {
				t.Fatalf("classifySMBProbeError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPickTopProbeErrorPriority(t *testing.T) {
	errors := []string{"probe_failed", "short_response", "timeout"}
	if got := pickTopProbeError(errors); got != "timeout" {
		t.Fatalf("expected timeout priority, got %q", got)
	}
}
