package scan

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

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
			if got := classifySMBProbeError(tt.err); string(got) != tt.want {
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

// The NetBIOS session response is one byte, and the difference between two of
// its values is the difference between a peer verdict and a frame we could not
// read. 0x83 is NEGATIVE SESSION RESPONSE -- the far end read our called name
// and refused it -- and it is the only value that earns the rejected bucket.
// 0x84 RETARGET is not a refusal, and a byte that is no NetBIOS session type at
// all is not something we read; both keep falling to probe_failed.
//
// This test exists because the split is invisible from the classifier: feeding
// classifySMBProbeError the right strings passes whether or not the emitter
// distinguishes the bytes. Reverting the split left the rest of the suite green.
func TestNetBIOSSessionResponse_OnlyANegativeResponseIsARefusal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		firstByte byte
		wantErr   bool
		wantCode  ProbeCode
	}{
		{name: "positive session response", firstByte: 0x82, wantErr: false},
		{name: "negative session response", firstByte: 0x83, wantErr: true, wantCode: ProbeCodeNetBIOSSessionRejected},
		{name: "retarget is not a refusal", firstByte: 0x84, wantErr: true, wantCode: ProbeCodeProbeFailed},
		{name: "not a session type at all", firstByte: 0x00, wantErr: true, wantCode: ProbeCodeProbeFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, server := net.Pipe()
			t.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
			})
			go func() {
				_ = server.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = server.Write([]byte{tt.firstByte, 0x00, 0x00, 0x00})
			}()

			err := readAndValidateNetBIOSSessionResponse(client)
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("first byte 0x%02x: unexpected error %v", tt.firstByte, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("first byte 0x%02x: expected an error and got none", tt.firstByte)
			}
			if got := classifySMBProbeError(err); got != tt.wantCode {
				t.Fatalf("first byte 0x%02x produced %q, which classifies as %q; want %q",
					tt.firstByte, err, got, tt.wantCode)
			}
		})
	}
}
