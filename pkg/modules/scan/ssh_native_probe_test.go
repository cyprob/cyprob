package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

func TestSSHNativeProbeModule_ExecuteFiltersCandidates(t *testing.T) {
	originalProbe := probeSSHDetailsFunc
	defer func() { probeSSHDetailsFunc = originalProbe }()

	calls := 0
	probeSSHDetailsFunc = func(ctx context.Context, target string, port int, opts SSHProbeOptions) SSHServiceInfo {
		calls++
		return SSHServiceInfo{
			Target:      target,
			Port:        port,
			SSHProbe:    true,
			SSHBanner:   "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.8",
			SSHProtocol: "2.0",
			SSHSoftware: "OpenSSH",
			SSHVersion:  "9.6p1",
		}
	}

	module := newSSHNativeProbeModule()
	if err := module.Init("test-ssh-native", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: "198.51.100.10", OpenPorts: []int{22, 443}},
		},
		"service.banner.tcp": []any{
			BannerGrabResult{IP: "198.51.100.10", Port: 2222, Protocol: "ssh"},
			BannerGrabResult{IP: "198.51.100.10", Port: 2222, Protocol: "ssh"}, // duplicate
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	var outputs []SSHServiceInfo
	for item := range out {
		info, ok := item.Data.(SSHServiceInfo)
		if !ok {
			continue
		}
		outputs = append(outputs, info)
	}

	if calls != 2 {
		t.Fatalf("expected 2 probe calls, got %d", calls)
	}
	if len(outputs) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(outputs))
	}
}

func TestSSHNativeProbeModule_ExecuteHonorsExplicitCandidatePorts(t *testing.T) {
	originalProbe := probeSSHDetailsFunc
	defer func() { probeSSHDetailsFunc = originalProbe }()

	calls := 0
	probeSSHDetailsFunc = func(ctx context.Context, target string, port int, opts SSHProbeOptions) SSHServiceInfo {
		calls++
		return SSHServiceInfo{Target: target, Port: port, SSHProbe: true}
	}

	module := newSSHNativeProbeModule()
	if err := module.Init("test-ssh-native-explicit-port", map[string]any{
		"candidate_ports": []int{2222},
	}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: "198.51.100.20", OpenPorts: []int{2222, 8080}},
		},
	}

	out := make(chan engine.ModuleOutput, 4)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	if calls != 1 {
		t.Fatalf("expected 1 explicit candidate probe call, got %d", calls)
	}
}

func TestParseSSHBannerLine(t *testing.T) {
	protocol, software, version, err := parseSSHBannerLine("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
	if err != nil {
		t.Fatalf("parseSSHBannerLine returned error: %v", err)
	}
	if protocol != "2.0" {
		t.Fatalf("expected protocol 2.0, got %q", protocol)
	}
	if software != "OpenSSH" {
		t.Fatalf("expected software OpenSSH, got %q", software)
	}
	if version != "8.9p1" {
		t.Fatalf("expected version 8.9p1, got %q", version)
	}
}

func TestParseSSHBannerLine_OpaqueSoftwareToken(t *testing.T) {
	protocol, software, version, err := parseSSHBannerLine("SSH-2.0-a73f77f")
	if err != nil {
		t.Fatalf("parseSSHBannerLine returned error: %v", err)
	}
	if protocol != "2.0" {
		t.Fatalf("expected protocol 2.0, got %q", protocol)
	}
	if software != "" {
		t.Fatalf("expected empty software for opaque token, got %q", software)
	}
	if version != "" {
		t.Fatalf("expected empty version for opaque token, got %q", version)
	}
}

func TestParseSSHKEXInitPayload(t *testing.T) {
	payload := buildTestSSHKEXInitPayload(
		"curve25519-sha256,diffie-hellman-group1-sha1",
		"ssh-ed25519,rsa-sha2-256",
		"chacha20-poly1305@openssh.com,aes128-ctr",
		"aes128-ctr,3des-cbc",
		"hmac-sha2-256,hmac-md5",
		"hmac-sha2-256",
	)

	kexAlgorithms, hostKeyAlgorithms, ciphers, macs, err := parseSSHKEXInitPayload(payload)
	if err != nil {
		t.Fatalf("parseSSHKEXInitPayload returned error: %v", err)
	}

	if len(kexAlgorithms) != 2 || kexAlgorithms[1] != "diffie-hellman-group1-sha1" {
		t.Fatalf("unexpected kex algorithms: %+v", kexAlgorithms)
	}
	if len(hostKeyAlgorithms) != 2 || hostKeyAlgorithms[0] != "ssh-ed25519" {
		t.Fatalf("unexpected host key algorithms: %+v", hostKeyAlgorithms)
	}
	if len(ciphers) != 3 {
		t.Fatalf("expected merged cipher list, got %+v", ciphers)
	}
	if len(macs) != 2 {
		t.Fatalf("expected merged mac list, got %+v", macs)
	}
}

func TestSSHWeakSignals(t *testing.T) {
	if !isWeakSSHProtocol("1.5") {
		t.Fatalf("expected SSH-1.5 to be weak")
	}
	if isWeakSSHProtocol("1.99") {
		t.Fatalf("expected SSH-1.99 to not be weak")
	}
	if !hasWeakSSHKEX([]string{"curve25519-sha256", "diffie-hellman-group1-sha1"}) {
		t.Fatalf("expected weak kex detection")
	}
	if !hasWeakSSHCipherPreference([]string{"3des-cbc", "aes128-cbc"}) {
		t.Fatalf("expected weak cipher dominance")
	}
	if hasWeakSSHCipherPreference([]string{"chacha20-poly1305@openssh.com", "aes128-ctr", "aes256-ctr", "3des-cbc"}) {
		t.Fatalf("expected modern cipher set to stay strong")
	}
	if !hasWeakSSHMAC([]string{"hmac-sha2-256", "hmac-md5"}) {
		t.Fatalf("expected weak mac detection")
	}
}

func TestClassifySSHProbeError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "timeout", err: errors.New("i/o timeout"), want: "timeout"},
		{name: "refused", err: errors.New("connection refused"), want: "refused"},
		{name: "no banner", err: errors.New("no_banner"), want: "no_banner"},
		{name: "protocol", err: errors.New("protocol_error"), want: "protocol_error"},
		{name: "kex", err: errors.New("kex_parse_failed"), want: "kex_parse_failed"},
		{name: "generic", err: errors.New("unexpected"), want: "probe_failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifySSHProbeError(tt.err); got != tt.want {
				t.Fatalf("classifySSHProbeError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPickTopSSHProbeErrorPriority(t *testing.T) {
	codes := []string{"probe_failed", "kex_parse_failed", "timeout"}
	if got := pickTopSSHProbeError(codes); got != "timeout" {
		t.Fatalf("expected timeout priority, got %q", got)
	}
}

func buildTestSSHKEXInitPayload(kex, hostKeys, encCTS, encSTC, macCTS, macSTC string) []byte {
	payload := make([]byte, 0, 256)
	payload = append(payload, byte(sshKEXInitMessageType))
	payload = append(payload, []byte("test-kex-cookie1")...)
	for _, list := range []string{
		kex,
		hostKeys,
		encCTS,
		encSTC,
		macCTS,
		macSTC,
		"none",
		"none",
		"",
		"",
	} {
		payload = appendSSHNameList(payload, list)
	}
	payload = append(payload, 0x00)
	payload = append(payload, 0x00, 0x00, 0x00, 0x00)
	return payload
}
