package scan

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"github.com/stretchr/testify/require"
)

func TestTelnetNativeProbeModuleExecuteFiltersCandidates(t *testing.T) {
	originalProbe := probeTelnetDetailsFunc
	defer func() { probeTelnetDetailsFunc = originalProbe }()

	calls := 0
	probeTelnetDetailsFunc = func(ctx context.Context, target string, port int, opts TelnetProbeOptions) TelnetServiceInfo {
		calls++
		return TelnetServiceInfo{Target: target, Port: port, TelnetProbe: true, TelnetProtocol: "telnet"}
	}

	module := newTelnetNativeProbeModule()
	require.NoError(t, module.Init("test-telnet-native", map[string]any{}))

	inputs := map[string]any{
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: "198.51.100.40", OpenPorts: []int{23, 80}},
		},
		"service.banner.tcp": []any{
			BannerGrabResult{IP: "198.51.100.40", Port: 2323, Protocol: "telnet", Banner: "RouterOS Login:"},
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	require.NoError(t, module.Execute(context.Background(), inputs, out))
	close(out)

	var outputs []TelnetServiceInfo
	for item := range out {
		info, ok := item.Data.(TelnetServiceInfo)
		if !ok {
			continue
		}
		outputs = append(outputs, info)
	}

	require.Equal(t, 2, calls)
	require.Len(t, outputs, 2)
	require.Equal(t, 23, outputs[0].Port)
	require.Equal(t, 2323, outputs[1].Port)
}

func TestIsTelnetBannerCandidate_AllowsStrongTelnetSignalOnNonStandardPort(t *testing.T) {
	require.True(t, isTelnetBannerCandidate(BannerGrabResult{
		IP:       "198.51.100.40",
		Port:     9000,
		Protocol: "telnet",
		Banner:   "",
	}, nil))

	require.True(t, isTelnetBannerCandidate(BannerGrabResult{
		IP:       "198.51.100.40",
		Port:     9000,
		Protocol: "",
		Banner:   "BusyBox telnetd\r\nlogin:",
	}, nil))

	require.False(t, isTelnetBannerCandidate(BannerGrabResult{
		IP:       "198.51.100.40",
		Port:     9000,
		Protocol: "",
		Banner:   "HELLO FROM CUSTOM TCP SERVICE",
	}, nil))
}

func TestProbeTelnetDetails_IACNegotiationConfirmsService(t *testing.T) {
	host, port, cleanup := startTelnetIACServer(t, []byte{
		telnetCommandIAC, telnetCommandWILL, 1,
		telnetCommandIAC, telnetCommandDO, 3,
		'W', 'e', 'l', 'c', 'o', 'm', 'e', ' ', 't', 'o', ' ', 'R', 'o', 'u', 't', 'e', 'r', 'O', 'S', '\r', '\n',
		'l', 'o', 'g', 'i', 'n', ':',
	})
	defer cleanup()

	result := probeTelnetDetails(context.Background(), host, port, defaultTelnetProbeOptions())

	require.True(t, result.TelnetProbe)
	require.Equal(t, "telnet", result.TelnetProtocol)
	require.True(t, result.IACDetected)
	require.Equal(t, []string{"do-suppress-go-ahead", "will-echo"}, result.NegotiationOptions)
	require.Contains(t, result.Banner, "RouterOS")
	require.Equal(t, "RouterOS Telnet", result.ProductHint)
	require.Equal(t, "MikroTik", result.VendorHint)
	require.Empty(t, result.ProbeError)
	require.Len(t, result.Attempts, 1)
	require.True(t, result.Attempts[0].Success)
}

func TestProbeTelnetDetails_LoginPromptWithoutIACIsPartialConfirmation(t *testing.T) {
	host, port, cleanup := startTelnetIACServer(t, []byte("BusyBox telnetd\r\nlogin:"))
	defer cleanup()

	result := probeTelnetDetails(context.Background(), host, port, defaultTelnetProbeOptions())

	require.True(t, result.TelnetProbe)
	require.False(t, result.IACDetected)
	require.Contains(t, result.Banner, "BusyBox")
	require.Equal(t, "BusyBox telnetd", result.ProductHint)
	require.Equal(t, "BusyBox", result.VendorHint)
	require.Empty(t, result.ProbeError)
}

func TestProbeTelnetDetails_NonTelnetPayloadIsProtocolMismatch(t *testing.T) {
	host, port, cleanup := startTelnetIACServer(t, []byte("HELLO FROM CUSTOM TCP SERVICE"))
	defer cleanup()

	result := probeTelnetDetails(context.Background(), host, port, defaultTelnetProbeOptions())

	require.False(t, result.TelnetProbe)
	require.Equal(t, "protocol_mismatch", result.ProbeError)
	require.Len(t, result.Attempts, 1)
	require.False(t, result.Attempts[0].Success)
	require.Equal(t, "protocol_mismatch", result.Attempts[0].Error)
}

func TestProbeTelnetDetails_Timeout(t *testing.T) {
	host, port, cleanup := startTelnetSilentServer(t)
	defer cleanup()

	result := probeTelnetDetails(context.Background(), host, port, TelnetProbeOptions{
		TotalTimeout:   1500 * time.Millisecond,
		ConnectTimeout: 300 * time.Millisecond,
		IOTimeout:      200 * time.Millisecond,
		Retries:        0,
	})

	require.False(t, result.TelnetProbe)
	require.Equal(t, "timeout", result.ProbeError)
	require.Len(t, result.Attempts, 1)
	require.Equal(t, "timeout", result.Attempts[0].Error)
}

func startTelnetIACServer(t *testing.T, payload []byte) (string, int, func()) {
	t.Helper()

	ln := mustListenTCP(t, "127.0.0.1:0")
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn.Write(payload)
			}(conn)
		}
	}()

	host, port, err := splitHostPort(ln.Addr().String())
	require.NoError(t, err)
	return host, port, func() {
		_ = ln.Close()
		<-done
	}
}

func startTelnetSilentServer(t *testing.T) (string, int, func()) {
	t.Helper()

	ln := mustListenTCP(t, "127.0.0.1:0")
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				time.Sleep(500 * time.Millisecond)
			}(conn)
		}
	}()

	host, port, err := splitHostPort(ln.Addr().String())
	require.NoError(t, err)
	return host, port, func() {
		_ = ln.Close()
		<-done
	}
}
