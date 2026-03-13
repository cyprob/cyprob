package scan

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"github.com/stretchr/testify/require"
)

func TestMySQLNativeProbeModuleExecuteFiltersCandidates(t *testing.T) {
	originalProbe := probeMySQLDetailsFunc
	defer func() { probeMySQLDetailsFunc = originalProbe }()

	calls := 0
	probeMySQLDetailsFunc = func(ctx context.Context, target string, hostname string, port int, opts MySQLProbeOptions) MySQLServiceInfo {
		calls++
		return MySQLServiceInfo{Target: target, Port: port, MySQLProbe: true}
	}

	module := newMySQLNativeProbeModule()
	require.NoError(t, module.Init("test-mysql-native", map[string]any{}))

	inputs := map[string]any{
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: "198.51.100.70", OpenPorts: []int{80, 3306, 33060}},
		},
		"service.banner.tcp": []any{
			BannerGrabResult{IP: "198.51.100.70", Port: 3307, Protocol: "mysql", Banner: "5.7.44-MySQL"},
		},
	}

	out := make(chan engine.ModuleOutput, 4)
	require.NoError(t, module.Execute(context.Background(), inputs, out))
	close(out)

	var outputs []MySQLServiceInfo
	for item := range out {
		info, ok := item.Data.(MySQLServiceInfo)
		if !ok {
			continue
		}
		outputs = append(outputs, info)
	}

	require.Equal(t, 1, calls)
	require.Len(t, outputs, 1)
	require.Equal(t, 3306, outputs[0].Port)
}

func TestProbeMySQLDetails_HandshakeAndTLS(t *testing.T) {
	host, port, cleanup := startMySQLHandshakeTestServer(t, mysqlTestServerConfig{
		ServerName:    "mysql.test",
		ServerVersion: "8.0.36-MySQL Community Server",
		SupportSSL:    true,
		TLSSuccess:    true,
	})
	defer cleanup()

	result := probeMySQLDetails(context.Background(), host, "mysql.test", port, MySQLProbeOptions{
		TotalTimeout:   2500 * time.Millisecond,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
	})

	require.True(t, result.MySQLProbe)
	require.Equal(t, "handshake", result.GreetingKind)
	require.Equal(t, 10, result.ProtocolVersion)
	require.Equal(t, "8.0.36-MySQL Community Server", result.ServerVersion)
	require.Equal(t, uint32(1234), result.ConnectionID)
	require.Equal(t, "caching_sha2_password", result.AuthPluginName)
	require.True(t, result.TLSSupported)
	require.True(t, result.TLSEnabled)
	require.Equal(t, "mysql.test", result.CertSubjectCN)
	require.Equal(t, "MySQL", result.ProductHint)
	require.Equal(t, "Oracle", result.VendorHint)
	require.Equal(t, "8.0.36", result.VersionHint)
	require.Empty(t, result.ProbeError)
	require.Len(t, result.Attempts, 2)
	require.True(t, result.Attempts[0].Success)
	require.True(t, result.Attempts[1].Success)
}

func TestProbeMySQLDetails_ErrorPacketIsNativeConfirmation(t *testing.T) {
	host, port, cleanup := startMySQLErrorPacketTestServer(t)
	defer cleanup()

	result := probeMySQLDetails(context.Background(), host, "", port, defaultMySQLProbeOptions())

	require.True(t, result.MySQLProbe)
	require.Equal(t, "err_packet", result.GreetingKind)
	require.Empty(t, result.ProbeError)
	require.Len(t, result.Attempts, 1)
	require.True(t, result.Attempts[0].Success)
}

func TestProbeMySQLDetails_InvalidErrorPacketDoesNotConfirm(t *testing.T) {
	host, port, cleanup := startMySQLInvalidErrorPacketTestServer(t)
	defer cleanup()

	result := probeMySQLDetails(context.Background(), host, "", port, defaultMySQLProbeOptions())

	require.False(t, result.MySQLProbe)
	require.Equal(t, "protocol_mismatch", result.ProbeError)
	require.Len(t, result.Attempts, 1)
	require.False(t, result.Attempts[0].Success)
	require.Equal(t, "protocol_mismatch", result.Attempts[0].Error)
}

func TestProbeMySQLDetails_PlainTextBannerDoesNotConfirm(t *testing.T) {
	host, port, cleanup := startMySQLPlainTextBannerTestServer(t)
	defer cleanup()

	result := probeMySQLDetails(context.Background(), host, "", port, defaultMySQLProbeOptions())

	require.False(t, result.MySQLProbe)
	require.Equal(t, "protocol_mismatch", result.ProbeError)
	require.Len(t, result.Attempts, 1)
	require.False(t, result.Attempts[0].Success)
	require.Equal(t, "protocol_mismatch", result.Attempts[0].Error)
}

func TestProbeMySQLDetails_TLSFailureIsPartialError(t *testing.T) {
	host, port, cleanup := startMySQLHandshakeTestServer(t, mysqlTestServerConfig{
		ServerName:    "mysql-fail.test",
		ServerVersion: "8.0.36-MySQL Community Server",
		SupportSSL:    true,
		TLSFailure:    true,
	})
	defer cleanup()

	result := probeMySQLDetails(context.Background(), host, "mysql-fail.test", port, defaultMySQLProbeOptions())

	require.True(t, result.MySQLProbe)
	require.Equal(t, "handshake", result.GreetingKind)
	require.True(t, result.TLSSupported)
	require.False(t, result.TLSEnabled)
	require.Equal(t, "tls_handshake_failed", result.ProbeError)
	require.Len(t, result.Attempts, 2)
	require.Equal(t, "mysql-starttls", result.Attempts[1].Strategy)
	require.Equal(t, "tls_handshake_failed", result.Attempts[1].Error)
}

type mysqlTestServerConfig struct {
	ServerName    string
	ServerVersion string
	SupportSSL    bool
	TLSSuccess    bool
	TLSFailure    bool
}

func startMySQLHandshakeTestServer(t *testing.T, cfg mysqlTestServerConfig) (string, int, func()) {
	t.Helper()

	ln := mustListenTCP(t, "127.0.0.1:0")
	var tlsConfig *tls.Config
	if cfg.SupportSSL && cfg.TLSSuccess {
		tlsConfig = mustSelfSignedTLSConfig(t, cfg.ServerName)
	}
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
				_, _ = conn.Write(buildMySQLPacket(0, buildMySQLHandshakePayload(cfg.ServerVersion, cfg.SupportSSL, "caching_sha2_password")))
				if !cfg.SupportSSL {
					return
				}

				header := make([]byte, 4)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				payloadLength := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
				if payloadLength <= 0 || payloadLength > mysqlPacketMaxPayloadSize {
					return
				}
				payload := make([]byte, payloadLength)
				if _, err := io.ReadFull(conn, payload); err != nil {
					return
				}

				if cfg.TLSFailure {
					return
				}
				if tlsConfig == nil {
					return
				}

				tlsConn := tls.Server(conn, tlsConfig)
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				_ = tlsConn.Close()
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

func startMySQLInvalidErrorPacketTestServer(t *testing.T) (string, int, func()) {
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
				_, _ = conn.Write(buildMySQLPacket(0, []byte{0xff, 0x01, 0x00, '#', 'H', 'Y', '0', '0', '0'}))
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

func startMySQLErrorPacketTestServer(t *testing.T) (string, int, func()) {
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
				_, _ = conn.Write(buildMySQLPacket(0, buildMySQLErrorPayload(1130, "HY000", "Host '198.51.100.1' is not allowed to connect to this MySQL server")))
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

func startMySQLPlainTextBannerTestServer(t *testing.T) (string, int, func()) {
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
				_, _ = io.WriteString(conn, "Host '198.51.100.1' is not allowed to connect to this MySQL server")
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

func buildMySQLPacket(sequenceID byte, payload []byte) []byte {
	frame := make([]byte, 4+len(payload))
	frame[0] = byte(len(payload))
	frame[1] = byte(len(payload) >> 8)
	frame[2] = byte(len(payload) >> 16)
	frame[3] = sequenceID
	copy(frame[4:], payload)
	return frame
}

func buildMySQLHandshakePayload(serverVersion string, supportSSL bool, authPlugin string) []byte {
	if strings.TrimSpace(serverVersion) == "" {
		serverVersion = "8.0.36-MySQL Community Server"
	}
	if strings.TrimSpace(authPlugin) == "" {
		authPlugin = "caching_sha2_password"
	}

	capabilities := uint32(mysqlCapabilityProtocol41 | mysqlCapabilitySecureConnection | mysqlCapabilityPluginAuth)
	if supportSSL {
		capabilities |= mysqlCapabilitySSL
	}

	authDataPart1 := []byte("12345678")
	authDataPart2 := []byte("abcdefghijklmn")
	authPluginLen := len(authDataPart1) + len(authDataPart2) + 1

	payload := make([]byte, 0, 128)
	payload = append(payload, 0x0a)
	payload = append(payload, []byte(serverVersion)...)
	payload = append(payload, 0x00)

	connectionID := make([]byte, 4)
	binary.LittleEndian.PutUint32(connectionID, 1234)
	payload = append(payload, connectionID...)
	payload = append(payload, authDataPart1...)
	payload = append(payload, 0x00)

	lowerCaps := make([]byte, 2)
	binary.LittleEndian.PutUint16(lowerCaps, uint16(capabilities))
	payload = append(payload, lowerCaps...)
	payload = append(payload, 0x21)

	statusFlags := make([]byte, 2)
	binary.LittleEndian.PutUint16(statusFlags, 0x0002)
	payload = append(payload, statusFlags...)

	upperCaps := make([]byte, 2)
	binary.LittleEndian.PutUint16(upperCaps, uint16(capabilities>>16))
	payload = append(payload, upperCaps...)
	payload = append(payload, byte(authPluginLen))
	payload = append(payload, make([]byte, 10)...)
	payload = append(payload, authDataPart2...)
	payload = append(payload, 0x00)
	payload = append(payload, []byte(authPlugin)...)
	payload = append(payload, 0x00)
	return payload
}

func buildMySQLErrorPayload(code uint16, sqlState string, message string) []byte {
	if strings.TrimSpace(sqlState) == "" {
		sqlState = "HY000"
	}
	if len(sqlState) < 5 {
		sqlState += strings.Repeat("0", 5-len(sqlState))
	}
	if len(sqlState) > 5 {
		sqlState = sqlState[:5]
	}

	payload := []byte{0xff, 0x00, 0x00}
	binary.LittleEndian.PutUint16(payload[1:3], code)
	payload = append(payload, '#')
	payload = append(payload, []byte(sqlState)...)
	payload = append(payload, []byte(message)...)
	return payload
}
