package scan

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"github.com/stretchr/testify/require"
)

func TestFTPNativeProbeModule_ExecuteFiltersCandidates(t *testing.T) {
	originalProbe := probeFTPDetailsFunc
	defer func() { probeFTPDetailsFunc = originalProbe }()

	calls := 0
	probeFTPDetailsFunc = func(ctx context.Context, target string, hostname string, port int, protocolHint string, opts FTPProbeOptions) FTPServiceInfo {
		calls++
		return FTPServiceInfo{
			Target:      target,
			Port:        port,
			FTPProbe:    true,
			FTPProtocol: ftpProtocolFromPort(port),
		}
	}

	module := newFTPNativeProbeModule()
	require.NoError(t, module.Init("test-ftp-native", map[string]any{}))

	inputs := map[string]any{
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: "198.51.100.60", OpenPorts: []int{21, 80}},
		},
		"service.banner.tcp": []any{
			BannerGrabResult{IP: "198.51.100.60", Port: 2121, Protocol: "ftp", Banner: "220 CrushFTP Server Ready!"},
			BannerGrabResult{IP: "198.51.100.60", Port: 2121, Protocol: "ftp", Banner: "220 CrushFTP Server Ready!"},
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	require.NoError(t, module.Execute(context.Background(), inputs, out))
	close(out)

	var outputs []FTPServiceInfo
	for item := range out {
		info, ok := item.Data.(FTPServiceInfo)
		if !ok {
			continue
		}
		outputs = append(outputs, info)
	}

	require.Equal(t, 2, calls)
	require.Len(t, outputs, 2)
}

func TestProbeFTPDetails_PlainExplicitTLS(t *testing.T) {
	host, port, cleanup := startFTPExplicitTLSTestServer(t, "ftp.test")
	defer cleanup()

	result := probeFTPDetails(context.Background(), host, "ftp.test", port, "ftp", FTPProbeOptions{
		TotalTimeout:   2500 * time.Millisecond,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
	})

	require.True(t, result.FTPProbe)
	require.Equal(t, "ftps", result.FTPProtocol)
	require.Equal(t, 220, result.GreetingCode)
	require.Equal(t, "CrushFTP", result.SoftwareHint)
	require.Equal(t, "CrushFTP, LLC", result.VendorHint)
	require.Contains(t, result.Features, "AUTH TLS")
	require.True(t, result.AuthTLSSupported)
	require.True(t, result.TLSEnabled)
	require.Equal(t, "ftp.test", result.CertSubjectCN)
	require.Equal(t, "UNIX Type: L8", result.SystemHint)
	require.Empty(t, result.ProbeError)
	require.Len(t, result.Attempts, 4)
	require.Equal(t, "ftp-auth-tls", result.Attempts[3].Strategy)
	require.True(t, result.Attempts[3].Success)
}

func TestProbeFTPDetails_ImplicitFTPS(t *testing.T) {
	host, port, cleanup := startFTPImplicitTLSTestServer(t, "ftps.test")
	defer cleanup()

	result := probeFTPDetails(context.Background(), host, "ftps.test", port, "ftps", FTPProbeOptions{
		TotalTimeout:   2500 * time.Millisecond,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
	})

	require.True(t, result.FTPProbe)
	require.Equal(t, "ftps", result.FTPProtocol)
	require.True(t, result.TLSEnabled)
	require.Equal(t, "ftps.test", result.CertSubjectCN)
	require.Equal(t, "FileZilla Server", result.SoftwareHint)
	require.Equal(t, "FileZilla Project", result.VendorHint)
	require.Equal(t, "1.9.4", result.VersionHint)
	require.Contains(t, result.Features, "UTF8")
	require.NotContains(t, result.Features, "Features:")
	require.NotContains(t, result.Features, "End")
	require.Equal(t, "UNIX Type: L8", result.SystemHint)
	require.Empty(t, result.ProbeError)
}

func TestParseFTPFeatures_SkipsGenericPreambleAndFooter(t *testing.T) {
	features := parseFTPFeatures(ftpResponse{
		Code: 211,
		Lines: []string{
			"211-Extensions supported:",
			" AUTH TLS",
			" UTF8",
			"211-Features:",
			" MDTM",
			"211 Features",
			" End",
			"211 End",
		},
	})

	require.Equal(t, []string{"AUTH TLS", "UTF8", "MDTM"}, features)
}

func TestProbeFTPDetails_PartialSuccess(t *testing.T) {
	host, port, cleanup := startFTPPartialTestServer(t)
	defer cleanup()

	result := probeFTPDetails(context.Background(), host, "", port, "ftp", FTPProbeOptions{
		TotalTimeout:   2 * time.Second,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
	})

	require.True(t, result.FTPProbe)
	require.Equal(t, 220, result.GreetingCode)
	require.Equal(t, "UNIX Type: L8", result.SystemHint)
	require.Empty(t, result.Features)
	require.False(t, result.TLSEnabled)
	require.Empty(t, result.ProbeError)
}

func TestProbeFTPDetails_ImplicitFTPS_FEATTimeoutSetsPartialError(t *testing.T) {
	host, port, cleanup := startFTPImplicitTLSFEATTimeoutServer(t, "ftps-timeout.test")
	defer cleanup()

	result := probeFTPDetails(context.Background(), host, "ftps-timeout.test", port, "ftps", FTPProbeOptions{
		TotalTimeout:   2500 * time.Millisecond,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      250 * time.Millisecond,
	})

	require.True(t, result.FTPProbe)
	require.True(t, result.TLSEnabled)
	require.Equal(t, "timeout", result.ProbeError)
	require.Len(t, result.Attempts, 3)
	require.Equal(t, "ftp-feat", result.Attempts[1].Strategy)
	require.Equal(t, "timeout", result.Attempts[1].Error)
	require.Equal(t, "ftp-syst", result.Attempts[2].Strategy)
}

func TestProbeFTPDetails_ImplicitFTPS_SYSTFailureSetsPartialError(t *testing.T) {
	host, port, cleanup := startFTPImplicitTLSSYSTEOFFailureServer(t, "ftps-syst.test")
	defer cleanup()

	result := probeFTPDetails(context.Background(), host, "ftps-syst.test", port, "ftps", FTPProbeOptions{
		TotalTimeout:   2500 * time.Millisecond,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
	})

	require.True(t, result.FTPProbe)
	require.True(t, result.TLSEnabled)
	require.Equal(t, "banner_read_failed", result.ProbeError)
	require.Len(t, result.Attempts, 3)
	require.Equal(t, "ftp-feat", result.Attempts[1].Strategy)
	require.True(t, result.Attempts[1].Success)
	require.Equal(t, "ftp-syst", result.Attempts[2].Strategy)
	require.Equal(t, "banner_read_failed", result.Attempts[2].Error)
}

func TestClassifyFTPErrors(t *testing.T) {
	require.Equal(t, "timeout", classifyFTPConnectError(os.ErrDeadlineExceeded))
	require.Equal(t, "banner_read_failed", classifyFTPBannerError(io.EOF))
	require.Equal(t, "protocol_mismatch", classifyFTPBannerError(ioError("protocol_mismatch")))
	require.Equal(t, "tls_handshake_failed", classifyFTPTLSError(ioError("tls: handshake failure")))
	require.Equal(t, "connect_failed", classifyFTPTLSError(ioError("connection refused")))
}

func startFTPExplicitTLSTestServer(t *testing.T, serverName string) (string, int, func()) {
	t.Helper()

	ln := mustListenTCP(t, "127.0.0.1:0")
	tlsConfig := mustSelfSignedTLSConfig(t, serverName)
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
				reader := bufio.NewReader(conn)
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = io.WriteString(conn, "220-Welcome to CrushFTP!\r\n220 CrushFTP Server Ready!\r\n")
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(strings.ToUpper(line), "FEAT"):
						_, _ = io.WriteString(conn, "211-Extensions supported:\r\n AUTH TLS\r\n UTF8\r\n211 End\r\n")
					case strings.HasPrefix(strings.ToUpper(line), "SYST"):
						_, _ = io.WriteString(conn, "215 UNIX Type: L8\r\n")
					case strings.HasPrefix(strings.ToUpper(line), "AUTH TLS"):
						_, _ = io.WriteString(conn, "234 AUTH TLS successful\r\n")
						tlsConn := tls.Server(conn, tlsConfig)
						if err := tlsConn.Handshake(); err != nil {
							return
						}
						conn = tlsConn
						reader = bufio.NewReader(tlsConn)
					default:
						_, _ = io.WriteString(conn, "500 Unknown command\r\n")
					}
				}
			}(conn)
		}
	}()

	addr := ln.Addr().String()
	host, port, err := splitHostPort(addr)
	require.NoError(t, err)
	return host, port, func() {
		_ = ln.Close()
		<-done
	}
}

func startFTPImplicitTLSTestServer(t *testing.T, serverName string) (string, int, func()) {
	t.Helper()

	ln := mustListenTCP(t, "127.0.0.1:0")
	tlsConfig := mustSelfSignedTLSConfig(t, serverName)
	tlsListener := tls.NewListener(ln, tlsConfig)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = io.WriteString(conn, "220 FileZilla Server 1.9.4 ready\r\n")
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(strings.ToUpper(line), "FEAT"):
						_, _ = io.WriteString(conn, "211-Features:\r\n UTF8\r\n MDTM\r\n211 End\r\n")
					case strings.HasPrefix(strings.ToUpper(line), "SYST"):
						_, _ = io.WriteString(conn, "215 UNIX Type: L8\r\n")
					default:
						_, _ = io.WriteString(conn, "500 Unknown command\r\n")
					}
				}
			}(conn)
		}
	}()

	addr := ln.Addr().String()
	host, port, err := splitHostPort(addr)
	require.NoError(t, err)
	return host, port, func() {
		_ = tlsListener.Close()
		<-done
	}
}

func startFTPImplicitTLSFEATTimeoutServer(t *testing.T, serverName string) (string, int, func()) {
	t.Helper()

	ln := mustListenTCP(t, "127.0.0.1:0")
	tlsConfig := mustSelfSignedTLSConfig(t, serverName)
	tlsListener := tls.NewListener(ln, tlsConfig)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				_, _ = io.WriteString(conn, "220 FileZilla Server 1.9.4 ready\r\n")
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(strings.ToUpper(line), "FEAT"):
						time.Sleep(600 * time.Millisecond)
					case strings.HasPrefix(strings.ToUpper(line), "SYST"):
						_, _ = io.WriteString(conn, "215 UNIX Type: L8\r\n")
					default:
						_, _ = io.WriteString(conn, "500 Unknown command\r\n")
					}
				}
			}(conn)
		}
	}()

	addr := ln.Addr().String()
	host, port, err := splitHostPort(addr)
	require.NoError(t, err)
	return host, port, func() {
		_ = tlsListener.Close()
		<-done
	}
}

func startFTPImplicitTLSSYSTEOFFailureServer(t *testing.T, serverName string) (string, int, func()) {
	t.Helper()

	ln := mustListenTCP(t, "127.0.0.1:0")
	tlsConfig := mustSelfSignedTLSConfig(t, serverName)
	tlsListener := tls.NewListener(ln, tlsConfig)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				_, _ = io.WriteString(conn, "220 FileZilla Server 1.9.4 ready\r\n")
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(strings.ToUpper(line), "FEAT"):
						_, _ = io.WriteString(conn, "211-Features:\r\n UTF8\r\n211 End\r\n")
					case strings.HasPrefix(strings.ToUpper(line), "SYST"):
						return
					default:
						_, _ = io.WriteString(conn, "500 Unknown command\r\n")
					}
				}
			}(conn)
		}
	}()

	addr := ln.Addr().String()
	host, port, err := splitHostPort(addr)
	require.NoError(t, err)
	return host, port, func() {
		_ = tlsListener.Close()
		<-done
	}
}

func startFTPPartialTestServer(t *testing.T) (string, int, func()) {
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
				reader := bufio.NewReader(conn)
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = io.WriteString(conn, "220 Welcome to test ftp\r\n")
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(strings.ToUpper(line), "FEAT"):
						_, _ = io.WriteString(conn, "500 FEAT not understood\r\n")
					case strings.HasPrefix(strings.ToUpper(line), "SYST"):
						_, _ = io.WriteString(conn, "215 UNIX Type: L8\r\n")
					default:
						_, _ = io.WriteString(conn, "500 Unknown command\r\n")
					}
				}
			}(conn)
		}
	}()

	addr := ln.Addr().String()
	host, port, err := splitHostPort(addr)
	require.NoError(t, err)
	return host, port, func() {
		_ = ln.Close()
		<-done
	}
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func ioError(msg string) error {
	return &net.OpError{Err: errorString(msg)}
}

type errorString string

func (e errorString) Error() string {
	return string(e)
}
