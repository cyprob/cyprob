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

func TestIsFTPBannerCandidate_IgnoresFailedFallbackEvidenceOnNonFTPPort(t *testing.T) {
	candidate := BannerGrabResult{
		IP:       "198.51.100.77",
		Port:     3389,
		Protocol: "tcp",
		Banner:   "",
		Evidence: []engine.ProbeObservation{
			{
				ProbeID:     "ftp-feat",
				Protocol:    "ftp",
				Description: "Active FTP FEAT probe",
				Response:    "",
				Error:       "timeout",
			},
		},
	}

	require.False(t, isFTPBannerCandidate(candidate, nil))
}

func TestIsFTPBannerCandidate_AcceptsFallbackEvidenceWithActualFTPResponse(t *testing.T) {
	candidate := BannerGrabResult{
		IP:       "198.51.100.78",
		Port:     2121,
		Protocol: "tcp",
		Banner:   "",
		Evidence: []engine.ProbeObservation{
			{
				ProbeID:     "ftp-feat",
				Protocol:    "ftp",
				Description: "Active FTP FEAT probe",
				Response:    "211-Extensions supported:\r\n UTF8\r\n211 End\r\n",
			},
		},
	}

	require.True(t, isFTPBannerCandidate(candidate, nil))
}

func TestMapEvidenceLooksLikeFTP_RequiresObservedFTPResponse(t *testing.T) {
	require.False(t, mapEvidenceLooksLikeFTP([]any{
		map[string]any{
			"probe_id":    "ftp-feat",
			"protocol":    "ftp",
			"description": "Active FTP FEAT probe",
			"response":    "",
			"error":       "timeout",
		},
	}))

	require.True(t, mapEvidenceLooksLikeFTP([]any{
		map[string]any{
			"probe_id":    "ftp-feat",
			"protocol":    "ftp",
			"description": "Active FTP FEAT probe",
			"response":    "220 FTP Server Ready",
		},
	}))
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
	require.Equal(t, testCertSerialFormatted, result.CertSerial, "cyprob#303: the serial is read but never emitted")
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
	require.Equal(t, testCertSerialFormatted, result.CertSerial, "cyprob#303: implicit TLS reads the same certificate")
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

	require.False(t, result.FTPProbe,
		"ftp_probe answers whether the probe succeeded, and this one reported timeout (cyprob#365)")
	require.NotEmpty(t, result.Banner, "the greeting still proves this is FTP; that reading moved to the banner")
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

	require.False(t, result.FTPProbe,
		"ftp_probe answers whether the probe succeeded, and this one reported banner_read_failed (cyprob#365)")
	require.NotEmpty(t, result.Banner)
	require.True(t, result.TLSEnabled)
	require.Equal(t, "banner_read_failed", result.ProbeError)
	require.Len(t, result.Attempts, 3)
	require.Equal(t, "ftp-feat", result.Attempts[1].Strategy)
	require.True(t, result.Attempts[1].Success)
	require.Equal(t, "ftp-syst", result.Attempts[2].Strategy)
	require.Equal(t, "banner_read_failed", result.Attempts[2].Error)
}

// The straddle cyprob#360 named: one code covered a server that answered and
// refused and a command whose read never completed. These are the two sides,
// and the point of the test is that they no longer resolve to the same code.
func TestClassifyFTPCommandErrors_AReadFailureIsNotARefusal(t *testing.T) {
	tests := []struct {
		name string
		got  ProbeCode
		want ProbeCode
	}{
		{"feat: the server answered and refused", classifyFTPFeatError(nil, ftpResponse{Code: 500}), ProbeCodeFeatFailed},
		{"syst: the server answered and refused", classifyFTPSystError(nil, ftpResponse{Code: 502}), ProbeCodeSystFailed},
		{"feat: the read never completed", classifyFTPFeatError(io.EOF, ftpResponse{}), ProbeCodeBannerReadFailed},
		{"syst: the read never completed", classifyFTPSystError(io.EOF, ftpResponse{}), ProbeCodeBannerReadFailed},
		{"feat: the read timed out", classifyFTPFeatError(os.ErrDeadlineExceeded, ftpResponse{}), ProbeCodeTimeout},
		{"syst: the read timed out", classifyFTPSystError(os.ErrDeadlineExceeded, ftpResponse{}), ProbeCodeTimeout},
		// An error wins over the reply, because a reply that did not arrive
		// carries no code and ftpResponse{}.Code is 0, not 211.
		{"feat: an error beside an empty reply is still the error", classifyFTPFeatError(ioError("protocol_mismatch"), ftpResponse{}), ProbeCodeProtocolMismatch},
		{"feat: the expected reply is not a failure", classifyFTPFeatError(nil, ftpResponse{Code: 211}), ""},
		{"syst: the expected reply is not a failure", classifyFTPSystError(nil, ftpResponse{Code: 215}), ""},
	}

	for _, tc := range tests {
		require.Equal(t, string(tc.want), string(tc.got), tc.name)
	}

	// The control. If both classifiers returned the error-side code for
	// everything, every case above except the last two would still pass and the
	// refusal side would have been lost. 211 and 215 are also not
	// interchangeable: each classifier tests its own command's code.
	require.Equal(t, string(ProbeCodeFeatFailed), string(classifyFTPFeatError(nil, ftpResponse{Code: 215})),
		"215 answers SYST, not FEAT; treating it as success would make the two classifiers the same function")
	require.Equal(t, string(ProbeCodeSystFailed), string(classifyFTPSystError(nil, ftpResponse{Code: 211})),
		"211 answers FEAT, not SYST")
}

// What the split changes for a real target, driven end to end over the plain
// path -- the one that had the straddle. Before cyprob#360 a FEAT whose read
// died produced feat_failed, pickTopFTPPartialError filtered it out, and the
// service reported no probe error at all. It now produces banner_read_failed,
// which that filter does keep.
//
// So the change is not a relabel: it is a step that reported nothing starting
// to report something. TestProbeFTPDetails_PartialSuccess is the control on the
// other side -- a server that refuses FEAT with 500 still reports nothing.
func TestProbeFTPDetails_Plain_AFEATReadFailureReachesTheServiceError(t *testing.T) {
	host, port, cleanup := startFTPPlainFEATHangupServer(t)
	defer cleanup()

	result := probeFTPDetails(context.Background(), host, "", port, "ftp", FTPProbeOptions{
		TotalTimeout:   2 * time.Second,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
	})

	require.False(t, result.FTPProbe,
		"ftp_probe answers whether the probe succeeded, and this one reported an error (cyprob#365)")
	require.Equal(t, 220, result.GreetingCode, "the greeting has to succeed or this is testing the connect path instead")
	require.Equal(t, "banner_read_failed", result.ProbeError,
		"a FEAT read that died used to produce feat_failed, which pickTopFTPPartialError drops; the service then reported nothing")

	var featAttempt *FTPProbeAttempt
	for i := range result.Attempts {
		if result.Attempts[i].Strategy == "ftp-feat" {
			featAttempt = &result.Attempts[i]
		}
	}
	require.NotNil(t, featAttempt, "no ftp-feat attempt was recorded, so the assertion above proves nothing")
	require.False(t, featAttempt.Success)
	require.Equal(t, "banner_read_failed", featAttempt.Error)
	require.NotEqual(t, "feat_failed", featAttempt.Error,
		"the straddle is back: a read failure is wearing the code that means the server refused")
}

// feat_failed and syst_failed rank in ftpProbeErrorPriority, which reads as
// though they can win the service-level answer. They cannot: they only ever
// enter attemptErrors, and pickTopFTPPartialError keeps six codes and neither
// of these is one of them.
//
// That is worth pinning rather than leaving to be rediscovered. It means the
// two codes live in Attempts[].Error alone -- they never reach ProbeError,
// ftp_probe_error in a report, or the reason column of cyprob-ee's probe
// coverage ledger, all three of which read ProbeError.
func TestPickTopFTPPartialError_FeatAndSystCannotWinTheServiceAnswer(t *testing.T) {
	require.Empty(t, pickTopFTPPartialError([]string{"feat_failed"}))
	require.Empty(t, pickTopFTPPartialError([]string{"syst_failed"}))
	require.Empty(t, pickTopFTPPartialError([]string{"feat_failed", "syst_failed"}))

	// The control: the filter is not simply returning "" for everything, and
	// a code it does keep beats the two it does not -- which is exactly what
	// happens now that a failed read is classified.
	require.Equal(t, "banner_read_failed",
		pickTopFTPPartialError([]string{"feat_failed", "banner_read_failed", "syst_failed"}))
	require.Equal(t, "timeout", pickTopFTPPartialError([]string{"banner_read_failed", "timeout"}))
}

func startFTPPlainFEATHangupServer(t *testing.T) (string, int, func()) {
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
					// The command is accepted and then the connection goes
					// away mid-reply: a read that never completes, which is
					// the side of feat_failed that was never a peer verdict.
					if strings.HasPrefix(strings.ToUpper(line), "FEAT") {
						return
					}
					_, _ = io.WriteString(conn, "500 Unknown command\r\n")
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

func TestClassifyFTPErrors(t *testing.T) {
	require.Equal(t, "timeout", string(classifyFTPConnectError(os.ErrDeadlineExceeded)))
	require.Equal(t, "banner_read_failed", string(classifyFTPBannerError(io.EOF)))
	require.Equal(t, "protocol_mismatch", string(classifyFTPBannerError(ioError("protocol_mismatch"))))
	require.Equal(t, "tls_handshake_failed", string(classifyFTPTLSError(ioError("tls: handshake failure"))))
	require.Equal(t, "connect_failed", string(classifyFTPTLSError(ioError("connection refused"))))
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
