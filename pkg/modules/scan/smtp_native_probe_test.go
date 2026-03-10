package scan

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

func TestSMTPNativeProbeModule_ExecuteFiltersCandidates(t *testing.T) {
	originalProbe := probeSMTPDetailsFunc
	defer func() { probeSMTPDetailsFunc = originalProbe }()

	calls := 0
	probeSMTPDetailsFunc = func(ctx context.Context, target string, hostname string, port int, opts SMTPProbeOptions) SMTPServiceInfo {
		calls++
		return SMTPServiceInfo{
			Target:       target,
			Port:         port,
			SMTPProbe:    true,
			SMTPProtocol: smtpProtocolFromPort(port),
		}
	}

	module := newSMTPNativeProbeModule()
	if err := module.Init("test-smtp-native", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: "198.51.100.30", OpenPorts: []int{25, 80}},
		},
		"service.banner.tcp": []any{
			BannerGrabResult{IP: "198.51.100.30", Port: 2525, Protocol: "smtp", Banner: "220 mail.example.test ESMTP"},
			BannerGrabResult{IP: "198.51.100.30", Port: 2525, Protocol: "smtp", Banner: "220 mail.example.test ESMTP"},
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	var outputs []SMTPServiceInfo
	for item := range out {
		info, ok := item.Data.(SMTPServiceInfo)
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

func TestSMTPNativeProbeModule_ExecuteHonorsExplicitCandidatePorts(t *testing.T) {
	originalProbe := probeSMTPDetailsFunc
	defer func() { probeSMTPDetailsFunc = originalProbe }()

	calls := 0
	probeSMTPDetailsFunc = func(ctx context.Context, target string, hostname string, port int, opts SMTPProbeOptions) SMTPServiceInfo {
		calls++
		return SMTPServiceInfo{Target: target, Port: port, SMTPProbe: true}
	}

	module := newSMTPNativeProbeModule()
	if err := module.Init("test-smtp-native-explicit", map[string]any{
		"candidate_ports": []int{2626},
	}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: "198.51.100.31", OpenPorts: []int{2626, 8080}},
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

func TestProbeSMTPDetails_PlainEHLOAndSTARTTLS(t *testing.T) {
	host, port, cleanup := startSMTPSTARTTLSTestServer(t, "smtp.test")
	defer cleanup()

	result := probeSMTPDetails(context.Background(), host, "smtp.test", port, SMTPProbeOptions{
		TotalTimeout:   2 * time.Second,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
	})

	if !result.SMTPProbe {
		t.Fatalf("expected SMTPProbe=true")
	}
	if result.SMTPProtocol != "smtp" {
		t.Fatalf("expected smtp protocol, got %q", result.SMTPProtocol)
	}
	if result.GreetingDomain != "mail.example.test" {
		t.Fatalf("expected greeting domain mail.example.test, got %q", result.GreetingDomain)
	}
	if !result.StartTLSSupported || !result.TLSEnabled {
		t.Fatalf("expected starttls and tls enabled, got starttls=%v tls=%v", result.StartTLSSupported, result.TLSEnabled)
	}
	if !result.AuthSupported || !result.PipeliningSupported || !result.ChunkingSupported || !result.SizeAdvertised {
		t.Fatalf("expected EHLO capabilities, got %+v", result)
	}
	if result.CertSubjectCN != "smtp.test" {
		t.Fatalf("expected cert subject cn smtp.test, got %q", result.CertSubjectCN)
	}
	if result.SoftwareHint != "SmarterMail" || result.VendorHint != "SmarterTools" || result.VersionHint != "17.1" {
		t.Fatalf("unexpected software hints: %q %q %q", result.SoftwareHint, result.VendorHint, result.VersionHint)
	}
	if result.ProbeError != "" {
		t.Fatalf("expected empty probe error, got %q", result.ProbeError)
	}
	if len(result.Attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(result.Attempts))
	}
}

func TestProbeSMTPDetails_ImplicitTLS(t *testing.T) {
	host, port, cleanup := startSMTPSImplicitTestServer(t, "smtp.test")
	defer cleanup()

	opts := SMTPProbeOptions{
		TotalTimeout:   2 * time.Second,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
	}
	client, tlsObs, err := dialSMTPTLS(context.Background(), host, "smtp.test", port, opts)
	if err != nil {
		t.Fatalf("dialSMTPTLS: %v", err)
	}
	defer client.close()

	outcome, err := runSMTPImplicitTLSSession(context.Background(), client, tlsObs, port, opts)
	if err != nil {
		t.Fatalf("runSMTPImplicitTLSSession: %v", err)
	}

	if !outcome.tlsEnabled {
		t.Fatalf("expected tls enabled")
	}
	if outcome.startTLSSupported {
		t.Fatalf("expected starttls_supported=false for implicit tls")
	}
	if !outcome.authSupported || !outcome.pipeliningSupported || !outcome.sizeAdvertised {
		t.Fatalf("expected EHLO capabilities, got %+v", outcome)
	}
	if outcome.softwareHint != "Postfix" || outcome.versionHint != "3.9.0" {
		t.Fatalf("unexpected software hints: %q %q", outcome.softwareHint, outcome.versionHint)
	}
}

func TestBuildSMTPOutcome_WeakTLSFlags(t *testing.T) {
	outcome := buildSMTPOutcome("smtp", smtpResponse{Raw: "220 mail.example.test ESMTP"}, smtpResponse{
		Raw:   "250-STARTTLS\r\n250 AUTH PLAIN",
		Lines: []string{"250-STARTTLS", "250 AUTH PLAIN"},
	}, &engine.TLSObservation{
		Version:     "TLS1.0",
		CipherSuite: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	})

	if !outcome.weakTLSProtocol {
		t.Fatalf("expected weak tls protocol")
	}
	if !outcome.weakTLSCipher {
		t.Fatalf("expected weak tls cipher")
	}
}

func TestClassifySMTPProbeError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "timeout", err: errors.New("i/o timeout"), want: "timeout"},
		{name: "refused", err: errors.New("connection refused"), want: "refused"},
		{name: "starttls", err: errors.New("starttls_failed"), want: "starttls_failed"},
		{name: "tls", err: errors.New("tls: handshake failure"), want: "tls_failed"},
		{name: "protocol", err: errors.New("protocol_error"), want: "protocol_error"},
		{name: "generic", err: errors.New("unexpected"), want: "probe_failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifySMTPProbeError(tt.err); got != tt.want {
				t.Fatalf("classifySMTPProbeError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPickTopSMTPProbeErrorPriority(t *testing.T) {
	codes := []string{"probe_failed", "starttls_failed", "timeout"}
	if got := pickTopSMTPProbeError(codes); got != "timeout" {
		t.Fatalf("expected timeout priority, got %q", got)
	}
}

func TestSMTPProtocolFromPort(t *testing.T) {
	if got := smtpProtocolFromPort(25); got != "smtp" {
		t.Fatalf("expected smtp on 25, got %q", got)
	}
	if got := smtpProtocolFromPort(465); got != "smtps" {
		t.Fatalf("expected smtps on 465, got %q", got)
	}
	if got := smtpProtocolFromPort(587); got != "submission" {
		t.Fatalf("expected submission on 587, got %q", got)
	}
}

func startSMTPSTARTTLSTestServer(t *testing.T, serverName string) (string, int, func()) {
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
				_, _ = io.WriteString(conn, "220 mail.example.test ESMTP SmarterMail 17.1\r\n")
				if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "EHLO ") {
					return
				}
				_, _ = io.WriteString(conn, "250-mail.example.test\r\n250-PIPELINING\r\n250-SIZE 10485760\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 CHUNKING\r\n")
				if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "STARTTLS") {
					return
				}
				_, _ = io.WriteString(conn, "220 Ready to start TLS\r\n")

				tlsConn := tls.Server(&bufferedConn{Conn: conn, reader: reader}, tlsConfig)
				if err := tlsConn.Handshake(); err != nil {
					_ = tlsConn.Close()
					return
				}
				tlsReader := bufio.NewReader(tlsConn)
				if line, err := tlsReader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "EHLO ") {
					_ = tlsConn.Close()
					return
				}
				_, _ = io.WriteString(tlsConn, "250-mail.example.test\r\n250-PIPELINING\r\n250-SIZE 10485760\r\n250-AUTH PLAIN LOGIN\r\n250 CHUNKING\r\n")
				_ = tlsConn.Close()
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, func() {
		_ = ln.Close()
		<-done
	}
}

func startSMTPSImplicitTestServer(t *testing.T, serverName string) (string, int, func()) {
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
				tlsConn := tls.Server(conn, tlsConfig)
				if err := tlsConn.Handshake(); err != nil {
					_ = tlsConn.Close()
					return
				}
				_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
				reader := bufio.NewReader(tlsConn)
				_, _ = io.WriteString(tlsConn, "220 mail.example.test ESMTP Postfix 3.9.0\r\n")
				if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "EHLO ") {
					_ = tlsConn.Close()
					return
				}
				_, _ = io.WriteString(tlsConn, "250-mail.example.test\r\n250-PIPELINING\r\n250-SIZE 2048000\r\n250 AUTH PLAIN LOGIN\r\n")
				_ = tlsConn.Close()
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, func() {
		_ = ln.Close()
		<-done
	}
}
