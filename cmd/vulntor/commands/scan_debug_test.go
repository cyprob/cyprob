package commands

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
	"github.com/stretchr/testify/require"
)

type scanDebugTestOutput struct {
	Target          string `json:"target"`
	ResolvedTargets []struct {
		Input string `json:"input"`
		IP    string `json:"ip"`
	} `json:"resolved_targets"`
	OpenPorts []struct {
		Target    string `json:"target"`
		OpenPorts []int  `json:"open_ports"`
	} `json:"open_ports"`
	Banners []struct {
		IP            string `json:"ip"`
		ResolvedIP    string `json:"resolved_ip"`
		ProbeHost     string `json:"probe_host"`
		SNIServerName string `json:"sni_server_name"`
		Port          int    `json:"port"`
		Banner        string `json:"banner"`
		Error         string `json:"error"`
		Evidence      []struct {
			ProbeID  string `json:"probe_id"`
			Response string `json:"response"`
			Error    string `json:"error"`
		} `json:"evidence"`
	} `json:"banners"`
	HTTPDetails []struct {
		Target     string `json:"target"`
		Port       int    `json:"port"`
		StatusCode int    `json:"status_code"`
	} `json:"http_details"`
	Fingerprints []struct {
		Target  string `json:"target"`
		Port    int    `json:"port"`
		Product string `json:"product"`
	} `json:"fingerprints"`
	TechTags []struct {
		Target string   `json:"target"`
		Port   int      `json:"port"`
		Tags   []string `json:"tags"`
	} `json:"tech_tags"`
	SMTPDetails []struct {
		Target              string `json:"target"`
		Port                int    `json:"port"`
		SMTPProbe           bool   `json:"smtp_probe"`
		SMTPProtocol        string `json:"smtp_protocol"`
		Banner              string `json:"banner"`
		GreetingDomain      string `json:"greeting_domain"`
		StartTLSSupported   bool   `json:"starttls_supported"`
		AuthSupported       bool   `json:"auth_supported"`
		PipeliningSupported bool   `json:"pipelining_supported"`
		SizeAdvertised      bool   `json:"size_advertised"`
		TLSEnabled          bool   `json:"tls_enabled"`
		SoftwareHint        string `json:"software_hint"`
		ProbeError          string `json:"probe_error"`
	} `json:"smtp_details"`
	SSHDetails []struct {
		Target      string   `json:"target"`
		Port        int      `json:"port"`
		SSHProbe    bool     `json:"ssh_probe"`
		SSHBanner   string   `json:"ssh_banner"`
		SSHProtocol string   `json:"ssh_protocol"`
		SSHSoftware string   `json:"ssh_software"`
		SSHVersion  string   `json:"ssh_version"`
		Ciphers     []string `json:"ciphers"`
		ProbeError  string   `json:"probe_error"`
	} `json:"ssh_details"`
	AssetProfiles []struct {
		Target string `json:"target"`
	} `json:"asset_profiles"`
	ServiceIdentity []struct {
		Target      string   `json:"target"`
		Port        int      `json:"port"`
		ServiceName string   `json:"service_name"`
		Product     string   `json:"product"`
		Version     string   `json:"version"`
		TechTags    []string `json:"tech_tags"`
	} `json:"service_identity"`
	Steps []struct {
		Step     string   `json:"step"`
		Errors   []string `json:"errors"`
		Warnings []string `json:"warnings"`
	} `json:"steps"`
}

func TestScanDebugTargetJSONSmoke(t *testing.T) {
	host, port, cleanup := startBannerTestServer(t)
	defer cleanup()

	cmd := NewCommand()
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs([]string{
		"scan-debug", "target", host,
		"--ports", fmt.Sprintf("%d-%d", port, port),
		"--timeout", "2s",
		"--format", "json",
	})

	err := cmd.Execute()
	require.NoError(t, err, "stderr: %s", errOut.String())

	var payload scanDebugTestOutput
	require.NoError(t, json.Unmarshal(out.Bytes(), &payload))

	require.Equal(t, host, payload.Target)
	require.NotEmpty(t, payload.ResolvedTargets)
	require.True(t, containsPort(payload.OpenPorts, port), "expected open port %d in output", port)
	require.NotEmpty(t, payload.Banners)
	require.Equal(t, payload.Banners[0].IP, payload.Banners[0].ResolvedIP)
	require.Equal(t, "127.0.0.1", payload.Banners[0].ProbeHost)
	require.NotEmpty(t, payload.Fingerprints)
	require.NotEmpty(t, payload.TechTags)
	require.NotEmpty(t, payload.SSHDetails)
	require.True(t, payload.SSHDetails[0].SSHProbe)
	require.Equal(t, "2.0", payload.SSHDetails[0].SSHProtocol)
	require.Equal(t, "OpenSSH", payload.SSHDetails[0].SSHSoftware)
	require.Empty(t, payload.SMTPDetails)
	require.NotEmpty(t, payload.ServiceIdentity)
	require.NotEmpty(t, payload.AssetProfiles)
	require.Equal(t, "ssh", payload.ServiceIdentity[0].ServiceName)
	require.True(t, hasTag(payload.TechTags, "ssh"), "expected ssh tag in tech_tags")

	for _, step := range payload.Steps {
		require.Empty(t, step.Errors, "step %s has errors: %v", step.Step, step.Errors)
	}
}

func TestScanDebugTargetHTTPSGetEvidenceSmoke(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/interface/root", http.StatusFound)
	}))
	defer ts.Close()

	addr := strings.TrimPrefix(ts.URL, "https://")
	host, portStr, err := net.SplitHostPort(addr)
	require.NoError(t, err)

	cmd := NewCommand()
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs([]string{
		"scan-debug", "target", host,
		"--ports", portStr,
		"--timeout", "4s",
		"--format", "json",
	})

	err = cmd.Execute()
	require.NoError(t, err, "stderr: %s", errOut.String())

	var payload scanDebugTestOutput
	require.NoError(t, json.Unmarshal(out.Bytes(), &payload))
	require.NotEmpty(t, payload.Banners)

	foundHTTPSGet := false
	for _, ev := range payload.Banners[0].Evidence {
		if ev.ProbeID == "https-get" {
			foundHTTPSGet = true
			require.NotContains(t, ev.Response, "400 Bad Request")
			require.True(t, strings.Contains(ev.Response, "302 Found") || strings.Contains(ev.Response, "200 OK"))
		}
	}
	if !foundHTTPSGet {
		require.NotEmpty(t, payload.Banners[0].Banner)
	}
}

func TestScanDebugTargetSMTPJSONSmoke(t *testing.T) {
	host, port, cleanup := startSMTPTestServer(t)
	defer cleanup()

	cmd := NewCommand()
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs([]string{
		"scan-debug", "target", host,
		"--ports", fmt.Sprintf("%d", port),
		"--timeout", "3s",
		"--format", "json",
	})

	err := cmd.Execute()
	require.NoError(t, err, "stderr: %s", errOut.String())

	var payload scanDebugTestOutput
	require.NoError(t, json.Unmarshal(out.Bytes(), &payload))
	require.NotEmpty(t, payload.SMTPDetails)
	require.Empty(t, payload.SSHDetails)
	require.True(t, payload.SMTPDetails[0].SMTPProbe)
	require.Equal(t, "smtp", payload.SMTPDetails[0].SMTPProtocol)
	require.True(t, payload.SMTPDetails[0].AuthSupported)
	require.True(t, payload.SMTPDetails[0].PipeliningSupported)
	require.True(t, payload.SMTPDetails[0].SizeAdvertised)
	require.Equal(t, "Postfix", payload.SMTPDetails[0].SoftwareHint)
	require.NotEmpty(t, payload.ServiceIdentity)
	require.NotEmpty(t, payload.AssetProfiles)
	require.Equal(t, "smtp", payload.ServiceIdentity[0].ServiceName)
	require.Equal(t, "Postfix", payload.ServiceIdentity[0].Product)
}

func TestDebugTLSExtraPortsFromBanners(t *testing.T) {
	require.Empty(t, debugTLSExtraPortsFromBanners([]scanpkg.BannerGrabResult{
		{IP: "127.0.0.1", Port: 10443, Protocol: "tcp", Banner: "HELLO"},
	}))

	require.Equal(t, []int{10443}, debugTLSExtraPortsFromBanners([]scanpkg.BannerGrabResult{
		{IP: "127.0.0.1", Port: 10443, Protocol: "https", Banner: "HTTP/1.1 200 OK"},
	}))
}

func startBannerTestServer(t *testing.T) (string, int, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Write([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"))
				buf := make([]byte, 256)
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	cleanup := func() {
		_ = ln.Close()
		<-done
	}
	return "127.0.0.1", addr.Port, cleanup
}

func startSMTPTestServer(t *testing.T) (string, int, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				reader := bufio.NewReader(c)
				_, _ = io.WriteString(c, "220 mail.example.test ESMTP Postfix\r\n")
				line, err := reader.ReadString('\n')
				if err != nil || !strings.HasPrefix(line, "EHLO ") {
					return
				}
				_, _ = io.WriteString(c, "250-mail.example.test\r\n250-PIPELINING\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 1024000\r\n")
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	cleanup := func() {
		_ = ln.Close()
		<-done
	}
	return "127.0.0.1", addr.Port, cleanup
}

func containsPort(results []struct {
	Target    string `json:"target"`
	OpenPorts []int  `json:"open_ports"`
}, port int,
) bool {
	for _, result := range results {
		if slices.Contains(result.OpenPorts, port) {
			return true
		}
	}
	return false
}

func hasTag(results []struct {
	Target string   `json:"target"`
	Port   int      `json:"port"`
	Tags   []string `json:"tags"`
}, tag string,
) bool {
	for _, result := range results {
		if slices.Contains(result.Tags, tag) {
			return true
		}
	}
	return false
}
