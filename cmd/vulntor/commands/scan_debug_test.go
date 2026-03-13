package commands

import (
	"bufio"
	"bytes"
	"context"
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

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
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
	OpenUDPPorts []struct {
		Target    string `json:"target"`
		OpenPorts []int  `json:"open_ports"`
	} `json:"open_udp_ports"`
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
	FTPDetails []struct {
		Target           string   `json:"target"`
		Port             int      `json:"port"`
		FTPProbe         bool     `json:"ftp_probe"`
		FTPProtocol      string   `json:"ftp_protocol"`
		Banner           string   `json:"banner"`
		GreetingCode     int      `json:"greeting_code"`
		Features         []string `json:"features"`
		AuthTLSSupported bool     `json:"auth_tls_supported"`
		TLSEnabled       bool     `json:"tls_enabled"`
		SystemHint       string   `json:"system_hint"`
		SoftwareHint     string   `json:"software_hint"`
		ProbeError       string   `json:"probe_error"`
	} `json:"ftp_details"`
	MySQLDetails []struct {
		Target          string `json:"target"`
		Port            int    `json:"port"`
		MySQLProbe      bool   `json:"mysql_probe"`
		GreetingKind    string `json:"greeting_kind"`
		ProtocolVersion int    `json:"protocol_version"`
		ServerVersion   string `json:"server_version"`
		AuthPluginName  string `json:"auth_plugin_name"`
		TLSSupported    bool   `json:"tls_supported"`
		TLSEnabled      bool   `json:"tls_enabled"`
		ProductHint     string `json:"product_hint"`
		VendorHint      string `json:"vendor_hint"`
		VersionHint     string `json:"version_hint"`
		ProbeError      string `json:"probe_error"`
	} `json:"mysql_details"`
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
	DNSDetails []struct {
		Target               string   `json:"target"`
		Port                 int      `json:"port"`
		Transport            string   `json:"transport"`
		DNSProbe             bool     `json:"dns_probe"`
		NSQueryResponded     bool     `json:"ns_query_responded"`
		VersionBindResponded bool     `json:"version_bind_responded"`
		VersionBindSupported bool     `json:"version_bind_supported"`
		ResponseCode         string   `json:"response_code"`
		NSRecords            []string `json:"ns_records"`
		VersionBind          string   `json:"version_bind"`
		ProductHint          string   `json:"product_hint"`
		VendorHint           string   `json:"vendor_hint"`
		ProbeError           string   `json:"probe_error"`
	} `json:"dns_details"`
	SNMPDetails []struct {
		Target        string `json:"target"`
		Port          int    `json:"port"`
		SNMPProbe     bool   `json:"snmp_probe"`
		SNMPVersion   string `json:"snmp_version"`
		Community     string `json:"community"`
		SysDescr      string `json:"sys_descr"`
		SysName       string `json:"sys_name"`
		SysObjectID   string `json:"sys_object_id"`
		ProductHint   string `json:"product_hint"`
		VendorHint    string `json:"vendor_hint"`
		ProbeError    string `json:"probe_error"`
		WeakProtocol  bool   `json:"weak_protocol"`
		WeakCommunity bool   `json:"weak_community"`
	} `json:"snmp_details"`
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

func TestScanDebugTargetFTPJSONSmoke(t *testing.T) {
	host, port, cleanup := startFTPTestServer(t)
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
	require.NotEmpty(t, payload.FTPDetails)
	require.True(t, payload.FTPDetails[0].FTPProbe)
	require.Equal(t, "ftp", payload.FTPDetails[0].FTPProtocol)
	require.Equal(t, 220, payload.FTPDetails[0].GreetingCode)
	require.Equal(t, "UNIX Type: L8", payload.FTPDetails[0].SystemHint)
	require.Equal(t, "FileZilla Server", payload.FTPDetails[0].SoftwareHint)
	require.Contains(t, payload.FTPDetails[0].Features, "UTF8")
	require.Empty(t, payload.FTPDetails[0].ProbeError)
	require.Empty(t, payload.SMTPDetails)
	require.Empty(t, payload.SSHDetails)
	require.NotEmpty(t, payload.ServiceIdentity)
	require.Equal(t, "ftp", payload.ServiceIdentity[0].ServiceName)
	require.Equal(t, "FileZilla Server", payload.ServiceIdentity[0].Product)
	require.NotEmpty(t, payload.AssetProfiles)
}

func TestRunDebugMySQLNativeProbeStageWithModule(t *testing.T) {
	const moduleType = "test-scan-debug-mysql-native-probe"
	engine.RegisterModuleFactory(moduleType, func() engine.Module {
		return &testScanDebugMySQLModule{
			meta: engine.ModuleMetadata{
				ID:   "test-scan-debug-mysql-native-probe-instance",
				Name: moduleType,
				Type: engine.ScanModuleType,
				Consumes: []engine.DataContractEntry{
					{Key: "discovery.open_tcp_ports", DataTypeName: "discovery.TCPPortDiscoveryResult", Cardinality: engine.CardinalityList},
					{Key: "service.banner.tcp", DataTypeName: "scan.BannerGrabResult", Cardinality: engine.CardinalityList, IsOptional: true},
					{Key: "config.original_cli_targets", DataTypeName: "[]string", Cardinality: engine.CardinalitySingle, IsOptional: true},
				},
				Produces: []engine.DataContractEntry{
					{Key: "service.mysql.details", DataTypeName: "scan.MySQLServiceInfo", Cardinality: engine.CardinalityList},
				},
			},
		}
	})

	steps := newScanDebugSteps("mysql-native-probe")
	results, err := runDebugMySQLNativeProbeStageWithModule(
		context.Background(),
		"mysql.example.test",
		scanDebugTargetOptions{Timeout: "2s"},
		steps,
		[]discovery.TCPPortDiscoveryResult{
			{Target: "127.0.0.1", OpenPorts: []int{3306}},
		},
		nil,
		"test_scan_debug_mysql_module",
		moduleType,
		"mysql-native-probe",
	)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.True(t, results[0].MySQLProbe)
	require.Equal(t, 3306, results[0].Port)
	require.Empty(t, steps.values()[0].Errors)
}

func TestRunDebugSNMPNativeProbeStageWithModule(t *testing.T) {
	const moduleType = "test-scan-debug-snmp-native-probe"
	engine.RegisterModuleFactory(moduleType, func() engine.Module {
		return &testScanDebugSNMPModule{
			meta: engine.ModuleMetadata{
				ID:   "test-scan-debug-snmp-native-probe-instance",
				Name: moduleType,
				Type: engine.ScanModuleType,
				Consumes: []engine.DataContractEntry{
					{Key: "discovery.open_udp_ports", DataTypeName: "discovery.UDPPortDiscoveryResult", Cardinality: engine.CardinalityList},
				},
				Produces: []engine.DataContractEntry{
					{Key: "service.snmp.details", DataTypeName: "scan.SNMPServiceInfo", Cardinality: engine.CardinalityList},
				},
			},
		}
	})

	steps := newScanDebugSteps("snmp-native-probe")
	results, err := runDebugSNMPNativeProbeStageWithModule(
		context.Background(),
		scanDebugTargetOptions{Timeout: "2s"},
		steps,
		[]discovery.UDPPortDiscoveryResult{
			{Target: "127.0.0.1", OpenPorts: []int{161}},
		},
		"test_scan_debug_snmp_module",
		moduleType,
		"snmp-native-probe",
	)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.True(t, results[0].SNMPProbe)
	require.Equal(t, "SNMPv2c", results[0].SNMPVersion)
	require.Empty(t, steps.values()[0].Errors)
}

func TestRunDebugDNSNativeProbeStageWithModule(t *testing.T) {
	const moduleType = "test-scan-debug-dns-native-probe"
	engine.RegisterModuleFactory(moduleType, func() engine.Module {
		return &testScanDebugDNSModule{
			meta: engine.ModuleMetadata{
				ID:   "test-scan-debug-dns-native-probe-instance",
				Name: moduleType,
				Type: engine.ScanModuleType,
				Consumes: []engine.DataContractEntry{
					{Key: "discovery.open_tcp_ports", DataTypeName: "discovery.TCPPortDiscoveryResult", Cardinality: engine.CardinalityList, IsOptional: true},
					{Key: "discovery.open_udp_ports", DataTypeName: "discovery.UDPPortDiscoveryResult", Cardinality: engine.CardinalityList, IsOptional: true},
				},
				Produces: []engine.DataContractEntry{
					{Key: "service.dns.details", DataTypeName: "scan.DNSServiceInfo", Cardinality: engine.CardinalityList},
				},
			},
		}
	})

	steps := newScanDebugSteps("dns-native-probe")
	results, err := runDebugDNSNativeProbeStageWithModule(
		context.Background(),
		scanDebugTargetOptions{Timeout: "2s"},
		steps,
		[]discovery.TCPPortDiscoveryResult{
			{Target: "127.0.0.1", OpenPorts: []int{53}},
		},
		[]discovery.UDPPortDiscoveryResult{
			{Target: "127.0.0.1", OpenPorts: []int{53}},
		},
		"test_scan_debug_dns_module",
		moduleType,
		"dns-native-probe",
	)
	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Empty(t, steps.values()[0].Errors)
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

func startFTPTestServer(t *testing.T) (string, int, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
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

	addr := listener.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, func() {
		_ = listener.Close()
		<-done
	}
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

type testScanDebugSNMPModule struct {
	meta engine.ModuleMetadata
}

type testScanDebugMySQLModule struct {
	meta engine.ModuleMetadata
}

func (m *testScanDebugSNMPModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *testScanDebugMySQLModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *testScanDebugSNMPModule) Init(instanceID string, config map[string]any) error {
	m.meta.ID = instanceID
	return nil
}

func (m *testScanDebugMySQLModule) Init(instanceID string, config map[string]any) error {
	m.meta.ID = instanceID
	return nil
}

func (m *testScanDebugSNMPModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	_ = ctx
	_ = inputs
	outputChan <- engine.ModuleOutput{
		FromModuleName: m.meta.ID,
		DataKey:        "service.snmp.details",
		Data: scanpkg.SNMPServiceInfo{
			Target:      "127.0.0.1",
			Port:        161,
			SNMPProbe:   true,
			SNMPVersion: "SNMPv2c",
			Community:   "public",
			ProductHint: "Net-SNMP",
		},
		Timestamp: time.Now(),
		Target:    "127.0.0.1",
	}
	return nil
}

func (m *testScanDebugMySQLModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	_ = ctx
	_ = inputs
	outputChan <- engine.ModuleOutput{
		FromModuleName: m.meta.ID,
		DataKey:        "service.mysql.details",
		Data: scanpkg.MySQLServiceInfo{
			Target:          "127.0.0.1",
			Port:            3306,
			MySQLProbe:      true,
			GreetingKind:    "handshake",
			ProtocolVersion: 10,
			ServerVersion:   "8.0.36-MySQL Community Server",
			AuthPluginName:  "caching_sha2_password",
			ProductHint:     "MySQL",
			VendorHint:      "Oracle",
			VersionHint:     "8.0.36-MySQL Community Server",
		},
		Timestamp: time.Now(),
		Target:    "127.0.0.1",
	}
	return nil
}

type testScanDebugDNSModule struct {
	meta engine.ModuleMetadata
}

func (m *testScanDebugDNSModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *testScanDebugDNSModule) Init(instanceID string, config map[string]any) error {
	m.meta.ID = instanceID
	return nil
}

func (m *testScanDebugDNSModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	_ = ctx
	_ = inputs
	outputChan <- engine.ModuleOutput{
		FromModuleName: m.meta.ID,
		DataKey:        "service.dns.details",
		Data: scanpkg.DNSServiceInfo{
			Target:               "127.0.0.1",
			Port:                 53,
			Transport:            "udp",
			DNSProbe:             true,
			NSQueryResponded:     true,
			VersionBindResponded: true,
			VersionBindSupported: true,
			ResponseCode:         "NOERROR",
			VersionBind:          "BIND 9.16.23",
			ProductHint:          "BIND",
			VendorHint:           "ISC",
		},
		Timestamp: time.Now(),
		Target:    "127.0.0.1",
	}
	outputChan <- engine.ModuleOutput{
		FromModuleName: m.meta.ID,
		DataKey:        "service.dns.details",
		Data: scanpkg.DNSServiceInfo{
			Target:           "127.0.0.1",
			Port:             53,
			Transport:        "tcp",
			DNSProbe:         true,
			NSQueryResponded: true,
			ResponseCode:     "NOERROR",
		},
		Timestamp: time.Now(),
		Target:    "127.0.0.1",
	}
	return nil
}
