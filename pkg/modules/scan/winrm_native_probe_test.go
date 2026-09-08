package scan

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"github.com/stretchr/testify/require"
)

func TestWINRMNativeProbeModule_ExecuteFiltersCandidates(t *testing.T) {
	originalProbe := probeWINRMDetailsFunc
	defer func() { probeWINRMDetailsFunc = originalProbe }()

	calls := 0
	probeWINRMDetailsFunc = func(ctx context.Context, target string, hostname string, port int, opts WINRMProbeOptions) WINRMServiceInfo {
		calls++
		return WINRMServiceInfo{
			Target:         target,
			Port:           port,
			WINRMProbe:     true,
			WINRMTransport: winrmTransportFromPort(port),
			ServiceHint:    "WinRM",
		}
	}

	module := newWINRMNativeProbeModule()
	require.NoError(t, module.Init("test-winrm-native", map[string]any{}))

	inputs := map[string]any{
		"config.original_cli_targets": []string{"host.example.test"},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: "198.51.100.80", OpenPorts: []int{5985, 5986, 80}},
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	require.NoError(t, module.Execute(context.Background(), inputs, out))
	close(out)

	var outputs []WINRMServiceInfo
	for item := range out {
		info, ok := item.Data.(WINRMServiceInfo)
		if !ok {
			continue
		}
		outputs = append(outputs, info)
	}

	require.Equal(t, 2, calls)
	require.Len(t, outputs, 2)
}

func TestProbeWINRMDetails_HTTPIdentifySuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertWINRMIdentifyRequest(t, r, "winrm.test")
		w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
		w.Header().Set("Content-Type", "application/soap+xml; charset=UTF-8")
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <s:Body>
    <wsmid:IdentifyResponse>
      <wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>
      <wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>
      <wsmid:ProductVersion>OS: 10.0.20348 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>
    </wsmid:IdentifyResponse>
  </s:Body>
</s:Envelope>`)
	}))
	defer server.Close()

	host, port := httpTestTarget(t, server.URL)
	result := probeWINRMDetails(context.Background(), host, "winrm.test", port, WINRMProbeOptions{
		TotalTimeout:   2500 * time.Millisecond,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
	})

	require.True(t, result.WINRMProbe)
	require.Equal(t, "http", result.WINRMTransport)
	require.Equal(t, winrmEndpointPath, result.EndpointPath)
	require.Equal(t, http.StatusOK, result.HTTPStatusCode)
	require.Equal(t, "Microsoft-HTTPAPI/2.0", result.ServerHeader)
	require.Equal(t, "application/soap+xml; charset=UTF-8", result.ContentType)
	require.False(t, result.AuthRequired)
	require.True(t, result.IdentifySupported)
	require.Equal(t, "WinRM", result.ServiceHint)
	require.Equal(t, "Microsoft Corporation", result.ProductVendor)
	require.Equal(t, "OS: 10.0.20348 SP: 0.0 Stack: 3.0", result.ProductVersion)
	require.Equal(t, "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd", result.WSMANProtocolVersion)
	require.Empty(t, result.ProbeError)
	require.Len(t, result.Attempts, 1)
	require.True(t, result.Attempts[0].Success)
	require.Equal(t, http.StatusOK, result.Attempts[0].StatusCode)
}

func TestExecuteWINRMRequest_HTTPSIdentifySuccess(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertWINRMIdentifyRequest(t, r, "winrm.tls.test")
		w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
		w.Header().Set("Content-Type", "application/soap+xml; charset=UTF-8")
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <s:Body>
    <wsmid:IdentifyResponse>
      <wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>
      <wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>
      <wsmid:ProductVersion>OS: 10.0.17763 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>
    </wsmid:IdentifyResponse>
  </s:Body>
</s:Envelope>`)
	}))
	defer server.Close()

	host, port := httpTestTarget(t, server.URL)
	result, err := executeWINRMRequest(context.Background(), host, "winrm.tls.test", port, "https", WINRMProbeOptions{
		TotalTimeout:   2500 * time.Millisecond,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
	})
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, result.statusCode)
	require.Equal(t, "Microsoft-HTTPAPI/2.0", result.serverHeader)
	require.Equal(t, "application/soap+xml; charset=UTF-8", result.contentType)
	require.NotNil(t, result.tlsObs)
	require.NotEmpty(t, result.tlsObs.Version)
	require.NotEmpty(t, result.tlsObs.CipherSuite)
	require.NotEmpty(t, result.tlsObs.Issuer)
	require.False(t, result.tlsObs.NotAfter.IsZero())
}

func TestProbeWINRMDetails_Strong401IsConfirmedPartialSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertWINRMIdentifyRequest(t, r, "winrm.auth.test")
		w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
		w.Header().Set("Content-Type", "application/soap+xml; charset=UTF-8")
		w.Header().Add("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault><s:Reason>wsmanfault</s:Reason></s:Fault></s:Body></s:Envelope>`)
	}))
	defer server.Close()

	host, port := httpTestTarget(t, server.URL)
	result := probeWINRMDetails(context.Background(), host, "winrm.auth.test", port, WINRMProbeOptions{
		TotalTimeout:   2500 * time.Millisecond,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
	})

	require.True(t, result.WINRMProbe)
	require.True(t, result.AuthRequired)
	require.False(t, result.IdentifySupported)
	require.Equal(t, "WinRM", result.ServiceHint)
	require.Equal(t, http.StatusUnauthorized, result.HTTPStatusCode)
	require.Equal(t, []string{"Negotiate"}, result.AuthSchemes)
	require.Empty(t, result.ProbeError)
	require.Len(t, result.Attempts, 1)
	require.True(t, result.Attempts[0].Success)
	require.Equal(t, http.StatusUnauthorized, result.Attempts[0].StatusCode)
}

func TestProbeWINRMDetails_Weak401IsFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertWINRMIdentifyRequest(t, r, "weak401.test")
		w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
		w.Header().Add("WWW-Authenticate", "Negotiate")
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "<html><body>login required</body></html>")
	}))
	defer server.Close()

	host, port := httpTestTarget(t, server.URL)
	result := probeWINRMDetails(context.Background(), host, "weak401.test", port, WINRMProbeOptions{
		TotalTimeout:   2500 * time.Millisecond,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
	})

	require.False(t, result.WINRMProbe)
	require.False(t, result.AuthRequired)
	require.False(t, result.IdentifySupported)
	require.Equal(t, "http_response_invalid", result.ProbeError)
	require.Len(t, result.Attempts, 1)
	require.False(t, result.Attempts[0].Success)
	require.Equal(t, "http_response_invalid", result.Attempts[0].Error)
}

func TestProbeWINRMDetails_InvalidHTTPResponse(t *testing.T) {
	ln := mustListenTCP(t, "127.0.0.1:0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HELLO\r\n")
	}()
	defer func() {
		_ = ln.Close()
		<-done
	}()

	host, port, err := splitHostPort(ln.Addr().String())
	require.NoError(t, err)
	result := probeWINRMDetails(context.Background(), host, "", port, WINRMProbeOptions{
		TotalTimeout:   1500 * time.Millisecond,
		ConnectTimeout: 300 * time.Millisecond,
		IOTimeout:      300 * time.Millisecond,
	})

	require.False(t, result.WINRMProbe)
	require.Equal(t, "http_response_invalid", result.ProbeError)
	require.Len(t, result.Attempts, 1)
	require.Equal(t, "http_response_invalid", result.Attempts[0].Error)
}

func TestProbeWINRMDetails_ConnectFailure(t *testing.T) {
	result := probeWINRMDetails(context.Background(), "127.0.0.1", "", 1, WINRMProbeOptions{
		TotalTimeout:   1200 * time.Millisecond,
		ConnectTimeout: 200 * time.Millisecond,
		IOTimeout:      200 * time.Millisecond,
	})

	require.False(t, result.WINRMProbe)
	require.Equal(t, "connect_failed", result.ProbeError)
	require.Len(t, result.Attempts, 1)
	require.Equal(t, "connect_failed", result.Attempts[0].Error)
}

func TestProbeWINRMDetails_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/soap+xml; charset=UTF-8")
		_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"></s:Envelope>`)
	}))
	defer server.Close()

	host, port := httpTestTarget(t, server.URL)
	result := probeWINRMDetails(context.Background(), host, "", port, WINRMProbeOptions{
		TotalTimeout:   300 * time.Millisecond,
		ConnectTimeout: 100 * time.Millisecond,
		IOTimeout:      100 * time.Millisecond,
	})

	require.False(t, result.WINRMProbe)
	require.Equal(t, "timeout", result.ProbeError)
	require.Len(t, result.Attempts, 1)
	require.Equal(t, "timeout", result.Attempts[0].Error)
}

func httpTestTarget(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)
	host, port, err := splitHostPort(parsed.Host)
	require.NoError(t, err)
	return host, port
}

func assertWINRMIdentifyRequest(t *testing.T, r *http.Request, expectedHost string) {
	t.Helper()
	require.Equal(t, http.MethodPost, r.Method)
	require.Equal(t, winrmEndpointPath, r.URL.Path)
	require.Equal(t, expectedHost, r.Host)
	require.Equal(t, "application/soap+xml; charset=UTF-8", r.Header.Get("Content-Type"))
	require.Equal(t, "application/soap+xml, application/xml, text/xml", r.Header.Get("Accept"))
	require.Equal(t, winrmIdentifyUserAgent, r.Header.Get("User-Agent"))

	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	require.Equal(t, winrmIdentifyEnvelope, strings.TrimSpace(string(body)))
}

// Both arms of the identify step, at the level of the classifier. They answer
// the same code today, and this says so on purpose: the two arms describe
// different facts and the vocabulary does not separate them yet.
func TestClassifyWINRMIdentifyError_BothWaysToHaveNoIdentity(t *testing.T) {
	require.Equal(t, string(ProbeCodeIdentifyFailed),
		string(classifyWINRMIdentifyError(errors.New("XML syntax error on line 1"), false)),
		"a body that is not well-formed XML")
	require.Equal(t, string(ProbeCodeIdentifyFailed),
		string(classifyWINRMIdentifyError(nil, false)),
		"well-formed XML carrying no IdentifyResponse")

	// The control. Without this the two lines above would pass just as well if
	// the function returned identify_failed unconditionally, and the success
	// arm -- the one that lets a real WinRM host through -- would be gone.
	require.Empty(t, string(classifyWINRMIdentifyError(nil, true)),
		"an IdentifyResponse was found and nothing failed")

	// A parse error wins over a found element, because a parser that errored
	// did not finish and what it reported finding is not trustworthy.
	require.Equal(t, string(ProbeCodeIdentifyFailed),
		string(classifyWINRMIdentifyError(errors.New("unexpected EOF"), true)))
}

// The same two arms driven end to end, which is what says the code moving into
// a classifier changed nothing a caller can see: both still answer
// identify_failed, in ProbeError and on the attempt, and both still stop the
// probe.
func TestProbeWINRMDetails_A200WithNoIdentityIsIdentifyFailed(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "the body is not well-formed XML",
			body: `<?xml version="1.0"?><s:Envelope><s:Body><wsmid:IdentifyResponse`,
		},
		{
			// A 200 that parses cleanly and is simply not an identify
			// response. The parser refused nothing here.
			name: "well-formed XML with no IdentifyResponse",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body><s:Fault><s:Reason><s:Text>Access is denied.</s:Text></s:Reason></s:Fault></s:Body>
</s:Envelope>`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/soap+xml; charset=UTF-8")
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()

			host, port := httpTestTarget(t, server.URL)
			result := probeWINRMDetails(context.Background(), host, "winrm.test", port, WINRMProbeOptions{
				TotalTimeout:   2500 * time.Millisecond,
				ConnectTimeout: 800 * time.Millisecond,
				IOTimeout:      800 * time.Millisecond,
				// One retry is allowed on purpose. With Retries at 0 the loop
				// runs once whatever the branch does, and the attempt count
				// below could not tell "stopped" from "looped again".
				Retries: 1,
			})

			// WINRMProbe stays false: it is set only on the paths that
			// confirm WinRM, and this is not one of them. Asserted rather
			// than skipped, because it is the difference between "we probed
			// and it is not WinRM" and "we never probed".
			require.False(t, result.WINRMProbe)
			require.Equal(t, http.StatusOK, result.HTTPStatusCode)
			require.False(t, result.IdentifySupported)
			require.Equal(t, "identify_failed", result.ProbeError)
			require.Len(t, result.Attempts, 1, "the probe should stop rather than retry a 200 it cannot read")
			require.False(t, result.Attempts[0].Success)
			require.Equal(t, "identify_failed", result.Attempts[0].Error)
		})
	}
}

func TestClassifyWINRMProbeError_TLSHandshake(t *testing.T) {
	err := &net.OpError{Err: errorString("tls: handshake failure")}
	require.Equal(t, "tls_handshake_failed", string(classifyWINRMProbeError(err)))
}
