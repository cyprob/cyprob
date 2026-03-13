package scan

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

const (
	winrmNativeProbeModuleID          = "winrm-native-probe-instance"
	winrmNativeProbeModuleName        = "winrm-native-probe"
	winrmNativeProbeModuleDescription = "Runs bounded native WinRM Identify probes and emits structured WS-Management metadata."

	winrmEndpointPath        = "/wsman"
	winrmIdentifyUserAgent   = "cyprob-winrm-probe/1"
	winrmResponseBodyMaxSize = 64 * 1024
)

const winrmIdentifyEnvelope = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Body><wsmid:Identify/></s:Body></s:Envelope>`

type WINRMProbeOptions struct {
	TotalTimeout   time.Duration `json:"total_timeout"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	IOTimeout      time.Duration `json:"io_timeout"`
	Retries        int           `json:"retries"`
}

type WINRMProbeAttempt struct {
	Strategy      string `json:"strategy"`
	Transport     string `json:"transport"`
	Success       bool   `json:"success"`
	DurationMS    int64  `json:"duration_ms"`
	StatusCode    int    `json:"status_code,omitempty"`
	Error         string `json:"error,omitempty"`
	TLSVersion    string `json:"tls_version,omitempty"`
	CipherSuite   string `json:"cipher_suite,omitempty"`
}

type WINRMServiceInfo struct {
	Target               string               `json:"target"`
	Port                 int                  `json:"port"`
	WINRMProbe           bool                 `json:"winrm_probe"`
	WINRMTransport       string               `json:"winrm_transport,omitempty"`
	EndpointPath         string               `json:"endpoint_path,omitempty"`
	HTTPStatusCode       int                  `json:"http_status_code,omitempty"`
	ServerHeader         string               `json:"server_header,omitempty"`
	ContentType          string               `json:"content_type,omitempty"`
	AuthSchemes          []string             `json:"auth_schemes,omitempty"`
	AuthRequired         bool                 `json:"auth_required"`
	IdentifySupported    bool                 `json:"identify_supported"`
	ServiceHint          string               `json:"service_hint,omitempty"`
	WSMANProtocolVersion string               `json:"wsman_protocol_version,omitempty"`
	ProductVendor        string               `json:"product_vendor,omitempty"`
	ProductVersion       string               `json:"product_version,omitempty"`
	TLSEnabled           bool                 `json:"tls_enabled"`
	TLSVersion           string               `json:"tls_version,omitempty"`
	TLSCipherSuite       string               `json:"tls_cipher_suite,omitempty"`
	CertSubjectCN        string               `json:"cert_subject_cn,omitempty"`
	CertIssuer           string               `json:"cert_issuer,omitempty"`
	CertNotAfter         time.Time            `json:"cert_not_after,omitempty"`
	CertIsSelfSigned     bool                 `json:"cert_is_self_signed"`
	ProbeError           string               `json:"probe_error,omitempty"`
	Attempts             []WINRMProbeAttempt  `json:"attempts,omitempty"`
}

type winrmNativeProbeModule struct {
	meta    engine.ModuleMetadata
	options WINRMProbeOptions
}

type winrmProbeCandidate struct {
	target   string
	hostname string
	port     int
}

type winrmHTTPResult struct {
	statusCode   int
	serverHeader string
	contentType  string
	authSchemes  []string
	body         []byte
	tlsObs       *engine.TLSObservation
	duration     time.Duration
}

var probeWINRMDetailsFunc = probeWINRMDetails

func newWINRMNativeProbeModule() *winrmNativeProbeModule {
	return &winrmNativeProbeModule{
		meta: buildTCPNativeProbeMetadata(tcpNativeProbeMetadataSpec{
			moduleID:              winrmNativeProbeModuleID,
			moduleName:            winrmNativeProbeModuleName,
			description:           winrmNativeProbeModuleDescription,
			outputKey:             "service.winrm.details",
			outputType:            "scan.WINRMServiceInfo",
			outputDescription:     "Structured WinRM native probe output per target and port.",
			tags:                  []string{"scan", "winrm", "wsman", "native_probe", "enrichment"},
			consumes:              []engine.DataContractEntry{nativeOpenTCPPortsConsume(false, "Open TCP ports used to identify WinRM candidate services."), nativeOriginalTargetsConsume("Original CLI targets used to preserve hostname for Host header and TLS SNI fallback.")},
			timeoutDefault:        "2500ms",
			connectTimeoutDefault: "800ms",
			ioTimeoutDefault:      "800ms",
		}),
		options: defaultWINRMProbeOptions(),
	}
}

func (m *winrmNativeProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *winrmNativeProbeModule) Init(instanceID string, configMap map[string]any) error {
	opts := defaultWINRMProbeOptions()
	initCommonTCPProbeOptions(&m.meta, instanceID, configMap, &opts.TotalTimeout, &opts.ConnectTimeout, &opts.IOTimeout, &opts.Retries)
	m.options = opts
	return nil
}

func (m *winrmNativeProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	rawOpenPorts, ok := inputs["discovery.open_tcp_ports"]
	if !ok {
		return nil
	}

	fallbackHostname := resolveSingleNonIPHostnameTarget(readOriginalTargets(inputs))
	candidates := make(map[string]winrmProbeCandidate)
	for _, item := range toAnySlice(rawOpenPorts) {
		for _, candidate := range winrmCandidatesFromOpenPorts(item) {
			if existing, exists := candidates[winrmCandidateKey(candidate)]; exists {
				if existing.hostname == "" && candidate.hostname != "" {
					existing.hostname = candidate.hostname
					candidates[winrmCandidateKey(candidate)] = existing
				}
				continue
			}
			candidates[winrmCandidateKey(candidate)] = candidate
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	if fallbackHostname != "" {
		for key, candidate := range candidates {
			if candidate.hostname != "" {
				continue
			}
			candidate.hostname = fallbackHostname
			candidates[key] = candidate
		}
	}

	keys := make([]string, 0, len(candidates))
	for key := range candidates {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left := candidates[keys[i]]
		right := candidates[keys[j]]
		if left.target == right.target {
			return left.port < right.port
		}
		return left.target < right.target
	})

	currentTarget := ""
	var targetCtx context.Context
	var cancel context.CancelFunc
	defer func() {
		if cancel != nil {
			cancel()
		}
	}()

	for _, key := range keys {
		candidate := candidates[key]
		if candidate.target != currentTarget {
			if cancel != nil {
				cancel()
			}
			currentTarget = candidate.target
			targetCtx = ctx
			cancel = nil
			if m.options.TotalTimeout > 0 {
				targetCtx, cancel = context.WithTimeout(ctx, m.options.TotalTimeout)
			}
		}

		result := probeWINRMDetailsFunc(targetCtx, candidate.target, candidate.hostname, candidate.port, m.options)
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        m.meta.Produces[0].Key,
			Data:           result,
			Timestamp:      time.Now(),
			Target:         candidate.target,
		}
	}

	return nil
}

func defaultWINRMProbeOptions() WINRMProbeOptions {
	return WINRMProbeOptions{
		TotalTimeout:   2500 * time.Millisecond,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
		Retries:        0,
	}
}

func winrmCandidatesFromOpenPorts(item any) []winrmProbeCandidate {
	candidates := make([]winrmProbeCandidate, 0, 2)
	appendCandidate := func(target, hostname string, port int) {
		target = strings.TrimSpace(target)
		hostname = normalizeNonIPHostname(hostname)
		if target == "" {
			return
		}
		if port != 5985 && port != 5986 {
			return
		}
		candidates = append(candidates, winrmProbeCandidate{
			target:   target,
			hostname: hostname,
			port:     port,
		})
	}

	switch v := item.(type) {
	case discovery.TCPPortDiscoveryResult:
		for _, port := range v.OpenPorts {
			appendCandidate(v.Target, v.Hostname, port)
		}
	case map[string]any:
		target := getMapString(v, "target", "Target")
		hostname := getMapString(v, "hostname", "Hostname")
		switch ports := v["open_ports"].(type) {
		case []int:
			for _, port := range ports {
				appendCandidate(target, hostname, port)
			}
		case []any:
			for _, item := range ports {
				switch port := item.(type) {
				case int:
					appendCandidate(target, hostname, port)
				case float64:
					appendCandidate(target, hostname, int(port))
				}
			}
		}
	}

	return candidates
}

func winrmCandidateKey(candidate winrmProbeCandidate) string {
	return fmt.Sprintf("%s:%d", candidate.target, candidate.port)
}

func probeWINRMDetails(ctx context.Context, target string, hostname string, port int, opts WINRMProbeOptions) WINRMServiceInfo {
	if port <= 0 {
		port = 5985
	}
	if opts.TotalTimeout <= 0 {
		opts.TotalTimeout = 2500 * time.Millisecond
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = 800 * time.Millisecond
	}
	if opts.IOTimeout <= 0 {
		opts.IOTimeout = 800 * time.Millisecond
	}
	if opts.Retries < 0 {
		opts.Retries = 0
	}

	probeCtx, cancel := context.WithTimeout(ctx, opts.TotalTimeout)
	defer cancel()

	result := WINRMServiceInfo{
		Target:         target,
		Port:           port,
		WINRMTransport: winrmTransportFromPort(port),
		EndpointPath:   winrmEndpointPath,
		Attempts:       make([]WINRMProbeAttempt, 0, opts.Retries+1),
	}

	errorCodes := make([]string, 0, opts.Retries+1)
	for retry := 0; retry <= opts.Retries; retry++ {
		httpResult, err := executeWINRMRequest(probeCtx, target, hostname, port, result.WINRMTransport, opts)
		if err != nil {
			code := classifyWINRMProbeError(err)
			errorCodes = append(errorCodes, code)
			attempt := WINRMProbeAttempt{
				Strategy:   "winrm-identify",
				Transport:  result.WINRMTransport,
				Success:    false,
				DurationMS: httpResult.duration.Milliseconds(),
				Error:      code,
			}
			applyWINRMTLSObservation(&result, &attempt, httpResult.tlsObs)
			result.Attempts = append(result.Attempts, attempt)
			continue
		}

		result.HTTPStatusCode = httpResult.statusCode
		result.ServerHeader = strings.TrimSpace(httpResult.serverHeader)
		result.ContentType = strings.TrimSpace(httpResult.contentType)
		result.AuthSchemes = append([]string(nil), httpResult.authSchemes...)
		strong401 := isConfirmedWINRM401(httpResult)

		switch {
		case httpResult.statusCode == http.StatusOK:
			protocolVersion, productVendor, productVersion, ok, parseErr := parseWINRMIdentifyResponse(httpResult.body)
			if parseErr != nil {
				errorCodes = append(errorCodes, "identify_failed")
				attempt := WINRMProbeAttempt{
					Strategy:   "winrm-identify",
					Transport:  result.WINRMTransport,
					Success:    false,
					DurationMS: httpResult.duration.Milliseconds(),
					StatusCode: httpResult.statusCode,
					Error:      "identify_failed",
				}
				applyWINRMTLSObservation(&result, &attempt, httpResult.tlsObs)
				result.Attempts = append(result.Attempts, attempt)
				result.ProbeError = "identify_failed"
				return result
			}
			if !ok {
				errorCodes = append(errorCodes, "identify_failed")
				attempt := WINRMProbeAttempt{
					Strategy:   "winrm-identify",
					Transport:  result.WINRMTransport,
					Success:    false,
					DurationMS: httpResult.duration.Milliseconds(),
					StatusCode: httpResult.statusCode,
					Error:      "identify_failed",
				}
				applyWINRMTLSObservation(&result, &attempt, httpResult.tlsObs)
				result.Attempts = append(result.Attempts, attempt)
				result.ProbeError = "identify_failed"
				return result
			}

			attempt := WINRMProbeAttempt{
				Strategy:   "winrm-identify",
				Transport:  result.WINRMTransport,
				Success:    true,
				DurationMS: httpResult.duration.Milliseconds(),
				StatusCode: httpResult.statusCode,
			}
			applyWINRMTLSObservation(&result, &attempt, httpResult.tlsObs)
			result.Attempts = append(result.Attempts, attempt)
			result.WINRMProbe = true
			result.AuthRequired = false
			result.IdentifySupported = true
			result.ServiceHint = "WinRM"
			result.WSMANProtocolVersion = strings.TrimSpace(protocolVersion)
			result.ProductVendor = strings.TrimSpace(productVendor)
			result.ProductVersion = strings.TrimSpace(productVersion)
			result.ProbeError = ""
			return result
		case httpResult.statusCode == http.StatusUnauthorized && strong401:
			attempt := WINRMProbeAttempt{
				Strategy:   "winrm-identify",
				Transport:  result.WINRMTransport,
				Success:    true,
				DurationMS: httpResult.duration.Milliseconds(),
				StatusCode: httpResult.statusCode,
			}
			applyWINRMTLSObservation(&result, &attempt, httpResult.tlsObs)
			result.Attempts = append(result.Attempts, attempt)
			result.WINRMProbe = true
			result.AuthRequired = true
			result.IdentifySupported = false
			result.ServiceHint = "WinRM"
			result.ProbeError = ""
			return result
		default:
			errorCode := "protocol_mismatch"
			if httpResult.statusCode == http.StatusUnauthorized {
				errorCode = "http_response_invalid"
			}
			errorCodes = append(errorCodes, errorCode)
			attempt := WINRMProbeAttempt{
				Strategy:   "winrm-identify",
				Transport:  result.WINRMTransport,
				Success:    false,
				DurationMS: httpResult.duration.Milliseconds(),
				StatusCode: httpResult.statusCode,
				Error:      errorCode,
			}
			applyWINRMTLSObservation(&result, &attempt, httpResult.tlsObs)
			result.Attempts = append(result.Attempts, attempt)
		}
	}

	result.ProbeError = pickTopWINRMProbeError(errorCodes)
	if result.ProbeError == "" {
		result.ProbeError = "probe_failed"
	}
	return result
}

func executeWINRMRequest(ctx context.Context, target string, hostname string, port int, transport string, opts WINRMProbeOptions) (winrmHTTPResult, error) {
	result := winrmHTTPResult{}
	scheme := "http"
	if transport == "https" {
		scheme = "https"
	}

	endpoint := url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(strings.TrimSpace(target), strconv.Itoa(port)),
		Path:   winrmEndpointPath,
	}

	dialer := &net.Dialer{Timeout: effectiveProbeTimeout(ctx, opts.ConnectTimeout)}
	var tlsState *tls.ConnectionState
	trace := &httptrace.ClientTrace{
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err != nil {
				return
			}
			copyState := state
			tlsState = &copyState
		},
	}

	transportConfig := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: effectiveProbeTimeout(ctx, opts.IOTimeout),
		TLSHandshakeTimeout:   effectiveProbeTimeout(ctx, opts.IOTimeout),
	}
	if scheme == "https" {
		transportConfig.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // Native probe gathers metadata from untrusted targets.
			ServerName:         winrmTLSServerName(hostname, target),
		}
	}

	client := &http.Client{
		Transport: transportConfig,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: effectiveProbeTimeout(ctx, opts.ConnectTimeout+opts.IOTimeout),
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost, endpoint.String(), strings.NewReader(winrmIdentifyEnvelope))
	if err != nil {
		return result, err
	}
	req.Close = true
	req.Host = winrmRequestHost(hostname, target)
	req.Header.Set("User-Agent", winrmIdentifyUserAgent)
	req.Header.Set("Content-Type", "application/soap+xml; charset=UTF-8")
	req.Header.Set("Accept", "application/soap+xml, application/xml, text/xml")
	req.Header.Set("Connection", "close")

	start := time.Now()
	resp, err := client.Do(req)
	result.duration = time.Since(start)
	if err != nil {
		if tlsState != nil {
			result.tlsObs = extractTLSObservation(*tlsState)
		}
		return result, err
	}
	defer resp.Body.Close()

	result.statusCode = resp.StatusCode
	result.serverHeader = resp.Header.Get("Server")
	result.contentType = resp.Header.Get("Content-Type")
	result.authSchemes = extractWINRMAuthSchemes(resp.Header.Values("WWW-Authenticate"))
	if tlsState != nil {
		result.tlsObs = extractTLSObservation(*tlsState)
	}

	body, readErr := readWINRMBody(resp.Body, winrmResponseBodyMaxSize)
	if readErr != nil {
		return result, readErr
	}
	result.body = body
	return result, nil
}

func readWINRMBody(body io.Reader, maxBytes int64) ([]byte, error) {
	if body == nil || maxBytes <= 0 {
		return nil, nil
	}
	limited := io.LimitReader(body, maxBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return raw[:maxBytes], nil
	}
	return raw, nil
}

func parseWINRMIdentifyResponse(body []byte) (string, string, string, bool, error) {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	inIdentify := false
	currentField := ""
	protocolVersion := ""
	productVendor := ""
	productVersion := ""
	foundIdentify := false

	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", "", "", false, err
		}

		switch typed := token.(type) {
		case xml.StartElement:
			switch strings.ToLower(strings.TrimSpace(typed.Name.Local)) {
			case "identifyresponse":
				inIdentify = true
				foundIdentify = true
				currentField = ""
			case "protocolversion", "productvendor", "productversion":
				if inIdentify {
					currentField = strings.ToLower(strings.TrimSpace(typed.Name.Local))
				}
			default:
				currentField = ""
			}
		case xml.EndElement:
			switch strings.ToLower(strings.TrimSpace(typed.Name.Local)) {
			case "identifyresponse":
				inIdentify = false
			}
			currentField = ""
		case xml.CharData:
			if !inIdentify || currentField == "" {
				continue
			}
			value := strings.TrimSpace(string(typed))
			if value == "" {
				continue
			}
			switch currentField {
			case "protocolversion":
				if protocolVersion == "" {
					protocolVersion = value
				}
			case "productvendor":
				if productVendor == "" {
					productVendor = value
				}
			case "productversion":
				if productVersion == "" {
					productVersion = value
				}
			}
		}
	}

	return protocolVersion, productVendor, productVersion, foundIdentify, nil
}

func extractWINRMAuthSchemes(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	authSchemes := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			fields := strings.Fields(strings.TrimSpace(part))
			if len(fields) == 0 {
				continue
			}
			scheme := canonicalWINRMAuthScheme(fields[0])
			if scheme == "" {
				continue
			}
			if _, ok := seen[scheme]; ok {
				continue
			}
			seen[scheme] = struct{}{}
			authSchemes = append(authSchemes, scheme)
		}
	}
	return authSchemes
}

func canonicalWINRMAuthScheme(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "negotiate":
		return "Negotiate"
	case "ntlm":
		return "NTLM"
	case "kerberos":
		return "Kerberos"
	case "basic":
		return "Basic"
	default:
		return ""
	}
}

func isConfirmedWINRM401(result winrmHTTPResult) bool {
	if result.statusCode != http.StatusUnauthorized {
		return false
	}
	if !strings.Contains(strings.ToLower(strings.TrimSpace(result.serverHeader)), "microsoft-httpapi/2.0") {
		return false
	}
	if !hasWINRMAuthScheme(result.authSchemes) {
		return false
	}
	if !hasWINRMSOAPSignal(result.contentType, result.body) {
		return false
	}
	return true
}

func hasWINRMAuthScheme(values []string) bool {
	for _, value := range values {
		switch strings.TrimSpace(value) {
		case "Negotiate", "NTLM", "Kerberos":
			return true
		}
	}
	return false
}

func hasWINRMSOAPSignal(contentType string, body []byte) bool {
	if strings.Contains(strings.ToLower(strings.TrimSpace(contentType)), "application/soap+xml") {
		return true
	}
	bodyText := strings.ToLower(string(body))
	return strings.Contains(bodyText, "schemas.dmtf.org/wbem/wsman") ||
		strings.Contains(bodyText, "wsmanfault") ||
		strings.Contains(bodyText, "identifyresponse")
}

func applyWINRMTLSObservation(result *WINRMServiceInfo, attempt *WINRMProbeAttempt, tlsObs *engine.TLSObservation) {
	if result == nil || tlsObs == nil {
		return
	}
	result.TLSEnabled = true
	result.TLSVersion = strings.TrimSpace(tlsObs.Version)
	result.TLSCipherSuite = strings.TrimSpace(tlsObs.CipherSuite)
	result.CertSubjectCN = strings.TrimSpace(tlsObs.PeerCommonName)
	result.CertIssuer = strings.TrimSpace(tlsObs.Issuer)
	result.CertNotAfter = tlsObs.NotAfter
	result.CertIsSelfSigned = tlsObs.IsSelfSigned
	if attempt != nil {
		attempt.TLSVersion = strings.TrimSpace(tlsObs.Version)
		attempt.CipherSuite = strings.TrimSpace(tlsObs.CipherSuite)
	}
}

func classifyWINRMProbeError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(message, "timeout"), strings.Contains(message, "deadline exceeded"), strings.Contains(message, "i/o timeout"):
		return "timeout"
	case strings.Contains(message, "malformed http response"), strings.Contains(message, "bad status"), strings.Contains(message, "unexpected eof"):
		return "http_response_invalid"
	case strings.Contains(message, "tls"), strings.Contains(message, "x509"), strings.Contains(message, "certificate"), strings.Contains(message, "handshake"):
		return "tls_handshake_failed"
	case strings.Contains(message, "connection refused"), strings.Contains(message, "dial tcp"), strings.Contains(message, "connect:"):
		return "connect_failed"
	default:
		return "http_request_failed"
	}
}

func pickTopWINRMProbeError(codes []string) string {
	best := ""
	bestPriority := -1
	for _, code := range codes {
		if priority := winrmProbeErrorPriority(code); priority > bestPriority {
			bestPriority = priority
			best = code
		}
	}
	return best
}

func winrmProbeErrorPriority(code string) int {
	switch strings.TrimSpace(code) {
	case "timeout":
		return 7
	case "connect_failed":
		return 6
	case "tls_handshake_failed":
		return 5
	case "http_request_failed":
		return 4
	case "http_response_invalid":
		return 3
	case "identify_failed":
		return 2
	case "protocol_mismatch":
		return 1
	default:
		return 0
	}
}

func winrmTransportFromPort(port int) string {
	if port == 5986 {
		return "https"
	}
	return "http"
}

func winrmRequestHost(hostname string, target string) string {
	if host := normalizeNonIPHostname(hostname); host != "" {
		return host
	}
	return strings.TrimSpace(target)
}

func winrmTLSServerName(hostname string, target string) string {
	if host := normalizeNonIPHostname(hostname); host != "" {
		return host
	}
	target = strings.TrimSpace(target)
	if target == "" || net.ParseIP(target) != nil {
		return ""
	}
	return target
}

func winrmNativeProbeModuleFactory() engine.Module {
	return newWINRMNativeProbeModule()
}

func init() {
	engine.RegisterModuleFactory(winrmNativeProbeModuleName, winrmNativeProbeModuleFactory)
}
