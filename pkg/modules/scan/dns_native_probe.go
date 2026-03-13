package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	dnsNativeProbeModuleID          = "dns-native-probe-instance"
	dnsNativeProbeModuleName        = "dns-native-probe"
	dnsNativeProbeModuleDescription = "Runs bounded native DNS probes against TCP/53 and UDP/53 and emits structured DNS metadata."

	dnsTransportUDP = "udp"
	dnsTransportTCP = "tcp"

	dnsStrategyRootNS      = "dns-root-ns"
	dnsStrategyVersionBind = "dns-version-bind"
	dnsVersionBindName     = "version.bind."
	dnsResponseMaxBytes    = 64 * 1024
)

type DNSProbeOptions struct {
	TotalTimeout   time.Duration `json:"total_timeout"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	IOTimeout      time.Duration `json:"io_timeout"`
	Retries        int           `json:"retries"`
}

type DNSProbeAttempt struct {
	Strategy    string `json:"strategy"`
	Transport   string `json:"transport"`
	Success     bool   `json:"success"`
	DurationMS  int64  `json:"duration_ms"`
	ResponseCode string `json:"response_code,omitempty"`
	Error       string `json:"error,omitempty"`
}

type DNSServiceInfo struct {
	Target               string            `json:"target"`
	Port                 int               `json:"port"`
	Transport            string            `json:"transport,omitempty"`
	DNSProbe             bool              `json:"dns_probe"`
	NSQueryResponded     bool              `json:"ns_query_responded"`
	VersionBindResponded bool              `json:"version_bind_responded"`
	VersionBindSupported bool              `json:"version_bind_supported"`
	ResponseCode         string            `json:"response_code,omitempty"`
	RecursionAvailable   bool              `json:"recursion_available"`
	AuthoritativeAnswer  bool              `json:"authoritative_answer"`
	TruncatedResponse    bool              `json:"truncated_response"`
	NSRecords            []string          `json:"ns_records,omitempty"`
	VersionBind          string            `json:"version_bind,omitempty"`
	VendorHint           string            `json:"vendor_hint,omitempty"`
	ProductHint          string            `json:"product_hint,omitempty"`
	VersionHint          string            `json:"version_hint,omitempty"`
	ProbeError           string            `json:"probe_error,omitempty"`
	Attempts             []DNSProbeAttempt `json:"attempts,omitempty"`
}

type dnsNativeProbeModule struct {
	meta    engine.ModuleMetadata
	options DNSProbeOptions
}

type dnsProbeCandidate struct {
	target    string
	port      int
	transport string
}

type dnsQueryResponse struct {
	responded          bool
	supported          bool
	responseCode       string
	recursionAvailable bool
	authoritative      bool
	truncated          bool
	nsRecords          []string
	versionBind        string
	vendorHint         string
	productHint        string
	versionHint        string
}

type dnsAttemptPlan struct {
	strategy   string
	name       string
	qtype      dnsmessage.Type
	class      dnsmessage.Class
	recursion  bool
}

var (
	probeDNSDetailsFunc = probeDNSDetails

	errDNSNoResponse = errors.New("dns no response")
	errDNSInvalid    = errors.New("dns invalid response")
	errDNSMismatch   = errors.New("dns protocol mismatch")
)

func newDNSNativeProbeModule() *dnsNativeProbeModule {
	return &dnsNativeProbeModule{
		meta: engine.ModuleMetadata{
			ID:          dnsNativeProbeModuleID,
			Name:        dnsNativeProbeModuleName,
			Description: dnsNativeProbeModuleDescription,
			Version:     "0.1.0",
			Type:        engine.ScanModuleType,
			Author:      "Vulntor Team",
			Tags:        []string{"scan", "dns", "native_probe", "enrichment"},
			Consumes: []engine.DataContractEntry{
				{
					Key:          "discovery.open_tcp_ports",
					DataTypeName: "discovery.TCPPortDiscoveryResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   true,
					Description:  "Open TCP ports used to identify DNS TCP candidates.",
				},
				{
					Key:          "discovery.open_udp_ports",
					DataTypeName: "discovery.UDPPortDiscoveryResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   true,
					Description:  "Open UDP ports used to identify DNS UDP candidates.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key:          "service.dns.details",
					DataTypeName: "scan.DNSServiceInfo",
					Cardinality:  engine.CardinalityList,
					Description:  "Structured DNS native probe output per target, port, and transport.",
				},
			},
			ConfigSchema: buildTCPNativeProbeConfigSchema(
				"2s",
				"800ms",
				"700ms",
				nil,
			),
		},
		options: defaultDNSProbeOptions(),
	}
}

func (m *dnsNativeProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *dnsNativeProbeModule) Init(instanceID string, configMap map[string]any) error {
	opts := defaultDNSProbeOptions()
	initCommonTCPProbeOptions(&m.meta, instanceID, configMap, &opts.TotalTimeout, &opts.ConnectTimeout, &opts.IOTimeout, &opts.Retries)
	m.options = opts
	return nil
}

func (m *dnsNativeProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	candidates := make(map[string]dnsProbeCandidate)
	if rawOpenTCPPorts, ok := inputs["discovery.open_tcp_ports"]; ok {
		for _, item := range toAnySlice(rawOpenTCPPorts) {
			for _, candidate := range dnsCandidatesFromOpenTCPPorts(item) {
				candidates[dnsCandidateKey(candidate)] = candidate
			}
		}
	}
	if rawOpenUDPPorts, ok := inputs["discovery.open_udp_ports"]; ok {
		for _, item := range toAnySlice(rawOpenUDPPorts) {
			for _, candidate := range dnsCandidatesFromOpenUDPPorts(item) {
				candidates[dnsCandidateKey(candidate)] = candidate
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	keys := make([]string, 0, len(candidates))
	for key := range candidates {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left := candidates[keys[i]]
		right := candidates[keys[j]]
		if left.target == right.target {
			if left.port == right.port {
				return left.transport < right.transport
			}
			return left.port < right.port
		}
		return left.target < right.target
	})

	for _, key := range keys {
		candidate := candidates[key]
		result := probeDNSDetailsFunc(ctx, candidate.target, candidate.port, candidate.transport, m.options)
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "service.dns.details",
			Data:           result,
			Timestamp:      time.Now(),
			Target:         candidate.target,
		}
	}

	return nil
}

func defaultDNSProbeOptions() DNSProbeOptions {
	return DNSProbeOptions{
		TotalTimeout:   2 * time.Second,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      700 * time.Millisecond,
		Retries:        0,
	}
}

func dnsCandidatesFromOpenTCPPorts(item any) []dnsProbeCandidate {
	result, ok := item.(discovery.TCPPortDiscoveryResult)
	if !ok || strings.TrimSpace(result.Target) == "" {
		return nil
	}
	candidates := make([]dnsProbeCandidate, 0, 1)
	for _, port := range result.OpenPorts {
		if port != 53 {
			continue
		}
		candidates = append(candidates, dnsProbeCandidate{
			target:    strings.TrimSpace(result.Target),
			port:      port,
			transport: dnsTransportTCP,
		})
	}
	return candidates
}

func dnsCandidatesFromOpenUDPPorts(item any) []dnsProbeCandidate {
	result, ok := item.(discovery.UDPPortDiscoveryResult)
	if !ok || strings.TrimSpace(result.Target) == "" {
		return nil
	}
	candidates := make([]dnsProbeCandidate, 0, 1)
	for _, port := range result.OpenPorts {
		if port != 53 {
			continue
		}
		candidates = append(candidates, dnsProbeCandidate{
			target:    strings.TrimSpace(result.Target),
			port:      port,
			transport: dnsTransportUDP,
		})
	}
	return candidates
}

func dnsCandidateKey(candidate dnsProbeCandidate) string {
	return fmt.Sprintf("%s:%d/%s", strings.TrimSpace(candidate.target), candidate.port, candidate.transport)
}

func probeDNSDetails(ctx context.Context, target string, port int, transport string, options DNSProbeOptions) DNSServiceInfo {
	result := DNSServiceInfo{
		Target:    strings.TrimSpace(target),
		Port:      port,
		Transport: strings.TrimSpace(transport),
	}
	if result.Target == "" || result.Port <= 0 || (result.Transport != dnsTransportUDP && result.Transport != dnsTransportTCP) {
		result.ProbeError = "no_candidate"
		return result
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if options.TotalTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.TotalTimeout)
		defer cancel()
	}

	plans := []dnsAttemptPlan{
		{
			strategy:  dnsStrategyRootNS,
			name:      ".",
			qtype:     dnsmessage.TypeNS,
			class:     dnsmessage.ClassINET,
			recursion: true,
		},
		{
			strategy:  dnsStrategyVersionBind,
			name:      dnsVersionBindName,
			qtype:     dnsmessage.TypeTXT,
			class:     dnsmessage.ClassCHAOS,
			recursion: false,
		},
	}

	var firstValid *dnsQueryResponse
	var nsResponse *dnsQueryResponse
	var versionResponse *dnsQueryResponse
	var errorsSeen []string

	for idx, plan := range plans {
		response, attempt, attemptErr := executeDNSAttempt(ctx, result.Target, result.Port, result.Transport, options, plan, uint16(idx+1))
		result.Attempts = append(result.Attempts, attempt)
		if attempt.Error != "" {
			errorsSeen = append(errorsSeen, attempt.Error)
		}
		if attemptErr != nil || !response.responded {
			continue
		}
		result.DNSProbe = true
		if firstValid == nil {
			copied := response
			firstValid = &copied
		}
		switch plan.strategy {
		case dnsStrategyRootNS:
			result.NSQueryResponded = true
			copied := response
			nsResponse = &copied
			if len(response.nsRecords) > 0 {
				result.NSRecords = append([]string(nil), response.nsRecords...)
			}
		case dnsStrategyVersionBind:
			result.VersionBindResponded = true
			if response.supported {
				result.VersionBindSupported = true
				result.VersionBind = strings.TrimSpace(response.versionBind)
				result.VendorHint = strings.TrimSpace(response.vendorHint)
				result.ProductHint = strings.TrimSpace(response.productHint)
				result.VersionHint = strings.TrimSpace(response.versionHint)
			}
			copied := response
			versionResponse = &copied
		}
	}

	selected := selectDNSPrimaryResponse(versionResponse, nsResponse, firstValid)
	if selected != nil {
		result.ResponseCode = selected.responseCode
		result.RecursionAvailable = selected.recursionAvailable
		result.AuthoritativeAnswer = selected.authoritative
		result.TruncatedResponse = selected.truncated
	}

	if result.DNSProbe {
		return result
	}

	result.ProbeError = pickTopDNSProbeError(errorsSeen)
	if result.ProbeError == "" {
		result.ProbeError = "probe_failed"
	}
	return result
}

func executeDNSAttempt(
	ctx context.Context,
	target string,
	port int,
	transport string,
	options DNSProbeOptions,
	plan dnsAttemptPlan,
	queryID uint16,
) (dnsQueryResponse, DNSProbeAttempt, error) {
	start := time.Now()
	attempt := DNSProbeAttempt{
		Strategy:  plan.strategy,
		Transport: transport,
	}

	packet, err := buildDNSQuery(plan, queryID)
	if err != nil {
		attempt.DurationMS = time.Since(start).Milliseconds()
		attempt.Error = "probe_failed"
		return dnsQueryResponse{}, attempt, err
	}

	var responsePacket []byte
	switch transport {
	case dnsTransportUDP:
		responsePacket, err = executeUDPDNSQuery(ctx, target, port, options, packet)
	case dnsTransportTCP:
		responsePacket, err = executeTCPDNSQuery(ctx, target, port, options, packet)
	default:
		err = errDNSMismatch
	}
	if err != nil {
		attempt.DurationMS = time.Since(start).Milliseconds()
		attempt.Error = classifyDNSAttemptError(err, transport)
		return dnsQueryResponse{}, attempt, err
	}

	response, err := parseDNSResponse(responsePacket, queryID, plan)
	attempt.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		attempt.Error = classifyDNSParseError(responsePacket, err)
		return dnsQueryResponse{}, attempt, err
	}

	attempt.Success = response.responded
	attempt.ResponseCode = response.responseCode
	return response, attempt, nil
}

func executeUDPDNSQuery(ctx context.Context, target string, port int, options DNSProbeOptions, packet []byte) ([]byte, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, dnsTransportUDP, net.JoinHostPort(target, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(options.IOTimeout)
	if options.IOTimeout <= 0 {
		deadline = time.Now().Add(700 * time.Millisecond)
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}

	response := make([]byte, dnsResponseMaxBytes)
	n, err := conn.Read(response)
	if err != nil {
		if isTimeoutError(err) {
			return nil, errDNSNoResponse
		}
		return nil, err
	}
	return response[:n], nil
}

func executeTCPDNSQuery(ctx context.Context, target string, port int, options DNSProbeOptions, packet []byte) ([]byte, error) {
	dialer := net.Dialer{Timeout: options.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, dnsTransportTCP, net.JoinHostPort(target, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(options.IOTimeout)
	if options.IOTimeout <= 0 {
		deadline = time.Now().Add(700 * time.Millisecond)
	}
	_ = conn.SetDeadline(deadline)

	frame := make([]byte, 2+len(packet))
	frame[0] = byte(len(packet) >> 8)
	frame[1] = byte(len(packet))
	copy(frame[2:], packet)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}

	lengthPrefix := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthPrefix); err != nil {
		if isTimeoutError(err) {
			return nil, errDNSNoResponse
		}
		return nil, err
	}
	length := int(lengthPrefix[0])<<8 | int(lengthPrefix[1])
	if length <= 0 || length > dnsResponseMaxBytes {
		return nil, errDNSMismatch
	}
	response := make([]byte, length)
	if _, err := io.ReadFull(conn, response); err != nil {
		if isTimeoutError(err) {
			return nil, errDNSNoResponse
		}
		return nil, err
	}
	return response, nil
}

func buildDNSQuery(plan dnsAttemptPlan, queryID uint16) ([]byte, error) {
	header := dnsmessage.Header{
		ID:                 queryID,
		Response:           false,
		OpCode:             0,
		RecursionDesired:   plan.recursion,
		RecursionAvailable: false,
	}
	builder := dnsmessage.NewBuilder(nil, header)
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	name, err := dnsmessage.NewName(plan.name)
	if err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  name,
		Type:  plan.qtype,
		Class: plan.class,
	}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

func parseDNSResponse(packet []byte, expectedID uint16, plan dnsAttemptPlan) (dnsQueryResponse, error) {
	if len(packet) < 12 {
		return dnsQueryResponse{}, errDNSMismatch
	}

	var message dnsmessage.Message
	if err := message.Unpack(packet); err != nil {
		return dnsQueryResponse{}, err
	}
	if !message.Header.Response {
		return dnsQueryResponse{}, errDNSMismatch
	}
	if message.Header.ID != expectedID {
		return dnsQueryResponse{}, errDNSMismatch
	}
	if len(message.Questions) == 0 {
		return dnsQueryResponse{}, errDNSInvalid
	}

	response := dnsQueryResponse{
		responded:          true,
		responseCode:       dnsRCodeName(message.Header.RCode),
		recursionAvailable: message.Header.RecursionAvailable,
		authoritative:      message.Header.Authoritative,
		truncated:          message.Header.Truncated,
	}

	switch plan.strategy {
	case dnsStrategyRootNS:
		response.nsRecords = collectDNSNSRecords(message)
	case dnsStrategyVersionBind:
		response.versionBind, response.supported = collectDNSVersionBindTXT(message)
		if response.supported {
			response.vendorHint, response.productHint, response.versionHint = deriveDNSVersionHints(response.versionBind)
		}
	}

	return response, nil
}

func collectDNSNSRecords(message dnsmessage.Message) []string {
	records := make([]string, 0, len(message.Answers)+len(message.Authorities))
	appendRecord := func(body dnsmessage.ResourceBody) {
		nsBody, ok := body.(*dnsmessage.NSResource)
		if !ok {
			return
		}
		value := strings.TrimSpace(nsBody.NS.String())
		if value == "" {
			return
		}
		records = append(records, value)
	}
	for _, answer := range message.Answers {
		appendRecord(answer.Body)
	}
	for _, authority := range message.Authorities {
		appendRecord(authority.Body)
	}
	slices.Sort(records)
	return slices.Compact(records)
}

func collectDNSVersionBindTXT(message dnsmessage.Message) (string, bool) {
	for _, answer := range message.Answers {
		txtBody, ok := answer.Body.(*dnsmessage.TXTResource)
		if !ok {
			continue
		}
		value := strings.TrimSpace(strings.Join(txtBody.TXT, ""))
		if value == "" {
			continue
		}
		return value, true
	}
	return "", false
}

func deriveDNSVersionHints(versionBind string) (string, string, string) {
	value := strings.TrimSpace(versionBind)
	if value == "" {
		return "", "", ""
	}

	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "powerdns recursor"):
		return "PowerDNS", "PowerDNS Recursor", extractDNSVersionToken(value)
	case strings.Contains(lower, "powerdns authoritative"):
		return "PowerDNS", "PowerDNS Authoritative Server", extractDNSVersionToken(value)
	case strings.Contains(lower, "microsoft dns"):
		return "Microsoft", "Microsoft DNS", extractDNSVersionToken(value)
	case strings.Contains(lower, "dnsmasq"):
		return "dnsmasq Project", "dnsmasq", extractDNSVersionToken(value)
	case strings.Contains(lower, "unbound"):
		return "NLnet Labs", "Unbound", extractDNSVersionToken(value)
	case strings.Contains(lower, "bind"):
		return "ISC", "BIND", extractDNSVersionToken(value)
	default:
		return "", "", ""
	}
}

func extractDNSVersionToken(value string) string {
	fields := strings.Fields(strings.TrimSpace(value))
	for _, field := range fields {
		field = strings.Trim(field, "(),;")
		hasDigit := false
		for _, ch := range field {
			if ch >= '0' && ch <= '9' {
				hasDigit = true
				break
			}
		}
		if hasDigit {
			return field
		}
	}
	return ""
}

func selectDNSPrimaryResponse(versionResponse, nsResponse, firstValid *dnsQueryResponse) *dnsQueryResponse {
	if versionResponse != nil && versionResponse.supported {
		return versionResponse
	}
	if nsResponse != nil && nsResponse.responded {
		return nsResponse
	}
	return firstValid
}

func classifyDNSAttemptError(err error, transport string) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errDNSNoResponse):
		return "no_response"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case isTimeoutError(err):
		if transport == dnsTransportUDP {
			return "no_response"
		}
		return "timeout"
	case errors.Is(err, errDNSMismatch):
		return "protocol_mismatch"
	case strings.Contains(strings.ToLower(err.Error()), "connect:"):
		return "connect_failed"
	case strings.Contains(strings.ToLower(err.Error()), "connection refused"):
		return "connect_failed"
	default:
		return "query_failed"
	}
}

func classifyDNSParseError(packet []byte, err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errDNSMismatch):
		return "protocol_mismatch"
	case len(packet) < 12:
		return "protocol_mismatch"
	default:
		return "decode_error"
	}
}

func pickTopDNSProbeError(errorsSeen []string) string {
	order := []string{
		"timeout",
		"connect_failed",
		"no_response",
		"decode_error",
		"protocol_mismatch",
		"query_failed",
		"probe_failed",
	}
	for _, candidate := range order {
		for _, errValue := range errorsSeen {
			if errValue == candidate {
				return candidate
			}
		}
	}
	return ""
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func dnsRCodeName(code dnsmessage.RCode) string {
	switch code {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE_%d", code)
	}
}

func dnsNativeProbeModuleFactory() engine.Module {
	return newDNSNativeProbeModule()
}

func init() {
	engine.RegisterModuleFactory(dnsNativeProbeModuleName, dnsNativeProbeModuleFactory)
}
