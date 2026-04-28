package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

const (
	telnetNativeProbeModuleID          = "telnet-native-probe-instance"
	telnetNativeProbeModuleName        = "telnet-native-probe"
	telnetNativeProbeModuleDescription = "Runs bounded Telnet banner and option negotiation probes to emit structured Telnet metadata."

	telnetCommandIAC  = 255
	telnetCommandDONT = 254
	telnetCommandDO   = 253
	telnetCommandWONT = 252
	telnetCommandWILL = 251
	telnetCommandSB   = 250
	telnetCommandSE   = 240

	telnetTranscriptMaxBytes = 4096
	telnetBannerMaxBytes     = 512
)

type TelnetProbeOptions struct {
	TotalTimeout   time.Duration `json:"total_timeout"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	IOTimeout      time.Duration `json:"io_timeout"`
	Retries        int           `json:"retries"`
	CandidatePorts []int         `json:"candidate_ports,omitempty"`
}

type TelnetProbeAttempt struct {
	Strategy   string `json:"strategy"`
	Transport  string `json:"transport"`
	Success    bool   `json:"success"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

type TelnetServiceInfo struct {
	Target             string               `json:"target"`
	Port               int                  `json:"port"`
	TelnetProbe        bool                 `json:"telnet_probe"`
	TelnetProtocol     string               `json:"telnet_protocol,omitempty"`
	Banner             string               `json:"banner,omitempty"`
	IACDetected        bool                 `json:"iac_detected"`
	NegotiationOptions []string             `json:"negotiation_options,omitempty"`
	ProductHint        string               `json:"product_hint,omitempty"`
	VendorHint         string               `json:"vendor_hint,omitempty"`
	VersionHint        string               `json:"version_hint,omitempty"`
	ProbeError         string               `json:"probe_error,omitempty"`
	Attempts           []TelnetProbeAttempt `json:"attempts,omitempty"`
}

type telnetNativeProbeModule struct {
	meta    engine.ModuleMetadata
	options TelnetProbeOptions
}

type telnetProbeCandidate struct {
	target string
	port   int
}

type telnetTranscriptOutcome struct {
	banner             string
	iacDetected        bool
	negotiationOptions []string
	productHint        string
	vendorHint         string
	versionHint        string
}

var (
	probeTelnetDetailsFunc = probeTelnetDetails

	telnetBusyBoxPattern   = regexp.MustCompile(`(?i)\bbusybox\s+telnetd\b(?:\s+v?([0-9][0-9a-z._-]*))?`)
	telnetCiscoPattern     = regexp.MustCompile(`(?i)\bcisco\s+ios(?:\s+software)?(?:,\s*version\s*([0-9][0-9a-z()._-]*))?`)
	telnetMikrotikPattern  = regexp.MustCompile(`(?i)\brouteros\b(?:\s+v?([0-9][0-9a-z._-]*))?|\bmikrotik\b`)
	telnetMicrosoftPattern = regexp.MustCompile(`(?i)\bmicrosoft\s+telnet\s+service\b(?:\s+v?([0-9][0-9a-z._-]*))?`)
	telnetPromptPattern    = regexp.MustCompile(`(?i)(?:^|[\r\n\s>])(login|username|user name|password)\s*[:>]`)
)

func newTelnetNativeProbeModuleWithSpec(moduleID string, moduleName string, description string, outputKey string, tags []string) *telnetNativeProbeModule {
	return &telnetNativeProbeModule{
		meta: buildTCPNativeProbeMetadata(tcpNativeProbeMetadataSpec{
			moduleID:              moduleID,
			moduleName:            moduleName,
			description:           description,
			outputKey:             outputKey,
			outputType:            "scan.TelnetServiceInfo",
			outputDescription:     "Structured Telnet native probe output per target and port.",
			tags:                  tags,
			consumes:              []engine.DataContractEntry{nativeOpenTCPPortsConsume(false, "Open TCP ports used to identify Telnet candidate services."), nativeBannerConsume("Banner results used as fallback Telnet candidate source.")},
			timeoutDefault:        "2s",
			connectTimeoutDefault: "800ms",
			ioTimeoutDefault:      "800ms",
			extraConfigParameters: map[string]engine.ParameterDefinition{
				"candidate_ports": {
					Description: "Optional explicit ports to treat as Telnet candidates when already known open.",
					Type:        "[]int",
					Required:    false,
				},
			},
		}),
		options: defaultTelnetProbeOptions(),
	}
}

func newTelnetNativeProbeModule() *telnetNativeProbeModule {
	return newTelnetNativeProbeModuleWithSpec(
		telnetNativeProbeModuleID,
		telnetNativeProbeModuleName,
		telnetNativeProbeModuleDescription,
		"service.telnet.details",
		[]string{"scan", "telnet", "enrichment", "native_probe"},
	)
}

func (m *telnetNativeProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *telnetNativeProbeModule) Init(instanceID string, configMap map[string]any) error {
	opts := defaultTelnetProbeOptions()
	initCommonTCPProbeOptions(&m.meta, instanceID, configMap, &opts.TotalTimeout, &opts.ConnectTimeout, &opts.IOTimeout, &opts.Retries)
	opts.CandidatePorts = parseOptionalPortList(configMap, "candidate_ports")
	m.options = opts
	return nil
}

func (m *telnetNativeProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	rawOpenPorts, ok := inputs["discovery.open_tcp_ports"]
	if !ok {
		return nil
	}

	explicitCandidatePorts := make(map[int]struct{}, len(m.options.CandidatePorts))
	for _, port := range m.options.CandidatePorts {
		if port > 0 && port <= 65535 {
			explicitCandidatePorts[port] = struct{}{}
		}
	}

	candidates := make(map[string]telnetProbeCandidate)
	for _, item := range toAnySlice(rawOpenPorts) {
		for _, candidate := range telnetCandidatesFromOpenPorts(item, explicitCandidatePorts) {
			candidates[telnetCandidateKey(candidate)] = candidate
		}
	}

	if rawBanner, ok := inputs["service.banner.tcp"]; ok {
		for _, item := range toAnySlice(rawBanner) {
			candidate, ok := telnetCandidateFromBanner(item, explicitCandidatePorts)
			if !ok {
				continue
			}
			candidates[telnetCandidateKey(candidate)] = candidate
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
			leftPriority := telnetPortPriority(left.port)
			rightPriority := telnetPortPriority(right.port)
			if leftPriority != rightPriority {
				return leftPriority > rightPriority
			}
			return left.port < right.port
		}
		return left.target < right.target
	})

	for _, key := range keys {
		candidate := candidates[key]
		result := probeTelnetDetailsFunc(ctx, candidate.target, candidate.port, m.options)
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

func defaultTelnetProbeOptions() TelnetProbeOptions {
	return TelnetProbeOptions{
		TotalTimeout:   2 * time.Second,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
		Retries:        0,
	}
}

func telnetCandidatesFromOpenPorts(item any, explicitCandidatePorts map[int]struct{}) []telnetProbeCandidate {
	candidates := make([]telnetProbeCandidate, 0, 2)
	appendCandidate := func(target string, port int) {
		target = strings.TrimSpace(target)
		if target == "" || port <= 0 || port > 65535 {
			return
		}
		if port != 23 {
			if _, ok := explicitCandidatePorts[port]; !ok {
				return
			}
		}
		candidates = append(candidates, telnetProbeCandidate{target: target, port: port})
	}

	switch v := item.(type) {
	case discovery.TCPPortDiscoveryResult:
		for _, port := range v.OpenPorts {
			appendCandidate(v.Target, port)
		}
	case map[string]any:
		target, _ := v["target"].(string)
		switch ports := v["open_ports"].(type) {
		case []int:
			for _, port := range ports {
				appendCandidate(target, port)
			}
		case []any:
			for _, item := range ports {
				switch port := item.(type) {
				case int:
					appendCandidate(target, port)
				case float64:
					appendCandidate(target, int(port))
				}
			}
		}
	}

	return candidates
}

func telnetCandidateFromBanner(item any, explicitCandidatePorts map[int]struct{}) (telnetProbeCandidate, bool) {
	switch v := item.(type) {
	case BannerGrabResult:
		if !isTelnetBannerCandidate(v, explicitCandidatePorts) {
			return telnetProbeCandidate{}, false
		}
		return telnetProbeCandidate{target: v.IP, port: v.Port}, true
	case map[string]any:
		banner := BannerGrabResult{}
		if ip, _ := v["ip"].(string); ip != "" {
			banner.IP = ip
		} else if target, _ := v["target"].(string); target != "" {
			banner.IP = target
		}
		banner.Port = mapIntValue(v, "port")
		banner.Protocol = mapStringValue(v, "protocol")
		banner.Banner = mapStringValue(v, "banner")
		if !isTelnetBannerCandidate(banner, explicitCandidatePorts) {
			return telnetProbeCandidate{}, false
		}
		return telnetProbeCandidate{target: banner.IP, port: banner.Port}, true
	default:
		return telnetProbeCandidate{}, false
	}
}

func isTelnetBannerCandidate(banner BannerGrabResult, explicitCandidatePorts map[int]struct{}) bool {
	if strings.TrimSpace(banner.IP) == "" || banner.Port <= 0 || banner.Port > 65535 {
		return false
	}
	if banner.Port != 23 {
		if _, ok := explicitCandidatePorts[banner.Port]; !ok && !strings.EqualFold(strings.TrimSpace(banner.Protocol), "telnet") && !bannerLooksLikeTelnet(strings.TrimSpace(banner.Banner)) {
			return false
		}
	}
	if strings.EqualFold(strings.TrimSpace(banner.Protocol), "telnet") {
		return true
	}
	if bannerLooksLikeTelnet(strings.TrimSpace(banner.Banner)) {
		return true
	}
	return false
}

func telnetCandidateKey(candidate telnetProbeCandidate) string {
	return candidate.target + ":" + strconv.Itoa(candidate.port)
}

func telnetPortPriority(port int) int {
	if port == 23 {
		return 2
	}
	return 1
}

func probeTelnetDetails(ctx context.Context, target string, port int, opts TelnetProbeOptions) TelnetServiceInfo {
	result := TelnetServiceInfo{
		Target: target,
		Port:   port,
	}
	if strings.TrimSpace(target) == "" || port <= 0 {
		result.ProbeError = "probe_failed"
		return result
	}

	attemptBudget := ctx
	cancel := func() {}
	if opts.TotalTimeout > 0 {
		attemptBudget, cancel = context.WithTimeout(ctx, opts.TotalTimeout)
	}
	defer cancel()

	maxAttempts := opts.Retries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	for attemptIndex := 0; attemptIndex < maxAttempts; attemptIndex++ {
		attempt, outcome, errCode := probeTelnetAttempt(attemptBudget, target, port, opts)
		result.Attempts = append(result.Attempts, attempt)
		if outcome != nil {
			result.Banner = outcome.banner
			result.IACDetected = outcome.iacDetected
			result.NegotiationOptions = append([]string(nil), outcome.negotiationOptions...)
			result.ProductHint = outcome.productHint
			result.VendorHint = outcome.vendorHint
			result.VersionHint = outcome.versionHint
		}
		if attempt.Success {
			result.TelnetProbe = true
			result.TelnetProtocol = "telnet"
			result.ProbeError = ""
			return result
		}
		result.ProbeError = errCode
		if !isRetryableTelnetError(errCode) {
			return result
		}
	}

	return result
}

func probeTelnetAttempt(ctx context.Context, target string, port int, opts TelnetProbeOptions) (TelnetProbeAttempt, *telnetTranscriptOutcome, string) {
	attempt := TelnetProbeAttempt{
		Strategy:  "telnet-banner-negotiation",
		Transport: "tcp",
	}
	start := time.Now()
	defer func() { attempt.DurationMS = time.Since(start).Milliseconds() }()

	dialer := net.Dialer{Timeout: opts.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target, strconv.Itoa(port)))
	if err != nil {
		attempt.Error = classifyTelnetConnectError(err)
		return attempt, nil, attempt.Error
	}
	defer conn.Close()

	if opts.IOTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(opts.IOTimeout))
	}

	payload, readErr := readTelnetPayload(conn, telnetTranscriptMaxBytes)
	if len(payload) == 0 && readErr != nil {
		attempt.Error = classifyTelnetReadError(readErr)
		return attempt, nil, attempt.Error
	}

	outcome := parseTelnetTranscript(payload)
	switch {
	case outcome.iacDetected:
		attempt.Success = true
		return attempt, &outcome, ""
	case bannerLooksLikeTelnet(outcome.banner):
		attempt.Success = true
		return attempt, &outcome, ""
	default:
		attempt.Error = "protocol_mismatch"
		return attempt, &outcome, attempt.Error
	}
}

func readTelnetPayload(conn net.Conn, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = telnetTranscriptMaxBytes
	}
	buffer := make([]byte, 0, maxBytes)
	chunk := make([]byte, 256)
	var lastErr error
	for len(buffer) < maxBytes {
		n, err := conn.Read(chunk)
		if n > 0 {
			buffer = append(buffer, chunk[:n]...)
		}
		if err != nil {
			lastErr = err
			if errors.Is(err, io.EOF) {
				break
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			break
		}
		if n == 0 {
			break
		}
	}
	return buffer, lastErr
}

func parseTelnetTranscript(payload []byte) telnetTranscriptOutcome {
	outcome := telnetTranscriptOutcome{}
	if len(payload) == 0 {
		return outcome
	}

	visible := make([]byte, 0, len(payload))
	optionSet := make(map[string]struct{})
	appendOption := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		optionSet[value] = struct{}{}
	}

	for i := 0; i < len(payload); i++ {
		b := payload[i]
		if b != telnetCommandIAC {
			if isTelnetBannerByte(b) {
				visible = append(visible, b)
			}
			continue
		}

		outcome.iacDetected = true
		if i+1 >= len(payload) {
			break
		}
		cmd := payload[i+1]
		i++
		switch cmd {
		case telnetCommandIAC:
			visible = append(visible, byte(telnetCommandIAC))
		case telnetCommandDO, telnetCommandDONT, telnetCommandWILL, telnetCommandWONT:
			if i+1 >= len(payload) {
				break
			}
			option := payload[i+1]
			i++
			appendOption(formatTelnetNegotiationOption(cmd, option))
		case telnetCommandSB:
			for i+1 < len(payload) {
				if payload[i] == telnetCommandIAC && payload[i+1] == telnetCommandSE {
					i++
					break
				}
				i++
			}
		default:
		}
	}

	if len(optionSet) > 0 {
		outcome.negotiationOptions = make([]string, 0, len(optionSet))
		for option := range optionSet {
			outcome.negotiationOptions = append(outcome.negotiationOptions, option)
		}
		sort.Strings(outcome.negotiationOptions)
	}

	outcome.banner = normalizeTelnetBanner(string(visible))
	outcome.productHint, outcome.vendorHint, outcome.versionHint = inferTelnetProductHints(outcome.banner)
	return outcome
}

func isTelnetBannerByte(b byte) bool {
	if b == '\r' || b == '\n' || b == '\t' {
		return true
	}
	return b >= 32 && b <= 126
}

func normalizeTelnetBanner(raw string) string {
	clean := strings.ReplaceAll(raw, "\r\n", "\n")
	clean = strings.ReplaceAll(clean, "\r", "\n")
	clean = strings.TrimSpace(clean)
	clean = strings.Join(strings.Fields(clean), " ")
	if len(clean) > telnetBannerMaxBytes {
		clean = clean[:telnetBannerMaxBytes]
	}
	return clean
}

func bannerLooksLikeTelnet(banner string) bool {
	clean := strings.ToLower(strings.TrimSpace(banner))
	if clean == "" {
		return false
	}
	if telnetPromptPattern.MatchString(clean) {
		return true
	}
	return strings.Contains(clean, "telnet") ||
		strings.Contains(clean, "busybox") ||
		strings.Contains(clean, "routeros") ||
		strings.Contains(clean, "mikrotik") ||
		strings.Contains(clean, "cisco ios") ||
		strings.Contains(clean, "microsoft telnet service")
}

func inferTelnetProductHints(banner string) (string, string, string) {
	switch {
	case telnetBusyBoxPattern.MatchString(banner):
		matches := telnetBusyBoxPattern.FindStringSubmatch(banner)
		return "BusyBox telnetd", "BusyBox", firstNonEmptyTelnetString(matches[1])
	case telnetCiscoPattern.MatchString(banner):
		matches := telnetCiscoPattern.FindStringSubmatch(banner)
		return "Cisco IOS", "Cisco", firstNonEmptyTelnetString(matches[1])
	case telnetMikrotikPattern.MatchString(banner):
		matches := telnetMikrotikPattern.FindStringSubmatch(banner)
		return "RouterOS Telnet", "MikroTik", firstNonEmptyTelnetString(matches[1])
	case telnetMicrosoftPattern.MatchString(banner):
		matches := telnetMicrosoftPattern.FindStringSubmatch(banner)
		return "Microsoft Telnet Service", "Microsoft", firstNonEmptyTelnetString(matches[1])
	default:
		return "", "", ""
	}
}

func formatTelnetNegotiationOption(cmd byte, option byte) string {
	return telnetCommandName(cmd) + "-" + telnetOptionName(option)
}

func telnetCommandName(cmd byte) string {
	switch cmd {
	case telnetCommandDO:
		return "do"
	case telnetCommandDONT:
		return "dont"
	case telnetCommandWILL:
		return "will"
	case telnetCommandWONT:
		return "wont"
	default:
		return fmt.Sprintf("cmd-%d", cmd)
	}
}

func telnetOptionName(option byte) string {
	switch option {
	case 0:
		return "binary"
	case 1:
		return "echo"
	case 3:
		return "suppress-go-ahead"
	case 24:
		return "terminal-type"
	case 31:
		return "naws"
	case 32:
		return "terminal-speed"
	case 33:
		return "remote-flow-control"
	case 34:
		return "linemode"
	case 39:
		return "new-environ"
	default:
		return strconv.Itoa(int(option))
	}
}

func classifyTelnetReadError(err error) string {
	if err == nil {
		return ""
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "timeout"
	}
	if errors.Is(err, io.EOF) {
		return "protocol_mismatch"
	}
	return "probe_failed"
}

func classifyTelnetConnectError(err error) string {
	if err == nil {
		return ""
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "timeout"
	}
	return "connect_failed"
}

func isRetryableTelnetError(code string) bool {
	switch code {
	case "timeout", "connect_failed", "probe_failed":
		return true
	default:
		return false
	}
}

func firstNonEmptyTelnetString(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func mapIntValue(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	default:
		return 0
	}
}

func mapStringValue(m map[string]any, key string) string {
	value, _ := m[key].(string)
	return strings.TrimSpace(value)
}

func init() {
	engine.RegisterModuleFactory(telnetNativeProbeModuleName, func() engine.Module {
		return newTelnetNativeProbeModule()
	})
}
