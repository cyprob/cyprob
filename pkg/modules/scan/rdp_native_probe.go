package scan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

const (
	rdpNativeProbeModuleID          = "rdp-native-probe-instance"
	rdpNativeProbeModuleName        = "rdp-native-probe"
	rdpNativeProbeModuleDescription = "Runs protocol-aware RDP X.224 probe and emits structured RDP metadata."
)

// RDPProbeOptions controls timeout and retry behavior for RDP native probe.
type RDPProbeOptions struct {
	TotalTimeout   time.Duration `json:"total_timeout"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	IOTimeout      time.Duration `json:"io_timeout"`
	Retries        int           `json:"retries"`
}

// RDPProbeAttempt represents one probe strategy attempt.
type RDPProbeAttempt struct {
	Strategy         string `json:"strategy"`
	Transport        string `json:"transport"`
	Success          bool   `json:"success"`
	DurationMS       int64  `json:"duration_ms"`
	Error            string `json:"error,omitempty"`
	Detected         string `json:"detected,omitempty"`
	SelectedProtocol string `json:"selected_protocol,omitempty"`
}

// RDPServiceInfo is the canonical RDP native probe output.
type RDPServiceInfo struct {
	Target           string            `json:"target"`
	Port             int               `json:"port"`
	RDPProbe         bool              `json:"rdp_probe,omitempty"`
	RDPDetected      string            `json:"rdp_detected,omitempty"`
	SelectedProtocol string            `json:"selected_protocol,omitempty"`
	NLACapable       *bool             `json:"nla_capable,omitempty"`
	TLSCapable       *bool             `json:"tls_capable,omitempty"`
	NegFailureCode   string            `json:"neg_failure_code,omitempty"`
	Error            string            `json:"probe_error,omitempty"`
	Attempts         []RDPProbeAttempt `json:"attempts,omitempty"`
}

type rdpNativeProbeModule struct {
	meta    engine.ModuleMetadata
	options RDPProbeOptions
}

type rdpProbeStrategy struct {
	name               string
	includeCookie      bool
	requestedProtocols uint32
}

type rdpProbeOutcome struct {
	detected            string
	selectedProtocol    string
	hasSelectedProtocol bool
	nlaCapable          bool
	tlsCapable          bool
	negFailureCode      string
	duration            time.Duration
}

var probeRDPDetailsFunc = probeRDPDetails

func newRDPNativeProbeModuleWithSpec(moduleID string, moduleName string, description string, outputKey string, tags []string) *rdpNativeProbeModule {
	return &rdpNativeProbeModule{
		meta: engine.ModuleMetadata{
			ID:          moduleID,
			Name:        moduleName,
			Description: description,
			Version:     "0.1.0",
			Type:        engine.ScanModuleType,
			Author:      "Vulntor Team",
			Tags:        tags,
			Consumes: []engine.DataContractEntry{
				{
					Key:          "discovery.open_tcp_ports",
					DataTypeName: "discovery.TCPPortDiscoveryResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   true,
					Description:  "Open TCP ports used to identify RDP candidate services.",
				},
				{
					Key:          "service.banner.tcp",
					DataTypeName: "scan.BannerGrabResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   true,
					Description:  "Banner results used as fallback RDP candidate source.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key:          outputKey,
					DataTypeName: "scan.RDPServiceInfo",
					Cardinality:  engine.CardinalityList,
					Description:  "Structured RDP native probe output per target and port.",
				},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				"timeout": {
					Description: "Total timeout budget per target (e.g. 2s).",
					Type:        "duration",
					Required:    false,
					Default:     "2s",
				},
				"connect_timeout": {
					Description: "TCP connect timeout per attempt.",
					Type:        "duration",
					Required:    false,
					Default:     "1s",
				},
				"io_timeout": {
					Description: "Read/write timeout per attempt.",
					Type:        "duration",
					Required:    false,
					Default:     "1s",
				},
				"retries": {
					Description: "Retry count per strategy.",
					Type:        "int",
					Required:    false,
					Default:     0,
				},
			},
		},
		options: defaultRDPProbeOptions(),
	}
}

func newRDPNativeProbeModule() *rdpNativeProbeModule {
	return newRDPNativeProbeModuleWithSpec(
		rdpNativeProbeModuleID,
		rdpNativeProbeModuleName,
		rdpNativeProbeModuleDescription,
		"service.rdp.details",
		[]string{"scan", "rdp", "enrichment", "native_probe"},
	)
}

func (m *rdpNativeProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *rdpNativeProbeModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	opts := defaultRDPProbeOptions()
	if configMap != nil {
		if d, ok := parseDurationConfig(configMap["timeout"]); ok && d > 0 {
			opts.TotalTimeout = d
		}
		if d, ok := parseDurationConfig(configMap["connect_timeout"]); ok && d > 0 {
			opts.ConnectTimeout = d
		}
		if d, ok := parseDurationConfig(configMap["io_timeout"]); ok && d > 0 {
			opts.IOTimeout = d
		}
		if retries, ok := configMap["retries"].(int); ok && retries >= 0 {
			opts.Retries = retries
		}
		if retries, ok := configMap["retries"].(float64); ok && retries >= 0 {
			opts.Retries = int(retries)
		}
	}
	m.options = opts
	return nil
}

func (m *rdpNativeProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	candidates := make(map[string]struct {
		target string
		port   int
	})

	if rawOpenPorts, ok := inputs["discovery.open_tcp_ports"]; ok {
		for _, item := range toAnySlice(rawOpenPorts) {
			for _, candidate := range rdpCandidatesFromOpenPorts(item) {
				key := fmt.Sprintf("%s:%d", candidate.target, candidate.port)
				candidates[key] = candidate
			}
		}
	}

	if rawBanner, ok := inputs["service.banner.tcp"]; ok {
		for _, item := range toAnySlice(rawBanner) {
			target, port := rdpCandidateFromBanner(item)
			if target == "" || port <= 0 {
				continue
			}
			key := fmt.Sprintf("%s:%d", target, port)
			candidates[key] = struct {
				target string
				port   int
			}{target: target, port: port}
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	keys := make([]string, 0, len(candidates))
	for key := range candidates {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		candidate := candidates[key]
		result := probeRDPDetailsFunc(ctx, candidate.target, candidate.port, m.options)
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

func rdpCandidatesFromOpenPorts(item any) []struct {
	target string
	port   int
} {
	candidates := make([]struct {
		target string
		port   int
	}, 0, 2)

	appendCandidate := func(target string, port int) {
		if strings.TrimSpace(target) == "" || port != 3389 {
			return
		}
		candidates = append(candidates, struct {
			target string
			port   int
		}{target: strings.TrimSpace(target), port: port})
	}

	switch v := item.(type) {
	case discovery.TCPPortDiscoveryResult:
		for _, p := range v.OpenPorts {
			appendCandidate(v.Target, p)
		}
	case map[string]any:
		target, _ := v["target"].(string)
		switch rawPorts := v["open_ports"].(type) {
		case []any:
			for _, rawPort := range rawPorts {
				switch p := rawPort.(type) {
				case int:
					appendCandidate(target, p)
				case float64:
					appendCandidate(target, int(p))
				}
			}
		case []int:
			for _, p := range rawPorts {
				appendCandidate(target, p)
			}
		}
	}

	return candidates
}

func rdpCandidateFromBanner(item any) (string, int) {
	switch v := item.(type) {
	case BannerGrabResult:
		if v.Port == 3389 || bannerLooksLikeRDP(v) {
			return strings.TrimSpace(v.IP), v.Port
		}
	case map[string]any:
		target, _ := v["ip"].(string)
		if target == "" {
			target, _ = v["IP"].(string)
		}
		if strings.TrimSpace(target) == "" {
			return "", 0
		}

		port := 0
		switch pv := v["port"].(type) {
		case int:
			port = pv
		case int64:
			port = int(pv)
		case float64:
			port = int(pv)
		}
		if port <= 0 {
			return "", 0
		}
		if port == 3389 {
			return strings.TrimSpace(target), port
		}

		protocol, _ := v["protocol"].(string)
		banner, _ := v["banner"].(string)
		if containsRDPHint(protocol) || containsRDPHint(banner) || mapEvidenceLooksLikeRDP(v["evidence"]) {
			return strings.TrimSpace(target), port
		}
	}
	return "", 0
}

func bannerLooksLikeRDP(b BannerGrabResult) bool {
	if containsRDPHint(b.Protocol) || containsRDPHint(b.Banner) {
		return true
	}
	for _, obs := range b.Evidence {
		if containsRDPHint(obs.Protocol) || containsRDPHint(obs.ProbeID) || containsRDPHint(obs.Description) {
			return true
		}
	}
	return false
}

func mapEvidenceLooksLikeRDP(raw any) bool {
	items, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if containsRDPHint(getMapString(m, "protocol", "Protocol")) ||
			containsRDPHint(getMapString(m, "probe_id", "ProbeID")) ||
			containsRDPHint(getMapString(m, "description", "Description")) {
			return true
		}
	}
	return false
}

func getMapString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		v, ok := m[key].(string)
		if ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func containsRDPHint(value string) bool {
	clean := strings.ToLower(strings.TrimSpace(value))
	if clean == "" {
		return false
	}
	return strings.Contains(clean, "rdp") ||
		strings.Contains(clean, "ms-wbt-server") ||
		strings.Contains(clean, "mstshash")
}

func defaultRDPProbeOptions() RDPProbeOptions {
	return RDPProbeOptions{
		TotalTimeout:   2 * time.Second,
		ConnectTimeout: time.Second,
		IOTimeout:      time.Second,
		Retries:        0,
	}
}

func buildRDPProbeStrategies() []rdpProbeStrategy {
	return []rdpProbeStrategy{
		{name: "x224-cookie", includeCookie: true, requestedProtocols: 0x00000003},
		{name: "x224-no-cookie", includeCookie: false, requestedProtocols: 0x00000003},
		{name: "x224-rdp-security", includeCookie: false, requestedProtocols: 0x00000000},
	}
}

func probeRDPDetails(ctx context.Context, target string, port int, opts RDPProbeOptions) RDPServiceInfo {
	if port <= 0 {
		port = 3389
	}
	if opts.TotalTimeout <= 0 {
		opts.TotalTimeout = 2 * time.Second
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = time.Second
	}
	if opts.IOTimeout <= 0 {
		opts.IOTimeout = time.Second
	}
	if opts.Retries < 0 {
		opts.Retries = 0
	}

	probeCtx, cancel := context.WithTimeout(ctx, opts.TotalTimeout)
	defer cancel()

	result := RDPServiceInfo{
		Target:   target,
		Port:     port,
		Attempts: make([]RDPProbeAttempt, 0, len(buildRDPProbeStrategies())*(opts.Retries+1)),
	}

	bestScore := -1
	var bestOutcome rdpProbeOutcome
	errorCodes := make([]string, 0, len(result.Attempts))

	for _, strategy := range buildRDPProbeStrategies() {
		for retry := 0; retry <= opts.Retries; retry++ {
			outcome, err := probeSingleRDPStrategy(probeCtx, target, port, strategy, opts)
			if err != nil {
				code := classifyRDPProbeError(err)
				errorCodes = append(errorCodes, code)
				result.Attempts = append(result.Attempts, RDPProbeAttempt{
					Strategy:   strategy.name,
					Transport:  strconv.Itoa(port),
					Success:    false,
					DurationMS: outcome.duration.Milliseconds(),
					Error:      code,
				})
				continue
			}

			result.Attempts = append(result.Attempts, RDPProbeAttempt{
				Strategy:         strategy.name,
				Transport:        strconv.Itoa(port),
				Success:          true,
				DurationMS:       outcome.duration.Milliseconds(),
				Detected:         outcome.detected,
				SelectedProtocol: outcome.selectedProtocol,
			})

			score := scoreRDPProbeOutcome(outcome)
			if score > bestScore {
				bestScore = score
				bestOutcome = outcome
			}
		}
	}

	if bestScore >= 0 {
		result.RDPProbe = true
		result.RDPDetected = bestOutcome.detected
		result.SelectedProtocol = bestOutcome.selectedProtocol
		if bestOutcome.hasSelectedProtocol {
			result.NLACapable = boolPtr(bestOutcome.nlaCapable)
			result.TLSCapable = boolPtr(bestOutcome.tlsCapable)
		}
		result.NegFailureCode = bestOutcome.negFailureCode
		result.Error = ""
		return result
	}

	result.RDPProbe = false
	result.Error = pickTopRDPProbeError(errorCodes)
	if result.Error == "" {
		result.Error = "probe_failed"
	}
	return result
}

func probeSingleRDPStrategy(
	ctx context.Context,
	target string,
	port int,
	strategy rdpProbeStrategy,
	opts RDPProbeOptions,
) (rdpProbeOutcome, error) {
	start := time.Now()
	outcome := rdpProbeOutcome{}

	address := net.JoinHostPort(target, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: opts.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		outcome.duration = time.Since(start)
		return outcome, err
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			return
		}
	}()

	if err := conn.SetDeadline(time.Now().Add(opts.IOTimeout)); err != nil {
		outcome.duration = time.Since(start)
		return outcome, err
	}

	req := buildRDPConnectionRequest(strategy.includeCookie, strategy.requestedProtocols)
	if _, err := conn.Write(req); err != nil {
		outcome.duration = time.Since(start)
		return outcome, err
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		outcome.duration = time.Since(start)
		return outcome, err
	}
	if n < 7 {
		outcome.duration = time.Since(start)
		return outcome, errors.New("short_rdp_response")
	}

	detected := detectRDPResponseKind(resp[:n])
	if detected == "" {
		outcome.duration = time.Since(start)
		return outcome, errors.New("unknown_rdp_response")
	}

	selectedProtocol, hasSelectedProtocol, nlaCapable, tlsCapable, negFailureCode := parseRDPNegotiationMetadata(resp[:n])
	outcome.detected = detected
	outcome.selectedProtocol = selectedProtocol
	outcome.hasSelectedProtocol = hasSelectedProtocol
	outcome.nlaCapable = nlaCapable
	outcome.tlsCapable = tlsCapable
	outcome.negFailureCode = negFailureCode
	outcome.duration = time.Since(start)
	return outcome, nil
}

func buildRDPConnectionRequest(includeCookie bool, requestedProtocols uint32) []byte {
	payload := []byte{
		0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR TPDU
	}

	if includeCookie {
		payload = append(payload, []byte("Cookie: mstshash=cyprob\r\n")...)
	}

	negReq := make([]byte, 8)
	negReq[0] = 0x01
	negReq[1] = 0x00
	negReq[2] = 0x08
	negReq[3] = 0x00
	binary.LittleEndian.PutUint32(negReq[4:], requestedProtocols)
	payload = append(payload, negReq...)

	// X.224 starts with LI (length indicator), then TPDU payload.
	x224 := append([]byte{byte(len(payload))}, payload...)
	totalLen := len(x224) + 4

	req := make([]byte, totalLen)
	req[0] = 0x03
	req[1] = 0x00
	binary.BigEndian.PutUint16(req[2:4], uint16(totalLen))
	copy(req[4:], x224)
	return req
}

func detectRDPResponseKind(resp []byte) string {
	if len(resp) < 7 || resp[0] != 0x03 || resp[1] != 0x00 {
		return ""
	}
	if resp[5] == 0xD0 {
		return "x224-confirm"
	}
	return "tpkt"
}

func parseRDPNegotiationMetadata(resp []byte) (string, bool, bool, bool, string) {
	start := 0
	if len(resp) >= 4 && resp[0] == 0x03 && resp[1] == 0x00 {
		start = 4
	}

	for i := start; i+8 <= len(resp); i++ {
		msgType := resp[i]
		if msgType != 0x02 && msgType != 0x03 {
			continue
		}
		if resp[i+2] != 0x08 || resp[i+3] != 0x00 {
			continue
		}

		value := binary.LittleEndian.Uint32(resp[i+4 : i+8])
		if msgType == 0x02 {
			selectedProtocol, nlaCapable, tlsCapable := mapRDPSelectedProtocol(value)
			return selectedProtocol, true, nlaCapable, tlsCapable, ""
		}
		return "", false, false, false, mapRDPNegotiationFailureCode(value)
	}

	return "", false, false, false, ""
}

func mapRDPSelectedProtocol(value uint32) (string, bool, bool) {
	switch value {
	case 0x00000000:
		return "rdp", false, false
	case 0x00000001:
		return "tls", false, true
	case 0x00000002:
		return "hybrid", true, true
	case 0x00000008:
		return "hybrid_ex", true, true
	default:
		return "unknown", false, false
	}
}

func mapRDPNegotiationFailureCode(code uint32) string {
	switch code {
	case 0x00000001:
		return "ssl_required_by_server"
	case 0x00000002:
		return "ssl_not_allowed_by_server"
	case 0x00000003:
		return "ssl_cert_not_on_server"
	case 0x00000004:
		return "inconsistent_flags"
	case 0x00000005:
		return "hybrid_required_by_server"
	case 0x00000006:
		return "ssl_with_user_auth_required_by_server"
	default:
		return fmt.Sprintf("0x%08x", code)
	}
}

func scoreRDPProbeOutcome(outcome rdpProbeOutcome) int {
	score := 0
	switch strings.TrimSpace(outcome.detected) {
	case "x224-confirm":
		score += 4
	case "tpkt":
		score += 2
	}
	if outcome.hasSelectedProtocol {
		if strings.TrimSpace(outcome.selectedProtocol) != "" && outcome.selectedProtocol != "unknown" {
			score += 2
		} else {
			score++
		}
	}
	if strings.TrimSpace(outcome.negFailureCode) != "" {
		score++
	}
	return score
}

func classifyRDPProbeError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"), strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case strings.Contains(msg, "connection refused"):
		return "refused"
	case strings.Contains(msg, "short_rdp_response"):
		return "short_response"
	case strings.Contains(msg, "unknown_rdp_response"):
		return "unknown_response"
	default:
		return "probe_failed"
	}
}

func pickTopRDPProbeError(codes []string) string {
	if len(codes) == 0 {
		return ""
	}

	priority := map[string]int{
		"timeout":          5,
		"refused":          4,
		"short_response":   3,
		"unknown_response": 2,
		"probe_failed":     1,
	}

	best := ""
	bestPriority := -1
	for _, code := range codes {
		if p := priority[code]; p > bestPriority {
			best = code
			bestPriority = p
		}
	}
	return best
}

func boolPtr(value bool) *bool {
	v := value
	return &v
}

func rdpNativeProbeModuleFactory() engine.Module {
	return newRDPNativeProbeModule()
}

func init() {
	engine.RegisterModuleFactory(rdpNativeProbeModuleName, rdpNativeProbeModuleFactory)
}
