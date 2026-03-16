package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	Target                 string            `json:"target"`
	Port                   int               `json:"port"`
	RDPProbe               bool              `json:"rdp_probe,omitempty"`
	RDPDetected            string            `json:"rdp_detected,omitempty"`
	SelectedProtocol       string            `json:"selected_protocol,omitempty"`
	NLACapable             *bool             `json:"nla_capable,omitempty"`
	TLSCapable             *bool             `json:"tls_capable,omitempty"`
	HybridExCapable        *bool             `json:"hybridex_capable,omitempty"`
	RestrictedAdminCapable *bool             `json:"restrictedadmin_capable,omitempty"`
	RestrictedAuthCapable  *bool             `json:"restrictedauth_capable,omitempty"`
	NegFailureCode         string            `json:"neg_failure_code,omitempty"`
	CertSubjectCN          string            `json:"cert_subject_cn,omitempty"`
	CertIssuer             string            `json:"cert_issuer,omitempty"`
	CertDNSNames           []string          `json:"cert_dns_names,omitempty"`
	CertNotBefore          time.Time         `json:"cert_not_before,omitzero"`
	CertNotAfter           time.Time         `json:"cert_not_after,omitzero"`
	CertIsSelfSigned       bool              `json:"cert_is_self_signed,omitempty"`
	CertSHA256             string            `json:"cert_sha256,omitempty"`
	NTLMComputerName       string            `json:"ntlm_computer_name,omitempty"`
	NTLMDomainName         string            `json:"ntlm_domain_name,omitempty"`
	NTLMDNSComputerName    string            `json:"ntlm_dns_computer_name,omitempty"`
	NTLMDNSDomainName      string            `json:"ntlm_dns_domain_name,omitempty"`
	NTLMDNSForestName      string            `json:"ntlm_dns_forest_name,omitempty"`
	LocalTime              time.Time         `json:"local_time,omitzero"`
	OSBuild                int               `json:"os_build,omitempty"`
	OSMajorVersion         string            `json:"os_major_version,omitempty"`
	OSMinorVersion         string            `json:"os_minor_version,omitempty"`
	Error                  string            `json:"probe_error,omitempty"`
	Attempts               []RDPProbeAttempt `json:"attempts,omitempty"`
}

type rdpNativeProbeModule struct {
	meta    engine.ModuleMetadata
	options RDPProbeOptions
}

type rdpProbeStrategy struct {
	name               string
	includeCookie      bool
	flags              byte
	requestedProtocols uint32
}

type rdpProbeOutcome struct {
	detected                 string
	selectedProtocol         string
	hasSelectedProtocol      bool
	nlaCapable               bool
	tlsCapable               bool
	hybridExCapable          bool
	restrictedAdminSupported bool
	restrictedAuthSupported  bool
	negFailureCode           string
	duration                 time.Duration
}

type rdpDeepMetadata struct {
	tlsObs        *engine.TLSObservation
	certSHA256    string
	ntlmChallenge *ntlmChallengeInfo
}

var probeRDPDetailsFunc = probeRDPDetails

func newRDPNativeProbeModuleWithSpec(moduleID string, moduleName string, description string, outputKey string, tags []string) *rdpNativeProbeModule {
	return &rdpNativeProbeModule{
		meta: buildTCPNativeProbeMetadata(tcpNativeProbeMetadataSpec{
			moduleID:              moduleID,
			moduleName:            moduleName,
			description:           description,
			outputKey:             outputKey,
			outputType:            "scan.RDPServiceInfo",
			outputDescription:     "Structured RDP native probe output per target and port.",
			tags:                  tags,
			consumes:              []engine.DataContractEntry{nativeOpenTCPPortsConsume(true, "Open TCP ports used to identify RDP candidate services."), nativeBannerConsume("Banner results used as fallback RDP candidate source.")},
			timeoutDefault:        "2s",
			connectTimeoutDefault: "1s",
			ioTimeoutDefault:      "1s",
		}),
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
	opts := defaultRDPProbeOptions()
	initCommonTCPProbeOptions(&m.meta, instanceID, configMap, &opts.TotalTimeout, &opts.ConnectTimeout, &opts.IOTimeout, &opts.Retries)
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
		Attempts: make([]RDPProbeAttempt, 0, (len(buildRDPProbeStrategies())+5)*(opts.Retries+1)),
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
		enrichRDPMetadata(probeCtx, target, port, bestOutcome, opts, &result)
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

	req := buildRDPConnectionRequestWithFlags(strategy.includeCookie, strategy.flags, strategy.requestedProtocols)
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

	details := parseRDPNegotiationDetails(resp[:n])
	outcome.detected = detected
	outcome.selectedProtocol = details.selectedProtocol
	outcome.hasSelectedProtocol = details.hasSelectedProtocol
	outcome.nlaCapable = details.nlaCapable
	outcome.tlsCapable = details.tlsCapable
	outcome.hybridExCapable = details.selectedProtocol == "hybrid_ex"
	outcome.restrictedAdminSupported = details.restrictedAdminSupported
	outcome.restrictedAuthSupported = details.restrictedAuthSupported
	outcome.negFailureCode = details.negFailureCode
	outcome.duration = time.Since(start)
	return outcome, nil
}

func buildRDPConnectionRequest(includeCookie bool, requestedProtocols uint32) []byte {
	return buildRDPConnectionRequestWithFlags(includeCookie, 0, requestedProtocols)
}

func buildRDPConnectionRequestWithFlags(includeCookie bool, flags byte, requestedProtocols uint32) []byte {
	payload := []byte{
		0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR TPDU
	}

	if includeCookie {
		payload = append(payload, []byte("Cookie: mstshash=cyprob\r\n")...)
	}

	negReq := make([]byte, 8)
	negReq[0] = 0x01
	negReq[1] = flags
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

type rdpNegotiationDetails struct {
	selectedProtocol         string
	hasSelectedProtocol      bool
	nlaCapable               bool
	tlsCapable               bool
	negFailureCode           string
	restrictedAdminSupported bool
	restrictedAuthSupported  bool
}

func parseRDPNegotiationDetails(resp []byte) rdpNegotiationDetails {
	details := rdpNegotiationDetails{}
	start := 0
	if len(resp) >= 4 && resp[0] == 0x03 && resp[1] == 0x00 {
		start = 4
	}

	for i := start; i+8 <= len(resp); i++ {
		msgType := resp[i]
		if msgType != 0x02 && msgType != 0x03 {
			continue
		}
		flags := resp[i+1]
		if resp[i+2] != 0x08 || resp[i+3] != 0x00 {
			continue
		}

		details.restrictedAdminSupported = (flags & 0x08) == 0x08
		details.restrictedAuthSupported = (flags & 0x10) == 0x10
		value := binary.LittleEndian.Uint32(resp[i+4 : i+8])
		if msgType == 0x02 {
			selectedProtocol, nlaCapable, tlsCapable := mapRDPSelectedProtocol(value)
			details.selectedProtocol = selectedProtocol
			details.hasSelectedProtocol = true
			details.nlaCapable = nlaCapable
			details.tlsCapable = tlsCapable
			return details
		}
		details.negFailureCode = mapRDPNegotiationFailureCode(value)
		return details
	}

	return details
}

func parseRDPNegotiationMetadata(resp []byte) (string, bool, bool, bool, string) {
	details := parseRDPNegotiationDetails(resp)
	return details.selectedProtocol, details.hasSelectedProtocol, details.nlaCapable, details.tlsCapable, details.negFailureCode
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

func enrichRDPMetadata(ctx context.Context, target string, port int, bestOutcome rdpProbeOutcome, opts RDPProbeOptions, result *RDPServiceInfo) {
	if result == nil || strings.TrimSpace(bestOutcome.detected) != "x224-confirm" {
		return
	}

	runCapabilityProbe := func(strategy rdpProbeStrategy, assign func(rdpProbeOutcome)) {
		outcome, err := probeSingleRDPStrategy(ctx, target, port, strategy, opts)
		if err != nil {
			result.Attempts = append(result.Attempts, RDPProbeAttempt{
				Strategy:   strategy.name,
				Transport:  strconv.Itoa(port),
				Success:    false,
				DurationMS: outcome.duration.Milliseconds(),
				Error:      classifyRDPMetadataError(err),
			})
			return
		}
		result.Attempts = append(result.Attempts, RDPProbeAttempt{
			Strategy:         strategy.name,
			Transport:        strconv.Itoa(port),
			Success:          true,
			DurationMS:       outcome.duration.Milliseconds(),
			Detected:         outcome.detected,
			SelectedProtocol: outcome.selectedProtocol,
		})
		assign(outcome)
	}

	runCapabilityProbe(rdpProbeStrategy{name: "x224-hybrid-ex", requestedProtocols: 0x0000000B}, func(outcome rdpProbeOutcome) {
		if outcome.hasSelectedProtocol {
			result.HybridExCapable = boolPtr(outcome.selectedProtocol == "hybrid_ex")
		}
	})
	runCapabilityProbe(rdpProbeStrategy{name: "x224-restricted-admin", flags: 0x01, requestedProtocols: 0x0000000B}, func(outcome rdpProbeOutcome) {
		if outcome.hasSelectedProtocol || outcome.negFailureCode != "" {
			result.RestrictedAdminCapable = boolPtr(outcome.restrictedAdminSupported)
		}
	})
	runCapabilityProbe(rdpProbeStrategy{name: "x224-redirected-auth", flags: 0x02, requestedProtocols: 0x0000000B}, func(outcome rdpProbeOutcome) {
		if outcome.hasSelectedProtocol || outcome.negFailureCode != "" {
			result.RestrictedAuthCapable = boolPtr(outcome.restrictedAuthSupported)
		}
	})

	if supportsRDPNTLMMetadata(bestOutcome.selectedProtocol) {
		start := time.Now()
		metadata, err := probeRDPNTLMMetadata(ctx, target, port, bestOutcome.selectedProtocol, opts)
		if err != nil {
			result.Attempts = append(result.Attempts, RDPProbeAttempt{
				Strategy:   "rdp-ntlm-target-info",
				Transport:  strconv.Itoa(port),
				Success:    false,
				DurationMS: time.Since(start).Milliseconds(),
				Error:      classifyRDPMetadataError(err),
			})
			return
		}
		result.Attempts = append(result.Attempts, RDPProbeAttempt{
			Strategy:   "rdp-ntlm-target-info",
			Transport:  strconv.Itoa(port),
			Success:    true,
			DurationMS: time.Since(start).Milliseconds(),
		})
		applyRDPDeepMetadata(result, metadata)
		return
	}

	if supportsRDPTLSMetadata(bestOutcome.selectedProtocol, bestOutcome.tlsCapable) {
		start := time.Now()
		metadata, err := probeRDPTLSMetadata(ctx, target, port, bestOutcome.selectedProtocol, opts)
		if err != nil {
			result.Attempts = append(result.Attempts, RDPProbeAttempt{
				Strategy:   "rdp-tls-cert",
				Transport:  strconv.Itoa(port),
				Success:    false,
				DurationMS: time.Since(start).Milliseconds(),
				Error:      classifyRDPMetadataError(err),
			})
			return
		}
		result.Attempts = append(result.Attempts, RDPProbeAttempt{
			Strategy:   "rdp-tls-cert",
			Transport:  strconv.Itoa(port),
			Success:    true,
			DurationMS: time.Since(start).Milliseconds(),
		})
		applyRDPDeepMetadata(result, metadata)
	}
}

func supportsRDPNTLMMetadata(selectedProtocol string) bool {
	switch strings.TrimSpace(selectedProtocol) {
	case "hybrid", "hybrid_ex":
		return true
	default:
		return false
	}
}

func supportsRDPTLSMetadata(selectedProtocol string, tlsCapable bool) bool {
	switch strings.TrimSpace(selectedProtocol) {
	case "tls", "hybrid", "hybrid_ex":
		return true
	default:
		return tlsCapable
	}
}

func probeRDPTLSMetadata(ctx context.Context, target string, port int, selectedProtocol string, opts RDPProbeOptions) (rdpDeepMetadata, error) {
	conn, negotiated, err := dialAndNegotiateRDP(ctx, target, port, selectedProtocol, opts)
	if err != nil {
		return rdpDeepMetadata{}, err
	}
	defer func() { _ = conn.Close() }()

	if !negotiated.hasSelectedProtocol || !supportsRDPTLSMetadata(negotiated.selectedProtocol, negotiated.tlsCapable) {
		return rdpDeepMetadata{}, errors.New("protocol_mismatch")
	}

	tlsObs, certSHA256, err := upgradeRDPTLS(conn, target, opts)
	if err != nil {
		return rdpDeepMetadata{}, err
	}
	return rdpDeepMetadata{tlsObs: tlsObs, certSHA256: certSHA256}, nil
}

func probeRDPNTLMMetadata(ctx context.Context, target string, port int, selectedProtocol string, opts RDPProbeOptions) (rdpDeepMetadata, error) {
	conn, negotiated, err := dialAndNegotiateRDP(ctx, target, port, selectedProtocol, opts)
	if err != nil {
		return rdpDeepMetadata{}, err
	}
	defer func() { _ = conn.Close() }()

	if !negotiated.hasSelectedProtocol || !supportsRDPNTLMMetadata(negotiated.selectedProtocol) {
		return rdpDeepMetadata{}, errors.New("protocol_mismatch")
	}

	tlsConn, tlsObs, certSHA256, err := upgradeRDPTLSConn(conn, target, opts)
	if err != nil {
		return rdpDeepMetadata{}, err
	}
	defer func() { _ = tlsConn.Close() }()

	if err := tlsConn.SetDeadline(time.Now().Add(opts.IOTimeout)); err != nil {
		return rdpDeepMetadata{}, err
	}
	if _, err := tlsConn.Write(buildRDPCredSSPNTLMNegotiateRequest()); err != nil {
		return rdpDeepMetadata{}, err
	}

	resp, err := readRDPNTLMChallenge(tlsConn)
	if err != nil {
		return rdpDeepMetadata{}, err
	}
	challenge, err := parseNTLMChallengeInfo(resp)
	if err != nil {
		return rdpDeepMetadata{}, err
	}

	return rdpDeepMetadata{
		tlsObs:        tlsObs,
		certSHA256:    certSHA256,
		ntlmChallenge: challenge,
	}, nil
}

func dialAndNegotiateRDP(ctx context.Context, target string, port int, selectedProtocol string, opts RDPProbeOptions) (net.Conn, rdpProbeOutcome, error) {
	address := net.JoinHostPort(target, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: opts.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, rdpProbeOutcome{}, err
	}

	if err := conn.SetDeadline(time.Now().Add(opts.IOTimeout)); err != nil {
		_ = conn.Close()
		return nil, rdpProbeOutcome{}, err
	}

	requestedProtocols := requestedRDPProtocolsForSelection(selectedProtocol)
	if _, err := conn.Write(buildRDPConnectionRequestWithFlags(false, 0, requestedProtocols)); err != nil {
		_ = conn.Close()
		return nil, rdpProbeOutcome{}, err
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		_ = conn.Close()
		return nil, rdpProbeOutcome{}, err
	}
	if n < 7 {
		_ = conn.Close()
		return nil, rdpProbeOutcome{}, errors.New("short_rdp_response")
	}
	detected := detectRDPResponseKind(resp[:n])
	if detected == "" {
		_ = conn.Close()
		return nil, rdpProbeOutcome{}, errors.New("unknown_rdp_response")
	}

	details := parseRDPNegotiationDetails(resp[:n])
	return conn, rdpProbeOutcome{
		detected:                 detected,
		selectedProtocol:         details.selectedProtocol,
		hasSelectedProtocol:      details.hasSelectedProtocol,
		nlaCapable:               details.nlaCapable,
		tlsCapable:               details.tlsCapable,
		hybridExCapable:          details.selectedProtocol == "hybrid_ex",
		restrictedAdminSupported: details.restrictedAdminSupported,
		restrictedAuthSupported:  details.restrictedAuthSupported,
		negFailureCode:           details.negFailureCode,
	}, nil
}

func requestedRDPProtocolsForSelection(selectedProtocol string) uint32 {
	switch strings.TrimSpace(selectedProtocol) {
	case "tls":
		return 0x00000001
	case "hybrid":
		return 0x00000003
	case "hybrid_ex":
		return 0x0000000B
	default:
		return 0x00000003
	}
}

func upgradeRDPTLS(conn net.Conn, target string, opts RDPProbeOptions) (*engine.TLSObservation, string, error) {
	tlsConn, tlsObs, certSHA256, err := upgradeRDPTLSConn(conn, target, opts)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = tlsConn.Close() }()
	return tlsObs, certSHA256, nil
}

func upgradeRDPTLSConn(conn net.Conn, target string, opts RDPProbeOptions) (*tls.Conn, *engine.TLSObservation, string, error) {
	serverName := ""
	if parsedIP := net.ParseIP(strings.TrimSpace(target)); parsedIP == nil {
		serverName = strings.TrimSpace(target)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS10,
	})
	if err := tlsConn.SetDeadline(time.Now().Add(opts.IOTimeout)); err != nil {
		return nil, nil, "", err
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, nil, "", err
	}

	state := tlsConn.ConnectionState()
	tlsObs := extractTLSObservation(state)
	if tlsObs == nil {
		return nil, nil, "", errors.New("tls_handshake_failed")
	}

	certSHA256 := ""
	if len(state.PeerCertificates) > 0 {
		sum := sha256.Sum256(state.PeerCertificates[0].Raw)
		certSHA256 = hex.EncodeToString(sum[:])
	}
	return tlsConn, tlsObs, certSHA256, nil
}

func buildRDPCredSSPNTLMNegotiateRequest() []byte {
	ntlm := buildRDPNTLMType1Token()
	mechType := []byte{
		0xa0, 0x0e,
		0x30, 0x0c,
		0x06, 0x0a,
		0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
	}
	mechToken := asn1Wrap(0xa2, asn1Wrap(0x04, ntlm))
	negTokenInit := asn1Wrap(0xa0, asn1Wrap(0x30, append(mechType, mechToken...)))
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	spnego := asn1Wrap(0x60, append(spnegoOID, negTokenInit...))
	negoTokens := asn1Wrap(0xa1, asn1Wrap(0x30, asn1Wrap(0x30, asn1Wrap(0xa0, asn1Wrap(0x04, spnego)))))
	version := asn1Wrap(0xa0, asn1Wrap(0x02, []byte{0x06}))
	return asn1Wrap(0x30, append(version, negoTokens...))
}

func buildRDPNTLMType1Token() []byte {
	msg := make([]byte, 40)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 1)
	binary.LittleEndian.PutUint32(msg[12:16], 0xe0888235)
	return msg
}

func asn1Wrap(tag byte, content []byte) []byte {
	out := make([]byte, 0, len(content)+4)
	out = append(out, tag)
	if len(content) < 128 {
		out = append(out, byte(len(content)))
	} else {
		out = append(out, 0x81, byte(len(content)))
	}
	out = append(out, content...)
	return out
}

func readRDPNTLMChallenge(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 2048)
	for len(buf) < 16384 {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if bytes.Contains(buf, []byte("NTLMSSP\x00\x02\x00\x00\x00")) {
				return buf, nil
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(buf) > 0 {
				break
			}
			return nil, err
		}
	}
	if len(buf) == 0 {
		return nil, errors.New("ntlm_challenge_not_found")
	}
	return buf, nil
}

func applyRDPDeepMetadata(result *RDPServiceInfo, metadata rdpDeepMetadata) {
	if result == nil {
		return
	}
	if metadata.tlsObs != nil {
		result.CertSubjectCN = strings.TrimSpace(metadata.tlsObs.PeerCommonName)
		result.CertIssuer = strings.TrimSpace(metadata.tlsObs.Issuer)
		if len(metadata.tlsObs.PeerDNSNames) > 0 {
			result.CertDNSNames = append([]string(nil), metadata.tlsObs.PeerDNSNames...)
		}
		result.CertNotBefore = metadata.tlsObs.NotBefore
		result.CertNotAfter = metadata.tlsObs.NotAfter
		result.CertIsSelfSigned = metadata.tlsObs.IsSelfSigned
		result.CertSHA256 = strings.TrimSpace(metadata.certSHA256)
	}
	if metadata.ntlmChallenge == nil {
		return
	}
	result.NTLMComputerName = strings.TrimSpace(metadata.ntlmChallenge.NetBIOSComputer)
	result.NTLMDomainName = strings.TrimSpace(metadata.ntlmChallenge.NetBIOSDomain)
	result.NTLMDNSComputerName = strings.TrimSpace(metadata.ntlmChallenge.DNSComputer)
	result.NTLMDNSDomainName = strings.TrimSpace(metadata.ntlmChallenge.DNSDomain)
	result.NTLMDNSForestName = strings.TrimSpace(metadata.ntlmChallenge.AVPairs[5])
	if metadata.ntlmChallenge.ServerTimeUTC != "" {
		if parsedTime, err := time.Parse(time.RFC3339, metadata.ntlmChallenge.ServerTimeUTC); err == nil {
			result.LocalTime = parsedTime
		}
	}
	if metadata.ntlmChallenge.VersionPresent {
		result.OSBuild = metadata.ntlmChallenge.VersionBuild
		result.OSMajorVersion = fmt.Sprintf("%d", metadata.ntlmChallenge.VersionMajor)
		result.OSMinorVersion = fmt.Sprintf("%d", metadata.ntlmChallenge.VersionMinor)
	}
}

func classifyRDPMetadataError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"), strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case strings.Contains(msg, "tls"), strings.Contains(msg, "x509"), strings.Contains(msg, "certificate"), strings.Contains(msg, "handshake"):
		return "tls_handshake_failed"
	case strings.Contains(msg, "ntlm_challenge_not_found"):
		return "ntlm_challenge_not_found"
	case strings.Contains(msg, "protocol_mismatch"):
		return "protocol_mismatch"
	default:
		return "metadata_failed"
	}
}

func rdpNativeProbeModuleFactory() engine.Module {
	return newRDPNativeProbeModule()
}

func init() {
	engine.RegisterModuleFactory(rdpNativeProbeModuleName, rdpNativeProbeModuleFactory)
}
