package scan

import (
	"bufio"
	"context"
	"crypto/tls"
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
	"github.com/rs/zerolog/log"
)

const (
	smtpNativeProbeModuleID          = "smtp-native-probe-instance"
	smtpNativeProbeModuleName        = "smtp-native-probe"
	smtpNativeProbeModuleDescription = "Runs native SMTP and SMTPS capability probes and emits structured SMTP metadata."

	smtpDefaultEHLODomain   = "cyprob.invalid"
	smtpResponseMaxBytes    = 4096
	smtpResponseMaxLines    = 32
	smtpEHLOResponseMaxSize = 2048
)

type SMTPProbeOptions struct {
	TotalTimeout   time.Duration `json:"total_timeout"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	IOTimeout      time.Duration `json:"io_timeout"`
	Retries        int           `json:"retries"`
	CandidatePorts []int         `json:"candidate_ports,omitempty"`
}

type SMTPProbeAttempt struct {
	Strategy    string `json:"strategy"`
	Transport   string `json:"transport"`
	Success     bool   `json:"success"`
	DurationMS  int64  `json:"duration_ms"`
	Error       string `json:"error,omitempty"`
	TLSVersion  string `json:"tls_version,omitempty"`
	CipherSuite string `json:"tls_cipher_suite,omitempty"`
}

type SMTPServiceInfo struct {
	Target              string             `json:"target"`
	Port                int                `json:"port"`
	SMTPProbe           bool               `json:"smtp_probe"`
	SMTPProtocol        string             `json:"smtp_protocol,omitempty"`
	Banner              string             `json:"banner,omitempty"`
	GreetingDomain      string             `json:"greeting_domain,omitempty"`
	EHLOResponse        string             `json:"ehlo_response,omitempty"`
	StartTLSSupported   bool               `json:"starttls_supported"`
	AuthSupported       bool               `json:"auth_supported"`
	PipeliningSupported bool               `json:"pipelining_supported"`
	ChunkingSupported   bool               `json:"chunking_supported"`
	SizeAdvertised      bool               `json:"size_advertised"`
	TLSEnabled          bool               `json:"tls_enabled"`
	TLSVersion          string             `json:"tls_version,omitempty"`
	TLSCipherSuite      string             `json:"tls_cipher_suite,omitempty"`
	CertSubjectCN       string             `json:"cert_subject_cn,omitempty"`
	CertIssuer          string             `json:"cert_issuer,omitempty"`
	CertNotAfter        time.Time          `json:"cert_not_after,omitempty"`
	CertIsSelfSigned    bool               `json:"cert_is_self_signed"`
	OpenRelaySuspected  bool               `json:"open_relay_suspected"`
	WeakTLSProtocol     bool               `json:"weak_tls_protocol"`
	WeakTLSCipher       bool               `json:"weak_tls_cipher"`
	SoftwareHint        string             `json:"software_hint,omitempty"`
	VendorHint          string             `json:"vendor_hint,omitempty"`
	VersionHint         string             `json:"version_hint,omitempty"`
	ProbeError          string             `json:"probe_error,omitempty"`
	Attempts            []SMTPProbeAttempt `json:"attempts,omitempty"`
}

type smtpNativeProbeModule struct {
	meta    engine.ModuleMetadata
	options SMTPProbeOptions
}

type smtpProbeCandidate struct {
	target   string
	hostname string
	port     int
}

type smtpCapabilities struct {
	startTLS   bool
	auth       bool
	pipelining bool
	chunking   bool
	size       bool
}

type smtpResponse struct {
	Code  int
	Raw   string
	Lines []string
}

type smtpProbeOutcome struct {
	banner              string
	greetingDomain      string
	ehloResponse        string
	startTLSSupported   bool
	authSupported       bool
	pipeliningSupported bool
	chunkingSupported   bool
	sizeAdvertised      bool
	tlsEnabled          bool
	tlsVersion          string
	tlsCipherSuite      string
	certSubjectCN       string
	certIssuer          string
	certNotAfter        time.Time
	certIsSelfSigned    bool
	openRelaySuspected  bool
	weakTLSProtocol     bool
	weakTLSCipher       bool
	softwareHint        string
	vendorHint          string
	versionHint         string
}

type smtpClient struct {
	conn   net.Conn
	reader *bufio.Reader
}

var (
	probeSMTPDetailsFunc = probeSMTPDetails

	smtpPostfixPattern = regexp.MustCompile(`(?i)\bpostfix(?:[ /_-]?v?([0-9][0-9a-z._-]*))?`)
	smtpEximPattern    = regexp.MustCompile(`(?i)\bexim(?:[ /_-]?v?([0-9][0-9a-z._-]*))?`)
	smtpSmarterPattern = regexp.MustCompile(`(?i)\bsmartermail(?:[ /_-]?v?([0-9][0-9a-z._-]*))?`)
	smtpOpenSMTPD      = regexp.MustCompile(`(?i)\bopensmtpd(?:[ /_-]?v?([0-9][0-9a-z._-]*))?`)
)

func newSMTPNativeProbeModule() *smtpNativeProbeModule {
	return &smtpNativeProbeModule{
		meta: engine.ModuleMetadata{
			ID:          smtpNativeProbeModuleID,
			Name:        smtpNativeProbeModuleName,
			Description: smtpNativeProbeModuleDescription,
			Version:     "0.1.0",
			Type:        engine.ScanModuleType,
			Author:      "Vulntor Team",
			Tags:        []string{"scan", "smtp", "mail", "enrichment", "native_probe"},
			Consumes: []engine.DataContractEntry{
				{
					Key:          "discovery.open_tcp_ports",
					DataTypeName: "discovery.TCPPortDiscoveryResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   false,
					Description:  "Open TCP ports used to identify SMTP candidate services.",
				},
				{
					Key:          "service.banner.tcp",
					DataTypeName: "scan.BannerGrabResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   true,
					Description:  "Banner results used as fallback SMTP candidate source.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key:          "service.smtp.details",
					DataTypeName: "scan.SMTPServiceInfo",
					Cardinality:  engine.CardinalityList,
					Description:  "Structured SMTP native probe output per target and port.",
				},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				"timeout": {
					Description: "Total timeout budget per target (e.g. 2500ms).",
					Type:        "duration",
					Required:    false,
					Default:     "2500ms",
				},
				"connect_timeout": {
					Description: "TCP connect timeout per attempt.",
					Type:        "duration",
					Required:    false,
					Default:     "800ms",
				},
				"io_timeout": {
					Description: "I/O timeout per SMTP exchange.",
					Type:        "duration",
					Required:    false,
					Default:     "800ms",
				},
				"retries": {
					Description: "Retry count per strategy.",
					Type:        "int",
					Required:    false,
					Default:     0,
				},
				"candidate_ports": {
					Description: "Optional explicit ports to treat as SMTP candidates when already known open.",
					Type:        "[]int",
					Required:    false,
				},
			},
		},
		options: defaultSMTPProbeOptions(),
	}
}

func (m *smtpNativeProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *smtpNativeProbeModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	opts := defaultSMTPProbeOptions()
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
		opts.CandidatePorts = parseExtraPortsConfig(configMap["candidate_ports"])
	}
	m.options = opts
	return nil
}

func (m *smtpNativeProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
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

	candidates := make(map[string]smtpProbeCandidate)
	for _, item := range toAnySlice(rawOpenPorts) {
		for _, candidate := range smtpCandidatesFromOpenPorts(item, explicitCandidatePorts) {
			mergeSMTPCandidate(candidates, candidate)
		}
	}

	if rawBanner, ok := inputs["service.banner.tcp"]; ok {
		for _, item := range toAnySlice(rawBanner) {
			candidate, ok := smtpCandidateFromBanner(item, explicitCandidatePorts)
			if !ok {
				continue
			}
			mergeSMTPCandidate(candidates, candidate)
		}
	}

	if len(candidates) == 0 {
		log.Debug().
			Str("module", smtpNativeProbeModuleName).
			Str("smtp_probe_skipped_reason", "no_candidate").
			Msg("smtp_probe_skipped")
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
			leftPriority := smtpPortPriority(left.port)
			rightPriority := smtpPortPriority(right.port)
			if leftPriority != rightPriority {
				return leftPriority > rightPriority
			}
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

		result := probeSMTPDetailsFunc(targetCtx, candidate.target, candidate.hostname, candidate.port, m.options)
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "service.smtp.details",
			Data:           result,
			Timestamp:      time.Now(),
			Target:         candidate.target,
		}
	}

	return nil
}

func defaultSMTPProbeOptions() SMTPProbeOptions {
	return SMTPProbeOptions{
		TotalTimeout:   2500 * time.Millisecond,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
		Retries:        0,
	}
}

func smtpCandidatesFromOpenPorts(item any, explicitCandidatePorts map[int]struct{}) []smtpProbeCandidate {
	candidates := make([]smtpProbeCandidate, 0, 4)
	appendCandidate := func(target, hostname string, port int) {
		target = strings.TrimSpace(target)
		hostname = normalizeNonIPHostname(hostname)
		if target == "" || port <= 0 || port > 65535 {
			return
		}
		if !isSMTPNativePort(port) {
			if _, ok := explicitCandidatePorts[port]; !ok {
				return
			}
		}
		candidates = append(candidates, smtpProbeCandidate{
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

func smtpCandidateFromBanner(item any, explicitCandidatePorts map[int]struct{}) (smtpProbeCandidate, bool) {
	switch v := item.(type) {
	case BannerGrabResult:
		if !isSMTPBannerCandidate(v, explicitCandidatePorts) {
			return smtpProbeCandidate{}, false
		}
		return smtpProbeCandidate{
			target:   strings.TrimSpace(v.IP),
			hostname: firstNonEmptyHostname(v.ProbeHost, v.SNIServerName),
			port:     v.Port,
		}, strings.TrimSpace(v.IP) != "" && v.Port > 0
	case map[string]any:
		target := getMapString(v, "ip", "IP")
		if target == "" {
			return smtpProbeCandidate{}, false
		}
		port := mapPortValue(v["port"])
		if port <= 0 {
			return smtpProbeCandidate{}, false
		}
		candidate := smtpProbeCandidate{
			target:   target,
			hostname: firstNonEmptyHostname(getMapString(v, "probe_host", "ProbeHost"), getMapString(v, "sni_server_name", "SNIServerName")),
			port:     port,
		}
		if isSMTPNativePort(port) || isExplicitSMTPPort(port, explicitCandidatePorts) {
			return candidate, true
		}
		if containsSMTPHint(getMapString(v, "protocol", "Protocol")) ||
			containsSMTPHint(getMapString(v, "banner", "Banner")) ||
			mapEvidenceLooksLikeSMTP(v["evidence"]) {
			return candidate, true
		}
	}
	return smtpProbeCandidate{}, false
}

func mergeSMTPCandidate(dst map[string]smtpProbeCandidate, candidate smtpProbeCandidate) {
	key := smtpCandidateKey(candidate)
	if current, ok := dst[key]; ok {
		if current.hostname == "" && candidate.hostname != "" {
			dst[key] = candidate
		}
		return
	}
	dst[key] = candidate
}

func isSMTPBannerCandidate(banner BannerGrabResult, explicitCandidatePorts map[int]struct{}) bool {
	if isSMTPNativePort(banner.Port) || isExplicitSMTPPort(banner.Port, explicitCandidatePorts) {
		return true
	}
	if containsSMTPHint(banner.Protocol) || containsSMTPHint(banner.Banner) {
		return true
	}
	for _, obs := range banner.Evidence {
		if containsSMTPHint(obs.Protocol) ||
			containsSMTPHint(obs.ProbeID) ||
			containsSMTPHint(obs.Description) ||
			containsSMTPHint(obs.Response) {
			return true
		}
	}
	return false
}

func mapEvidenceLooksLikeSMTP(raw any) bool {
	items, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if containsSMTPHint(getMapString(m, "protocol", "Protocol")) ||
			containsSMTPHint(getMapString(m, "probe_id", "ProbeID")) ||
			containsSMTPHint(getMapString(m, "description", "Description")) ||
			containsSMTPHint(getMapString(m, "response", "Response")) {
			return true
		}
	}
	return false
}

func containsSMTPHint(value string) bool {
	clean := strings.ToLower(strings.TrimSpace(value))
	if clean == "" {
		return false
	}
	return strings.Contains(clean, "smtp") ||
		strings.Contains(clean, "esmtp") ||
		strings.Contains(clean, "submission")
}

func smtpCandidateKey(candidate smtpProbeCandidate) string {
	return fmt.Sprintf("%s:%d", candidate.target, candidate.port)
}

func smtpPortPriority(port int) int {
	switch port {
	case 25:
		return 4
	case 587:
		return 3
	case 465:
		return 2
	case 2525:
		return 1
	default:
		return 0
	}
}

func smtpProtocolFromPort(port int) string {
	switch port {
	case 465:
		return "smtps"
	case 587, 2525:
		return "submission"
	default:
		return "smtp"
	}
}

func isSMTPNativePort(port int) bool {
	switch port {
	case 25, 465, 587, 2525:
		return true
	default:
		return false
	}
}

func isExplicitSMTPPort(port int, explicitCandidatePorts map[int]struct{}) bool {
	_, ok := explicitCandidatePorts[port]
	return ok
}

func firstNonEmptyHostname(values ...string) string {
	for _, value := range values {
		if hostname := normalizeNonIPHostname(value); hostname != "" {
			return hostname
		}
	}
	return ""
}

func mapPortValue(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

func probeSMTPDetails(ctx context.Context, target string, hostname string, port int, opts SMTPProbeOptions) SMTPServiceInfo {
	if port <= 0 {
		port = 25
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

	result := SMTPServiceInfo{
		Target:       target,
		Port:         port,
		SMTPProtocol: smtpProtocolFromPort(port),
		Attempts:     make([]SMTPProbeAttempt, 0, 2*(opts.Retries+1)),
	}

	if result.SMTPProtocol == "smtps" {
		return probeSMTPSImplicitTLS(probeCtx, target, hostname, port, opts, result)
	}
	return probeSMTPPlainAndStartTLS(probeCtx, target, hostname, port, opts, result)
}

func probeSMTPSImplicitTLS(ctx context.Context, target string, hostname string, port int, opts SMTPProbeOptions, result SMTPServiceInfo) SMTPServiceInfo {
	errorCodes := make([]string, 0, opts.Retries+1)

	for retry := 0; retry <= opts.Retries; retry++ {
		log.Debug().
			Str("module", smtpNativeProbeModuleName).
			Str("target", target).
			Int("port", port).
			Str("strategy", "smtps-implicit-tls").
			Msg("smtp_tls_attempted")

		start := time.Now()
		client, tlsObs, err := dialSMTPTLS(ctx, target, hostname, port, opts)
		if err != nil {
			code := classifySMTPProbeError(err)
			errorCodes = append(errorCodes, code)
			result.Attempts = append(result.Attempts, SMTPProbeAttempt{
				Strategy:   "smtps-implicit-tls",
				Transport:  strconv.Itoa(port),
				Success:    false,
				DurationMS: time.Since(start).Milliseconds(),
				Error:      code,
			})
			log.Debug().
				Str("module", smtpNativeProbeModuleName).
				Str("target", target).
				Int("port", port).
				Str("strategy", "smtps-implicit-tls").
				Str("probe_error", code).
				Msg("smtp_tls_failed")
			continue
		}

		outcome, err := runSMTPImplicitTLSSession(ctx, client, tlsObs, port, opts)
		_ = client.close()
		if err != nil {
			code := classifySMTPProbeError(err)
			errorCodes = append(errorCodes, code)
			result.Attempts = append(result.Attempts, SMTPProbeAttempt{
				Strategy:    "smtps-implicit-tls",
				Transport:   strconv.Itoa(port),
				Success:     false,
				DurationMS:  time.Since(start).Milliseconds(),
				Error:       code,
				TLSVersion:  strings.TrimSpace(outcome.tlsVersion),
				CipherSuite: strings.TrimSpace(outcome.tlsCipherSuite),
			})
			log.Debug().
				Str("module", smtpNativeProbeModuleName).
				Str("target", target).
				Int("port", port).
				Str("strategy", "smtps-implicit-tls").
				Str("probe_error", code).
				Msg("smtp_tls_failed")
			continue
		}

		result.Attempts = append(result.Attempts, SMTPProbeAttempt{
			Strategy:    "smtps-implicit-tls",
			Transport:   strconv.Itoa(port),
			Success:     true,
			DurationMS:  time.Since(start).Milliseconds(),
			TLSVersion:  strings.TrimSpace(outcome.tlsVersion),
			CipherSuite: strings.TrimSpace(outcome.tlsCipherSuite),
		})
		applySMTPOutcome(&result, outcome)
		result.SMTPProbe = true
		result.ProbeError = ""
		log.Debug().
			Str("module", smtpNativeProbeModuleName).
			Str("target", target).
			Int("port", port).
			Str("strategy", "smtps-implicit-tls").
			Msg("smtp_tls_success")
		return result
	}

	result.ProbeError = pickTopSMTPProbeError(errorCodes)
	if result.ProbeError == "" {
		result.ProbeError = "probe_failed"
	}
	return result
}

func probeSMTPPlainAndStartTLS(ctx context.Context, target string, hostname string, port int, opts SMTPProbeOptions, result SMTPServiceInfo) SMTPServiceInfo {
	errorCodes := make([]string, 0, opts.Retries+1)

	for retry := 0; retry <= opts.Retries; retry++ {
		log.Debug().
			Str("module", smtpNativeProbeModuleName).
			Str("target", target).
			Int("port", port).
			Str("strategy", "smtp-plain-ehlo").
			Msg("smtp_probe_attempted")

		start := time.Now()
		client, err := dialSMTPPlain(ctx, target, port, opts)
		if err != nil {
			code := classifySMTPProbeError(err)
			errorCodes = append(errorCodes, code)
			result.Attempts = append(result.Attempts, SMTPProbeAttempt{
				Strategy:   "smtp-plain-ehlo",
				Transport:  strconv.Itoa(port),
				Success:    false,
				DurationMS: time.Since(start).Milliseconds(),
				Error:      code,
			})
			log.Debug().
				Str("module", smtpNativeProbeModuleName).
				Str("target", target).
				Int("port", port).
				Str("strategy", "smtp-plain-ehlo").
				Str("probe_error", code).
				Msg("smtp_probe_failed")
			continue
		}

		plainOutcome, err := runSMTPPlainSession(ctx, client, port, opts)
		if err != nil {
			_ = client.close()
			code := classifySMTPProbeError(err)
			errorCodes = append(errorCodes, code)
			result.Attempts = append(result.Attempts, SMTPProbeAttempt{
				Strategy:   "smtp-plain-ehlo",
				Transport:  strconv.Itoa(port),
				Success:    false,
				DurationMS: time.Since(start).Milliseconds(),
				Error:      code,
			})
			log.Debug().
				Str("module", smtpNativeProbeModuleName).
				Str("target", target).
				Int("port", port).
				Str("strategy", "smtp-plain-ehlo").
				Str("probe_error", code).
				Msg("smtp_probe_failed")
			continue
		}

		result.Attempts = append(result.Attempts, SMTPProbeAttempt{
			Strategy:   "smtp-plain-ehlo",
			Transport:  strconv.Itoa(port),
			Success:    true,
			DurationMS: time.Since(start).Milliseconds(),
		})
		applySMTPOutcome(&result, plainOutcome)
		result.SMTPProbe = true
		log.Debug().
			Str("module", smtpNativeProbeModuleName).
			Str("target", target).
			Int("port", port).
			Str("strategy", "smtp-plain-ehlo").
			Msg("smtp_probe_success")

		if !plainOutcome.startTLSSupported {
			_ = client.close()
			result.ProbeError = ""
			return result
		}

		log.Debug().
			Str("module", smtpNativeProbeModuleName).
			Str("target", target).
			Int("port", port).
			Str("strategy", "smtp-starttls-ehlo").
			Msg("smtp_starttls_attempted")

		startTLSStart := time.Now()
		startTLSOutcome, err := runSMTPStartTLSSession(ctx, client, hostname, port, opts)
		_ = client.close()
		if err != nil {
			code := classifySMTPProbeError(err)
			result.Attempts = append(result.Attempts, SMTPProbeAttempt{
				Strategy:   "smtp-starttls-ehlo",
				Transport:  strconv.Itoa(port),
				Success:    false,
				DurationMS: time.Since(startTLSStart).Milliseconds(),
				Error:      code,
			})
			log.Debug().
				Str("module", smtpNativeProbeModuleName).
				Str("target", target).
				Int("port", port).
				Str("strategy", "smtp-starttls-ehlo").
				Str("probe_error", code).
				Msg("smtp_starttls_failed")
			result.ProbeError = ""
			return result
		}

		result.Attempts = append(result.Attempts, SMTPProbeAttempt{
			Strategy:    "smtp-starttls-ehlo",
			Transport:   strconv.Itoa(port),
			Success:     true,
			DurationMS:  time.Since(startTLSStart).Milliseconds(),
			TLSVersion:  strings.TrimSpace(startTLSOutcome.tlsVersion),
			CipherSuite: strings.TrimSpace(startTLSOutcome.tlsCipherSuite),
		})
		applySMTPOutcome(&result, startTLSOutcome)
		result.SMTPProbe = true
		result.ProbeError = ""
		log.Debug().
			Str("module", smtpNativeProbeModuleName).
			Str("target", target).
			Int("port", port).
			Str("strategy", "smtp-starttls-ehlo").
			Msg("smtp_starttls_success")
		return result
	}

	result.ProbeError = pickTopSMTPProbeError(errorCodes)
	if result.ProbeError == "" {
		result.ProbeError = "probe_failed"
	}
	return result
}

func applySMTPOutcome(result *SMTPServiceInfo, outcome smtpProbeOutcome) {
	if result == nil {
		return
	}
	if result.SMTPProtocol == "" {
		result.SMTPProtocol = "smtp"
	}
	if strings.TrimSpace(result.Banner) == "" && strings.TrimSpace(outcome.banner) != "" {
		result.Banner = strings.TrimSpace(outcome.banner)
	}
	if strings.TrimSpace(result.GreetingDomain) == "" && strings.TrimSpace(outcome.greetingDomain) != "" {
		result.GreetingDomain = strings.TrimSpace(outcome.greetingDomain)
	}
	if strings.TrimSpace(outcome.ehloResponse) != "" {
		result.EHLOResponse = strings.TrimSpace(outcome.ehloResponse)
	}
	result.StartTLSSupported = result.StartTLSSupported || outcome.startTLSSupported
	result.AuthSupported = result.AuthSupported || outcome.authSupported
	result.PipeliningSupported = result.PipeliningSupported || outcome.pipeliningSupported
	result.ChunkingSupported = result.ChunkingSupported || outcome.chunkingSupported
	result.SizeAdvertised = result.SizeAdvertised || outcome.sizeAdvertised
	result.TLSEnabled = result.TLSEnabled || outcome.tlsEnabled
	if strings.TrimSpace(outcome.tlsVersion) != "" {
		result.TLSVersion = strings.TrimSpace(outcome.tlsVersion)
	}
	if strings.TrimSpace(outcome.tlsCipherSuite) != "" {
		result.TLSCipherSuite = strings.TrimSpace(outcome.tlsCipherSuite)
	}
	if strings.TrimSpace(outcome.certSubjectCN) != "" {
		result.CertSubjectCN = strings.TrimSpace(outcome.certSubjectCN)
	}
	if strings.TrimSpace(outcome.certIssuer) != "" {
		result.CertIssuer = strings.TrimSpace(outcome.certIssuer)
	}
	if !outcome.certNotAfter.IsZero() {
		result.CertNotAfter = outcome.certNotAfter
	}
	result.CertIsSelfSigned = result.CertIsSelfSigned || outcome.certIsSelfSigned
	result.OpenRelaySuspected = result.OpenRelaySuspected || outcome.openRelaySuspected
	result.WeakTLSProtocol = result.WeakTLSProtocol || outcome.weakTLSProtocol
	result.WeakTLSCipher = result.WeakTLSCipher || outcome.weakTLSCipher
	if strings.TrimSpace(result.SoftwareHint) == "" && strings.TrimSpace(outcome.softwareHint) != "" {
		result.SoftwareHint = strings.TrimSpace(outcome.softwareHint)
	}
	if strings.TrimSpace(result.VendorHint) == "" && strings.TrimSpace(outcome.vendorHint) != "" {
		result.VendorHint = strings.TrimSpace(outcome.vendorHint)
	}
	if strings.TrimSpace(result.VersionHint) == "" && strings.TrimSpace(outcome.versionHint) != "" {
		result.VersionHint = strings.TrimSpace(outcome.versionHint)
	}
}

func runSMTPPlainSession(ctx context.Context, client *smtpClient, port int, opts SMTPProbeOptions) (smtpProbeOutcome, error) {
	greeting, err := client.readResponse(ctx, opts.IOTimeout)
	if err != nil {
		return smtpProbeOutcome{}, err
	}
	if greeting.Code != 220 {
		return smtpProbeOutcome{}, errors.New("protocol_error")
	}

	if err := client.writeCommand(ctx, opts.IOTimeout, "EHLO "+smtpDefaultEHLODomain+"\r\n"); err != nil {
		return smtpProbeOutcome{}, err
	}
	ehlo, err := client.readResponse(ctx, opts.IOTimeout)
	if err != nil {
		return smtpProbeOutcome{}, err
	}
	if ehlo.Code != 250 {
		return smtpProbeOutcome{}, errors.New("protocol_error")
	}

	return buildSMTPOutcome(smtpProtocolFromPort(port), greeting, ehlo, nil), nil
}

func runSMTPStartTLSSession(ctx context.Context, client *smtpClient, hostname string, port int, opts SMTPProbeOptions) (smtpProbeOutcome, error) {
	if err := client.writeCommand(ctx, opts.IOTimeout, "STARTTLS\r\n"); err != nil {
		return smtpProbeOutcome{}, err
	}
	startTLSResp, err := client.readResponse(ctx, opts.IOTimeout)
	if err != nil {
		return smtpProbeOutcome{}, err
	}
	if startTLSResp.Code != 220 {
		return smtpProbeOutcome{}, errors.New("starttls_failed")
	}

	tlsObs, err := client.upgradeTLS(ctx, hostname, opts)
	if err != nil {
		return smtpProbeOutcome{}, err
	}
	if err := client.writeCommand(ctx, opts.IOTimeout, "EHLO "+smtpDefaultEHLODomain+"\r\n"); err != nil {
		return smtpProbeOutcome{}, err
	}
	ehlo, err := client.readResponse(ctx, opts.IOTimeout)
	if err != nil {
		return smtpProbeOutcome{}, err
	}
	if ehlo.Code != 250 {
		return smtpProbeOutcome{}, errors.New("protocol_error")
	}

	outcome := buildSMTPOutcome(smtpProtocolFromPort(port), startTLSResp, ehlo, tlsObs)
	outcome.startTLSSupported = true
	return outcome, nil
}

func runSMTPImplicitTLSSession(ctx context.Context, client *smtpClient, tlsObs *engine.TLSObservation, port int, opts SMTPProbeOptions) (smtpProbeOutcome, error) {
	greeting, err := client.readResponse(ctx, opts.IOTimeout)
	if err != nil {
		return smtpProbeOutcome{}, err
	}
	if greeting.Code != 220 {
		return smtpProbeOutcome{}, errors.New("protocol_error")
	}

	if err := client.writeCommand(ctx, opts.IOTimeout, "EHLO "+smtpDefaultEHLODomain+"\r\n"); err != nil {
		return smtpProbeOutcome{}, err
	}
	ehlo, err := client.readResponse(ctx, opts.IOTimeout)
	if err != nil {
		return smtpProbeOutcome{}, err
	}
	if ehlo.Code != 250 {
		return smtpProbeOutcome{}, errors.New("protocol_error")
	}

	outcome := buildSMTPOutcome(smtpProtocolFromPort(port), greeting, ehlo, tlsObs)
	outcome.tlsEnabled = true
	return outcome, nil
}

func buildSMTPOutcome(protocol string, greeting smtpResponse, ehlo smtpResponse, tlsObs *engine.TLSObservation) smtpProbeOutcome {
	capabilities := parseSMTPCapabilities(ehlo)
	outcome := smtpProbeOutcome{
		banner:              sanitizeSMTPResponse(greeting.Raw, 512),
		greetingDomain:      extractSMTPGreetingDomain(greeting),
		ehloResponse:        sanitizeSMTPResponse(ehlo.Raw, smtpEHLOResponseMaxSize),
		startTLSSupported:   capabilities.startTLS,
		authSupported:       capabilities.auth,
		pipeliningSupported: capabilities.pipelining,
		chunkingSupported:   capabilities.chunking,
		sizeAdvertised:      capabilities.size,
		openRelaySuspected:  inferOpenRelaySuspicion(greeting.Raw, ehlo.Raw),
	}

	product, vendor, version := inferSMTPSoftwareHints(strings.Join([]string{greeting.Raw, ehlo.Raw}, "\n"))
	outcome.softwareHint = product
	outcome.vendorHint = vendor
	outcome.versionHint = version

	if tlsObs == nil {
		return outcome
	}

	outcome.tlsEnabled = true
	outcome.tlsVersion = strings.TrimSpace(tlsObs.Version)
	outcome.tlsCipherSuite = strings.TrimSpace(tlsObs.CipherSuite)
	outcome.certSubjectCN = strings.TrimSpace(tlsObs.PeerCommonName)
	outcome.certIssuer = strings.TrimSpace(tlsObs.Issuer)
	outcome.certNotAfter = tlsObs.NotAfter
	outcome.certIsSelfSigned = tlsObs.IsSelfSigned
	outcome.weakTLSProtocol = isWeakTLSVersion(outcome.tlsVersion)
	outcome.weakTLSCipher = isWeakCipher(outcome.tlsCipherSuite)

	if protocol == "smtp" && outcome.startTLSSupported {
		outcome.startTLSSupported = true
	}
	return outcome
}

func parseSMTPCapabilities(resp smtpResponse) smtpCapabilities {
	capabilities := smtpCapabilities{}
	for _, line := range resp.Lines {
		text := strings.ToUpper(strings.TrimSpace(smtpResponseText(line)))
		if text == "" {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) == 0 {
			continue
		}
		keyword := fields[0]
		switch {
		case keyword == "STARTTLS":
			capabilities.startTLS = true
		case keyword == "PIPELINING":
			capabilities.pipelining = true
		case keyword == "CHUNKING":
			capabilities.chunking = true
		case keyword == "SIZE":
			capabilities.size = true
		case keyword == "AUTH", strings.HasPrefix(keyword, "AUTH="):
			capabilities.auth = true
		case strings.Contains(text, " AUTH "):
			capabilities.auth = true
		}
	}
	return capabilities
}

func extractSMTPGreetingDomain(resp smtpResponse) string {
	if len(resp.Lines) == 0 {
		return ""
	}
	text := strings.TrimSpace(smtpResponseText(resp.Lines[0]))
	if text == "" {
		return ""
	}
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return ""
	}
	candidate := strings.TrimSpace(fields[0])
	if candidate == "" || strings.HasPrefix(candidate, "[") {
		return ""
	}
	return strings.Trim(candidate, "<>")
}

func inferSMTPSoftwareHints(raw string) (string, string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", ""
	}

	if strings.Contains(strings.ToLower(raw), "microsoft esmtp mail service") {
		return "Microsoft ESMTP MAIL Service", "Microsoft", ""
	}
	if product, version := extractSMTPProductVersion(smtpSmarterPattern, raw, "SmarterMail"); product != "" {
		return product, "SmarterTools", version
	}
	if product, version := extractSMTPProductVersion(smtpPostfixPattern, raw, "Postfix"); product != "" {
		return product, "", version
	}
	if product, version := extractSMTPProductVersion(smtpEximPattern, raw, "Exim"); product != "" {
		return product, "", version
	}
	if product, version := extractSMTPProductVersion(smtpOpenSMTPD, raw, "OpenSMTPD"); product != "" {
		return product, "", version
	}
	return "", "", ""
}

func extractSMTPProductVersion(pattern *regexp.Regexp, raw string, product string) (string, string) {
	matches := pattern.FindStringSubmatch(raw)
	if len(matches) == 0 {
		return "", ""
	}
	version := ""
	if len(matches) > 1 {
		version = strings.TrimSpace(matches[1])
	}
	return product, version
}

func inferOpenRelaySuspicion(greeting string, ehlo string) bool {
	combined := strings.ToLower(strings.TrimSpace(greeting + "\n" + ehlo))
	return strings.Contains(combined, "open relay")
}

func sanitizeSMTPResponse(raw string, maxLen int) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || maxLen <= 0 || len(raw) <= maxLen {
		return raw
	}
	return raw[:maxLen]
}

func smtpResponseText(line string) string {
	line = strings.TrimSpace(line)
	if len(line) >= 4 && isSMTPCodePrefix(line[:3]) {
		return strings.TrimSpace(line[4:])
	}
	return line
}

func dialSMTPPlain(ctx context.Context, target string, port int, opts SMTPProbeOptions) (*smtpClient, error) {
	address := net.JoinHostPort(strings.TrimSpace(target), strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: effectiveProbeTimeout(ctx, opts.ConnectTimeout)}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	return &smtpClient{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}, nil
}

func dialSMTPTLS(ctx context.Context, target string, hostname string, port int, opts SMTPProbeOptions) (*smtpClient, *engine.TLSObservation, error) {
	address := net.JoinHostPort(strings.TrimSpace(target), strconv.Itoa(port))
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: effectiveProbeTimeout(ctx, opts.ConnectTimeout)},
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // Native probe gathers metadata from untrusted targets.
			ServerName:         smtpTLSServerName(hostname, target),
		},
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	conn, ok := rawConn.(*tls.Conn)
	if !ok {
		_ = rawConn.Close()
		return nil, nil, errors.New("tls_failed")
	}
	if err := conn.SetDeadline(time.Now().Add(effectiveProbeTimeout(ctx, opts.IOTimeout))); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	state := conn.ConnectionState()
	tlsObs := extractTLSObservation(state)
	if tlsObs == nil {
		_ = conn.Close()
		return nil, nil, errors.New("tls_failed")
	}
	return &smtpClient{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}, tlsObs, nil
}

func (c *smtpClient) close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *smtpClient) writeCommand(ctx context.Context, ioTimeout time.Duration, command string) error {
	if c == nil || c.conn == nil {
		return errors.New("probe_failed")
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(effectiveProbeTimeout(ctx, ioTimeout))); err != nil {
		return err
	}
	_, err := io.WriteString(c.conn, command)
	return err
}

func (c *smtpClient) readResponse(ctx context.Context, ioTimeout time.Duration) (smtpResponse, error) {
	if c == nil || c.reader == nil || c.conn == nil {
		return smtpResponse{}, errors.New("probe_failed")
	}

	lines := make([]string, 0, 4)
	var builder strings.Builder
	code := 0

	for len(lines) < smtpResponseMaxLines && builder.Len() < smtpResponseMaxBytes {
		if err := c.conn.SetReadDeadline(time.Now().Add(effectiveProbeTimeout(ctx, ioTimeout))); err != nil {
			return smtpResponse{Code: code, Lines: lines, Raw: builder.String()}, err
		}
		line, err := c.reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) && strings.TrimSpace(line) != "" {
				// Keep the partial line.
			} else {
				return smtpResponse{Code: code, Lines: lines, Raw: builder.String()}, err
			}
		}
		line = strings.TrimRight(line, "\r\n")
		if line != "" {
			if builder.Len() > 0 {
				builder.WriteString("\r\n")
			}
			builder.WriteString(line)
			lines = append(lines, line)
		}
		if code == 0 {
			if len(line) < 3 || !isSMTPCodePrefix(line[:3]) {
				return smtpResponse{Lines: lines, Raw: builder.String()}, errors.New("protocol_error")
			}
			parsed, convErr := strconv.Atoi(line[:3])
			if convErr != nil {
				return smtpResponse{Lines: lines, Raw: builder.String()}, errors.New("protocol_error")
			}
			code = parsed
		}
		if len(line) >= 4 && line[3] == '-' {
			if err == nil {
				continue
			}
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return smtpResponse{Code: code, Lines: lines, Raw: builder.String()}, err
		}
		break
	}

	if len(lines) == 0 {
		return smtpResponse{}, errors.New("protocol_error")
	}

	return smtpResponse{
		Code:  code,
		Raw:   builder.String(),
		Lines: lines,
	}, nil
}

func (c *smtpClient) upgradeTLS(ctx context.Context, hostname string, opts SMTPProbeOptions) (*engine.TLSObservation, error) {
	if c == nil || c.conn == nil {
		return nil, errors.New("tls_failed")
	}

	tlsConn := tls.Client(c.conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // Native probe gathers metadata from untrusted targets.
		ServerName:         smtpTLSServerName(hostname, ""),
	})
	if err := tlsConn.SetDeadline(time.Now().Add(effectiveProbeTimeout(ctx, opts.IOTimeout))); err != nil {
		return nil, err
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	tlsObs := extractTLSObservation(tlsConn.ConnectionState())
	if tlsObs == nil {
		return nil, errors.New("tls_failed")
	}

	c.conn = tlsConn
	c.reader = bufio.NewReader(tlsConn)
	return tlsObs, nil
}

func smtpTLSServerName(hostname string, target string) string {
	if host := normalizeNonIPHostname(hostname); host != "" {
		return host
	}
	target = strings.TrimSpace(target)
	if target != "" {
		return target
	}
	return ""
}

func effectiveProbeTimeout(ctx context.Context, fallback time.Duration) time.Duration {
	if fallback <= 0 {
		fallback = time.Second
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		switch {
		case remaining <= 0:
			return time.Millisecond
		case remaining < fallback:
			return remaining
		}
	}
	return fallback
}

func isSMTPCodePrefix(value string) bool {
	if len(value) != 3 {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func classifySMTPProbeError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"), strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case strings.Contains(msg, "connection refused"):
		return "refused"
	case strings.Contains(msg, "starttls_failed"):
		return "starttls_failed"
	case strings.Contains(msg, "tls_failed"), strings.Contains(msg, "tls:"), strings.Contains(msg, "handshake"):
		return "tls_failed"
	case strings.Contains(msg, "protocol_error"):
		return "protocol_error"
	default:
		return "probe_failed"
	}
}

func pickTopSMTPProbeError(codes []string) string {
	best := ""
	bestPriority := -1
	for _, code := range codes {
		if priority := smtpProbeErrorPriority(code); priority > bestPriority {
			bestPriority = priority
			best = code
		}
	}
	return best
}

func smtpProbeErrorPriority(code string) int {
	switch code {
	case "timeout":
		return 6
	case "refused":
		return 5
	case "tls_failed":
		return 4
	case "starttls_failed":
		return 3
	case "protocol_error":
		return 2
	case "probe_failed":
		return 1
	default:
		return 0
	}
}

func smtpNativeProbeModuleFactory() engine.Module {
	return newSMTPNativeProbeModule()
}

func init() {
	engine.RegisterModuleFactory(smtpNativeProbeModuleName, smtpNativeProbeModuleFactory)
}
