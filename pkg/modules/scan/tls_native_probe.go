package scan

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"github.com/rs/zerolog/log"
)

const (
	tlsNativeProbeModuleID          = "tls-native-probe-instance"
	tlsNativeProbeModuleName        = "tls-native-probe"
	tlsNativeProbeModuleDescription = "Runs native TLS handshake probes and emits structured TLS metadata and security signals."
)

// TLSProbeOptions controls timeout and retry behavior for TLS native probe.
type TLSProbeOptions struct {
	TotalTimeout   time.Duration `json:"total_timeout"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	IOTimeout      time.Duration `json:"io_timeout"`
	Retries        int           `json:"retries"`
	ExtraPorts     []int         `json:"extra_ports"`
}

// TLSProbeAttempt represents one probe strategy attempt.
type TLSProbeAttempt struct {
	Strategy      string `json:"strategy"`
	Transport     string `json:"transport"`
	Success       bool   `json:"success"`
	DurationMS    int64  `json:"duration_ms"`
	Error         string `json:"error,omitempty"`
	TLSVersion    string `json:"tls_version,omitempty"`
	CipherSuite   string `json:"cipher_suite,omitempty"`
	SNIServerName string `json:"sni_server_name,omitempty"`
}

// TLSServiceInfo is the canonical TLS native probe output.
type TLSServiceInfo struct {
	Target           string            `json:"target"`
	Port             int               `json:"port"`
	TLSProbe         bool              `json:"tls_probe"`
	TLSVersion       string            `json:"tls_version,omitempty"`
	CipherSuite      string            `json:"cipher_suite,omitempty"`
	ALPN             string            `json:"alpn,omitempty"`
	SNIServerName    string            `json:"sni_server_name,omitempty"`
	CertSubjectCN    string            `json:"cert_subject_cn,omitempty"`
	CertIssuer       string            `json:"cert_issuer,omitempty"`
	CertDNSNames     []string          `json:"cert_dns_names,omitempty"`
	CertNotBefore    time.Time         `json:"cert_not_before,omitempty"`
	CertNotAfter     time.Time         `json:"cert_not_after,omitempty"`
	CertIsExpired    bool              `json:"cert_is_expired"`
	CertIsSelfSigned bool              `json:"cert_is_self_signed"`
	CertSHA256       string            `json:"cert_sha256,omitempty"`
	WeakProtocol     bool              `json:"weak_protocol"`
	WeakCipher       bool              `json:"weak_cipher"`
	HostnameMismatch bool              `json:"hostname_mismatch"`
	CertExpiringSoon bool              `json:"cert_expiring_soon"`
	ProbeError       string            `json:"probe_error,omitempty"`
	Attempts         []TLSProbeAttempt `json:"attempts,omitempty"`
}

type tlsNativeProbeModule struct {
	meta    engine.ModuleMetadata
	options TLSProbeOptions
}

type tlsProbeCandidate struct {
	target         string
	hostname       string
	hostnameSource string
	port           int
}

type tlsProbeStrategy struct {
	name       string
	useSNI     bool
	forceTLS12 bool
}

type tlsProbeOutcome struct {
	tlsVersion       string
	cipherSuite      string
	alpn             string
	sniServerName    string
	certSubjectCN    string
	certIssuer       string
	certDNSNames     []string
	certNotBefore    time.Time
	certNotAfter     time.Time
	certIsExpired    bool
	certIsSelfSigned bool
	certSHA256       string
	weakProtocol     bool
	weakCipher       bool
	hostnameMismatch bool
	certExpiringSoon bool
	duration         time.Duration
}

var probeTLSDetailsFunc = probeTLSDetails

func newTLSNativeProbeModule() *tlsNativeProbeModule {
	return &tlsNativeProbeModule{
		meta: engine.ModuleMetadata{
			ID:          tlsNativeProbeModuleID,
			Name:        tlsNativeProbeModuleName,
			Description: tlsNativeProbeModuleDescription,
			Version:     "0.1.0",
			Type:        engine.ScanModuleType,
			Author:      "Vulntor Team",
			Tags:        []string{"scan", "tls", "enrichment", "native_probe"},
			Consumes: []engine.DataContractEntry{
				{
					Key:          "discovery.open_tcp_ports",
					DataTypeName: "discovery.TCPPortDiscoveryResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   true,
					Description:  "Open TCP ports used to identify TLS candidate services.",
				},
				{
					Key:          "config.original_cli_targets",
					DataTypeName: "[]string",
					Cardinality:  engine.CardinalitySingle,
					IsOptional:   true,
					Description:  "Original CLI targets used to preserve hostname for SNI fallback.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key:          "service.tls.details",
					DataTypeName: "scan.TLSServiceInfo",
					Cardinality:  engine.CardinalityList,
					Description:  "Structured TLS native probe output per target and port.",
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
					Description: "I/O timeout per attempt.",
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
				"extra_ports": {
					Description: "Additional TLS candidate ports to probe.",
					Type:        "[]int",
					Required:    false,
				},
			},
		},
		options: defaultTLSProbeOptions(),
	}
}

func (m *tlsNativeProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *tlsNativeProbeModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	opts := defaultTLSProbeOptions()
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
		opts.ExtraPorts = parseExtraPortsConfig(configMap["extra_ports"])
	}
	m.options = opts
	return nil
}

func (m *tlsNativeProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	rawOpenPorts, ok := inputs["discovery.open_tcp_ports"]
	if !ok {
		return nil
	}

	candidatePorts := buildTLSCandidatePortSet(m.options.ExtraPorts)
	fallbackHostname := resolveSingleNonIPHostnameTarget(readOriginalTargets(inputs))
	candidates := make(map[string]tlsProbeCandidate)
	for _, item := range toAnySlice(rawOpenPorts) {
		for _, candidate := range tlsCandidatesFromOpenPorts(item, candidatePorts) {
			key := fmt.Sprintf("%s:%d", candidate.target, candidate.port)
			if existing, exists := candidates[key]; exists {
				// Prefer candidate with hostname for SNI strategy.
				if existing.hostname == "" && candidate.hostname != "" {
					candidates[key] = candidate
				}
				continue
			}
			candidates[key] = candidate
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
			candidate.hostnameSource = "config.original_cli_targets"
			candidates[key] = candidate
		}
	}

	keys := make([]string, 0, len(candidates))
	for key := range candidates {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		c := candidates[key]
		log.Debug().
			Str("module", tlsNativeProbeModuleName).
			Str("target", c.target).
			Int("port", c.port).
			Str("candidate_hostname", c.hostname).
			Str("hostname_source", c.hostnameSource).
			Msg("Resolved TLS probe candidate hostname")
		result := probeTLSDetailsFunc(ctx, c.target, c.hostname, c.port, m.options)
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "service.tls.details",
			Data:           result,
			Timestamp:      time.Now(),
			Target:         c.target,
		}
	}

	return nil
}

func defaultTLSProbeOptions() TLSProbeOptions {
	return TLSProbeOptions{
		TotalTimeout:   2 * time.Second,
		ConnectTimeout: 1 * time.Second,
		IOTimeout:      1 * time.Second,
		Retries:        0,
	}
}

func buildTLSCandidatePortSet(extraPorts []int) map[int]struct{} {
	set := map[int]struct{}{
		443:  {},
		8443: {},
		9443: {},
	}
	for _, port := range extraPorts {
		if port > 0 && port <= 65535 {
			set[port] = struct{}{}
		}
	}
	return set
}

func parseExtraPortsConfig(raw any) []int {
	appendPort := func(result *[]int, seen map[int]struct{}, port int) {
		if port <= 0 || port > 65535 {
			return
		}
		if _, ok := seen[port]; ok {
			return
		}
		seen[port] = struct{}{}
		*result = append(*result, port)
	}

	result := make([]int, 0)
	seen := map[int]struct{}{}
	switch v := raw.(type) {
	case []int:
		for _, p := range v {
			appendPort(&result, seen, p)
		}
	case []any:
		for _, item := range v {
			switch p := item.(type) {
			case int:
				appendPort(&result, seen, p)
			case int64:
				appendPort(&result, seen, int(p))
			case float64:
				appendPort(&result, seen, int(p))
			case string:
				if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
					appendPort(&result, seen, n)
				}
			}
		}
	case []string:
		for _, s := range v {
			if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
				appendPort(&result, seen, n)
			}
		}
	case string:
		parts := strings.Split(v, ",")
		for _, part := range parts {
			if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
				appendPort(&result, seen, n)
			}
		}
	}

	sort.Ints(result)
	return result
}

func tlsCandidatesFromOpenPorts(item any, portSet map[int]struct{}) []tlsProbeCandidate {
	candidates := make([]tlsProbeCandidate, 0, 4)
	appendCandidate := func(target, hostname string, port int) {
		target = strings.TrimSpace(target)
		hostname = normalizeNonIPHostname(hostname)
		if target == "" {
			return
		}
		if _, ok := portSet[port]; !ok {
			return
		}
		source := ""
		if hostname != "" {
			source = "discovery.open_tcp_ports.hostname"
		}
		candidates = append(candidates, tlsProbeCandidate{
			target:         target,
			hostname:       hostname,
			hostnameSource: source,
			port:           port,
		})
	}

	switch v := item.(type) {
	case discovery.TCPPortDiscoveryResult:
		for _, port := range v.OpenPorts {
			appendCandidate(v.Target, v.Hostname, port)
		}
	case map[string]any:
		target, _ := v["target"].(string)
		hostname, _ := v["hostname"].(string)
		switch ports := v["open_ports"].(type) {
		case []int:
			for _, port := range ports {
				appendCandidate(target, hostname, port)
			}
		case []any:
			for _, rawPort := range ports {
				switch port := rawPort.(type) {
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

func buildTLSProbeStrategies(hostname string) []tlsProbeStrategy {
	hostname = strings.TrimSpace(hostname)
	strategies := make([]tlsProbeStrategy, 0, 3)
	if hostname != "" && net.ParseIP(hostname) == nil {
		strategies = append(strategies, tlsProbeStrategy{name: "tls-sni", useSNI: true})
	}
	strategies = append(strategies,
		tlsProbeStrategy{name: "tls-no-sni"},
		tlsProbeStrategy{name: "tls12-fallback", forceTLS12: true},
	)
	return strategies
}

func tlsStrategyNames(strategies []tlsProbeStrategy) []string {
	names := make([]string, 0, len(strategies))
	for _, strategy := range strategies {
		names = append(names, strategy.name)
	}
	return names
}

func probeTLSDetails(ctx context.Context, target, hostname string, port int, opts TLSProbeOptions) TLSServiceInfo {
	if opts.TotalTimeout <= 0 {
		opts.TotalTimeout = 2 * time.Second
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = 1 * time.Second
	}
	if opts.IOTimeout <= 0 {
		opts.IOTimeout = 1 * time.Second
	}
	if opts.Retries < 0 {
		opts.Retries = 0
	}

	probeCtx, cancel := context.WithTimeout(ctx, opts.TotalTimeout)
	defer cancel()

	result := TLSServiceInfo{
		Target:   target,
		Port:     port,
		Attempts: make([]TLSProbeAttempt, 0, len(buildTLSProbeStrategies(hostname))*(opts.Retries+1)),
	}

	bestScore := -1
	var bestOutcome tlsProbeOutcome
	errorCodes := make([]string, 0, len(result.Attempts))
	strategies := buildTLSProbeStrategies(hostname)

	log.Debug().
		Str("module", tlsNativeProbeModuleName).
		Str("target", target).
		Int("port", port).
		Str("hostname", hostname).
		Strs("strategies", tlsStrategyNames(strategies)).
		Msg("Prepared TLS probe strategies")

	for _, strategy := range strategies {
		for retry := 0; retry <= opts.Retries; retry++ {
			log.Debug().
				Str("module", tlsNativeProbeModuleName).
				Str("target", target).
				Int("port", port).
				Str("hostname", hostname).
				Str("strategy", strategy.name).
				Int("retry", retry).
				Msg("Running TLS probe strategy")
			outcome, err := probeSingleTLSStrategy(probeCtx, target, hostname, port, strategy, opts)
			if err != nil {
				code := classifyTLSProbeError(err)
				errorCodes = append(errorCodes, code)
				log.Debug().
					Str("module", tlsNativeProbeModuleName).
					Str("target", target).
					Int("port", port).
					Str("strategy", strategy.name).
					Str("error", code).
					Msg("TLS probe strategy failed")
				result.Attempts = append(result.Attempts, TLSProbeAttempt{
					Strategy:   strategy.name,
					Transport:  strconv.Itoa(port),
					Success:    false,
					DurationMS: outcome.duration.Milliseconds(),
					Error:      code,
				})
				continue
			}

			result.Attempts = append(result.Attempts, TLSProbeAttempt{
				Strategy:      strategy.name,
				Transport:     strconv.Itoa(port),
				Success:       true,
				DurationMS:    outcome.duration.Milliseconds(),
				TLSVersion:    outcome.tlsVersion,
				CipherSuite:   outcome.cipherSuite,
				SNIServerName: outcome.sniServerName,
			})
			log.Debug().
				Str("module", tlsNativeProbeModuleName).
				Str("target", target).
				Int("port", port).
				Str("strategy", strategy.name).
				Str("tls_version", outcome.tlsVersion).
				Str("sni_server_name", outcome.sniServerName).
				Msg("TLS probe strategy succeeded")

			score := scoreTLSOutcome(outcome)
			if score > bestScore {
				bestScore = score
				bestOutcome = outcome
			}
		}
	}

	if bestScore >= 0 {
		result.TLSProbe = true
		result.TLSVersion = bestOutcome.tlsVersion
		result.CipherSuite = bestOutcome.cipherSuite
		result.ALPN = bestOutcome.alpn
		result.SNIServerName = bestOutcome.sniServerName
		result.CertSubjectCN = bestOutcome.certSubjectCN
		result.CertIssuer = bestOutcome.certIssuer
		result.CertDNSNames = append([]string(nil), bestOutcome.certDNSNames...)
		result.CertNotBefore = bestOutcome.certNotBefore
		result.CertNotAfter = bestOutcome.certNotAfter
		result.CertIsExpired = bestOutcome.certIsExpired
		result.CertIsSelfSigned = bestOutcome.certIsSelfSigned
		result.CertSHA256 = bestOutcome.certSHA256
		result.WeakProtocol = bestOutcome.weakProtocol
		result.WeakCipher = bestOutcome.weakCipher
		result.HostnameMismatch = bestOutcome.hostnameMismatch
		result.CertExpiringSoon = bestOutcome.certExpiringSoon
		result.ProbeError = ""
		return result
	}

	result.TLSProbe = false
	result.ProbeError = pickTopTLSProbeError(errorCodes)
	if result.ProbeError == "" {
		result.ProbeError = "probe_failed"
	}
	return result
}

func probeSingleTLSStrategy(
	ctx context.Context,
	target string,
	hostname string,
	port int,
	strategy tlsProbeStrategy,
	opts TLSProbeOptions,
) (tlsProbeOutcome, error) {
	start := time.Now()
	outcome := tlsProbeOutcome{}

	address := net.JoinHostPort(target, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: opts.ConnectTimeout}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // Native probe gathers metadata from untrusted targets.
	}
	if strategy.useSNI {
		hostname = strings.TrimSpace(hostname)
		if hostname != "" && net.ParseIP(hostname) == nil {
			tlsConfig.ServerName = hostname
		}
	}
	if strategy.forceTLS12 {
		tlsConfig.MaxVersion = tls.VersionTLS12
	}

	tlsDialer := &tls.Dialer{
		NetDialer: dialer,
		Config:    tlsConfig,
	}

	rawConn, err := tlsDialer.DialContext(ctx, "tcp", address)
	if err != nil {
		outcome.duration = time.Since(start)
		return outcome, err
	}
	conn, ok := rawConn.(*tls.Conn)
	if !ok {
		_ = rawConn.Close()
		outcome.duration = time.Since(start)
		return outcome, errors.New("handshake_failed")
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

	state := conn.ConnectionState()
	tlsObs := extractTLSObservation(state)
	if tlsObs == nil {
		outcome.duration = time.Since(start)
		return outcome, errors.New("short_tls_response")
	}

	outcome.tlsVersion = strings.TrimSpace(tlsObs.Version)
	outcome.cipherSuite = strings.TrimSpace(tlsObs.CipherSuite)
	outcome.alpn = strings.TrimSpace(state.NegotiatedProtocol)
	outcome.sniServerName = strings.TrimSpace(tlsObs.ServerName)
	if outcome.sniServerName == "" {
		outcome.sniServerName = strings.TrimSpace(tlsConfig.ServerName)
	}
	outcome.certSubjectCN = strings.TrimSpace(tlsObs.PeerCommonName)
	outcome.certIssuer = strings.TrimSpace(tlsObs.Issuer)
	outcome.certDNSNames = append([]string(nil), tlsObs.PeerDNSNames...)
	outcome.certNotBefore = tlsObs.NotBefore
	outcome.certNotAfter = tlsObs.NotAfter
	outcome.certIsExpired = tlsObs.IsExpired
	outcome.certIsSelfSigned = tlsObs.IsSelfSigned
	outcome.weakProtocol = isWeakTLSVersion(outcome.tlsVersion)
	outcome.weakCipher = isWeakCipher(outcome.cipherSuite)
	outcome.certExpiringSoon = isCertExpiringSoon(outcome.certNotAfter, time.Now())

	if len(state.PeerCertificates) > 0 {
		sum := sha256.Sum256(state.PeerCertificates[0].Raw)
		outcome.certSHA256 = hex.EncodeToString(sum[:])
		if tlsConfig.ServerName != "" {
			outcome.hostnameMismatch = state.PeerCertificates[0].VerifyHostname(tlsConfig.ServerName) != nil
		}
	}

	outcome.duration = time.Since(start)
	return outcome, nil
}

func scoreTLSOutcome(outcome tlsProbeOutcome) int {
	score := 0
	if strings.TrimSpace(outcome.tlsVersion) != "" {
		score += 2
	}
	if strings.TrimSpace(outcome.cipherSuite) != "" {
		score += 2
	}
	if strings.TrimSpace(outcome.certSubjectCN) != "" {
		score += 2
	}
	if !outcome.certNotAfter.IsZero() {
		score++
	}
	if strings.TrimSpace(outcome.certSHA256) != "" {
		score++
	}
	if strings.TrimSpace(outcome.sniServerName) != "" {
		score++
	}
	return score
}

func isWeakTLSVersion(version string) bool {
	v := strings.ToUpper(strings.TrimSpace(version))
	return strings.Contains(v, "TLS1.0") ||
		strings.Contains(v, "TLS1.1") ||
		strings.Contains(v, "SSL")
}

func isWeakCipher(cipherSuite string) bool {
	c := strings.ToUpper(strings.TrimSpace(cipherSuite))
	if c == "" {
		return false
	}
	weakTokens := []string{"RC4", "3DES", "_DES_", "NULL", "MD5", "EXPORT"}
	for _, token := range weakTokens {
		if strings.Contains(c, token) {
			return true
		}
	}
	return false
}

func isCertExpiringSoon(notAfter time.Time, now time.Time) bool {
	if notAfter.IsZero() {
		return false
	}
	return !notAfter.After(now.Add(30 * 24 * time.Hour))
}

func classifyTLSProbeError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"), strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case strings.Contains(msg, "connection refused"):
		return "refused"
	case strings.Contains(msg, "short_tls_response"):
		return "short_response"
	case strings.Contains(msg, "tls:"), strings.Contains(msg, "handshake"):
		return "handshake_failed"
	default:
		return "probe_failed"
	}
}

func pickTopTLSProbeError(codes []string) string {
	if len(codes) == 0 {
		return ""
	}
	priority := map[string]int{
		"timeout":          5,
		"refused":          4,
		"handshake_failed": 3,
		"short_response":   2,
		"probe_failed":     1,
	}

	best := ""
	bestPriority := -1
	for _, code := range codes {
		if p := priority[code]; p > bestPriority {
			bestPriority = p
			best = code
		}
	}
	return best
}

func tlsNativeProbeModuleFactory() engine.Module {
	return newTLSNativeProbeModule()
}

func init() {
	engine.RegisterModuleFactory(tlsNativeProbeModuleName, tlsNativeProbeModuleFactory)
}
