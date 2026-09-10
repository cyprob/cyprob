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
	"github.com/cyprob/cyprob/pkg/fingerprint"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cast"
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
	// EnumerateCipherSuites turns on the suite and version walk. It is off by
	// default, and that default is the point: enumeration asks a service the
	// same question repeatedly, so its cost is a function of what the server
	// supports rather than of one handshake, and it is paid on every port that
	// completes one. Until a real estate has been measured, that belongs behind
	// a switch rather than in everyone's ordinary scan.
	EnumerateCipherSuites bool `json:"enumerate_cipher_suites"`
}

// TLSProbeAttempt represents one probe strategy attempt.
type TLSProbeAttempt struct {
	Strategy   string `json:"strategy"`
	Transport  string `json:"transport"`
	Success    bool   `json:"success"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
	// CertParseError is the x509 rule the server's certificate broke, verbatim,
	// on the attempt that met it. Error carries the code and this carries the
	// reason, for the same reason the raw ServerHello reader keeps the verdict
	// and the alert in separate fields (cyprob#294): a code and a reason in one
	// string is the defect this issue is about, one level down.
	CertParseError string `json:"cert_parse_error,omitempty"`
	TLSVersion     string `json:"tls_version,omitempty"`
	CipherSuite    string `json:"cipher_suite,omitempty"`
	SNIServerName  string `json:"sni_server_name,omitempty"`
}

// TLSServiceInfo is the canonical TLS native probe output.
type TLSServiceInfo struct {
	Target           string    `json:"target"`
	Port             int       `json:"port"`
	TLSProbe         bool      `json:"tls_probe"`
	TLSVersion       string    `json:"tls_version,omitempty"`
	CipherSuite      string    `json:"cipher_suite,omitempty"`
	ALPN             string    `json:"alpn,omitempty"`
	SNIServerName    string    `json:"sni_server_name,omitempty"`
	CertSubjectCN    string    `json:"cert_subject_cn,omitempty"`
	CertIssuer       string    `json:"cert_issuer,omitempty"`
	CertDNSNames     []string  `json:"cert_dns_names,omitempty"`
	CertNotBefore    time.Time `json:"cert_not_before,omitzero"`
	CertNotAfter     time.Time `json:"cert_not_after,omitzero"`
	CertIsExpired    bool      `json:"cert_is_expired"`
	CertIsSelfSigned bool      `json:"cert_is_self_signed"`
	CertSHA256       string    `json:"cert_sha256,omitempty"`
	// CertSerial is the leaf certificate serial, uppercase colon-separated hex.
	// It answers a different question from CertSHA256: the hash says whether two
	// observations are the same certificate, the serial is what the issuing CA
	// indexes by, so it is the key for a revocation list or a PKI inventory.
	CertSerial string `json:"cert_serial,omitempty"`
	// Enumeration is what else the server would have accepted, which the
	// negotiated suite and version above cannot say. Nil when the service was
	// never reached. See tls_suite_enumeration.go.
	Enumeration *TLSEnumeration `json:"enumeration,omitempty"`
	// VendorHint/ProductHint are device identity derived from the certificate
	// subject/issuer. Appliances sign their own management certificates and name
	// themselves in them, so this identifies hosts that expose nothing else.
	VendorHint       string `json:"vendor_hint,omitempty"`
	ProductHint      string `json:"product_hint,omitempty"`
	WeakProtocol     bool   `json:"weak_protocol"`
	WeakCipher       bool   `json:"weak_cipher"`
	HostnameMismatch bool   `json:"hostname_mismatch"`
	CertExpiringSoon bool   `json:"cert_expiring_soon"`
	ProbeError       string `json:"probe_error,omitempty"`
	// CertParseError is the reason behind a "cert_parse_failed" ProbeError. It
	// is repeated from the attempt because Attempts never reaches the reporting
	// layer -- asset_profile_builder writes ProbeError and nothing else -- so
	// without it the operator learns that a certificate was refused and never
	// which rule it broke, which is the actionable half.
	CertParseError string            `json:"cert_parse_error,omitempty"`
	Attempts       []TLSProbeAttempt `json:"attempts,omitempty"`
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
	name   string
	useSNI bool
	// forceTLS12 lowers the ceiling to TLS 1.2. It does not lower the floor:
	// crypto/tls refuses TLS 1.0 and 1.1 by default and this does not change
	// that. The strategy is named for the ceiling for that reason.
	forceTLS12 bool
	// observation marks the strategy as belonging to the observation channel,
	// which dials on wider terms than anything that carries traffic. See
	// tls_observation_channel.go.
	observation bool
	// offerALPN advertises the application protocols below. It is per-strategy
	// rather than global because offering ALPN can cost a handshake: a server
	// that configures ALPN and shares none of our protocols answers alert 120
	// instead of completing (measured, cyprob#306). The observation channel
	// therefore never offers it -- that channel exists to read services nothing
	// else can, and a question that loses the answer has no place in it.
	offerALPN bool
}

// tlsProbeALPNProtocols is what the probe advertises. Deliberately the pair
// that answers one question -- is this TLS carrying HTTP -- rather than a long
// list, because every entry is a protocol we claim to speak and then do not.
//
// Note which way the risk runs, since it is the opposite of what it looks like:
// a LONGER list is *safer* against alert 120, not riskier, because the alert
// comes from having no protocol in common. Widening this is therefore a
// question about what we are willing to claim, not about losing handshakes.
var tlsProbeALPNProtocols = []string{"h2", "http/1.1"}

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
	certSerial       string
	weakProtocol     bool
	weakCipher       bool
	hostnameMismatch bool
	certExpiringSoon bool
	duration         time.Duration
}

var probeTLSDetailsFunc = probeTLSDetails

func newTLSNativeProbeModuleWithSpec(moduleID string, moduleName string, description string, outputKey string, tags []string) *tlsNativeProbeModule {
	return &tlsNativeProbeModule{
		meta: buildTCPNativeProbeMetadata(tcpNativeProbeMetadataSpec{
			moduleID:              moduleID,
			moduleName:            moduleName,
			description:           description,
			outputKey:             outputKey,
			outputType:            "scan.TLSServiceInfo",
			outputDescription:     "Structured TLS native probe output per target and port.",
			tags:                  tags,
			consumes:              []engine.DataContractEntry{nativeOpenTCPPortsConsume(true, "Open TCP ports used to identify TLS candidate services."), nativeOriginalTargetsConsume("Original CLI targets used to preserve hostname for SNI fallback.")},
			timeoutDefault:        "2s",
			connectTimeoutDefault: "1s",
			ioTimeoutDefault:      "1s",
			extraConfigParameters: map[string]engine.ParameterDefinition{
				"extra_ports": {
					Description: "Additional TLS candidate ports to probe.",
					Type:        "[]int",
					Required:    false,
				},
				"enumerate_cipher_suites": {
					Description: "Walk the cipher suites and versions each TLS service accepts. Off by default: it costs one dial per supported suite per service.",
					Type:        "bool",
					Required:    false,
					Default:     false,
				},
			},
		}),
		options: defaultTLSProbeOptions(),
	}
}

func newTLSNativeProbeModule() *tlsNativeProbeModule {
	return newTLSNativeProbeModuleWithSpec(
		tlsNativeProbeModuleID,
		tlsNativeProbeModuleName,
		tlsNativeProbeModuleDescription,
		"service.tls.details",
		[]string{"scan", "tls", "enrichment", "native_probe"},
	)
}

func (m *tlsNativeProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *tlsNativeProbeModule) Init(instanceID string, configMap map[string]any) error {
	opts := defaultTLSProbeOptions()
	initCommonTCPProbeOptions(&m.meta, instanceID, configMap, &opts.TotalTimeout, &opts.ConnectTimeout, &opts.IOTimeout, &opts.Retries)
	opts.ExtraPorts = parseOptionalPortList(configMap, "extra_ports")
	if value, ok := configMap["enumerate_cipher_suites"]; ok {
		opts.EnumerateCipherSuites = cast.ToBool(value)
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
			DataKey:        m.meta.Produces[0].Key,
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
		if port <= 0 || port > 65535 {
			continue
		}
		// extra_ports is whatever the caller scanned, not a list of ports anyone
		// believed speak TLS: EE fills it from the scan's own port spec, so the
		// default set already contains 515 and 9099-9103. A ClientHello on those
		// is not a failed probe, it is a print job — the listener turns bytes
		// into paper (cyprob-ee#590). Dropped here rather than filtered by the
		// caller so no configuration can put them back.
		if fingerprint.IsPrintPort(port) {
			continue
		}
		set[port] = struct{}{}
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
		strategies = append(strategies, tlsProbeStrategy{name: "tls-sni", useSNI: true, offerALPN: true})
	}
	strategies = append(strategies,
		tlsProbeStrategy{name: "tls-no-sni", offerALPN: true},
		tlsProbeStrategy{name: "tls12-ceiling", forceTLS12: true, offerALPN: true},
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
	// Second floor, deliberately not the only one: candidate selection above
	// already drops these ports. This module builds its own connections and
	// never passes through the banner-grab funnel that carries the equivalent
	// check, so a future caller that assembles candidates some other way would
	// otherwise reach the dial with nothing in the way (cyprob-ee#590).
	if fingerprint.IsPrintPort(port) {
		return TLSServiceInfo{
			Target:     target,
			Port:       port,
			ProbeError: "print_port_write_blocked",
			Attempts:   []TLSProbeAttempt{},
		}
	}

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

	var runStrategy func(strategy tlsProbeStrategy, retry int)
	runStrategy = func(strategy tlsProbeStrategy, retry int) {
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
			errorCodes = append(errorCodes, string(code))
			log.Debug().
				Str("module", tlsNativeProbeModuleName).
				Str("target", target).
				Int("port", port).
				Str("strategy", strategy.name).
				Str("error", string(code)).
				// The raw text, because after classification the specific x509
				// rule survives in CertParseError and nowhere else. If that
				// field is ever dropped this line is the only way back.
				Str("detail", err.Error()).
				Msg("TLS probe strategy failed")
			attempt := TLSProbeAttempt{
				Strategy:   strategy.name,
				Transport:  strconv.Itoa(port),
				Success:    false,
				DurationMS: outcome.duration.Milliseconds(),
				Error:      string(code),
			}
			// On the attempt that met it, not on every attempt: a probe that
			// times out on one strategy and meets an unreadable certificate on
			// the next must not report a certificate reason against the
			// timeout.
			if code == ProbeCodeCertParseFailed {
				attempt.CertParseError = certParseReason(err)
			}
			result.Attempts = append(result.Attempts, attempt)
			// Asking cost the answer, so un-ask it. A server that configures
			// ALPN and shares none of our protocols answers alert 120 rather
			// than completing, and without this the probe would lose a service
			// it reads today purely because we started offering ALPN. One extra
			// dial, only for that population, and both attempts stay in the
			// record so the cost is visible rather than hidden inside one.
			if strategy.offerALPN && isALPNRefusal(err) {
				retryStrategy := strategy
				retryStrategy.offerALPN = false
				retryStrategy.name = strategy.name + "-no-alpn"
				runStrategy(retryStrategy, retry)
			}
			return
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

	for _, strategy := range strategies {
		for retry := 0; retry <= opts.Retries; retry++ {
			runStrategy(strategy, retry)
		}
	}

	// The observation channel runs only where it can add something: a service
	// every ordinary strategy already read has been observed, and dialing it
	// again on wider terms would return the same negotiation at the cost of an
	// extra handshake. crypto/tls picks the highest version both sides accept,
	// so a wide dial against a healthy server reports exactly what the strict
	// one did. Reaching here means the service was not read at all, which is
	// the case the channel exists for.
	if bestScore < 0 {
		log.Debug().
			Str("module", tlsNativeProbeModuleName).
			Str("target", target).
			Int("port", port).
			Msg("No strategy completed a handshake, falling back to the observation channel")
		runStrategy(buildTLSObservationStrategy(hostname), 0)
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
		result.CertSerial = bestOutcome.certSerial
		result.VendorHint, result.ProductHint = deriveTLSCertIdentity(result.CertSubjectCN, result.CertIssuer)
		result.WeakProtocol = bestOutcome.weakProtocol
		result.WeakCipher = bestOutcome.weakCipher
		result.HostnameMismatch = bestOutcome.hostnameMismatch
		result.CertExpiringSoon = bestOutcome.certExpiringSoon
		result.ProbeError = ""
		// Enumeration asks a different question from everything above, so it
		// runs on every service that answered at all -- including one only the
		// observation channel could reach, which is the service most worth
		// asking. It carries its own budget rather than the probe's, because
		// its cost is a function of what the server supports and not of how
		// long a single handshake takes.
		if opts.EnumerateCipherSuites {
			result.Enumeration = enumerateTLS(ctx, target, hostname, port, opts)
		}
		return result
	}

	result.TLSProbe = false
	result.ProbeError = pickTopTLSProbeError(errorCodes)
	if result.ProbeError == "" {
		result.ProbeError = string(ProbeCodeProbeFailed)
	}
	if result.ProbeError == string(ProbeCodeCertParseFailed) {
		result.CertParseError = firstCertParseReason(result.Attempts)
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
	if strategy.observation {
		applyTLSObservationConfig(tlsConfig)
	}
	if strategy.offerALPN {
		tlsConfig.NextProtos = append([]string(nil), tlsProbeALPNProtocols...)
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
	outcome.certSerial = tlsObs.CertSerial
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

// certParseReason pulls the x509 rule out of crypto/tls's wrapper, which reads
// "tls: failed to parse certificate from server: x509: <rule>". The wrapper
// adds nothing a reader wants and the rule is the whole value, so the prefix is
// dropped -- but only when it is actually there, so an unexpected shape is
// carried whole rather than truncated into something misleading.
func certParseReason(err error) string {
	if err == nil {
		return ""
	}
	const marker = "failed to parse certificate from server: "
	text := err.Error()
	if index := strings.Index(text, marker); index >= 0 {
		return strings.TrimSpace(text[index+len(marker):])
	}
	return strings.TrimSpace(text)
}

// firstCertParseReason returns the reason from the first attempt that met an
// unreadable certificate. First rather than last because the strategies run in
// a deliberate order and the earliest is the closest to what an ordinary client
// would have done.
func firstCertParseReason(attempts []TLSProbeAttempt) string {
	for _, attempt := range attempts {
		if attempt.Error == string(ProbeCodeCertParseFailed) && attempt.CertParseError != "" {
			return attempt.CertParseError
		}
	}
	return ""
}

// isALPNRefusal reports the one handshake failure that this probe causes by
// asking: RFC 7301 lets a server that shares no application protocol with the
// client abort with no_application_protocol rather than negotiate nothing.
// Measured against a real listener: a server configured with an unrelated
// protocol completes the handshake for a client that offers none, and refuses
// the same client the moment it offers h2 and http/1.1 (cyprob#306).
//
// Matched on the message rather than on the alert byte because crypto/tls
// surfaces it as a *tls.AlertError only on some paths and as a plain
// "remote error: tls: no application protocol" here.
func isALPNRefusal(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "no application protocol")
}

func classifyTLSProbeError(err error) ProbeCode {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"), strings.Contains(msg, "i/o timeout"):
		return ProbeCodeTimeout
	case strings.Contains(msg, "connection refused"):
		return ProbeCodeRefused
	case strings.Contains(msg, "short_tls_response"):
		return ProbeCodeShortResponse
	// Above the "tls:" arm on purpose: that arm matches this message too, and
	// below it this case is unreachable. Matched on the full server-side
	// sentence rather than on "x509:" or "failed to parse certificate":
	// crypto/tls emits this exact wrapper from one place, handshake_client.go's
	// verifyServerCertificate, on both the 1.2 and 1.3 paths. The other two
	// "failed to parse certificate" sites in crypto/tls are about OUR OWN
	// certificate, which this probe never presents; and "x509:" alone would
	// also catch verification failures, which cannot arise while the probe
	// dials with InsecureSkipVerify but would be misfiled the day a verifying
	// strategy is added.
	case strings.Contains(msg, "failed to parse certificate from server"):
		return ProbeCodeCertParseFailed
	case strings.Contains(msg, "tls:"), strings.Contains(msg, "handshake"):
		return ProbeCodeHandshakeFailed
	default:
		return ProbeCodeProbeFailed
	}
}

func pickTopTLSProbeError(codes []string) string {
	if len(codes) == 0 {
		return ""
	}
	priority := map[string]int{
		// Above timeout, and that is load-bearing rather than cosmetic. One
		// probeCtx budget is shared across every strategy and retry, so a
		// single slow attempt anywhere contributes "timeout" -- which would
		// otherwise outrank and hide the one code in this set that is backed by
		// bytes we received and identified. Every other code here is also what
		// a dead port looks like.
		string(ProbeCodeCertParseFailed): 6,
		string(ProbeCodeTimeout):         5,
		string(ProbeCodeRefused):         4,
		string(ProbeCodeHandshakeFailed): 3,
		string(ProbeCodeShortResponse):   2,
		string(ProbeCodeProbeFailed):     1,
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
