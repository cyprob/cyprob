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
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

const (
	ftpNativeProbeModuleID          = "ftp-native-probe-instance"
	ftpNativeProbeModuleName        = "ftp-native-probe"
	ftpNativeProbeModuleDescription = "Runs bounded FTP and FTPS probes and emits structured FTP metadata."

	ftpResponseMaxBytes = 4096
	ftpResponseMaxLines = 48
	ftpBannerMaxSize    = 512
	ftpFeatureMaxSize   = 2048
)

type FTPProbeOptions struct {
	TotalTimeout   time.Duration `json:"total_timeout"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	IOTimeout      time.Duration `json:"io_timeout"`
	Retries        int           `json:"retries"`
	CandidatePorts []int         `json:"candidate_ports,omitempty"`
}

type FTPProbeAttempt struct {
	Strategy    string `json:"strategy"`
	Transport   string `json:"transport"`
	Success     bool   `json:"success"`
	DurationMS  int64  `json:"duration_ms"`
	Error       string `json:"error,omitempty"`
	TLSVersion  string `json:"tls_version,omitempty"`
	CipherSuite string `json:"tls_cipher_suite,omitempty"`
}

type FTPServiceInfo struct {
	Target           string            `json:"target"`
	Port             int               `json:"port"`
	FTPProbe         bool              `json:"ftp_probe"`
	FTPProtocol      string            `json:"ftp_protocol,omitempty"`
	Banner           string            `json:"banner,omitempty"`
	GreetingCode     int               `json:"greeting_code,omitempty"`
	Features         []string          `json:"features,omitempty"`
	AuthTLSSupported bool              `json:"auth_tls_supported"`
	TLSEnabled       bool              `json:"tls_enabled"`
	TLSVersion       string            `json:"tls_version,omitempty"`
	TLSCipherSuite   string            `json:"tls_cipher_suite,omitempty"`
	CertSubjectCN    string            `json:"cert_subject_cn,omitempty"`
	CertIssuer       string            `json:"cert_issuer,omitempty"`
	CertNotAfter     time.Time         `json:"cert_not_after,omitzero"`
	CertIsSelfSigned bool              `json:"cert_is_self_signed"`
	SystemHint       string            `json:"system_hint,omitempty"`
	SoftwareHint     string            `json:"software_hint,omitempty"`
	VendorHint       string            `json:"vendor_hint,omitempty"`
	VersionHint      string            `json:"version_hint,omitempty"`
	WeakTLSProtocol  bool              `json:"weak_tls_protocol"`
	WeakTLSCipher    bool              `json:"weak_tls_cipher"`
	ProbeError       string            `json:"probe_error,omitempty"`
	Attempts         []FTPProbeAttempt `json:"attempts,omitempty"`
}

type ftpNativeProbeModule struct {
	meta    engine.ModuleMetadata
	options FTPProbeOptions
}

type ftpProbeCandidate struct {
	target       string
	hostname     string
	port         int
	protocolHint string
}

type ftpResponse struct {
	Code  int
	Raw   string
	Lines []string
}

type ftpProbeOutcome struct {
	banner           string
	greetingCode     int
	features         []string
	authTLSSupported bool
	tlsEnabled       bool
	tlsVersion       string
	tlsCipherSuite   string
	certSubjectCN    string
	certIssuer       string
	certNotAfter     time.Time
	certIsSelfSigned bool
	systemHint       string
	softwareHint     string
	vendorHint       string
	versionHint      string
	weakTLSProtocol  bool
	weakTLSCipher    bool
}

type ftpClient struct {
	conn   net.Conn
	reader *bufio.Reader
}

var (
	probeFTPDetailsFunc = probeFTPDetails

	ftpCrushPattern     = regexp.MustCompile(`(?i)\bcrushftp(?:sshd)?(?:\s+v?([0-9][0-9a-z._-]*))?`)
	ftpPurePattern      = regexp.MustCompile(`(?i)\bpure-ftpd(?:\s+([0-9][0-9a-z._-]*))?`)
	ftpProFTPDPattern   = regexp.MustCompile(`(?i)\bproftpd(?:\s+([0-9][0-9a-z._-]*))?`)
	ftpVSFTPDPattern    = regexp.MustCompile(`(?i)\bvsftpd(?:\s+([0-9][0-9a-z._-]*))?|\(vsftpd\s+([0-9][0-9a-z._-]*)\)`)
	ftpFileZillaPattern = regexp.MustCompile(`(?i)\bfilezilla server(?: version)?\s*([0-9][0-9a-z._-]*)?`)
)

func newFTPNativeProbeModuleWithSpec(moduleID string, moduleName string, description string, outputKey string, tags []string) *ftpNativeProbeModule {
	return &ftpNativeProbeModule{
		meta: buildTCPNativeProbeMetadata(tcpNativeProbeMetadataSpec{
			moduleID:              moduleID,
			moduleName:            moduleName,
			description:           description,
			outputKey:             outputKey,
			outputType:            "scan.FTPServiceInfo",
			outputDescription:     "Structured FTP native probe output per target and port.",
			tags:                  tags,
			consumes:              []engine.DataContractEntry{nativeOpenTCPPortsConsume(false, "Open TCP ports used to identify FTP candidate services."), nativeBannerConsume("Banner results used as fallback FTP candidate source."), nativeOriginalTargetsConsume("Original CLI targets used to preserve hostname for TLS server name fallback.")},
			timeoutDefault:        "2500ms",
			connectTimeoutDefault: "800ms",
			ioTimeoutDefault:      "800ms",
			extraConfigParameters: map[string]engine.ParameterDefinition{
				"candidate_ports": {
					Description: "Optional explicit ports to treat as FTP candidates when already known open.",
					Type:        "[]int",
					Required:    false,
				},
			},
		}),
		options: defaultFTPProbeOptions(),
	}
}

func newFTPNativeProbeModule() *ftpNativeProbeModule {
	return newFTPNativeProbeModuleWithSpec(
		ftpNativeProbeModuleID,
		ftpNativeProbeModuleName,
		ftpNativeProbeModuleDescription,
		"service.ftp.details",
		[]string{"scan", "ftp", "enrichment", "native_probe"},
	)
}

func (m *ftpNativeProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *ftpNativeProbeModule) Init(instanceID string, configMap map[string]any) error {
	opts := defaultFTPProbeOptions()
	initCommonTCPProbeOptions(&m.meta, instanceID, configMap, &opts.TotalTimeout, &opts.ConnectTimeout, &opts.IOTimeout, &opts.Retries)
	opts.CandidatePorts = parseOptionalPortList(configMap, "candidate_ports")
	m.options = opts
	return nil
}

func (m *ftpNativeProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
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

	fallbackHostname := resolveSingleNonIPHostnameTarget(readOriginalTargets(inputs))
	candidates := make(map[string]ftpProbeCandidate)
	for _, item := range toAnySlice(rawOpenPorts) {
		for _, candidate := range ftpCandidatesFromOpenPorts(item, explicitCandidatePorts) {
			mergeFTPCandidate(candidates, candidate)
		}
	}

	if rawBanner, ok := inputs["service.banner.tcp"]; ok {
		for _, item := range toAnySlice(rawBanner) {
			candidate, ok := ftpCandidateFromBanner(item, explicitCandidatePorts)
			if !ok {
				continue
			}
			mergeFTPCandidate(candidates, candidate)
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
			leftPriority := ftpPortPriority(left.port)
			rightPriority := ftpPortPriority(right.port)
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

		result := probeFTPDetailsFunc(targetCtx, candidate.target, candidate.hostname, candidate.port, candidate.protocolHint, m.options)
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

func defaultFTPProbeOptions() FTPProbeOptions {
	return FTPProbeOptions{
		TotalTimeout:   2500 * time.Millisecond,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
		Retries:        0,
	}
}

func ftpCandidatesFromOpenPorts(item any, explicitCandidatePorts map[int]struct{}) []ftpProbeCandidate {
	candidates := make([]ftpProbeCandidate, 0, 2)
	appendCandidate := func(target, hostname string, port int) {
		target = strings.TrimSpace(target)
		hostname = normalizeNonIPHostname(hostname)
		if target == "" || port <= 0 || port > 65535 {
			return
		}
		if !isFTPNativePort(port) {
			if _, ok := explicitCandidatePorts[port]; !ok {
				return
			}
		}
		candidates = append(candidates, ftpProbeCandidate{
			target:       target,
			hostname:     hostname,
			port:         port,
			protocolHint: ftpProtocolFromPort(port),
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

func ftpCandidateFromBanner(item any, explicitCandidatePorts map[int]struct{}) (ftpProbeCandidate, bool) {
	switch v := item.(type) {
	case BannerGrabResult:
		if !isFTPBannerCandidate(v, explicitCandidatePorts) {
			return ftpProbeCandidate{}, false
		}
		return ftpProbeCandidate{
			target:       strings.TrimSpace(v.IP),
			hostname:     firstNonEmptyHostname(v.ProbeHost, v.SNIServerName),
			port:         v.Port,
			protocolHint: ftpProtocolFromBanner(v.Protocol, v.Banner),
		}, strings.TrimSpace(v.IP) != "" && v.Port > 0
	case map[string]any:
		target := getMapString(v, "ip", "IP")
		if target == "" {
			return ftpProbeCandidate{}, false
		}
		port := mapPortValue(v["port"])
		if port <= 0 {
			return ftpProbeCandidate{}, false
		}
		candidate := ftpProbeCandidate{
			target:       target,
			hostname:     firstNonEmptyHostname(getMapString(v, "probe_host", "ProbeHost"), getMapString(v, "sni_server_name", "SNIServerName")),
			port:         port,
			protocolHint: ftpProtocolFromBanner(getMapString(v, "protocol", "Protocol"), getMapString(v, "banner", "Banner")),
		}
		if isFTPNativePort(port) || isExplicitFTPPort(port, explicitCandidatePorts) {
			return candidate, true
		}
		if containsFTPHint(getMapString(v, "protocol", "Protocol")) ||
			containsFTPHint(getMapString(v, "banner", "Banner")) ||
			mapEvidenceLooksLikeFTP(v["evidence"]) {
			return candidate, true
		}
	}
	return ftpProbeCandidate{}, false
}

func mergeFTPCandidate(dst map[string]ftpProbeCandidate, candidate ftpProbeCandidate) {
	key := ftpCandidateKey(candidate)
	if current, ok := dst[key]; ok {
		if current.hostname == "" && candidate.hostname != "" {
			current.hostname = candidate.hostname
		}
		if current.protocolHint != "ftps" && candidate.protocolHint == "ftps" {
			current.protocolHint = candidate.protocolHint
		}
		dst[key] = current
		return
	}
	dst[key] = candidate
}

func isFTPBannerCandidate(banner BannerGrabResult, explicitCandidatePorts map[int]struct{}) bool {
	if isFTPNativePort(banner.Port) || isExplicitFTPPort(banner.Port, explicitCandidatePorts) {
		return true
	}
	if containsFTPHint(banner.Protocol) || containsFTPHint(banner.Banner) {
		return true
	}
	for _, obs := range banner.Evidence {
		if containsFTPHint(obs.Protocol) ||
			containsFTPHint(obs.ProbeID) ||
			containsFTPHint(obs.Description) ||
			containsFTPHint(obs.Response) {
			return true
		}
	}
	return false
}

func mapEvidenceLooksLikeFTP(raw any) bool {
	items, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if containsFTPHint(getMapString(m, "protocol", "Protocol")) ||
			containsFTPHint(getMapString(m, "probe_id", "ProbeID")) ||
			containsFTPHint(getMapString(m, "description", "Description")) ||
			containsFTPHint(getMapString(m, "response", "Response")) {
			return true
		}
	}
	return false
}

func containsFTPHint(value string) bool {
	clean := strings.ToLower(strings.TrimSpace(value))
	if clean == "" {
		return false
	}
	return clean == "ftp" ||
		clean == "ftps" ||
		strings.Contains(clean, "crushftp") ||
		strings.Contains(clean, "pure-ftpd") ||
		strings.Contains(clean, "proftpd") ||
		strings.Contains(clean, "vsftpd") ||
		strings.Contains(clean, "filezilla server") ||
		strings.Contains(clean, "ftp server ready") ||
		strings.Contains(clean, "welcome to crushftp")
}

func ftpProtocolFromBanner(protocol string, banner string) string {
	if strings.EqualFold(strings.TrimSpace(protocol), "ftps") || strings.Contains(strings.ToLower(strings.TrimSpace(banner)), "ftps") {
		return "ftps"
	}
	return "ftp"
}

func ftpCandidateKey(candidate ftpProbeCandidate) string {
	return fmt.Sprintf("%s:%d", candidate.target, candidate.port)
}

func ftpPortPriority(port int) int {
	switch port {
	case 21:
		return 2
	case 990:
		return 1
	default:
		return 0
	}
}

func ftpProtocolFromPort(port int) string {
	if port == 990 {
		return "ftps"
	}
	return "ftp"
}

func isFTPNativePort(port int) bool {
	return port == 21 || port == 990
}

func isExplicitFTPPort(port int, explicitCandidatePorts map[int]struct{}) bool {
	_, ok := explicitCandidatePorts[port]
	return ok
}

func probeFTPDetails(ctx context.Context, target string, hostname string, port int, protocolHint string, opts FTPProbeOptions) FTPServiceInfo {
	if port <= 0 {
		port = 21
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

	result := FTPServiceInfo{
		Target:      target,
		Port:        port,
		FTPProtocol: ftpProtocolFromPort(port),
		Attempts:    make([]FTPProbeAttempt, 0, 4+opts.Retries),
	}
	if strings.EqualFold(strings.TrimSpace(protocolHint), "ftps") {
		result.FTPProtocol = "ftps"
	}

	if result.FTPProtocol == "ftps" {
		return probeFTPSImplicitTLS(probeCtx, target, hostname, port, opts, result)
	}
	return probeFTPPlainAndExplicitTLS(probeCtx, target, hostname, port, opts, result)
}

func probeFTPPlainAndExplicitTLS(ctx context.Context, target string, hostname string, port int, opts FTPProbeOptions, result FTPServiceInfo) FTPServiceInfo {
	errorCodes := make([]string, 0, opts.Retries+1)

	for retry := 0; retry <= opts.Retries; retry++ {
		client, err := dialFTPPlain(ctx, target, port, opts)
		if err != nil {
			code := classifyFTPConnectError(err)
			errorCodes = append(errorCodes, code)
			result.Attempts = append(result.Attempts, FTPProbeAttempt{
				Strategy:   "ftp-connect",
				Transport:  "tcp",
				Success:    false,
				DurationMS: 0,
				Error:      code,
			})
			continue
		}

		attemptErrors := make([]string, 0, 2)
		greetingStart := time.Now()
		greeting, err := client.readResponse(ctx, opts.IOTimeout)
		if err != nil {
			_ = client.close()
			code := classifyFTPBannerError(err)
			errorCodes = append(errorCodes, code)
			result.Attempts = append(result.Attempts, FTPProbeAttempt{
				Strategy:   "ftp-greeting",
				Transport:  "tcp",
				Success:    false,
				DurationMS: time.Since(greetingStart).Milliseconds(),
				Error:      code,
			})
			continue
		}
		if greeting.Code != 220 {
			_ = client.close()
			errorCodes = append(errorCodes, "protocol_mismatch")
			result.Attempts = append(result.Attempts, FTPProbeAttempt{
				Strategy:   "ftp-greeting",
				Transport:  "tcp",
				Success:    false,
				DurationMS: time.Since(greetingStart).Milliseconds(),
				Error:      "protocol_mismatch",
			})
			continue
		}

		result.Attempts = append(result.Attempts, FTPProbeAttempt{
			Strategy:   "ftp-greeting",
			Transport:  "tcp",
			Success:    true,
			DurationMS: time.Since(greetingStart).Milliseconds(),
		})
		result.FTPProbe = true
		outcome := buildFTPOutcome(result.FTPProtocol, greeting, ftpResponse{}, ftpResponse{}, nil)
		applyFTPOutcome(&result, outcome)

		featStart := time.Now()
		feat, featErr := runFTPCommand(ctx, client, opts, "FEAT\r\n")
		if featErr != nil || feat.Code != 211 {
			code := "feat_failed"
			if featErr != nil && isFTPTimeoutError(featErr) {
				code = "timeout"
			}
			result.Attempts = append(result.Attempts, FTPProbeAttempt{
				Strategy:   "ftp-feat",
				Transport:  "tcp",
				Success:    false,
				DurationMS: time.Since(featStart).Milliseconds(),
				Error:      code,
			})
			attemptErrors = append(attemptErrors, code)
		} else {
			result.Attempts = append(result.Attempts, FTPProbeAttempt{
				Strategy:   "ftp-feat",
				Transport:  "tcp",
				Success:    true,
				DurationMS: time.Since(featStart).Milliseconds(),
			})
			applyFTPOutcome(&result, buildFTPOutcome(result.FTPProtocol, ftpResponse{}, feat, ftpResponse{}, nil))
		}

		systStart := time.Now()
		syst, systErr := runFTPCommand(ctx, client, opts, "SYST\r\n")
		if systErr != nil || syst.Code != 215 {
			code := "syst_failed"
			if systErr != nil && isFTPTimeoutError(systErr) {
				code = "timeout"
			}
			result.Attempts = append(result.Attempts, FTPProbeAttempt{
				Strategy:   "ftp-syst",
				Transport:  "tcp",
				Success:    false,
				DurationMS: time.Since(systStart).Milliseconds(),
				Error:      code,
			})
			attemptErrors = append(attemptErrors, code)
		} else {
			result.Attempts = append(result.Attempts, FTPProbeAttempt{
				Strategy:   "ftp-syst",
				Transport:  "tcp",
				Success:    true,
				DurationMS: time.Since(systStart).Milliseconds(),
			})
			applyFTPOutcome(&result, buildFTPOutcome(result.FTPProtocol, ftpResponse{}, ftpResponse{}, syst, nil))
		}

		if result.AuthTLSSupported {
			tlsStart := time.Now()
			authTLSResp, authTLSErr := runFTPCommand(ctx, client, opts, "AUTH TLS\r\n")
			if authTLSErr != nil || (authTLSResp.Code != 234 && authTLSResp.Code != 334) {
				code := "auth_tls_failed"
				if authTLSErr != nil && isFTPTimeoutError(authTLSErr) {
					code = "timeout"
				}
				result.Attempts = append(result.Attempts, FTPProbeAttempt{
					Strategy:   "ftp-auth-tls",
					Transport:  "tcp",
					Success:    false,
					DurationMS: time.Since(tlsStart).Milliseconds(),
					Error:      code,
				})
				attemptErrors = append(attemptErrors, code)
			} else {
				tlsObs, tlsErr := client.upgradeTLS(ctx, hostname, target, opts)
				if tlsErr != nil {
					code := classifyFTPTLSError(tlsErr)
					result.Attempts = append(result.Attempts, FTPProbeAttempt{
						Strategy:   "ftp-auth-tls",
						Transport:  "tcp+tls",
						Success:    false,
						DurationMS: time.Since(tlsStart).Milliseconds(),
						Error:      code,
					})
					attemptErrors = append(attemptErrors, code)
				} else {
					result.Attempts = append(result.Attempts, FTPProbeAttempt{
						Strategy:    "ftp-auth-tls",
						Transport:   "tcp+tls",
						Success:     true,
						DurationMS:  time.Since(tlsStart).Milliseconds(),
						TLSVersion:  strings.TrimSpace(tlsObs.Version),
						CipherSuite: strings.TrimSpace(tlsObs.CipherSuite),
					})
					applyFTPOutcome(&result, buildFTPOutcome("ftps", ftpResponse{}, ftpResponse{}, ftpResponse{}, tlsObs))
					result.FTPProtocol = "ftps"
				}
			}
		}

		_ = client.close()
		if len(attemptErrors) > 0 && strings.TrimSpace(result.ProbeError) == "" {
			result.ProbeError = pickTopFTPPartialError(attemptErrors)
		}
		return result
	}

	result.ProbeError = pickTopFTPProbeError(errorCodes)
	if result.ProbeError == "" {
		result.ProbeError = "probe_failed"
	}
	return result
}

func probeFTPSImplicitTLS(ctx context.Context, target string, hostname string, port int, opts FTPProbeOptions, result FTPServiceInfo) FTPServiceInfo {
	errorCodes := make([]string, 0, opts.Retries+1)

	for retry := 0; retry <= opts.Retries; retry++ {
		start := time.Now()
		client, tlsObs, err := dialFTPTLS(ctx, target, hostname, port, opts)
		if err != nil {
			code := classifyFTPTLSError(err)
			errorCodes = append(errorCodes, code)
			result.Attempts = append(result.Attempts, FTPProbeAttempt{
				Strategy:   "ftps-implicit-tls",
				Transport:  "tls",
				Success:    false,
				DurationMS: time.Since(start).Milliseconds(),
				Error:      code,
			})
			continue
		}

		greeting, err := client.readResponse(ctx, opts.IOTimeout)
		if err != nil {
			_ = client.close()
			code := classifyFTPBannerError(err)
			errorCodes = append(errorCodes, code)
			result.Attempts = append(result.Attempts, FTPProbeAttempt{
				Strategy:    "ftps-implicit-tls",
				Transport:   "tls",
				Success:     false,
				DurationMS:  time.Since(start).Milliseconds(),
				Error:       code,
				TLSVersion:  strings.TrimSpace(tlsObs.Version),
				CipherSuite: strings.TrimSpace(tlsObs.CipherSuite),
			})
			continue
		}
		if greeting.Code != 220 {
			_ = client.close()
			errorCodes = append(errorCodes, "protocol_mismatch")
			result.Attempts = append(result.Attempts, FTPProbeAttempt{
				Strategy:    "ftps-implicit-tls",
				Transport:   "tls",
				Success:     false,
				DurationMS:  time.Since(start).Milliseconds(),
				Error:       "protocol_mismatch",
				TLSVersion:  strings.TrimSpace(tlsObs.Version),
				CipherSuite: strings.TrimSpace(tlsObs.CipherSuite),
			})
			continue
		}

		result.Attempts = append(result.Attempts, FTPProbeAttempt{
			Strategy:    "ftps-implicit-tls",
			Transport:   "tls",
			Success:     true,
			DurationMS:  time.Since(start).Milliseconds(),
			TLSVersion:  strings.TrimSpace(tlsObs.Version),
			CipherSuite: strings.TrimSpace(tlsObs.CipherSuite),
		})
		result.FTPProbe = true
		result.FTPProtocol = "ftps"
		applyFTPOutcome(&result, buildFTPOutcome("ftps", greeting, ftpResponse{}, ftpResponse{}, tlsObs))
		attemptErrors := make([]string, 0, 2)

		featStart := time.Now()
		feat, featErr := runFTPCommand(ctx, client, opts, "FEAT\r\n")
		if featErr == nil && feat.Code == 211 {
			result.Attempts = append(result.Attempts, FTPProbeAttempt{
				Strategy:   "ftp-feat",
				Transport:  "tls",
				Success:    true,
				DurationMS: time.Since(featStart).Milliseconds(),
			})
			applyFTPOutcome(&result, buildFTPOutcome(result.FTPProtocol, ftpResponse{}, feat, ftpResponse{}, nil))
		} else {
			code := "feat_failed"
			if featErr != nil {
				code = classifyFTPBannerError(featErr)
			}
			result.Attempts = append(result.Attempts, FTPProbeAttempt{
				Strategy:   "ftp-feat",
				Transport:  "tls",
				Success:    false,
				DurationMS: time.Since(featStart).Milliseconds(),
				Error:      code,
			})
			attemptErrors = append(attemptErrors, code)
		}

		systStart := time.Now()
		syst, systErr := runFTPCommand(ctx, client, opts, "SYST\r\n")
		if systErr == nil && syst.Code == 215 {
			result.Attempts = append(result.Attempts, FTPProbeAttempt{
				Strategy:   "ftp-syst",
				Transport:  "tls",
				Success:    true,
				DurationMS: time.Since(systStart).Milliseconds(),
			})
			applyFTPOutcome(&result, buildFTPOutcome(result.FTPProtocol, ftpResponse{}, ftpResponse{}, syst, nil))
		} else {
			code := "syst_failed"
			if systErr != nil {
				code = classifyFTPBannerError(systErr)
			}
			result.Attempts = append(result.Attempts, FTPProbeAttempt{
				Strategy:   "ftp-syst",
				Transport:  "tls",
				Success:    false,
				DurationMS: time.Since(systStart).Milliseconds(),
				Error:      code,
			})
			attemptErrors = append(attemptErrors, code)
		}

		_ = client.close()
		if len(attemptErrors) > 0 && strings.TrimSpace(result.ProbeError) == "" {
			result.ProbeError = pickTopFTPPartialError(attemptErrors)
		}
		return result
	}

	result.ProbeError = pickTopFTPProbeError(errorCodes)
	if result.ProbeError == "" {
		result.ProbeError = "probe_failed"
	}
	return result
}

func applyFTPOutcome(result *FTPServiceInfo, outcome ftpProbeOutcome) {
	if result == nil {
		return
	}
	if strings.TrimSpace(result.Banner) == "" && strings.TrimSpace(outcome.banner) != "" {
		result.Banner = strings.TrimSpace(outcome.banner)
	}
	if result.GreetingCode == 0 && outcome.greetingCode > 0 {
		result.GreetingCode = outcome.greetingCode
	}
	if len(outcome.features) > 0 {
		for _, feature := range outcome.features {
			feature = strings.TrimSpace(feature)
			if feature == "" || slices.Contains(result.Features, feature) {
				continue
			}
			result.Features = append(result.Features, feature)
		}
		sort.Strings(result.Features)
	}
	result.AuthTLSSupported = result.AuthTLSSupported || outcome.authTLSSupported
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
	if strings.TrimSpace(result.SystemHint) == "" && strings.TrimSpace(outcome.systemHint) != "" {
		result.SystemHint = strings.TrimSpace(outcome.systemHint)
	}
	if strings.TrimSpace(result.SoftwareHint) == "" && strings.TrimSpace(outcome.softwareHint) != "" {
		result.SoftwareHint = strings.TrimSpace(outcome.softwareHint)
	}
	if strings.TrimSpace(result.VendorHint) == "" && strings.TrimSpace(outcome.vendorHint) != "" {
		result.VendorHint = strings.TrimSpace(outcome.vendorHint)
	}
	if strings.TrimSpace(result.VersionHint) == "" && strings.TrimSpace(outcome.versionHint) != "" {
		result.VersionHint = strings.TrimSpace(outcome.versionHint)
	}
	result.WeakTLSProtocol = result.WeakTLSProtocol || outcome.weakTLSProtocol
	result.WeakTLSCipher = result.WeakTLSCipher || outcome.weakTLSCipher
}

func buildFTPOutcome(protocol string, greeting ftpResponse, feat ftpResponse, syst ftpResponse, tlsObs *engine.TLSObservation) ftpProbeOutcome {
	outcome := ftpProbeOutcome{}
	if strings.TrimSpace(greeting.Raw) != "" {
		outcome.banner = sanitizeFTPResponse(greeting.Raw, ftpBannerMaxSize)
		outcome.greetingCode = greeting.Code
	}
	if strings.TrimSpace(feat.Raw) != "" {
		outcome.features = parseFTPFeatures(feat)
		outcome.authTLSSupported = ftpFeaturesSupportAuthTLS(outcome.features)
	}
	if strings.TrimSpace(syst.Raw) != "" {
		outcome.systemHint = extractFTPSystemHint(syst)
	}

	product, vendor, version := inferFTPSoftwareHints(strings.Join([]string{greeting.Raw, feat.Raw, syst.Raw}, "\n"))
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
	if strings.EqualFold(protocol, "ftps") {
		outcome.tlsEnabled = true
	}
	return outcome
}

func parseFTPFeatures(resp ftpResponse) []string {
	features := make([]string, 0, len(resp.Lines))
	for _, line := range resp.Lines {
		text := strings.TrimSpace(ftpResponseText(line))
		if text == "" {
			continue
		}
		if isGenericFTPFeatureLine(text) {
			continue
		}
		features = append(features, text)
	}
	if len(features) == 0 {
		return nil
	}
	return features
}

func isGenericFTPFeatureLine(line string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(line))
	normalized = strings.TrimSuffix(normalized, ".")
	switch normalized {
	case "EXTENSIONS SUPPORTED", "EXTENSIONS SUPPORTED:", "FEATURES", "FEATURES:", "END":
		return true
	default:
		return false
	}
}

func ftpFeaturesSupportAuthTLS(features []string) bool {
	for _, feature := range features {
		if strings.Contains(strings.ToUpper(strings.TrimSpace(feature)), "AUTH TLS") {
			return true
		}
	}
	return false
}

func extractFTPSystemHint(resp ftpResponse) string {
	if len(resp.Lines) == 0 {
		return ""
	}
	return strings.TrimSpace(ftpResponseText(resp.Lines[0]))
}

func inferFTPSoftwareHints(raw string) (string, string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", ""
	}
	if product, version := extractFTPProductVersion(ftpCrushPattern, raw, "CrushFTP"); product != "" {
		return product, "CrushFTP, LLC", version
	}
	if product, version := extractFTPProductVersion(ftpPurePattern, raw, "Pure-FTPd"); product != "" {
		return product, "PureFTPd Project", version
	}
	if product, version := extractFTPProductVersion(ftpProFTPDPattern, raw, "ProFTPD"); product != "" {
		return product, "ProFTPD Project", version
	}
	if product, version := extractFTPProductVersion(ftpVSFTPDPattern, raw, "vsftpd"); product != "" {
		return product, "vsftpd Project", version
	}
	if product, version := extractFTPProductVersion(ftpFileZillaPattern, raw, "FileZilla Server"); product != "" {
		return product, "FileZilla Project", version
	}
	if strings.Contains(strings.ToLower(raw), "microsoft ftp service") {
		return "Microsoft FTP Service", "Microsoft", ""
	}
	return "", "", ""
}

func extractFTPProductVersion(pattern *regexp.Regexp, raw string, product string) (string, string) {
	matches := pattern.FindStringSubmatch(raw)
	if len(matches) == 0 {
		return "", ""
	}
	for idx := 1; idx < len(matches); idx++ {
		if version := strings.TrimSpace(matches[idx]); version != "" {
			return product, version
		}
	}
	return product, ""
}

func sanitizeFTPResponse(raw string, maxLen int) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || maxLen <= 0 || len(raw) <= maxLen {
		return raw
	}
	return raw[:maxLen]
}

func dialFTPPlain(ctx context.Context, target string, port int, opts FTPProbeOptions) (*ftpClient, error) {
	address := net.JoinHostPort(strings.TrimSpace(target), strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: effectiveProbeTimeout(ctx, opts.ConnectTimeout)}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	return &ftpClient{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}, nil
}

func dialFTPTLS(ctx context.Context, target string, hostname string, port int, opts FTPProbeOptions) (*ftpClient, *engine.TLSObservation, error) {
	address := net.JoinHostPort(strings.TrimSpace(target), strconv.Itoa(port))
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: effectiveProbeTimeout(ctx, opts.ConnectTimeout)},
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // Native probe gathers metadata from untrusted targets.
			ServerName:         ftpTLSServerName(hostname, target),
		},
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	conn, ok := rawConn.(*tls.Conn)
	if !ok {
		_ = rawConn.Close()
		return nil, nil, errors.New("tls_handshake_failed")
	}
	if err := conn.SetDeadline(time.Now().Add(effectiveProbeTimeout(ctx, opts.IOTimeout))); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	state := conn.ConnectionState()
	tlsObs := extractTLSObservation(state)
	if tlsObs == nil {
		_ = conn.Close()
		return nil, nil, errors.New("tls_handshake_failed")
	}
	return &ftpClient{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}, tlsObs, nil
}

func (c *ftpClient) close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *ftpClient) writeCommand(ctx context.Context, ioTimeout time.Duration, command string) error {
	if c == nil || c.conn == nil {
		return errors.New("probe_failed")
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(effectiveProbeTimeout(ctx, ioTimeout))); err != nil {
		return err
	}
	_, err := io.WriteString(c.conn, command)
	return err
}

func (c *ftpClient) readResponse(ctx context.Context, ioTimeout time.Duration) (ftpResponse, error) {
	if c == nil || c.reader == nil || c.conn == nil {
		return ftpResponse{}, errors.New("probe_failed")
	}

	lines := make([]string, 0, 4)
	var builder strings.Builder
	code := 0
	multiline := false

	for len(lines) < ftpResponseMaxLines && builder.Len() < ftpResponseMaxBytes {
		if err := c.conn.SetReadDeadline(time.Now().Add(effectiveProbeTimeout(ctx, ioTimeout))); err != nil {
			return ftpResponse{Code: code, Lines: lines, Raw: builder.String()}, err
		}
		line, err := c.reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) && strings.TrimSpace(line) != "" {
				// keep partial line
			} else {
				return ftpResponse{Code: code, Lines: lines, Raw: builder.String()}, err
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
			if len(line) < 3 || !isFTPCodePrefix(line[:3]) {
				return ftpResponse{Lines: lines, Raw: builder.String()}, errors.New("protocol_mismatch")
			}
			parsed, convErr := strconv.Atoi(line[:3])
			if convErr != nil {
				return ftpResponse{Lines: lines, Raw: builder.String()}, errors.New("protocol_mismatch")
			}
			code = parsed
			multiline = len(line) > 3 && line[3] == '-'
			if !multiline {
				break
			}
		} else if multiline && len(line) > 3 && line[:3] == fmt.Sprintf("%03d", code) && line[3] == ' ' {
			break
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return ftpResponse{Code: code, Lines: lines, Raw: builder.String()}, err
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}

	if len(lines) == 0 {
		return ftpResponse{}, errors.New("banner_read_failed")
	}
	return ftpResponse{
		Code:  code,
		Raw:   builder.String(),
		Lines: lines,
	}, nil
}

func (c *ftpClient) upgradeTLS(ctx context.Context, hostname string, target string, opts FTPProbeOptions) (*engine.TLSObservation, error) {
	if c == nil || c.conn == nil {
		return nil, errors.New("tls_handshake_failed")
	}

	tlsConn := tls.Client(c.conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // Native probe gathers metadata from untrusted targets.
		ServerName:         ftpTLSServerName(hostname, target),
	})
	if err := tlsConn.SetDeadline(time.Now().Add(effectiveProbeTimeout(ctx, opts.IOTimeout))); err != nil {
		return nil, err
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	tlsObs := extractTLSObservation(tlsConn.ConnectionState())
	if tlsObs == nil {
		return nil, errors.New("tls_handshake_failed")
	}
	c.conn = tlsConn
	c.reader = bufio.NewReader(tlsConn)
	return tlsObs, nil
}

func runFTPCommand(ctx context.Context, client *ftpClient, opts FTPProbeOptions, command string) (ftpResponse, error) {
	if err := client.writeCommand(ctx, opts.IOTimeout, command); err != nil {
		return ftpResponse{}, err
	}
	return client.readResponse(ctx, opts.IOTimeout)
}

func ftpTLSServerName(hostname string, target string) string {
	if host := normalizeNonIPHostname(hostname); host != "" {
		return host
	}
	target = strings.TrimSpace(target)
	if target != "" {
		return target
	}
	return ""
}

func ftpResponseText(line string) string {
	line = strings.TrimSpace(line)
	if len(line) >= 4 && isFTPCodePrefix(line[:3]) {
		return strings.TrimSpace(line[4:])
	}
	return line
}

func isFTPCodePrefix(value string) bool {
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

func isFTPTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "i/o timeout")
}

func classifyFTPConnectError(err error) string {
	if err == nil {
		return ""
	}
	if isFTPTimeoutError(err) {
		return "timeout"
	}
	return "connect_failed"
}

func classifyFTPBannerError(err error) string {
	if err == nil {
		return ""
	}
	if isFTPTimeoutError(err) {
		return "timeout"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "protocol_mismatch"):
		return "protocol_mismatch"
	case strings.Contains(msg, "banner_read_failed"), strings.Contains(msg, "eof"):
		return "banner_read_failed"
	default:
		return "banner_read_failed"
	}
}

func classifyFTPTLSError(err error) string {
	if err == nil {
		return ""
	}
	if isFTPTimeoutError(err) {
		return "timeout"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection refused"):
		return "connect_failed"
	case strings.Contains(msg, "auth_tls_failed"):
		return "auth_tls_failed"
	case strings.Contains(msg, "tls"), strings.Contains(msg, "handshake"):
		return "tls_handshake_failed"
	default:
		return "tls_handshake_failed"
	}
}

func pickTopFTPProbeError(codes []string) string {
	best := ""
	bestPriority := -1
	for _, code := range codes {
		if priority := ftpProbeErrorPriority(code); priority > bestPriority {
			bestPriority = priority
			best = code
		}
	}
	return best
}

func pickTopFTPPartialError(codes []string) string {
	filtered := make([]string, 0, len(codes))
	for _, code := range codes {
		switch strings.TrimSpace(code) {
		case "timeout", "auth_tls_failed", "tls_handshake_failed", "connect_failed", "banner_read_failed", "protocol_mismatch":
			filtered = append(filtered, code)
		}
	}
	if len(filtered) == 0 {
		return ""
	}
	return pickTopFTPProbeError(filtered)
}

func ftpProbeErrorPriority(code string) int {
	switch code {
	case "timeout":
		return 9
	case "connect_failed":
		return 8
	case "tls_handshake_failed":
		return 7
	case "auth_tls_failed":
		return 6
	case "banner_read_failed":
		return 5
	case "protocol_mismatch":
		return 4
	case "feat_failed":
		return 3
	case "syst_failed":
		return 2
	case "probe_failed":
		return 1
	default:
		return 0
	}
}

func ftpNativeProbeModuleFactory() engine.Module {
	return newFTPNativeProbeModule()
}

func init() {
	engine.RegisterModuleFactory(ftpNativeProbeModuleName, ftpNativeProbeModuleFactory)
}
