package scan

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

const (
	mysqlNativeProbeModuleID          = "mysql-native-probe-instance"
	mysqlNativeProbeModuleName        = "mysql-native-probe"
	mysqlNativeProbeModuleDescription = "Runs bounded native MySQL handshake probes and emits structured MySQL metadata."

	mysqlPacketMaxPayloadSize = 16 * 1024

	mysqlCapabilitySSL              = 0x00000800
	mysqlCapabilityProtocol41       = 0x00000200
	mysqlCapabilitySecureConnection = 0x00008000
	mysqlCapabilityPluginAuth       = 0x00080000
	mysqlClientSSLRequestCaps       = mysqlCapabilityProtocol41 | mysqlCapabilitySSL | mysqlCapabilitySecureConnection | mysqlCapabilityPluginAuth
)

type MySQLProbeOptions struct {
	TotalTimeout   time.Duration `json:"total_timeout"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	IOTimeout      time.Duration `json:"io_timeout"`
	Retries        int           `json:"retries"`
	CandidatePorts []int         `json:"candidate_ports,omitempty"`
}

type MySQLProbeAttempt struct {
	Strategy    string `json:"strategy"`
	Transport   string `json:"transport"`
	Success     bool   `json:"success"`
	DurationMS  int64  `json:"duration_ms"`
	Error       string `json:"error,omitempty"`
	TLSVersion  string `json:"tls_version,omitempty"`
	CipherSuite string `json:"tls_cipher_suite,omitempty"`
}

type MySQLServiceInfo struct {
	Target           string              `json:"target"`
	Port             int                 `json:"port"`
	MySQLProbe       bool                `json:"mysql_probe"`
	GreetingKind     string              `json:"greeting_kind,omitempty"`
	ProtocolVersion  int                 `json:"protocol_version,omitempty"`
	ServerVersion    string              `json:"server_version,omitempty"`
	ConnectionID     uint32              `json:"connection_id,omitempty"`
	CapabilityFlags  uint32              `json:"capability_flags,omitempty"`
	StatusFlags      uint16              `json:"status_flags,omitempty"`
	CharacterSet     int                 `json:"character_set,omitempty"`
	AuthPluginName   string              `json:"auth_plugin_name,omitempty"`
	TLSSupported     bool                `json:"tls_supported"`
	TLSEnabled       bool                `json:"tls_enabled"`
	TLSVersion       string              `json:"tls_version,omitempty"`
	TLSCipherSuite   string              `json:"tls_cipher_suite,omitempty"`
	CertSubjectCN    string              `json:"cert_subject_cn,omitempty"`
	CertIssuer       string              `json:"cert_issuer,omitempty"`
	CertNotAfter     time.Time           `json:"cert_not_after,omitzero"`
	CertIsSelfSigned bool                `json:"cert_is_self_signed"`
	ProductHint      string              `json:"product_hint,omitempty"`
	VendorHint       string              `json:"vendor_hint,omitempty"`
	VersionHint      string              `json:"version_hint,omitempty"`
	ProbeError       string              `json:"probe_error,omitempty"`
	Attempts         []MySQLProbeAttempt `json:"attempts,omitempty"`
}

type mysqlNativeProbeModule struct {
	meta    engine.ModuleMetadata
	options MySQLProbeOptions
}

type mysqlProbeCandidate struct {
	target   string
	hostname string
	port     int
}

type mysqlPacket struct {
	sequenceID byte
	payload    []byte
}

type mysqlHandshakePacket struct {
	protocolVersion int
	serverVersion   string
	connectionID    uint32
	capabilityFlags uint32
	statusFlags     uint16
	characterSet    int
	authPluginName  string
}

type mysqlErrorPacket struct {
	code     uint16
	sqlState string
	message  string
}

var (
	probeMySQLDetailsFunc = probeMySQLDetails

	mysqlMariaDBPattern     = regexp.MustCompile(`(?i)\bmariadb(?:\s+server)?(?:[ /_-]?([0-9][0-9a-z._-]*))?`)
	mysqlPerconaPattern     = regexp.MustCompile(`(?i)\bpercona(?:\s+server)?(?:[ /_-]?([0-9][0-9a-z._-]*))?`)
	mysqlVersionPattern     = regexp.MustCompile(`([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-_a-z0-9.]*)?)`)
	mysqlCoreVersionPattern = regexp.MustCompile(`([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
)

func newMySQLNativeProbeModuleWithSpec(moduleID string, moduleName string, description string, outputKey string, tags []string) *mysqlNativeProbeModule {
	return &mysqlNativeProbeModule{
		meta: buildTCPNativeProbeMetadata(tcpNativeProbeMetadataSpec{
			moduleID:              moduleID,
			moduleName:            moduleName,
			description:           description,
			outputKey:             outputKey,
			outputType:            "scan.MySQLServiceInfo",
			outputDescription:     "Structured MySQL native probe output per target and port.",
			tags:                  tags,
			consumes:              []engine.DataContractEntry{nativeOpenTCPPortsConsume(false, "Open TCP ports used to identify MySQL candidate services."), nativeBannerConsume("Banner results used as MySQL candidate hints."), nativeOriginalTargetsConsume("Original CLI targets used to preserve hostname for TLS server name fallback.")},
			timeoutDefault:        "2500ms",
			connectTimeoutDefault: "800ms",
			ioTimeoutDefault:      "800ms",
			extraConfigParameters: map[string]engine.ParameterDefinition{
				"candidate_ports": {
					Description: "Optional explicit ports to treat as MySQL candidates when already known open.",
					Type:        "[]int",
					Required:    false,
				},
			},
		}),
		options: defaultMySQLProbeOptions(),
	}
}

func newMySQLNativeProbeModule() *mysqlNativeProbeModule {
	return newMySQLNativeProbeModuleWithSpec(
		mysqlNativeProbeModuleID,
		mysqlNativeProbeModuleName,
		mysqlNativeProbeModuleDescription,
		"service.mysql.details",
		[]string{"scan", "mysql", "database", "enrichment", "native_probe"},
	)
}

func (m *mysqlNativeProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *mysqlNativeProbeModule) Init(instanceID string, configMap map[string]any) error {
	opts := defaultMySQLProbeOptions()
	initCommonTCPProbeOptions(&m.meta, instanceID, configMap, &opts.TotalTimeout, &opts.ConnectTimeout, &opts.IOTimeout, &opts.Retries)
	opts.CandidatePorts = parseOptionalPortList(configMap, "candidate_ports")
	m.options = opts
	return nil
}

func (m *mysqlNativeProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
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
	candidates := make(map[string]mysqlProbeCandidate)
	for _, item := range toAnySlice(rawOpenPorts) {
		for _, candidate := range mysqlCandidatesFromOpenPorts(item, explicitCandidatePorts) {
			mergeMySQLCandidate(candidates, candidate)
		}
	}

	if rawBanner, ok := inputs["service.banner.tcp"]; ok {
		for _, item := range toAnySlice(rawBanner) {
			candidate, ok := mysqlCandidateFromBanner(item, explicitCandidatePorts)
			if !ok {
				continue
			}
			mergeMySQLCandidate(candidates, candidate)
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
			leftPriority := mysqlPortPriority(left.port)
			rightPriority := mysqlPortPriority(right.port)
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

		result := probeMySQLDetailsFunc(targetCtx, candidate.target, candidate.hostname, candidate.port, m.options)
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

func defaultMySQLProbeOptions() MySQLProbeOptions {
	return MySQLProbeOptions{
		TotalTimeout:   2500 * time.Millisecond,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
		Retries:        0,
	}
}

func mysqlCandidatesFromOpenPorts(item any, explicitCandidatePorts map[int]struct{}) []mysqlProbeCandidate {
	candidates := make([]mysqlProbeCandidate, 0, 1)
	appendCandidate := func(target string, hostname string, port int) {
		target = strings.TrimSpace(target)
		hostname = normalizeNonIPHostname(hostname)
		if target == "" || port <= 0 || port > 65535 {
			return
		}
		if !isMySQLNativePort(port) {
			if _, ok := explicitCandidatePorts[port]; !ok {
				return
			}
		}
		candidates = append(candidates, mysqlProbeCandidate{
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

func mysqlCandidateFromBanner(item any, explicitCandidatePorts map[int]struct{}) (mysqlProbeCandidate, bool) {
	switch v := item.(type) {
	case BannerGrabResult:
		if !isMySQLBannerCandidate(v, explicitCandidatePorts) {
			return mysqlProbeCandidate{}, false
		}
		return mysqlProbeCandidate{
			target:   strings.TrimSpace(v.IP),
			hostname: firstNonEmptyHostname(v.ProbeHost, v.SNIServerName),
			port:     v.Port,
		}, strings.TrimSpace(v.IP) != "" && v.Port > 0
	case map[string]any:
		target := getMapString(v, "ip", "IP")
		if target == "" {
			return mysqlProbeCandidate{}, false
		}
		port := mapPortValue(v["port"])
		if port <= 0 {
			return mysqlProbeCandidate{}, false
		}
		candidate := mysqlProbeCandidate{
			target:   target,
			hostname: firstNonEmptyHostname(getMapString(v, "probe_host", "ProbeHost"), getMapString(v, "sni_server_name", "SNIServerName")),
			port:     port,
		}
		if (isMySQLNativePort(port) || isExplicitMySQLPort(port, explicitCandidatePorts)) && (containsMySQLHint(getMapString(v, "protocol", "Protocol")) ||
			containsMySQLHint(getMapString(v, "banner", "Banner")) ||
			mapEvidenceLooksLikeMySQL(v["evidence"]) ||
			isMySQLNativePort(port)) {
			return candidate, true
		}
	}
	return mysqlProbeCandidate{}, false
}

func mergeMySQLCandidate(dst map[string]mysqlProbeCandidate, candidate mysqlProbeCandidate) {
	key := mysqlCandidateKey(candidate)
	if current, ok := dst[key]; ok {
		if current.hostname == "" && candidate.hostname != "" {
			current.hostname = candidate.hostname
		}
		dst[key] = current
		return
	}
	dst[key] = candidate
}

func isMySQLBannerCandidate(banner BannerGrabResult, explicitCandidatePorts map[int]struct{}) bool {
	if isMySQLNativePort(banner.Port) || isExplicitMySQLPort(banner.Port, explicitCandidatePorts) {
		return true
	}
	return false
}

func mapEvidenceLooksLikeMySQL(raw any) bool {
	items, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if containsMySQLHint(getMapString(m, "protocol", "Protocol")) ||
			containsMySQLHint(getMapString(m, "probe_id", "ProbeID")) ||
			containsMySQLHint(getMapString(m, "description", "Description")) ||
			containsMySQLHint(getMapString(m, "response", "Response")) {
			return true
		}
	}
	return false
}

func containsMySQLHint(value string) bool {
	clean := strings.ToLower(strings.TrimSpace(value))
	if clean == "" {
		return false
	}
	return clean == "mysql" ||
		strings.Contains(clean, "mariadb") ||
		strings.Contains(clean, "percona") ||
		strings.Contains(clean, "mysql")
}

func mysqlCandidateKey(candidate mysqlProbeCandidate) string {
	return fmt.Sprintf("%s:%d", candidate.target, candidate.port)
}

func mysqlPortPriority(port int) int {
	if port == 3306 {
		return 1
	}
	return 0
}

func isMySQLNativePort(port int) bool {
	return port == 3306
}

func isExplicitMySQLPort(port int, explicitCandidatePorts map[int]struct{}) bool {
	_, ok := explicitCandidatePorts[port]
	return ok
}

func probeMySQLDetails(ctx context.Context, target string, hostname string, port int, opts MySQLProbeOptions) MySQLServiceInfo {
	if port <= 0 {
		port = 3306
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

	result := MySQLServiceInfo{
		Target:   target,
		Port:     port,
		Attempts: make([]MySQLProbeAttempt, 0, 2+opts.Retries),
	}
	errorCodes := make([]string, 0, opts.Retries+1)

	for retry := 0; retry <= opts.Retries; retry++ {
		start := time.Now()
		conn, err := dialMySQLPlain(probeCtx, target, port, opts)
		if err != nil {
			code := classifyMySQLConnectError(err)
			errorCodes = append(errorCodes, code)
			result.Attempts = append(result.Attempts, MySQLProbeAttempt{
				Strategy:   "mysql-greeting",
				Transport:  "tcp",
				Success:    false,
				DurationMS: time.Since(start).Milliseconds(),
				Error:      code,
			})
			continue
		}

		packet, err := readMySQLPacket(probeCtx, conn, opts.IOTimeout)
		if err != nil {
			_ = conn.Close()
			code := classifyMySQLReadError(err)
			errorCodes = append(errorCodes, code)
			result.Attempts = append(result.Attempts, MySQLProbeAttempt{
				Strategy:   "mysql-greeting",
				Transport:  "tcp",
				Success:    false,
				DurationMS: time.Since(start).Milliseconds(),
				Error:      code,
			})
			continue
		}

		handshake, handshakeErr := parseMySQLHandshakePacket(packet.payload)
		if handshakeErr == nil {
			result.Attempts = append(result.Attempts, MySQLProbeAttempt{
				Strategy:   "mysql-greeting",
				Transport:  "tcp",
				Success:    true,
				DurationMS: time.Since(start).Milliseconds(),
			})
			result.MySQLProbe = true
			result.GreetingKind = "handshake"
			result.ProtocolVersion = handshake.protocolVersion
			result.ServerVersion = handshake.serverVersion
			result.ConnectionID = handshake.connectionID
			result.CapabilityFlags = handshake.capabilityFlags
			result.StatusFlags = handshake.statusFlags
			result.CharacterSet = handshake.characterSet
			result.AuthPluginName = handshake.authPluginName
			result.TLSSupported = handshake.capabilityFlags&mysqlCapabilitySSL != 0
			productHint, vendorHint, versionHint := inferMySQLHints(handshake.serverVersion)
			result.ProductHint = productHint
			result.VendorHint = vendorHint
			result.VersionHint = versionHint

			if result.TLSSupported {
				tlsStart := time.Now()
				tlsObs, tlsErr := upgradeMySQLTLS(probeCtx, conn, hostname, target, packet.sequenceID, opts)
				if tlsErr != nil {
					code := classifyMySQLTLSError(tlsErr)
					result.Attempts = append(result.Attempts, MySQLProbeAttempt{
						Strategy:   "mysql-starttls",
						Transport:  "tcp+tls",
						Success:    false,
						DurationMS: time.Since(tlsStart).Milliseconds(),
						Error:      code,
					})
					result.ProbeError = pickTopMySQLPartialError([]string{code})
					_ = conn.Close()
					return result
				}
				result.Attempts = append(result.Attempts, MySQLProbeAttempt{
					Strategy:    "mysql-starttls",
					Transport:   "tcp+tls",
					Success:     true,
					DurationMS:  time.Since(tlsStart).Milliseconds(),
					TLSVersion:  strings.TrimSpace(tlsObs.Version),
					CipherSuite: strings.TrimSpace(tlsObs.CipherSuite),
				})
				result.TLSEnabled = true
				result.TLSVersion = strings.TrimSpace(tlsObs.Version)
				result.TLSCipherSuite = strings.TrimSpace(tlsObs.CipherSuite)
				result.CertSubjectCN = strings.TrimSpace(tlsObs.PeerCommonName)
				result.CertIssuer = strings.TrimSpace(tlsObs.Issuer)
				result.CertNotAfter = tlsObs.NotAfter
				result.CertIsSelfSigned = tlsObs.IsSelfSigned
			}

			_ = conn.Close()
			return result
		}

		errPacket, errPacketErr := parseMySQLErrorPacket(packet.payload)
		if errPacketErr == nil {
			result.Attempts = append(result.Attempts, MySQLProbeAttempt{
				Strategy:   "mysql-greeting",
				Transport:  "tcp",
				Success:    true,
				DurationMS: time.Since(start).Milliseconds(),
			})
			result.MySQLProbe = true
			result.GreetingKind = "err_packet"
			if errPacket.code > 0 && result.ProbeError == "" {
				result.ProbeError = ""
			}
			_ = conn.Close()
			return result
		}

		_ = conn.Close()
		errorCodes = append(errorCodes, "protocol_mismatch")
		result.Attempts = append(result.Attempts, MySQLProbeAttempt{
			Strategy:   "mysql-greeting",
			Transport:  "tcp",
			Success:    false,
			DurationMS: time.Since(start).Milliseconds(),
			Error:      "protocol_mismatch",
		})
	}

	result.ProbeError = pickTopMySQLProbeError(errorCodes)
	if result.ProbeError == "" {
		result.ProbeError = "probe_failed"
	}
	return result
}

func dialMySQLPlain(ctx context.Context, target string, port int, opts MySQLProbeOptions) (net.Conn, error) {
	address := net.JoinHostPort(strings.TrimSpace(target), fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: effectiveProbeTimeout(ctx, opts.ConnectTimeout)}
	return dialer.DialContext(ctx, "tcp", address)
}

func readMySQLPacket(ctx context.Context, conn net.Conn, ioTimeout time.Duration) (mysqlPacket, error) {
	if conn == nil {
		return mysqlPacket{}, errors.New("probe_failed")
	}

	header := make([]byte, 4)
	if err := readMySQLBytes(ctx, conn, ioTimeout, header); err != nil {
		return mysqlPacket{}, err
	}
	payloadLength := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	if payloadLength <= 0 || payloadLength > mysqlPacketMaxPayloadSize {
		return mysqlPacket{}, errors.New("protocol_mismatch")
	}

	payload := make([]byte, payloadLength)
	if err := readMySQLBytes(ctx, conn, ioTimeout, payload); err != nil {
		return mysqlPacket{}, err
	}

	return mysqlPacket{
		sequenceID: header[3],
		payload:    payload,
	}, nil
}

func readMySQLBytes(ctx context.Context, conn net.Conn, ioTimeout time.Duration, buf []byte) error {
	if err := conn.SetReadDeadline(time.Now().Add(effectiveProbeTimeout(ctx, ioTimeout))); err != nil {
		return err
	}
	_, err := io.ReadFull(conn, buf)
	return err
}

func writeMySQLPacket(ctx context.Context, conn net.Conn, ioTimeout time.Duration, sequenceID byte, payload []byte) error {
	if conn == nil {
		return errors.New("probe_failed")
	}
	if len(payload) == 0 || len(payload) > 0xFFFFFF {
		return errors.New("protocol_mismatch")
	}

	frame := make([]byte, 4+len(payload))
	frame[0] = byte(len(payload))
	frame[1] = byte(len(payload) >> 8)
	frame[2] = byte(len(payload) >> 16)
	frame[3] = sequenceID
	copy(frame[4:], payload)

	if err := conn.SetWriteDeadline(time.Now().Add(effectiveProbeTimeout(ctx, ioTimeout))); err != nil {
		return err
	}
	_, err := conn.Write(frame)
	return err
}

func parseMySQLHandshakePacket(payload []byte) (mysqlHandshakePacket, error) {
	if len(payload) < 1 || payload[0] != 0x0a {
		return mysqlHandshakePacket{}, errors.New("protocol_mismatch")
	}

	pos := 1
	serverVersion, nextPos, ok := readMySQLNullTerminatedString(payload, pos)
	if !ok {
		return mysqlHandshakePacket{}, errors.New("protocol_mismatch")
	}
	pos = nextPos
	if pos+4+8+1+2 > len(payload) {
		return mysqlHandshakePacket{}, errors.New("protocol_mismatch")
	}

	handshake := mysqlHandshakePacket{
		protocolVersion: int(payload[0]),
		serverVersion:   strings.TrimSpace(serverVersion),
		connectionID:    binary.LittleEndian.Uint32(payload[pos : pos+4]),
	}
	pos += 4
	pos += 8
	pos++
	handshake.capabilityFlags = uint32(binary.LittleEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	if pos >= len(payload) {
		return handshake, nil
	}
	if len(payload[pos:]) < 13 {
		return mysqlHandshakePacket{}, errors.New("protocol_mismatch")
	}

	handshake.characterSet = int(payload[pos])
	pos++
	handshake.statusFlags = binary.LittleEndian.Uint16(payload[pos : pos+2])
	pos += 2
	handshake.capabilityFlags |= uint32(binary.LittleEndian.Uint16(payload[pos:pos+2])) << 16
	pos += 2
	authPluginDataLen := int(payload[pos])
	pos++
	pos += 10
	if pos > len(payload) {
		return mysqlHandshakePacket{}, errors.New("protocol_mismatch")
	}

	if handshake.capabilityFlags&mysqlCapabilitySecureConnection != 0 {
		authDataLen := 13
		if authPluginDataLen > 8 {
			authDataLen = authPluginDataLen - 8
			if authDataLen < 13 {
				authDataLen = 13
			}
		}
		if pos+authDataLen > len(payload) {
			authDataLen = len(payload) - pos
		}
		if authDataLen > 0 {
			pos += authDataLen
		}
	}

	if handshake.capabilityFlags&mysqlCapabilityPluginAuth != 0 && pos < len(payload) {
		authPluginName, _, ok := readMySQLNullTerminatedString(payload, pos)
		if ok {
			handshake.authPluginName = strings.TrimSpace(authPluginName)
		}
	}

	return handshake, nil
}

func parseMySQLErrorPacket(payload []byte) (mysqlErrorPacket, error) {
	// Treat ERR as native confirmation only for protocol 4.1 style frames.
	if len(payload) < 10 || payload[0] != 0xff {
		return mysqlErrorPacket{}, errors.New("protocol_mismatch")
	}

	packet := mysqlErrorPacket{
		code: binary.LittleEndian.Uint16(payload[1:3]),
	}
	if packet.code == 0 || payload[3] != '#' {
		return mysqlErrorPacket{}, errors.New("protocol_mismatch")
	}
	packet.sqlState = string(payload[4:9])
	if !isMySQLSQLState(packet.sqlState) {
		return mysqlErrorPacket{}, errors.New("protocol_mismatch")
	}
	packet.message = strings.TrimSpace(strings.Trim(string(payload[9:]), "\x00"))
	if packet.message == "" || !isMySQLPrintableText(packet.message) {
		return mysqlErrorPacket{}, errors.New("protocol_mismatch")
	}
	return packet, nil
}

func readMySQLNullTerminatedString(payload []byte, pos int) (string, int, bool) {
	if pos < 0 || pos >= len(payload) {
		return "", pos, false
	}
	for idx := pos; idx < len(payload); idx++ {
		if payload[idx] == 0x00 {
			return string(payload[pos:idx]), idx + 1, true
		}
	}
	return "", pos, false
}

func upgradeMySQLTLS(ctx context.Context, conn net.Conn, hostname string, target string, sequenceID byte, opts MySQLProbeOptions) (*engine.TLSObservation, error) {
	sslRequest := make([]byte, 32)
	binary.LittleEndian.PutUint32(sslRequest[0:4], mysqlClientSSLRequestCaps)
	binary.LittleEndian.PutUint32(sslRequest[4:8], 0)
	sslRequest[8] = 0x21

	if err := writeMySQLPacket(ctx, conn, opts.IOTimeout, sequenceID+1, sslRequest); err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // Native probe gathers metadata from untrusted targets.
		ServerName:         mysqlTLSServerName(hostname, target),
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
	return tlsObs, nil
}

func mysqlTLSServerName(hostname string, target string) string {
	if host := normalizeNonIPHostname(hostname); host != "" {
		return host
	}
	target = strings.TrimSpace(target)
	if net.ParseIP(target) == nil {
		return target
	}
	return ""
}

func inferMySQLHints(serverVersion string) (string, string, string) {
	clean := strings.TrimSpace(serverVersion)
	if clean == "" {
		return "", "", ""
	}

	switch {
	case mysqlMariaDBPattern.MatchString(clean):
		version := extractMySQLHintVersion(clean, mysqlMariaDBPattern)
		return "MariaDB", "MariaDB Foundation", version
	case mysqlPerconaPattern.MatchString(clean):
		version := extractMySQLHintVersion(clean, mysqlPerconaPattern)
		return "Percona Server", "Percona", version
	default:
		return "MySQL", "Oracle", extractMySQLCoreVersion(clean)
	}
}

func extractMySQLHintVersion(value string, pattern *regexp.Regexp) string {
	matches := pattern.FindStringSubmatch(value)
	if len(matches) > 1 && strings.TrimSpace(matches[1]) != "" {
		return strings.TrimSpace(matches[1])
	}
	if version := mysqlVersionPattern.FindString(value); version != "" {
		return strings.TrimSpace(version)
	}
	return ""
}

func extractMySQLCoreVersion(value string) string {
	if version := mysqlCoreVersionPattern.FindString(value); version != "" {
		return strings.TrimSpace(version)
	}
	return ""
}

func isMySQLSQLState(value string) bool {
	if len(value) != 5 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

func isMySQLPrintableText(value string) bool {
	for _, r := range value {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func classifyMySQLConnectError(err error) string {
	if err == nil {
		return ""
	}
	if isMySQLTimeoutError(err) {
		return "timeout"
	}
	return "connect_failed"
}

func classifyMySQLReadError(err error) string {
	if err == nil {
		return ""
	}
	if isMySQLTimeoutError(err) {
		return "timeout"
	}
	if errors.Is(err, io.EOF) {
		return "probe_failed"
	}
	if strings.Contains(strings.ToLower(err.Error()), "protocol_mismatch") {
		return "protocol_mismatch"
	}
	return "probe_failed"
}

func classifyMySQLTLSError(err error) string {
	if err == nil {
		return ""
	}
	if isMySQLTimeoutError(err) {
		return "timeout"
	}
	return "tls_handshake_failed"
}

func isMySQLTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "i/o timeout")
}

func pickTopMySQLProbeError(codes []string) string {
	best := ""
	bestPriority := -1
	for _, code := range codes {
		if priority := mysqlProbeErrorPriority(code); priority > bestPriority {
			bestPriority = priority
			best = code
		}
	}
	return best
}

func pickTopMySQLPartialError(codes []string) string {
	filtered := make([]string, 0, len(codes))
	for _, code := range codes {
		switch strings.TrimSpace(code) {
		case "timeout", "tls_handshake_failed", "connect_failed", "protocol_mismatch", "probe_failed":
			filtered = append(filtered, code)
		}
	}
	if len(filtered) == 0 {
		return ""
	}
	return pickTopMySQLProbeError(filtered)
}

func mysqlProbeErrorPriority(code string) int {
	switch code {
	case "timeout":
		return 5
	case "connect_failed":
		return 4
	case "tls_handshake_failed":
		return 3
	case "protocol_mismatch":
		return 2
	case "probe_failed":
		return 1
	default:
		return 0
	}
}

func mysqlNativeProbeModuleFactory() engine.Module {
	return newMySQLNativeProbeModule()
}

func init() {
	engine.RegisterModuleFactory(mysqlNativeProbeModuleName, mysqlNativeProbeModuleFactory)
}
