package scan

import (
	"bufio"
	"context"
	"encoding/binary"
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
	sshNativeProbeModuleID          = "ssh-native-probe-instance"
	sshNativeProbeModuleName        = "ssh-native-probe"
	sshNativeProbeModuleDescription = "Runs native SSH banner and KEX probes to emit structured SSH metadata."

	sshKEXInitMessageType = 20
)

// SSHProbeOptions controls timeout and retry behavior for SSH native probe.
type SSHProbeOptions struct {
	TotalTimeout   time.Duration `json:"total_timeout"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	IOTimeout      time.Duration `json:"io_timeout"`
	Retries        int           `json:"retries"`
	CandidatePorts []int         `json:"candidate_ports,omitempty"`
}

// SSHProbeAttempt represents one SSH probe strategy attempt.
type SSHProbeAttempt struct {
	Strategy   string `json:"strategy"`
	Transport  string `json:"transport"`
	Success    bool   `json:"success"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

// SSHServiceInfo is the canonical SSH native probe output.
type SSHServiceInfo struct {
	Target            string            `json:"target"`
	Port              int               `json:"port"`
	SSHProbe          bool              `json:"ssh_probe"`
	SSHBanner         string            `json:"ssh_banner,omitempty"`
	SSHProtocol       string            `json:"ssh_protocol,omitempty"`
	SSHSoftware       string            `json:"ssh_software,omitempty"`
	SSHVersion        string            `json:"ssh_version,omitempty"`
	KEXAlgorithms     []string          `json:"kex_algorithms,omitempty"`
	HostKeyAlgorithms []string          `json:"host_key_algorithms,omitempty"`
	Ciphers           []string          `json:"ciphers,omitempty"`
	MACs              []string          `json:"macs,omitempty"`
	AuthMethods       []string          `json:"auth_methods,omitempty"`
	WeakProtocol      bool              `json:"weak_protocol"`
	WeakKEX           bool              `json:"weak_kex"`
	WeakCipher        bool              `json:"weak_cipher"`
	WeakMAC           bool              `json:"weak_mac"`
	ProbeError        string            `json:"probe_error,omitempty"`
	Attempts          []SSHProbeAttempt `json:"attempts,omitempty"`
}

type sshNativeProbeModule struct {
	meta    engine.ModuleMetadata
	options SSHProbeOptions
}

type sshProbeCandidate struct {
	target string
	port   int
}

type sshBannerOutcome struct {
	banner   string
	protocol string
	software string
	version  string
	duration time.Duration
}

type sshKEXOutcome struct {
	kexAlgorithms     []string
	hostKeyAlgorithms []string
	ciphers           []string
	macs              []string
	duration          time.Duration
}

var probeSSHDetailsFunc = probeSSHDetails

func newSSHNativeProbeModuleWithSpec(moduleID string, moduleName string, description string, outputKey string, tags []string) *sshNativeProbeModule {
	return &sshNativeProbeModule{
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
					Description:  "Open TCP ports used to identify SSH candidate services.",
				},
				{
					Key:          "service.banner.tcp",
					DataTypeName: "scan.BannerGrabResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   true,
					Description:  "Banner results used as fallback SSH candidate source.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key:          outputKey,
					DataTypeName: "scan.SSHServiceInfo",
					Cardinality:  engine.CardinalityList,
					Description:  "Structured SSH native probe output per target and port.",
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
				"candidate_ports": {
					Description: "Optional explicit ports to treat as SSH candidates when already known open.",
					Type:        "[]int",
					Required:    false,
				},
			},
		},
		options: defaultSSHProbeOptions(),
	}
}

func newSSHNativeProbeModule() *sshNativeProbeModule {
	return newSSHNativeProbeModuleWithSpec(
		sshNativeProbeModuleID,
		sshNativeProbeModuleName,
		sshNativeProbeModuleDescription,
		"service.ssh.details",
		[]string{"scan", "ssh", "enrichment", "native_probe"},
	)
}

func (m *sshNativeProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *sshNativeProbeModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	opts := defaultSSHProbeOptions()
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

func (m *sshNativeProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	candidateMap := make(map[string]sshProbeCandidate)
	explicitCandidatePorts := make(map[int]struct{}, len(m.options.CandidatePorts))
	for _, port := range m.options.CandidatePorts {
		if port > 0 {
			explicitCandidatePorts[port] = struct{}{}
		}
	}

	if rawOpenPorts, ok := inputs["discovery.open_tcp_ports"]; ok {
		for _, item := range toAnySlice(rawOpenPorts) {
			for _, candidate := range sshCandidatesFromOpenPorts(item, explicitCandidatePorts) {
				candidateMap[sshCandidateKey(candidate)] = candidate
			}
		}
	}

	if rawBanner, ok := inputs["service.banner.tcp"]; ok {
		for _, item := range toAnySlice(rawBanner) {
			candidate, ok := sshCandidateFromBanner(item)
			if !ok {
				continue
			}
			candidateMap[sshCandidateKey(candidate)] = candidate
		}
	}

	if len(candidateMap) == 0 {
		return nil
	}

	keys := make([]string, 0, len(candidateMap))
	for key := range candidateMap {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left := candidateMap[keys[i]]
		right := candidateMap[keys[j]]
		if left.target == right.target {
			leftPriority := sshPortPriority(left.port)
			rightPriority := sshPortPriority(right.port)
			if leftPriority != rightPriority {
				return leftPriority > rightPriority
			}
			return left.port < right.port
		}
		return left.target < right.target
	})

	for _, key := range keys {
		candidate := candidateMap[key]
		result := probeSSHDetailsFunc(ctx, candidate.target, candidate.port, m.options)
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "service.ssh.details",
			Data:           result,
			Timestamp:      time.Now(),
			Target:         candidate.target,
		}
	}

	return nil
}

func defaultSSHProbeOptions() SSHProbeOptions {
	return SSHProbeOptions{
		TotalTimeout:   2 * time.Second,
		ConnectTimeout: time.Second,
		IOTimeout:      time.Second,
		Retries:        0,
	}
}

func sshCandidatesFromOpenPorts(item any, explicitCandidatePorts map[int]struct{}) []sshProbeCandidate {
	candidates := make([]sshProbeCandidate, 0, 2)
	appendCandidate := func(target string, port int) {
		target = strings.TrimSpace(target)
		if target == "" || port <= 0 {
			return
		}
		if port != 22 {
			if _, ok := explicitCandidatePorts[port]; !ok {
				return
			}
		}
		if port > 65535 {
			return
		}
		candidates = append(candidates, sshProbeCandidate{target: target, port: port})
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

func sshCandidateFromBanner(item any) (sshProbeCandidate, bool) {
	switch v := item.(type) {
	case BannerGrabResult:
		if v.Port == 22 || bannerLooksLikeSSH(v) {
			return sshProbeCandidate{target: strings.TrimSpace(v.IP), port: v.Port}, strings.TrimSpace(v.IP) != "" && v.Port > 0
		}
	case map[string]any:
		target := getMapString(v, "ip", "IP")
		if target == "" {
			return sshProbeCandidate{}, false
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
			return sshProbeCandidate{}, false
		}
		if port == 22 {
			return sshProbeCandidate{target: target, port: port}, true
		}
		if containsSSHHint(getMapString(v, "protocol", "Protocol")) ||
			containsSSHHint(getMapString(v, "banner", "Banner")) ||
			mapEvidenceLooksLikeSSH(v["evidence"]) {
			return sshProbeCandidate{target: target, port: port}, true
		}
	}
	return sshProbeCandidate{}, false
}

func bannerLooksLikeSSH(b BannerGrabResult) bool {
	if containsSSHHint(b.Protocol) || containsSSHHint(b.Banner) {
		return true
	}
	for _, obs := range b.Evidence {
		if containsSSHHint(obs.Protocol) || containsSSHHint(obs.ProbeID) || containsSSHHint(obs.Description) || containsSSHHint(obs.Response) {
			return true
		}
	}
	return false
}

func mapEvidenceLooksLikeSSH(raw any) bool {
	items, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if containsSSHHint(getMapString(m, "protocol", "Protocol")) ||
			containsSSHHint(getMapString(m, "probe_id", "ProbeID")) ||
			containsSSHHint(getMapString(m, "description", "Description")) ||
			containsSSHHint(getMapString(m, "response", "Response")) {
			return true
		}
	}
	return false
}

func containsSSHHint(value string) bool {
	clean := strings.ToLower(strings.TrimSpace(value))
	if clean == "" {
		return false
	}
	return strings.Contains(clean, "ssh") || strings.HasPrefix(clean, "ssh-")
}

func sshCandidateKey(candidate sshProbeCandidate) string {
	return fmt.Sprintf("%s:%d", candidate.target, candidate.port)
}

func sshPortPriority(port int) int {
	if port == 22 {
		return 2
	}
	return 1
}

func probeSSHDetails(ctx context.Context, target string, port int, opts SSHProbeOptions) SSHServiceInfo {
	if port <= 0 {
		port = 22
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

	result := SSHServiceInfo{
		Target:   target,
		Port:     port,
		Attempts: make([]SSHProbeAttempt, 0, 2*(opts.Retries+1)),
	}

	bannerErrors := make([]string, 0, opts.Retries+1)
	kexErrors := make([]string, 0, opts.Retries+1)

	var bannerOutcome sshBannerOutcome
	bannerSuccess := false
	for retry := 0; retry <= opts.Retries; retry++ {
		outcome, err := probeSSHBanner(probeCtx, target, port, opts)
		if err != nil {
			code := classifySSHProbeError(err)
			bannerErrors = append(bannerErrors, code)
			result.Attempts = append(result.Attempts, SSHProbeAttempt{
				Strategy:   "banner-read",
				Transport:  strconv.Itoa(port),
				Success:    false,
				DurationMS: outcome.duration.Milliseconds(),
				Error:      code,
			})
			continue
		}
		bannerOutcome = outcome
		bannerSuccess = true
		result.Attempts = append(result.Attempts, SSHProbeAttempt{
			Strategy:   "banner-read",
			Transport:  strconv.Itoa(port),
			Success:    true,
			DurationMS: outcome.duration.Milliseconds(),
		})
		break
	}

	if !bannerSuccess {
		result.SSHProbe = false
		result.ProbeError = pickTopSSHProbeError(bannerErrors)
		if result.ProbeError == "" {
			result.ProbeError = "probe_failed"
		}
		return result
	}

	result.SSHProbe = true
	result.SSHBanner = bannerOutcome.banner
	result.SSHProtocol = bannerOutcome.protocol
	result.SSHSoftware = bannerOutcome.software
	result.SSHVersion = bannerOutcome.version
	result.WeakProtocol = isWeakSSHProtocol(result.SSHProtocol)

	kexSuccess := false
	var kexOutcome sshKEXOutcome
	for retry := 0; retry <= opts.Retries; retry++ {
		outcome, err := probeSSHKEXInit(probeCtx, target, port, opts)
		if err != nil {
			code := classifySSHProbeError(err)
			kexErrors = append(kexErrors, code)
			result.Attempts = append(result.Attempts, SSHProbeAttempt{
				Strategy:   "kexinit-capture",
				Transport:  strconv.Itoa(port),
				Success:    false,
				DurationMS: outcome.duration.Milliseconds(),
				Error:      code,
			})
			continue
		}
		kexOutcome = outcome
		kexSuccess = true
		result.Attempts = append(result.Attempts, SSHProbeAttempt{
			Strategy:   "kexinit-capture",
			Transport:  strconv.Itoa(port),
			Success:    true,
			DurationMS: outcome.duration.Milliseconds(),
		})
		break
	}

	if kexSuccess {
		result.KEXAlgorithms = append([]string(nil), kexOutcome.kexAlgorithms...)
		result.HostKeyAlgorithms = append([]string(nil), kexOutcome.hostKeyAlgorithms...)
		result.Ciphers = append([]string(nil), kexOutcome.ciphers...)
		result.MACs = append([]string(nil), kexOutcome.macs...)
		result.WeakKEX = hasWeakSSHKEX(result.KEXAlgorithms)
		result.WeakCipher = hasWeakSSHCipherPreference(result.Ciphers)
		result.WeakMAC = hasWeakSSHMAC(result.MACs)
		result.ProbeError = ""
		return result
	}

	result.ProbeError = pickTopSSHProbeError(kexErrors)
	if result.ProbeError == "" {
		result.ProbeError = ""
	}
	return result
}

func probeSSHBanner(ctx context.Context, target string, port int, opts SSHProbeOptions) (sshBannerOutcome, error) {
	start := time.Now()
	outcome := sshBannerOutcome{}

	conn, err := dialSSH(ctx, target, port, opts)
	if err != nil {
		outcome.duration = time.Since(start)
		return outcome, err
	}
	defer func() {
		_ = conn.Close()
	}()

	reader := bufio.NewReader(conn)
	banner, err := readSSHIdentification(reader)
	if err != nil {
		outcome.duration = time.Since(start)
		return outcome, err
	}

	protocol, software, version, err := parseSSHBannerLine(banner)
	outcome.banner = banner
	outcome.protocol = protocol
	outcome.software = software
	outcome.version = version
	outcome.duration = time.Since(start)
	return outcome, err
}

func probeSSHKEXInit(ctx context.Context, target string, port int, opts SSHProbeOptions) (sshKEXOutcome, error) {
	start := time.Now()
	outcome := sshKEXOutcome{}

	conn, err := dialSSH(ctx, target, port, opts)
	if err != nil {
		outcome.duration = time.Since(start)
		return outcome, err
	}
	defer func() {
		_ = conn.Close()
	}()

	reader := bufio.NewReader(conn)
	if _, err := readSSHIdentification(reader); err != nil {
		outcome.duration = time.Since(start)
		return outcome, err
	}

	if _, err := conn.Write([]byte("SSH-2.0-cyprob-native-probe\r\n")); err != nil {
		outcome.duration = time.Since(start)
		return outcome, err
	}

	if _, err := conn.Write(buildSSHClientKEXInitPacket()); err != nil {
		outcome.duration = time.Since(start)
		return outcome, err
	}

	payload, err := readSSHKEXInitPayload(reader)
	if err != nil {
		outcome.duration = time.Since(start)
		return outcome, err
	}

	kexAlgorithms, hostKeyAlgorithms, ciphers, macs, err := parseSSHKEXInitPayload(payload)
	if err != nil {
		outcome.duration = time.Since(start)
		return outcome, err
	}

	outcome.kexAlgorithms = kexAlgorithms
	outcome.hostKeyAlgorithms = hostKeyAlgorithms
	outcome.ciphers = ciphers
	outcome.macs = macs
	outcome.duration = time.Since(start)
	return outcome, nil
}

func dialSSH(ctx context.Context, target string, port int, opts SSHProbeOptions) (net.Conn, error) {
	address := net.JoinHostPort(target, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: opts.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(opts.IOTimeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func readSSHIdentification(reader *bufio.Reader) (string, error) {
	for i := 0; i < 20; i++ {
		line, err := reader.ReadString('\n')
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "SSH-") {
			return trimmed, nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", errors.New("no_banner")
			}
			return "", err
		}
	}
	return "", errors.New("no_banner")
}

func parseSSHBannerLine(banner string) (string, string, string, error) {
	banner = strings.TrimSpace(banner)
	if !strings.HasPrefix(banner, "SSH-") {
		return "", "", "", errors.New("protocol_error")
	}

	parts := strings.SplitN(banner, "-", 3)
	if len(parts) < 3 {
		return "", "", "", errors.New("protocol_error")
	}

	protocol := strings.TrimSpace(parts[1])
	versionInfo := strings.TrimSpace(parts[2])
	if protocol == "" || versionInfo == "" {
		return protocol, "", "", errors.New("protocol_error")
	}

	token := versionInfo
	if fields := strings.Fields(versionInfo); len(fields) > 0 {
		token = fields[0]
	}
	software, version := extractSSHSoftwareAndVersion(token)
	return protocol, software, version, nil
}

func extractSSHSoftwareAndVersion(versionInfo string) (string, string) {
	versionInfo = strings.TrimSpace(versionInfo)
	if versionInfo == "" {
		return "", ""
	}

	parts := strings.SplitN(versionInfo, "_", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}

	if idx := strings.LastIndex(versionInfo, "-"); idx > 0 && idx < len(versionInfo)-1 {
		software := strings.TrimSpace(versionInfo[:idx])
		version := strings.TrimSpace(versionInfo[idx+1:])
		if software != "" && looksLikeSSHVersion(version) {
			return software, version
		}
	}

	fields := strings.Fields(versionInfo)
	if len(fields) == 0 {
		return versionInfo, ""
	}
	if len(fields) == 1 {
		if isOpaqueSSHSoftwareToken(fields[0]) {
			return "", ""
		}
		return fields[0], ""
	}
	return fields[0], fields[1]
}

func looksLikeSSHVersion(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, r := range value {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func isOpaqueSSHSoftwareToken(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" || len(value) < 6 || len(value) > 16 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func buildSSHClientKEXInitPacket() []byte {
	payload := make([]byte, 0, 512)
	payload = append(payload, byte(sshKEXInitMessageType))
	payload = append(payload, []byte("cyprob-kexinit-1")...)

	nameLists := []string{
		"curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256",
		"ssh-ed25519,rsa-sha2-512,rsa-sha2-256",
		"chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr",
		"chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr",
		"hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512",
		"hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512",
		"none",
		"none",
		"",
		"",
	}
	for _, list := range nameLists {
		payload = appendSSHNameList(payload, list)
	}

	payload = append(payload, 0x00) // first_kex_packet_follows=false
	payload = append(payload, 0x00, 0x00, 0x00, 0x00)

	paddingLength := 8 - ((len(payload) + 5) % 8)
	if paddingLength < 4 {
		paddingLength += 8
	}

	packetLength := 1 + len(payload) + paddingLength
	packet := make([]byte, 4+packetLength)
	binary.BigEndian.PutUint32(packet[0:4], uint32(packetLength))
	packet[4] = byte(paddingLength)
	copy(packet[5:], payload)
	paddingStart := 5 + len(payload)
	for i := 0; i < paddingLength; i++ {
		packet[paddingStart+i] = byte(i + 1)
	}

	return packet
}

func appendSSHNameList(dst []byte, value string) []byte {
	data := []byte(value)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(len(data)))
	dst = append(dst, buf...)
	dst = append(dst, data...)
	return dst
}

func readSSHKEXInitPayload(reader *bufio.Reader) ([]byte, error) {
	for i := 0; i < 3; i++ {
		payload, err := readSSHPacket(reader)
		if err != nil {
			return nil, err
		}
		if len(payload) == 0 {
			continue
		}
		if payload[0] == sshKEXInitMessageType {
			return payload, nil
		}
	}
	return nil, errors.New("kex_parse_failed")
}

func readSSHPacket(reader *bufio.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}

	packetLength := binary.BigEndian.Uint32(header)
	if packetLength < 6 || packetLength > 35000 {
		return nil, errors.New("protocol_error")
	}

	packet := make([]byte, packetLength)
	if _, err := io.ReadFull(reader, packet); err != nil {
		return nil, err
	}

	paddingLength := int(packet[0])
	if paddingLength < 4 || paddingLength >= len(packet) {
		return nil, errors.New("protocol_error")
	}

	payloadLength := len(packet) - 1 - paddingLength
	if payloadLength <= 0 {
		return nil, errors.New("protocol_error")
	}

	return packet[1 : 1+payloadLength], nil
}

func parseSSHKEXInitPayload(payload []byte) ([]string, []string, []string, []string, error) {
	if len(payload) < 17 || payload[0] != sshKEXInitMessageType {
		return nil, nil, nil, nil, errors.New("kex_parse_failed")
	}

	offset := 17 // message type + cookie
	nameLists := make([][]string, 0, 10)
	for i := 0; i < 10; i++ {
		values, nextOffset, err := readSSHNameList(payload, offset)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		nameLists = append(nameLists, values)
		offset = nextOffset
	}

	if offset+5 > len(payload) {
		return nil, nil, nil, nil, errors.New("kex_parse_failed")
	}

	return nameLists[0], nameLists[1], mergeSSHNameLists(nameLists[2], nameLists[3]), mergeSSHNameLists(nameLists[4], nameLists[5]), nil
}

func readSSHNameList(payload []byte, offset int) ([]string, int, error) {
	if offset+4 > len(payload) {
		return nil, offset, errors.New("kex_parse_failed")
	}
	length := int(binary.BigEndian.Uint32(payload[offset : offset+4]))
	offset += 4
	if length < 0 || offset+length > len(payload) {
		return nil, offset, errors.New("kex_parse_failed")
	}
	if length == 0 {
		return nil, offset, nil
	}
	value := string(payload[offset : offset+length])
	offset += length
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result, offset, nil
}

func mergeSSHNameLists(primary, secondary []string) []string {
	merged := make([]string, 0, len(primary)+len(secondary))
	seen := make(map[string]struct{}, len(primary)+len(secondary))
	for _, item := range append(append([]string(nil), primary...), secondary...) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		merged = append(merged, item)
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

func classifySSHProbeError(err error) string {
	if err == nil {
		return ""
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"), strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case strings.Contains(msg, "connection refused"):
		return "refused"
	case strings.Contains(msg, "no_banner"):
		return "no_banner"
	case strings.Contains(msg, "kex_parse_failed"):
		return "kex_parse_failed"
	case strings.Contains(msg, "protocol_error"):
		return "protocol_error"
	default:
		return "probe_failed"
	}
}

func pickTopSSHProbeError(codes []string) string {
	bestCode := ""
	bestScore := -1
	for _, code := range codes {
		score := sshProbeErrorPriority(code)
		if score > bestScore {
			bestScore = score
			bestCode = code
		}
	}
	return bestCode
}

func sshProbeErrorPriority(code string) int {
	switch code {
	case "timeout":
		return 6
	case "refused":
		return 5
	case "no_banner":
		return 4
	case "protocol_error":
		return 3
	case "kex_parse_failed":
		return 2
	case "probe_failed":
		return 1
	default:
		return 0
	}
}

func isWeakSSHProtocol(protocol string) bool {
	protocol = strings.TrimSpace(protocol)
	if protocol == "" || protocol == "1.99" {
		return false
	}
	return strings.HasPrefix(protocol, "1.")
}

func hasWeakSSHKEX(kexAlgorithms []string) bool {
	for _, algorithm := range kexAlgorithms {
		switch strings.ToLower(strings.TrimSpace(algorithm)) {
		case "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1":
			return true
		}
	}
	return false
}

func hasWeakSSHCipherPreference(ciphers []string) bool {
	if len(ciphers) == 0 {
		return false
	}
	legacy := 0
	modern := 0
	for _, cipher := range ciphers {
		if isLegacySSHCipher(cipher) {
			legacy++
			continue
		}
		modern++
	}
	return legacy > 0 && legacy >= modern
}

func isLegacySSHCipher(cipher string) bool {
	cipher = strings.ToLower(strings.TrimSpace(cipher))
	if cipher == "" {
		return false
	}
	return strings.Contains(cipher, "3des-cbc") ||
		strings.Contains(cipher, "arcfour") ||
		strings.HasSuffix(cipher, "-cbc")
}

func hasWeakSSHMAC(macs []string) bool {
	for _, mac := range macs {
		clean := strings.ToLower(strings.TrimSpace(mac))
		if clean == "" {
			continue
		}
		if strings.Contains(clean, "hmac-md5") || strings.HasSuffix(clean, "-96") {
			return true
		}
	}
	return false
}

func sshNativeProbeModuleFactory() engine.Module {
	return newSSHNativeProbeModule()
}

func init() {
	engine.RegisterModuleFactory(sshNativeProbeModuleName, sshNativeProbeModuleFactory)
}
