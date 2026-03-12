package scan

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/rs/zerolog/log"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

const (
	smbNativeProbeModuleID          = "smb-native-probe-instance"
	smbNativeProbeModuleName        = "smb-native-probe"
	smbNativeProbeModuleDescription = "Runs protocol-aware SMB negotiate + enum probe and emits structured SMB metadata."

	ntStatusMoreProcessingRequired = 0xC0000016
	ntStatusSuccess                = 0x00000000
	ntlmNegotiateVersionFlag       = 0x02000000
)

// SMBProbeOptions controls timeout and retry behavior for SMB native probe.
type SMBProbeOptions struct {
	TotalTimeout      time.Duration `json:"total_timeout"`
	ConnectTimeout    time.Duration `json:"connect_timeout"`
	IOTimeout         time.Duration `json:"io_timeout"`
	Retries           int           `json:"retries"`
	IncludeEnum       bool          `json:"include_enum"`
	FallbackToNetBIOS bool          `json:"fallback_to_netbios"`
}

// SMBProbeAttempt represents one probe strategy attempt.
type SMBProbeAttempt struct {
	Strategy   string `json:"strategy"`
	Transport  string `json:"transport"`
	Success    bool   `json:"success"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

// SMBHostHints contains host identity hints extracted from SMB metadata.
type SMBHostHints struct {
	TargetName  string `json:"target_name,omitempty"`
	NBComputer  string `json:"nb_computer,omitempty"`
	NBDomain    string `json:"nb_domain,omitempty"`
	DNSComputer string `json:"dns_computer,omitempty"`
	DNSDomain   string `json:"dns_domain,omitempty"`
}

// SMBOSHints contains OS hints extracted from SMB metadata.
type SMBOSHints struct {
	Family  string `json:"family,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// SMBServiceInfo is the canonical SMB native probe output.
type SMBServiceInfo struct {
	Target          string            `json:"target"`
	Port            int               `json:"port"`
	ProtocolVersion string            `json:"protocol_version,omitempty"`
	Dialect         string            `json:"dialect,omitempty"`
	SigningRequired *bool             `json:"signing_required,omitempty"`
	Product         string            `json:"product,omitempty"`
	Vendor          string            `json:"vendor,omitempty"`
	ProductVersion  string            `json:"product_version,omitempty"`
	OSHints         SMBOSHints        `json:"os_hints,omitzero"`
	HostHints       SMBHostHints      `json:"host_hints,omitzero"`
	Error           string            `json:"error,omitempty"`
	Attempts        []SMBProbeAttempt `json:"attempts,omitempty"`
}

type smbNativeProbeModule struct {
	meta    engine.ModuleMetadata
	options SMBProbeOptions
}

var probeSMBDetailsFunc = probeSMBDetails

func newSMBNativeProbeModuleWithSpec(moduleID string, moduleName string, description string, outputKey string, tags []string) *smbNativeProbeModule {
	return &smbNativeProbeModule{
		meta: buildTCPNativeProbeMetadata(tcpNativeProbeMetadataSpec{
			moduleID:              moduleID,
			moduleName:            moduleName,
			description:           description,
			outputKey:             outputKey,
			outputType:            "scan.SMBServiceInfo",
			outputDescription:     "Structured SMB native probe output per target and port.",
			tags:                  tags,
			consumes:              []engine.DataContractEntry{nativeOpenTCPPortsConsume(true, "Open TCP ports used to identify SMB candidate services."), nativeBannerConsume("Banner results used as fallback SMB candidate source.")},
			timeoutDefault:        "2s",
			connectTimeoutDefault: "1s",
			ioTimeoutDefault:      "1s",
		}),
		options: defaultSMBProbeOptions(),
	}
}

func newSMBNativeProbeModule() *smbNativeProbeModule {
	return newSMBNativeProbeModuleWithSpec(
		smbNativeProbeModuleID,
		smbNativeProbeModuleName,
		smbNativeProbeModuleDescription,
		"service.smb.details",
		[]string{"scan", "smb", "enrichment", "native_probe"},
	)
}

func (m *smbNativeProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *smbNativeProbeModule) Init(instanceID string, configMap map[string]any) error {
	opts := defaultSMBProbeOptions()
	initCommonTCPProbeOptions(&m.meta, instanceID, configMap, &opts.TotalTimeout, &opts.ConnectTimeout, &opts.IOTimeout, &opts.Retries)
	if configMap != nil {
		if includeEnum, ok := configMap["include_enum"].(bool); ok {
			opts.IncludeEnum = includeEnum
		}
		if fallbackNetBIOS, ok := configMap["fallback_to_netbios"].(bool); ok {
			opts.FallbackToNetBIOS = fallbackNetBIOS
		}
	}
	m.options = opts
	return nil
}

func (m *smbNativeProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	candidates := make(map[string]struct {
		target string
		port   int
	})

	if rawOpenPorts, ok := inputs["discovery.open_tcp_ports"]; ok {
		for _, item := range toAnySlice(rawOpenPorts) {
			for _, candidate := range smbCandidatesFromOpenPorts(item) {
				key := fmt.Sprintf("%s:%d", candidate.target, candidate.port)
				candidates[key] = candidate
			}
		}
	}

	if rawBanner, ok := inputs["service.banner.tcp"]; ok {
		for _, item := range toAnySlice(rawBanner) {
			target, port := smbCandidateFromBanner(item)
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

	for _, c := range candidates {
		result := probeSMBDetailsFunc(ctx, c.target, c.port, m.options)
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

func toAnySlice(raw any) []any {
	switch v := raw.(type) {
	case []any:
		return v
	case []BannerGrabResult:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, item)
		}
		return out
	case []discovery.TCPPortDiscoveryResult:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, item)
		}
		return out
	case []discovery.UDPPortDiscoveryResult:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, item)
		}
		return out
	default:
		return nil
	}
}

func smbCandidatesFromOpenPorts(item any) []struct {
	target string
	port   int
} {
	candidates := make([]struct {
		target string
		port   int
	}, 0, 2)

	appendCandidate := func(target string, port int) {
		if target == "" || (port != 445 && port != 139) {
			return
		}
		candidates = append(candidates, struct {
			target string
			port   int
		}{target: target, port: port})
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

func smbCandidateFromBanner(item any) (string, int) {
	switch v := item.(type) {
	case BannerGrabResult:
		if v.Port == 445 || v.Port == 139 {
			return v.IP, v.Port
		}
		for _, obs := range v.Evidence {
			proto := strings.ToLower(strings.TrimSpace(obs.Protocol))
			if proto == "smb" || proto == "netbios" {
				return v.IP, v.Port
			}
		}
	case map[string]any:
		target, _ := v["ip"].(string)
		if target == "" {
			target, _ = v["IP"].(string)
		}
		port := 0
		switch pv := v["port"].(type) {
		case int:
			port = pv
		case float64:
			port = int(pv)
		case int64:
			port = int(pv)
		}
		if port == 445 || port == 139 {
			return target, port
		}
	}
	return "", 0
}

func defaultSMBProbeOptions() SMBProbeOptions {
	return SMBProbeOptions{
		TotalTimeout:      2 * time.Second,
		ConnectTimeout:    time.Second,
		IOTimeout:         time.Second,
		Retries:           0,
		IncludeEnum:       true,
		FallbackToNetBIOS: true,
	}
}

func parseDurationConfig(raw any) (time.Duration, bool) {
	switch v := raw.(type) {
	case string:
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil {
			return 0, false
		}
		return d, true
	case time.Duration:
		if v <= 0 {
			return 0, false
		}
		return v, true
	default:
		return 0, false
	}
}

type smbNegotiateResult struct {
	protocolVersion string
	dialect         string
	signingRequired *bool
	conn            net.Conn
	duration        time.Duration
}

type smbEnumResult struct {
	product        string
	vendor         string
	productVersion string
	osHints        SMBOSHints
	hostHints      SMBHostHints
	err            error
}

type smbProbeStrategy struct {
	name      string
	transport int
	netBIOS   bool
	request   []byte
}

type ntlmChallengeInfo struct {
	TargetName      string
	NegotiateFlags  uint32
	AVPairs         map[uint16]string
	VersionMajor    int
	VersionMinor    int
	VersionBuild    int
	VersionPresent  bool
	ServerTimeUTC   string
	NetBIOSComputer string
	NetBIOSDomain   string
	DNSComputer     string
	DNSDomain       string
}

//nolint:gocyclo // SMB probing keeps protocol fallback ordering explicit.
func probeSMBDetails(ctx context.Context, target string, port int, opts SMBProbeOptions) SMBServiceInfo {
	if port <= 0 {
		port = 445
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

	result := SMBServiceInfo{
		Target:   target,
		Port:     port,
		Attempts: make([]SMBProbeAttempt, 0, opts.Retries+2),
	}

	strategies := buildSMBProbeStrategies(port, opts.FallbackToNetBIOS)

	attemptErrors := make([]string, 0, len(strategies)*(opts.Retries+1))
	negotiateOK := false
	bestEnumScore := -1
	var bestEnum smbEnumResult
	var bestNeg smbNegotiateResult

	for _, strategy := range strategies {
		for retry := 0; retry <= opts.Retries; retry++ {
			neg, enum, err := probeSingleSMBStrategy(probeCtx, target, strategy, opts)
			if err != nil {
				errCode := classifySMBProbeError(err)
				attemptErrors = append(attemptErrors, errCode)
				result.Attempts = append(result.Attempts, SMBProbeAttempt{
					Strategy:   strategy.name,
					Transport:  strconv.Itoa(strategy.transport),
					Success:    false,
					DurationMS: neg.duration.Milliseconds(),
					Error:      errCode,
				})
				continue
			}

			negotiateOK = true
			result.ProtocolVersion = neg.protocolVersion
			result.Dialect = neg.dialect
			result.SigningRequired = neg.signingRequired
			result.Attempts = append(result.Attempts, SMBProbeAttempt{
				Strategy:   strategy.name,
				Transport:  strconv.Itoa(strategy.transport),
				Success:    true,
				DurationMS: neg.duration.Milliseconds(),
			})

			if opts.IncludeEnum {
				if enum.err == nil {
					score := scoreSMBEnumResult(enum)
					if score > bestEnumScore {
						bestEnumScore = score
						bestEnum = enum
						bestNeg = neg
					}
					// Rich metadata found, no need to spend more budget.
					if score >= 4 {
						result.ProtocolVersion = bestNeg.protocolVersion
						result.Dialect = bestNeg.dialect
						result.SigningRequired = bestNeg.signingRequired
						result.Product = bestEnum.product
						result.Vendor = bestEnum.vendor
						result.ProductVersion = bestEnum.productVersion
						result.OSHints = bestEnum.osHints
						result.HostHints = bestEnum.hostHints
						if result.Product == "" {
							result.Product = "smb"
						}
						result.Error = ""
						return result
					}
					continue
				}
				result.Error = classifySMBProbeError(enum.err)
				continue
			}

			result.Error = ""
			return result
		}
	}

	if negotiateOK {
		if opts.IncludeEnum && bestEnumScore >= 0 {
			result.ProtocolVersion = bestNeg.protocolVersion
			result.Dialect = bestNeg.dialect
			result.SigningRequired = bestNeg.signingRequired
			result.Product = bestEnum.product
			result.Vendor = bestEnum.vendor
			result.ProductVersion = bestEnum.productVersion
			result.OSHints = bestEnum.osHints
			result.HostHints = bestEnum.hostHints
			if result.Product == "" {
				result.Product = "smb"
			}
			result.Error = ""
			return result
		}

		if result.Error == "" {
			result.Error = "enum_failed"
		}
		return result
	}

	result.Error = pickTopProbeError(attemptErrors)
	if result.Error == "" {
		result.Error = "probe_failed"
	}
	return result
}

func buildSMBProbeStrategies(port int, includeNetBIOS bool) []smbProbeStrategy {
	strategies := []smbProbeStrategy{
		{
			name:      "legacy_direct_smb2",
			transport: port,
			request:   buildSMB2NegotiateRequest(),
		},
		{
			name:      "direct-smb2-impacket",
			transport: port,
			request:   buildSMB2NegotiateRequestImpacket(),
		},
	}

	if includeNetBIOS && port != 139 {
		strategies = append(strategies,
			smbProbeStrategy{
				name:      "nbss-legacy_direct_smb2",
				transport: 139,
				netBIOS:   true,
				request:   buildSMB2NegotiateRequest(),
			},
			smbProbeStrategy{
				name:      "nbss-direct-smb2-impacket",
				transport: 139,
				netBIOS:   true,
				request:   buildSMB2NegotiateRequestImpacket(),
			},
		)
	}
	return strategies
}

//nolint:gocyclo // SMB strategy execution keeps transport-specific branches explicit.
func probeSingleSMBStrategy(ctx context.Context, ip string, strategy smbProbeStrategy, opts SMBProbeOptions) (smbNegotiateResult, smbEnumResult, error) {
	start := time.Now()
	address := net.JoinHostPort(ip, strconv.Itoa(strategy.transport))
	dialer := &net.Dialer{Timeout: opts.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return smbNegotiateResult{duration: time.Since(start)}, smbEnumResult{}, err
	}

	if err := conn.SetDeadline(time.Now().Add(opts.IOTimeout)); err != nil {
		_ = conn.Close()
		return smbNegotiateResult{duration: time.Since(start)}, smbEnumResult{}, err
	}

	if strategy.netBIOS {
		if err := writeNetBIOSSessionRequest(conn); err != nil {
			_ = conn.Close()
			return smbNegotiateResult{duration: time.Since(start)}, smbEnumResult{}, err
		}
		if err := readAndValidateNetBIOSSessionResponse(conn); err != nil {
			_ = conn.Close()
			return smbNegotiateResult{duration: time.Since(start)}, smbEnumResult{}, err
		}
	}

	if _, err := conn.Write(strategy.request); err != nil {
		_ = conn.Close()
		return smbNegotiateResult{duration: time.Since(start)}, smbEnumResult{}, err
	}

	resp, err := readSMBFrame(conn)
	if err != nil {
		_ = conn.Close()
		return smbNegotiateResult{duration: time.Since(start)}, smbEnumResult{}, err
	}

	neg, err := parseSMBNegotiateResponse(resp)
	if err != nil {
		_ = conn.Close()
		return smbNegotiateResult{duration: time.Since(start)}, smbEnumResult{}, err
	}

	neg.duration = time.Since(start)
	neg.conn = conn
	enum := smbEnumResult{}
	if opts.IncludeEnum && neg.protocolVersion != "smb1" {
		enum = runSMBEnumFromExistingSession(conn, opts.IOTimeout)
		if enum.err != nil || scoreSMBEnumResult(enum) == 0 {
			fallbackEnum := runSMBEnumFromStrategy(ctx, ip, strategy, opts)
			if fallbackEnum.err == nil && (enum.err != nil || scoreSMBEnumResult(fallbackEnum) > scoreSMBEnumResult(enum)) {
				enum = fallbackEnum
			}
		}
	} else if opts.IncludeEnum {
		enum.err = fmt.Errorf("enum_not_supported_for_smb1")
	}
	_ = conn.Close()
	return neg, enum, nil
}

func buildSMB2NegotiateRequest() []byte {
	header := make([]byte, 64)
	header[0] = 0xFE
	header[1] = 'S'
	header[2] = 'M'
	header[3] = 'B'
	binary.LittleEndian.PutUint16(header[4:6], 64)
	binary.LittleEndian.PutUint16(header[12:14], 0)
	binary.LittleEndian.PutUint16(header[14:16], 1)
	binary.LittleEndian.PutUint32(header[32:36], 0x0000FEFF)

	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302}
	body := make([]byte, 36+len(dialects)*2)
	binary.LittleEndian.PutUint16(body[0:2], 36)
	binary.LittleEndian.PutUint16(body[2:4], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(body[4:6], 1)
	copy(body[12:28], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77})
	copy(body[28:36], []byte{0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(body[36+i*2:38+i*2], d)
	}

	payload := make([]byte, 0, len(header)+len(body))
	payload = append(payload, header...)
	payload = append(payload, body...)
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(payload)))
	copy(frame[4:], payload)
	return frame
}

func buildSMB2NegotiateRequestImpacket() []byte {
	const payloadHex = "fe534d424000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002400030001000000400000006f7150457a544f695048675466744b570000000000000000020210020003"
	payload := mustDecodeHex(payloadHex)
	req := make([]byte, 4+len(payload))
	req[0] = 0x00
	req[1] = 0x00
	req[2] = byte(len(payload) >> 8)
	req[3] = byte(len(payload))
	copy(req[4:], payload)
	return req
}

func parseSMBNegotiateResponse(frame []byte) (smbNegotiateResult, error) {
	if len(frame) < 4+64+8 {
		return smbNegotiateResult{}, fmt.Errorf("short_negotiate_response")
	}

	const nbss = 4
	sig := frame[nbss : nbss+4]
	if sig[0] == 0xFF && sig[1] == 'S' && sig[2] == 'M' && sig[3] == 'B' {
		return smbNegotiateResult{
			protocolVersion: "smb1",
			dialect:         "0x0000",
			signingRequired: nil,
		}, nil
	}
	if sig[0] != 0xFE || sig[1] != 'S' || sig[2] != 'M' || sig[3] != 'B' {
		return smbNegotiateResult{}, fmt.Errorf("unknown_smb_signature")
	}

	status := binary.LittleEndian.Uint32(frame[nbss+8 : nbss+12])
	command := binary.LittleEndian.Uint16(frame[nbss+12 : nbss+14])
	if command != 0 {
		return smbNegotiateResult{}, fmt.Errorf("unexpected_smb2_command_0x%04x", command)
	}
	if status != ntStatusSuccess {
		return smbNegotiateResult{}, fmt.Errorf("smb2_negotiate_status_0x%08x", status)
	}

	payload := frame[nbss+64:]
	if len(payload) < 65 {
		return smbNegotiateResult{}, fmt.Errorf("short_smb2_negotiate_payload")
	}
	structureSize := binary.LittleEndian.Uint16(payload[0:2])
	if structureSize != 65 {
		return smbNegotiateResult{}, fmt.Errorf("invalid_negotiate_structure_size_%d", structureSize)
	}

	secMode := binary.LittleEndian.Uint16(payload[2:4])
	dialect := binary.LittleEndian.Uint16(payload[4:6])
	if dialect < 0x0202 {
		return smbNegotiateResult{}, fmt.Errorf("invalid_smb2_dialect_0x%04x", dialect)
	}
	signingRequired := (secMode & 0x0002) == 0x0002

	return smbNegotiateResult{
		protocolVersion: dialectToProtocolVersion(dialect),
		dialect:         fmt.Sprintf("0x%04x", dialect),
		signingRequired: &signingRequired,
	}, nil
}

func runSMBEnumFromStrategy(ctx context.Context, target string, strategy smbProbeStrategy, opts SMBProbeOptions) smbEnumResult {
	legacyReq, legacyReqErr := buildSMB2SessionSetupRequest()
	if legacyReqErr != nil {
		return smbEnumResult{err: legacyReqErr}
	}

	sessionRequests := [][]byte{
		legacyReq,
		smb2SessionSetupNTLMNegotiateRequest(),
		smb2SessionSetupAnonymousRequest(),
	}

	bestScore := -1
	var bestResult smbEnumResult
	var errs []error
	for _, sessionReq := range sessionRequests {
		result, err := runSMBEnumSessionRequest(ctx, target, strategy, opts, sessionReq)
		if err == nil {
			score := scoreSMBEnumResult(result)
			if score > bestScore {
				bestScore = score
				bestResult = result
			}
			if score >= 4 {
				break
			}
			continue
		}
		errs = append(errs, err)
	}

	if bestScore >= 0 {
		return bestResult
	}

	if len(errs) == 0 {
		return smbEnumResult{err: fmt.Errorf("smb_enum_failed")}
	}
	return smbEnumResult{err: fmt.Errorf("smb_enum_failed: %w", errors.Join(errs...))}
}

//nolint:gocyclo // SMB session parsing is branch-heavy because the wire format is branch-heavy.
func runSMBEnumSessionRequest(
	ctx context.Context,
	target string,
	strategy smbProbeStrategy,
	opts SMBProbeOptions,
	sessionReq []byte,
) (smbEnumResult, error) {
	address := net.JoinHostPort(target, strconv.Itoa(strategy.transport))
	dialer := &net.Dialer{Timeout: opts.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return smbEnumResult{}, err
	}
	defer func() {
		_ = conn.Close()
	}()

	if strategy.netBIOS {
		if err := refreshConnDeadline(conn, opts.IOTimeout); err != nil {
			return smbEnumResult{}, err
		}
		if err := writeNetBIOSSessionRequest(conn); err != nil {
			return smbEnumResult{}, err
		}
		if err := readAndValidateNetBIOSSessionResponse(conn); err != nil {
			return smbEnumResult{}, err
		}
	}

	if err := refreshConnDeadline(conn, opts.IOTimeout); err != nil {
		return smbEnumResult{}, err
	}
	if _, err := conn.Write(strategy.request); err != nil {
		return smbEnumResult{}, err
	}
	if err := refreshConnDeadline(conn, opts.IOTimeout); err != nil {
		return smbEnumResult{}, err
	}
	negotiateResp, err := readSMBFrame(conn)
	if err != nil {
		return smbEnumResult{}, err
	}
	negotiated, err := parseSMBNegotiateResponse(negotiateResp)
	if err != nil {
		return smbEnumResult{}, err
	}
	if negotiated.protocolVersion != "smb2+" && negotiated.protocolVersion != "smb3" {
		return smbEnumResult{}, fmt.Errorf("smb2_required_for_ntlm_info")
	}

	if err := refreshConnDeadline(conn, opts.IOTimeout); err != nil {
		return smbEnumResult{}, err
	}
	if _, err := conn.Write(sessionReq); err != nil {
		return smbEnumResult{}, err
	}
	if err := refreshConnDeadline(conn, opts.IOTimeout); err != nil {
		return smbEnumResult{}, err
	}
	sessionResp, err := readSMBFrame(conn)
	if err != nil {
		return smbEnumResult{}, err
	}

	challenge, err := parseNTLMChallengeFromSessionResponse(sessionResp)
	if err != nil {
		return smbEnumResult{}, fmt.Errorf("ntlm_challenge_not_found status=0x%08x", smb2StatusCode(sessionResp))
	}
	return enumResultFromChallenge(challenge, sessionResp), nil
}

func scoreSMBEnumResult(result smbEnumResult) int {
	score := 0
	if result.productVersion != "" {
		score += 2
	}
	if result.vendor != "" {
		score++
	}
	if result.osHints.Family != "" {
		score++
	}
	if result.hostHints.TargetName != "" || result.hostHints.NBComputer != "" || result.hostHints.DNSComputer != "" {
		score++
	}
	return score
}

func buildSMB2SessionSetupRequest() ([]byte, error) {
	ntlm := buildNTLMType1Token()
	header := make([]byte, 64)
	header[0] = 0xFE
	header[1] = 'S'
	header[2] = 'M'
	header[3] = 'B'
	binary.LittleEndian.PutUint16(header[4:6], 64)
	binary.LittleEndian.PutUint16(header[12:14], 1)
	binary.LittleEndian.PutUint16(header[14:16], 1)
	binary.LittleEndian.PutUint32(header[32:36], 0x0000FEFF)
	binary.LittleEndian.PutUint64(header[24:32], 1)

	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 25)
	body[2] = 0
	body[3] = 1
	binary.LittleEndian.PutUint16(body[12:14], uint16(64+24))
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(ntlm)))

	payload := make([]byte, 0, len(header)+len(body)+len(ntlm))
	payload = append(payload, header...)
	payload = append(payload, body...)
	payload = append(payload, ntlm...)
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(payload)))
	copy(frame[4:], payload)
	return frame, nil
}

func runSMBEnumFromExistingSession(conn net.Conn, ioTimeout time.Duration) smbEnumResult {
	legacyReq, legacyReqErr := buildSMB2SessionSetupRequest()
	if legacyReqErr != nil {
		return smbEnumResult{err: legacyReqErr}
	}

	if err := refreshConnDeadline(conn, ioTimeout); err != nil {
		return smbEnumResult{err: err}
	}
	if _, err := conn.Write(legacyReq); err != nil {
		return smbEnumResult{err: err}
	}
	if err := refreshConnDeadline(conn, ioTimeout); err != nil {
		return smbEnumResult{err: err}
	}
	resp, err := readSMBFrame(conn)
	if err != nil {
		return smbEnumResult{err: err}
	}
	challenge, err := parseNTLMChallengeFromSessionResponse(resp)
	if err != nil {
		return smbEnumResult{err: fmt.Errorf("ntlm_challenge_not_found status=0x%08x", smb2StatusCode(resp))}
	}
	return enumResultFromChallenge(challenge, resp)
}

func enumResultFromChallenge(challenge *ntlmChallengeInfo, raw []byte) smbEnumResult {
	product, productVersion := mapSMBEnumProductVersion(challenge)
	enum := smbEnumResult{
		product:        product,
		productVersion: productVersion,
		hostHints: SMBHostHints{
			TargetName:  challenge.TargetName,
			NBComputer:  challenge.NetBIOSComputer,
			NBDomain:    challenge.NetBIOSDomain,
			DNSComputer: challenge.DNSComputer,
			DNSDomain:   challenge.DNSDomain,
		},
	}

	if challenge.VersionPresent {
		enum.vendor = "microsoft"
		enum.osHints = SMBOSHints{
			Family:  "windows",
			Name:    "Windows",
			Version: mapWindowsVersion(challenge.VersionMajor, challenge.VersionMinor, challenge.VersionBuild),
		}
	}
	if strings.Contains(strings.ToUpper(string(raw)), "SAMBA") {
		enum.vendor = "samba"
		enum.product = "samba"
		if enum.productVersion == "" {
			enum.productVersion = extractSambaVersion(string(raw))
		}
		if enum.osHints.Family == "" {
			enum.osHints = SMBOSHints{Family: "linux", Name: "Linux"}
		}
	}
	if enum.product == "" {
		enum.product = "smb"
	}
	return enum
}

func smb2SessionSetupNTLMNegotiateRequest() []byte {
	securityBlob := mustDecodeHex("604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000978208e20000000000000000000000000a0063450000000f")
	packetLen := 64 + 24 + len(securityBlob)
	req := make([]byte, 4+packetLen)
	req[0] = 0x00
	req[1] = byte(packetLen >> 16)
	req[2] = byte(packetLen >> 8)
	req[3] = byte(packetLen)

	off := 4
	copy(req[off:off+4], []byte{0xFE, 'S', 'M', 'B'})
	off += 4
	binary.LittleEndian.PutUint16(req[off:off+2], 64)
	off += 2
	off += 2
	off += 4
	binary.LittleEndian.PutUint16(req[off:off+2], 0x0001)
	off += 2
	binary.LittleEndian.PutUint16(req[off:off+2], 1)
	off += 2
	off += 4
	off += 4
	binary.LittleEndian.PutUint64(req[off:off+8], 1)
	off += 8
	off += 4
	off += 4
	off += 8
	off += 16

	binary.LittleEndian.PutUint16(req[off:off+2], 0x0019)
	off += 2
	req[off] = 0x00
	off++
	req[off] = 0x01
	off++
	off += 4
	off += 4
	binary.LittleEndian.PutUint16(req[off:off+2], 0x0058)
	off += 2
	binary.LittleEndian.PutUint16(req[off:off+2], uint16(len(securityBlob)))
	off += 2
	off += 8

	copy(req[off:], securityBlob)
	binary.LittleEndian.PutUint32(req[4+32:4+36], 0x0000FEFF)
	return req
}

func smb2SessionSetupAnonymousRequest() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x58,
		0xFE, 0x53, 0x4D, 0x42,
		0x40, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x19, 0x00,
		0x00,
		0x01,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x58, 0x00,
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

func parseNTLMChallengeFromSessionResponse(resp []byte) (*ntlmChallengeInfo, error) {
	blob, err := extractSMB2SecurityBlob(resp)
	if err == nil {
		if challenge, parseErr := parseNTLMChallengeInfo(blob); parseErr == nil {
			return challenge, nil
		}
	}

	return parseNTLMChallengeInfo(resp)
}

func extractSMB2SecurityBlob(resp []byte) ([]byte, error) {
	if len(resp) < 4+64+8 {
		return nil, errors.New("short_session_setup_response")
	}
	if resp[4] != 0xFE || resp[5] != 'S' || resp[6] != 'M' || resp[7] != 'B' {
		return nil, errors.New("invalid_session_setup_signature")
	}

	payload := resp[4+64:]
	if len(payload) < 8 {
		return nil, errors.New("short_session_setup_payload")
	}
	securityOffset := int(binary.LittleEndian.Uint16(payload[4:6]))
	securityLen := int(binary.LittleEndian.Uint16(payload[6:8]))
	if securityOffset <= 0 || securityLen <= 0 {
		return nil, errors.New("empty_security_blob")
	}
	start := 4 + securityOffset
	end := start + securityLen
	if start < 0 || end > len(resp) || start >= end {
		return nil, errors.New("invalid_security_blob_bounds")
	}
	return resp[start:end], nil
}

func parseNTLMChallengeInfo(blob []byte) (*ntlmChallengeInfo, error) {
	signature := []byte("NTLMSSP\x00\x02\x00\x00\x00")
	idx := bytes.Index(blob, signature)
	if idx < 0 {
		return nil, errors.New("ntlm_challenge_not_found")
	}
	msg := blob[idx:]
	if len(msg) < 48 {
		return nil, errors.New("short_ntlm_challenge")
	}

	targetNameLen := int(binary.LittleEndian.Uint16(msg[12:14]))
	targetNameOff := int(binary.LittleEndian.Uint32(msg[16:20]))
	flags := binary.LittleEndian.Uint32(msg[20:24])
	targetInfoLen := int(binary.LittleEndian.Uint16(msg[40:42]))
	targetInfoOff := int(binary.LittleEndian.Uint32(msg[44:48]))

	targetName := parseNTLMUTF16(msg, targetNameOff, targetNameLen)
	avRaw, _ := readSlice(msg, targetInfoOff, targetInfoLen)

	avPairs, serverTime := parseNTLMAVPairs(avRaw)
	info := &ntlmChallengeInfo{
		TargetName:      targetName,
		NegotiateFlags:  flags,
		AVPairs:         avPairs,
		ServerTimeUTC:   serverTime,
		NetBIOSComputer: avPairs[1],
		NetBIOSDomain:   avPairs[2],
		DNSComputer:     avPairs[3],
		DNSDomain:       avPairs[4],
	}

	if len(msg) >= 56 {
		major := int(msg[48])
		minor := int(msg[49])
		build := int(binary.LittleEndian.Uint16(msg[50:52]))
		if major > 0 {
			info.VersionPresent = (flags&ntlmNegotiateVersionFlag) != 0 || major > 0
			info.VersionMajor = major
			info.VersionMinor = minor
			info.VersionBuild = build
		}
	}
	return info, nil
}

func readSlice(buf []byte, off, n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	if off < 0 || n < 0 || off+n > len(buf) {
		return nil, errors.New("invalid_ntlm_offset")
	}
	return buf[off : off+n], nil
}

func parseNTLMUTF16(buf []byte, off, n int) string {
	data, err := readSlice(buf, off, n)
	if err != nil || len(data) == 0 {
		return ""
	}
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	return decodeUTF16LE(data)
}

func parseNTLMAVPairs(raw []byte) (map[uint16]string, string) {
	out := make(map[uint16]string)
	serverTime := ""
	for i := 0; i+4 <= len(raw); {
		avID := binary.LittleEndian.Uint16(raw[i : i+2])
		avLen := int(binary.LittleEndian.Uint16(raw[i+2 : i+4]))
		i += 4
		if avID == 0 {
			break
		}
		if i+avLen > len(raw) {
			break
		}
		value := raw[i : i+avLen]
		if avID == 7 && len(value) == 8 {
			filetime := int64(binary.LittleEndian.Uint64(value))
			unixNanos := (filetime - 116444736000000000) * 100
			if unixNanos > 0 {
				serverTime = time.Unix(0, unixNanos).UTC().Format(time.RFC3339)
			}
		} else {
			out[avID] = parseNTLMUTF16(value, 0, len(value))
		}
		i += avLen
	}
	return out, serverTime
}

func mapSMBEnumProductVersion(challenge *ntlmChallengeInfo) (string, string) {
	if challenge == nil || !challenge.VersionPresent {
		return "smb", ""
	}
	return "Microsoft Windows SMB", fmt.Sprintf("%d.%d", challenge.VersionMajor, challenge.VersionMinor)
}

func refreshConnDeadline(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = time.Second
	}
	return conn.SetDeadline(time.Now().Add(timeout))
}

func smb2StatusCode(resp []byte) uint32 {
	if len(resp) < 16 {
		return 0
	}
	return binary.LittleEndian.Uint32(resp[12:16])
}

func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	u16 := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		u16 = append(u16, binary.LittleEndian.Uint16(data[i:i+2]))
	}
	return strings.TrimSpace(string(utf16.Decode(u16)))
}

func extractSambaVersion(blob string) string {
	upper := strings.ToUpper(blob)
	idx := strings.Index(upper, "SAMBA ")
	if idx < 0 {
		return ""
	}
	start := idx + len("SAMBA ")
	if start >= len(blob) {
		return ""
	}
	end := start
	for end < len(blob) {
		ch := blob[end]
		if (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_' {
			end++
			continue
		}
		break
	}
	if end <= start {
		return ""
	}
	return blob[start:end]
}

func mapWindowsVersion(major, minor, build int) string {
	switch {
	case major == 10 && build >= 26100:
		return "Windows 11 / Server 2025 Build 26100"
	case major == 10 && build >= 22000:
		return "Windows 11 / Server 2022+"
	case major == 10 && build >= 17763:
		return "Windows 10 / Server 2019+"
	case major == 10:
		return "Windows 10 / Server 2016"
	case major == 6 && minor == 3:
		return "Windows 8.1 / Server 2012 R2"
	case major == 6 && minor == 2:
		return "Windows 8 / Server 2012"
	case major == 6 && minor == 1:
		return "Windows 7 / Server 2008 R2"
	default:
		return fmt.Sprintf("Windows %d.%d build %d", major, minor, build)
	}
}

func dialectToProtocolVersion(dialect uint16) string {
	switch {
	case dialect >= 0x0300:
		return "smb3"
	case dialect >= 0x0202:
		return "smb2+"
	default:
		return "smb1"
	}
}

func classifySMBProbeError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"), strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case strings.Contains(msg, "refused"):
		return "refused"
	case strings.Contains(msg, "ntlm_challenge_not_found"):
		return "ntlm_challenge_not_found"
	case strings.Contains(msg, "enum_not_supported_for_smb1"):
		return "enum_not_supported"
	case strings.Contains(msg, "smb2_negotiate_status"):
		return "smb2_negotiate_failed"
	case strings.Contains(msg, "invalid_smb2_dialect"):
		return "invalid_smb2_dialect"
	case strings.Contains(msg, "unexpected_smb2_command"):
		return "unexpected_smb2_command"
	case strings.Contains(msg, "session_setup_status"):
		return "session_setup_failed"
	case strings.Contains(msg, "short"):
		return "short_response"
	default:
		return "probe_failed"
	}
}

func pickTopProbeError(errors []string) string {
	if len(errors) == 0 {
		return ""
	}
	priority := []string{
		"timeout",
		"refused",
		"unexpected_smb2_command",
		"smb2_negotiate_failed",
		"invalid_smb2_dialect",
		"short_response",
		"ntlm_challenge_not_found",
		"session_setup_failed",
		"probe_failed",
	}
	for _, p := range priority {
		if slices.Contains(errors, p) {
			return p
		}
	}
	return errors[len(errors)-1]
}

func readSMBFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(header))
	if length <= 0 || length > 1<<20 {
		return nil, fmt.Errorf("invalid_frame_length")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	out := make([]byte, 4+length)
	copy(out[:4], header)
	copy(out[4:], payload)
	return out, nil
}

func buildNTLMType1Token() []byte {
	flags := uint32(0x00000001 |
		0x00000004 |
		0x00000200 |
		0x00008000 |
		0x00080000 |
		0x00800000 |
		0x02000000 |
		0x20000000 |
		0x80000000)

	msg := make([]byte, 40)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 1)
	binary.LittleEndian.PutUint32(msg[12:16], flags)
	msg[32] = 10
	msg[33] = 0
	binary.LittleEndian.PutUint16(msg[34:36], 19045)
	msg[39] = 15
	return msg
}

func writeNetBIOSSessionRequest(conn net.Conn) error {
	req := []byte{0x81, 0x00, 0x00, 0x44}
	req = append(req, []byte(" CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")...)
	req = append(req, []byte(" EHEPFCELEHFCEPFFFACACACACACACACA")...)
	_, err := conn.Write(req)
	return err
}

func readAndValidateNetBIOSSessionResponse(conn net.Conn) error {
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x82 {
		return fmt.Errorf("netbios_session_rejected")
	}
	return nil
}

func mustDecodeHex(input string) []byte {
	decoded, err := hex.DecodeString(input)
	if err != nil {
		panic(fmt.Sprintf("invalid hex payload: %v", err))
	}
	return decoded
}

func smbNativeProbeModuleFactory() engine.Module {
	return newSMBNativeProbeModule()
}

func init() {
	engine.RegisterModuleFactory(smbNativeProbeModuleName, smbNativeProbeModuleFactory)
	log.Debug().Str("module", smbNativeProbeModuleName).Msg("SMB native probe module registered")
}
