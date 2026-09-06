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

// The IPMI native probe asks a BMC on UDP/623 who it is and how weakly it is
// configured. It sends two requests and reads the replies:
//
//  1. IPMI v1.5 "Get Channel Authentication Capabilities" — identifies the host
//     as a BMC and reports the authentication types it supports plus the
//     anonymous/null-user and per-message/user-level authentication flags.
//  2. IPMI v2.0 RMCP+ "Open Session Request" with a real cipher suite —
//     establishes whether the BMC actually speaks IPMI 2.0 RMCP+ *by its
//     response*, not by the capability bit, which can disagree with behavior.
//
// A BMC that answers the v2.0 Open Session Request implements RMCP+ RAKP and is
// therefore subject to the pre-authentication RAKP message-2 HMAC disclosure
// (CVE-2013-4786). This probe reports that exposure; it does not itself request
// a RAKP message to extract a hash.
const (
	ipmiNativeProbeModuleID          = "ipmi-native-probe-instance"
	ipmiNativeProbeModuleName        = "ipmi-native-probe"
	ipmiNativeProbeModuleDescription = "Runs bounded native IPMI/RMCP probes against UDP/623 and reports BMC identity and weak authentication configuration."

	ipmiPort = 623

	// RMCP header: version 0x06, reserved 0x00, sequence 0xff (no ACK),
	// class 0x07 (IPMI).
	rmcpVersion1   = 0x06
	rmcpSeqNoACK   = 0xff
	rmcpClassIPMI  = 0x07
	rmcpAuthTypeNo = 0x00 // IPMI v1.5 session header authentication type: none

	// IPMI message framing (Get Channel Authentication Capabilities request).
	ipmiBMCAddress            = 0x20      // responder address (the BMC)
	ipmiNetFnAppRequest       = 0x06 << 2 // App network function, request, LUN 0
	ipmiRemoteConsoleAddr     = 0x81      // requester address (remote console software id)
	ipmiRequesterSeq          = 0x01 << 2 // requester sequence 1, LUN 0
	ipmiCmdGetChannelAuthCaps = 0x38      // Get Channel Authentication Capabilities
	ipmiCurrentChannel        = 0x0e      // "the channel this request arrived on"
	ipmiGet20ExtDataBit       = 0x80      // channel byte bit 7: request IPMI v2.0 extended data
	ipmiPrivAdministrator     = 0x04      // requested maximum privilege level: administrator

	// RMCP+ session header (Open Session Request/Response).
	rmcpPlusAuthFormat             = 0x06 // authentication type/format byte: RMCP+
	rmcpPlusPayloadOpenSessionReq  = 0x10 // payload type: RMCP+ Open Session Request
	rmcpPlusPayloadOpenSessionResp = 0x11 // payload type: RMCP+ Open Session Response

	// Cipher suite 3: RAKP-HMAC-SHA1 authentication, HMAC-SHA1-96 integrity,
	// AES-CBC-128 confidentiality. Offered so the BMC has a real suite to accept
	// or reject; an all-zero offer is rejected with "no matching cipher suite".
	ipmiCipherSuite3     = 3
	ipmiAuthAlgHMACSHA1  = 0x01
	ipmiIntegAlgHMACSHA1 = 0x01
	ipmiConfAlgAESCBC128 = 0x01

	// A fixed remote-console session id for the Open Session Request; the BMC
	// echoes it in the response.
	ipmiConsoleSessionID uint32 = 0xa4a3a2a0

	defaultIPMITotalTimeout           = 2 * time.Second
	defaultIPMIPerAttemptTimeout      = 700 * time.Millisecond
	ipmiReadBufferSize                = 512
	getChannelAuthCapResponseMinLen   = 24 // through the authentication-status byte
	rmcpPlusOpenSessionResponseMinLen = 18 // through the status-code byte
	getChannelAuthCapCompletionOK     = 0x00
)

// IPMIProbeOptions bounds a single probe attempt.
type IPMIProbeOptions struct {
	TotalTimeout      time.Duration `json:"total_timeout"`
	PerAttemptTimeout time.Duration `json:"per_attempt_timeout"`
}

func defaultIPMIProbeOptions() IPMIProbeOptions {
	return IPMIProbeOptions{
		TotalTimeout:      defaultIPMITotalTimeout,
		PerAttemptTimeout: defaultIPMIPerAttemptTimeout,
	}
}

type ipmiProbeCandidate struct {
	target string
	port   int
}

// IPMIServiceInfo is the structured result of probing one BMC.
type IPMIServiceInfo struct {
	Target    string `json:"target"`
	Port      int    `json:"port"`
	IPMIProbe bool   `json:"ipmi_probe"` // a well-formed IPMI response was received (host runs a BMC)

	// Get Channel Authentication Capabilities (identity).
	ChannelAuthReceived bool `json:"channel_auth_received"`
	Channel             int  `json:"channel,omitempty"`

	// Authentication types the channel supports (auth-type-support byte).
	AuthTypeNone     bool `json:"auth_type_none"`
	AuthTypeMD2      bool `json:"auth_type_md2"`
	AuthTypeMD5      bool `json:"auth_type_md5"`
	AuthTypePassword bool `json:"auth_type_password"`
	AuthTypeOEM      bool `json:"auth_type_oem"`

	// IPMI 2.0 support as the device *claims* it (capability byte bit 7).
	IPMI20Claimed bool `json:"ipmi_2_0_claimed"`

	// Authentication status flags.
	AnonymousLoginEnabled  bool `json:"anonymous_login_enabled"`
	NullUserEnabled        bool `json:"null_user_enabled"`
	NonNullUserEnabled     bool `json:"non_null_user_enabled"`
	UserLevelAuthDisabled  bool `json:"user_level_auth_disabled"`
	PerMessageAuthDisabled bool `json:"per_message_auth_disabled"`
	KGDefault              bool `json:"kg_default"`

	// RMCP+ Open Session (behavioral IPMI 2.0 confirmation).
	OpenSessionAttempted bool `json:"open_session_attempted"`
	OpenSessionResponded bool `json:"open_session_responded"` // a valid Open Session Response arrived
	OpenSessionStatus    int  `json:"open_session_status"`    // status code from the response
	CipherSuiteOffered   int  `json:"cipher_suite_offered,omitempty"`

	// IPMI 2.0 support as the device *behaves*: it answered a v2.0 Open Session
	// Request with a v2.0 Open Session Response, independent of the claim byte.
	IPMI20Confirmed bool `json:"ipmi_2_0_confirmed"`

	// The device claimed no 2.0 support yet answered a 2.0 request. The
	// capability byte is a claim, the response is behavior, and they disagree.
	AuthClaimBehaviorMismatch bool `json:"auth_claim_behavior_mismatch"`

	// Machine-readable weak-configuration findings.
	Findings []string `json:"findings,omitempty"`

	// Raw bytes for audit and downstream re-derivation.
	AuthTypeSupportByte int `json:"auth_type_support_byte,omitempty"`
	AuthStatusByte      int `json:"auth_status_byte,omitempty"`

	DurationMS int64  `json:"duration_ms"`
	ErrorClass string `json:"error_class,omitempty"`
}

// Finding slugs.
const (
	ipmiFindingAnonymousLogin        = "anonymous_login_enabled"
	ipmiFindingNullUser              = "null_user_enabled"
	ipmiFindingUserLevelAuthDisabled = "user_level_auth_disabled"
	ipmiFindingPerMessageAuthOff     = "per_message_auth_disabled"
	ipmiFindingRAKPHashDisclosure    = "ipmi_2_0_rakp_hash_disclosure"    // CVE-2013-4786 exposure
	ipmiFindingClaimBehaviorMismatch = "ipmi_2_0_claim_behavior_mismatch" // capability byte disagrees with behavior
)

type ipmiNativeProbeModule struct {
	meta    engine.ModuleMetadata
	options IPMIProbeOptions
}

// probeIPMIDetailsFunc is a test seam so Execute can be exercised without a
// network.
var probeIPMIDetailsFunc = probeIPMIDetails

func newIPMINativeProbeModule() *ipmiNativeProbeModule {
	return &ipmiNativeProbeModule{
		meta: engine.ModuleMetadata{
			ID:          ipmiNativeProbeModuleID,
			Name:        ipmiNativeProbeModuleName,
			Description: ipmiNativeProbeModuleDescription,
			Version:     "0.1.0",
			Type:        engine.ScanModuleType,
			Author:      nativeProbeModuleAuthor,
			Tags:        []string{"scan", "ipmi", "bmc", "udp", "native_probe", "enrichment"},
			Consumes: []engine.DataContractEntry{
				{
					Key:          "discovery.open_udp_ports",
					DataTypeName: "discovery.UDPPortDiscoveryResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   false,
					Description:  "Open UDP ports used to identify IPMI/BMC candidates on port 623.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key:          "service.ipmi.details",
					DataTypeName: "scan.IPMIServiceInfo",
					Cardinality:  engine.CardinalityList,
					Description:  "Structured IPMI/BMC native probe output per target and port.",
				},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				"timeout": {
					Description: "Total timeout budget per target (e.g. 2s).",
					Type:        "duration",
					Required:    false,
					Default:     "2s",
				},
				"per_attempt_timeout": {
					Description: "Timeout per IPMI request/response exchange.",
					Type:        "duration",
					Required:    false,
					Default:     "700ms",
				},
			},
		},
		options: defaultIPMIProbeOptions(),
	}
}

func (m *ipmiNativeProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *ipmiNativeProbeModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	opts := defaultIPMIProbeOptions()
	if configMap != nil {
		if d, ok := parseDurationConfig(configMap["timeout"]); ok && d > 0 {
			opts.TotalTimeout = d
		}
		if d, ok := parseDurationConfig(configMap["per_attempt_timeout"]); ok && d > 0 {
			opts.PerAttemptTimeout = d
		}
	}
	m.options = opts
	return nil
}

func (m *ipmiNativeProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	rawOpenPorts, ok := inputs["discovery.open_udp_ports"]
	if !ok {
		return nil
	}

	candidateMap := map[string]ipmiProbeCandidate{}
	for _, item := range toAnySlice(rawOpenPorts) {
		for _, candidate := range ipmiCandidatesFromOpenPorts(item) {
			candidateMap[ipmiCandidateKey(candidate)] = candidate
		}
	}
	if len(candidateMap) == 0 {
		return nil
	}

	keys := make([]string, 0, len(candidateMap))
	for key := range candidateMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		candidate := candidateMap[key]
		result := probeIPMIDetailsFunc(ctx, candidate.target, candidate.port, m.options)
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "service.ipmi.details",
			Data:           result,
			Timestamp:      time.Now(),
			Target:         candidate.target,
		}
	}
	return nil
}

func ipmiCandidatesFromOpenPorts(item any) []ipmiProbeCandidate {
	candidates := make([]ipmiProbeCandidate, 0, 1)
	appendCandidate := func(target string, port int) {
		target = strings.TrimSpace(target)
		if target == "" || port != ipmiPort {
			return
		}
		candidates = append(candidates, ipmiProbeCandidate{target: target, port: port})
	}

	switch v := item.(type) {
	case discovery.UDPPortDiscoveryResult:
		for _, port := range v.OpenPorts {
			appendCandidate(v.Target, port)
		}
	case map[string]any:
		target := getMapString(v, "target", "Target")
		switch ports := v["open_ports"].(type) {
		case []int:
			for _, port := range ports {
				appendCandidate(target, port)
			}
		case []any:
			for _, entry := range ports {
				switch port := entry.(type) {
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

func ipmiCandidateKey(candidate ipmiProbeCandidate) string {
	return fmt.Sprintf("%s:%d", candidate.target, candidate.port)
}

// probeIPMIDetails sends the two IPMI requests to one target and returns what it
// learned. It never returns an error; failures are recorded in ErrorClass.
func probeIPMIDetails(ctx context.Context, target string, port int, opts IPMIProbeOptions) IPMIServiceInfo {
	info := IPMIServiceInfo{Target: target, Port: port, CipherSuiteOffered: ipmiCipherSuite3}
	start := time.Now()
	finish := func() IPMIServiceInfo {
		info.DurationMS = time.Since(start).Milliseconds()
		return info
	}

	if port <= 0 {
		info.ErrorClass = "invalid_port"
		return finish()
	}

	perAttempt := opts.PerAttemptTimeout
	if perAttempt <= 0 {
		perAttempt = defaultIPMIPerAttemptTimeout
	}
	total := opts.TotalTimeout
	if total <= 0 {
		total = defaultIPMITotalTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, total)
	defer cancel()

	dialer := net.Dialer{Timeout: perAttempt}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(target, strconv.Itoa(port)))
	if err != nil {
		info.ErrorClass = "dial_error"
		return finish()
	}
	defer func() { _ = conn.Close() }()

	// Phase 1: Get Channel Authentication Capabilities. A non-response here is
	// not fatal — a single lost datagram (measured against a real BMC over a
	// warming-up tunnel) must not hide a host whose RMCP+ path still answers, so
	// phase 2 runs regardless.
	authReq := buildGetChannelAuthCapRequest(ipmiPrivAdministrator, true)
	authResp, authErr := ipmiExchange(ctx, conn, authReq, perAttempt)
	if authErr == nil {
		if caps, ok := parseGetChannelAuthCapResponse(authResp); ok {
			info.IPMIProbe = true
			info.ChannelAuthReceived = true
			applyAuthCaps(&info, caps)
		}
	}

	// Phase 2: RMCP+ Open Session Request (behavioral IPMI 2.0 check).
	info.OpenSessionAttempted = true
	openReq := buildOpenSessionRequest(ipmiConsoleSessionID, ipmiAuthAlgHMACSHA1, ipmiIntegAlgHMACSHA1, ipmiConfAlgAESCBC128)
	openResp, openErr := ipmiExchange(ctx, conn, openReq, perAttempt)
	if openErr == nil {
		if status, respOK := parseOpenSessionResponse(openResp); respOK {
			info.OpenSessionResponded = true
			info.OpenSessionStatus = status
			// Any well-formed Open Session Response proves the BMC processes
			// RMCP+, regardless of whether it accepted the offered cipher suite.
			info.IPMI20Confirmed = true
			info.IPMIProbe = true
		}
	}

	if !info.IPMIProbe {
		if authErr != nil && openErr != nil {
			info.ErrorClass = classifyIPMIError(authErr)
		} else {
			// Bytes came back but neither phase parsed as IPMI.
			info.ErrorClass = "decode_error"
		}
		return finish()
	}

	deriveIPMIFindings(&info)
	return finish()
}

// getChannelAuthCaps holds the decoded fields of a Get Channel Authentication
// Capabilities response.
type getChannelAuthCaps struct {
	channel           int
	authTypeSupport   byte
	authStatus        byte
	ipmi20Claimed     bool
	authTypeNone      bool
	authTypeMD2       bool
	authTypeMD5       bool
	authTypePassword  bool
	authTypeOEM       bool
	anonymousLogin    bool
	nullUser          bool
	nonNullUser       bool
	userLevelAuthOff  bool
	perMessageAuthOff bool
	kgDefault         bool
}

func applyAuthCaps(info *IPMIServiceInfo, caps getChannelAuthCaps) {
	info.Channel = caps.channel
	info.AuthTypeSupportByte = int(caps.authTypeSupport)
	info.AuthStatusByte = int(caps.authStatus)
	info.IPMI20Claimed = caps.ipmi20Claimed
	info.AuthTypeNone = caps.authTypeNone
	info.AuthTypeMD2 = caps.authTypeMD2
	info.AuthTypeMD5 = caps.authTypeMD5
	info.AuthTypePassword = caps.authTypePassword
	info.AuthTypeOEM = caps.authTypeOEM
	info.AnonymousLoginEnabled = caps.anonymousLogin
	info.NullUserEnabled = caps.nullUser
	info.NonNullUserEnabled = caps.nonNullUser
	info.UserLevelAuthDisabled = caps.userLevelAuthOff
	info.PerMessageAuthDisabled = caps.perMessageAuthOff
	info.KGDefault = caps.kgDefault
}

func deriveIPMIFindings(info *IPMIServiceInfo) {
	findings := make([]string, 0, 4)
	if info.AnonymousLoginEnabled {
		findings = append(findings, ipmiFindingAnonymousLogin)
	}
	if info.NullUserEnabled {
		findings = append(findings, ipmiFindingNullUser)
	}
	if info.UserLevelAuthDisabled {
		findings = append(findings, ipmiFindingUserLevelAuthDisabled)
	}
	if info.PerMessageAuthDisabled {
		findings = append(findings, ipmiFindingPerMessageAuthOff)
	}
	if info.IPMI20Confirmed {
		findings = append(findings, ipmiFindingRAKPHashDisclosure)
		if !info.IPMI20Claimed {
			info.AuthClaimBehaviorMismatch = true
			findings = append(findings, ipmiFindingClaimBehaviorMismatch)
		}
	}
	if len(findings) > 0 {
		info.Findings = findings
	}
}

// buildGetChannelAuthCapRequest builds the IPMI v1.5 Get Channel Authentication
// Capabilities request. When request20 is set, bit 7 of the channel byte asks
// the BMC to include IPMI v2.0 extended capabilities in its reply.
func buildGetChannelAuthCapRequest(privLevel byte, request20 bool) []byte {
	channel := byte(ipmiCurrentChannel)
	if request20 {
		channel |= ipmiGet20ExtDataBit
	}

	// IPMI message body.
	rsAddr := byte(ipmiBMCAddress)
	netFnLUN := byte(ipmiNetFnAppRequest)
	chk1 := ipmiChecksum(rsAddr, netFnLUN)
	rqAddr := byte(ipmiRemoteConsoleAddr)
	rqSeqLUN := byte(ipmiRequesterSeq)
	cmd := byte(ipmiCmdGetChannelAuthCaps)
	chk2 := ipmiChecksum(rqAddr, rqSeqLUN, cmd, channel, privLevel)
	msg := []byte{rsAddr, netFnLUN, chk1, rqAddr, rqSeqLUN, cmd, channel, privLevel, chk2}

	// RMCP header + IPMI v1.5 session header + message length.
	packet := []byte{
		rmcpVersion1, 0x00, rmcpSeqNoACK, rmcpClassIPMI,
		rmcpAuthTypeNo,         // session authentication type: none
		0x00, 0x00, 0x00, 0x00, // session sequence number
		0x00, 0x00, 0x00, 0x00, // session id
		byte(len(msg)), // IPMI message length
	}
	return append(packet, msg...)
}

// buildOpenSessionRequest builds an IPMI v2.0 RMCP+ Open Session Request that
// offers one authentication, integrity and confidentiality algorithm.
func buildOpenSessionRequest(consoleSessionID uint32, authAlg, integAlg, confAlg byte) []byte {
	payload := make([]byte, 0, 32)
	payload = append(payload, 0x00)       // message tag
	payload = append(payload, 0x00)       // requested maximum privilege level: highest available
	payload = append(payload, 0x00, 0x00) // reserved

	sessionID := make([]byte, 4)
	binary.LittleEndian.PutUint32(sessionID, consoleSessionID)
	payload = append(payload, sessionID...) // remote console session id

	// Authentication algorithm payload (type 0x00).
	payload = append(payload, 0x00, 0x00, 0x00, 0x08, authAlg, 0x00, 0x00, 0x00)
	// Integrity algorithm payload (type 0x01).
	payload = append(payload, 0x01, 0x00, 0x00, 0x08, integAlg, 0x00, 0x00, 0x00)
	// Confidentiality algorithm payload (type 0x02).
	payload = append(payload, 0x02, 0x00, 0x00, 0x08, confAlg, 0x00, 0x00, 0x00)

	payloadLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(payloadLen, uint16(len(payload)))

	header := []byte{
		rmcpVersion1, 0x00, rmcpSeqNoACK, rmcpClassIPMI,
		rmcpPlusAuthFormat,            // authentication type/format: RMCP+
		rmcpPlusPayloadOpenSessionReq, // payload type: Open Session Request
		0x00, 0x00, 0x00, 0x00,        // session id
		0x00, 0x00, 0x00, 0x00, // session sequence number
		payloadLen[0], payloadLen[1], // payload length (little endian)
	}
	return append(header, payload...)
}

// ipmiChecksum returns the IPMI two's-complement checksum of the given bytes.
func ipmiChecksum(bytes ...byte) byte {
	var sum byte
	for _, b := range bytes {
		sum += b
	}
	return byte(-int8(sum))
}

// parseGetChannelAuthCapResponse decodes a Get Channel Authentication
// Capabilities response. Byte offsets follow the RMCP/IPMI framing: the
// completion code is at offset 20, and the response data field (channel,
// authentication-type-support byte, authentication-status byte) begins at 21.
func parseGetChannelAuthCapResponse(data []byte) (getChannelAuthCaps, bool) {
	var caps getChannelAuthCaps
	if len(data) < getChannelAuthCapResponseMinLen {
		return caps, false
	}
	if data[0] != rmcpVersion1 || data[3] != rmcpClassIPMI {
		return caps, false
	}
	if data[20] != getChannelAuthCapCompletionOK {
		return caps, false
	}

	caps.channel = int(data[21] & 0x0f)
	authSupport := data[22]
	authStatus := data[23]
	caps.authTypeSupport = authSupport
	caps.authStatus = authStatus

	caps.authTypeNone = authSupport&(1<<0) != 0
	caps.authTypeMD2 = authSupport&(1<<1) != 0
	caps.authTypeMD5 = authSupport&(1<<2) != 0
	caps.authTypePassword = authSupport&(1<<4) != 0
	caps.authTypeOEM = authSupport&(1<<5) != 0
	caps.ipmi20Claimed = authSupport&(1<<7) != 0

	caps.anonymousLogin = authStatus&(1<<0) != 0
	caps.nullUser = authStatus&(1<<1) != 0
	caps.nonNullUser = authStatus&(1<<2) != 0
	caps.userLevelAuthOff = authStatus&(1<<3) != 0
	caps.perMessageAuthOff = authStatus&(1<<4) != 0
	caps.kgDefault = authStatus&(1<<5) != 0

	return caps, true
}

// parseOpenSessionResponse decodes an RMCP+ Open Session Response and returns
// its status code. The second return value is false unless the packet is a
// well-formed Open Session Response (payload type 0x11), which is the
// behavioral proof that the BMC speaks IPMI 2.0 RMCP+.
func parseOpenSessionResponse(data []byte) (int, bool) {
	if len(data) < rmcpPlusOpenSessionResponseMinLen {
		return 0, false
	}
	if data[0] != rmcpVersion1 || data[3] != rmcpClassIPMI {
		return 0, false
	}
	if data[4] != rmcpPlusAuthFormat || data[5] != rmcpPlusPayloadOpenSessionResp {
		return 0, false
	}
	// Payload: byte 0 = message tag, byte 1 = status code. The payload begins
	// after the 16-byte RMCP+ session header.
	status := int(data[17])
	return status, true
}

func ipmiExchange(ctx context.Context, conn net.Conn, request []byte, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	buf := make([]byte, ipmiReadBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func classifyIPMIError(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "no_response"
}

func init() {
	engine.RegisterModuleFactory(ipmiNativeProbeModuleName, func() engine.Module {
		return newIPMINativeProbeModule()
	})
}
