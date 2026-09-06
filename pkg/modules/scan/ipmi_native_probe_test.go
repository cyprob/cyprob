package scan

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"github.com/stretchr/testify/require"
)

// Captured against a real BMC (192.168.0.43). These are the ground truth the
// builders and parsers are checked against.
var (
	// IPMI v1.5 Get Channel Authentication Capabilities request, channel byte
	// 0x0e (no v2.0 extended-data bit). This is byte-for-byte the field-tested
	// discovery payload shipped in cyprob#292.
	capturedGetAuthCapRequest15 = []byte{
		0x06, 0x00, 0xff, 0x07,
		0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x09,
		0x20, 0x18, 0xc8, 0x81, 0x04, 0x38, 0x0e, 0x04, 0x31,
	}

	// The BMC's response to that request.
	capturedGetAuthCapResponse = []byte{
		0x06, 0x00, 0xff, 0x07,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10,
		0x81, 0x1c, 0x63, 0x20, 0x04, 0x38,
		0x00, // completion code
		0x01, // channel
		0x14, // authentication type support: MD5 + straight password, bit7 (2.0) clear
		0x04, // authentication status: non-null users enabled
		0x00, 0x00, 0x00, 0x00, 0x00, 0x8b,
	}

	// RMCP+ Open Session Request offering an all-zero cipher suite, remote
	// console session id 0xa4a3a2a0. The BMC parsed the algorithm payloads and
	// rejected the suite, which is what makes it a field-validated framing.
	capturedOpenSessionRequestZero = []byte{
		0x06, 0x00, 0xff, 0x07,
		0x06, 0x10,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x20, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xa0, 0xa2, 0xa3, 0xa4,
		0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
	}

	// The BMC's Open Session Response: status 0x11 "no matching cipher suite".
	capturedOpenSessionResponse = []byte{
		0x06, 0x00, 0xff, 0x07,
		0x06, 0x11,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x08, 0x00,
		0x00, 0x11, 0x00, 0x00,
		0xa0, 0xa2, 0xa3, 0xa4,
	}
)

// twosComplementChecksum is an independent reimplementation of the IPMI
// checksum, deliberately not the production one, so the framing tests verify a
// value rather than restate the production computation.
func twosComplementChecksum(b []byte) byte {
	var sum int
	for _, x := range b {
		sum += int(x)
	}
	return byte((0x100 - (sum & 0xff)) & 0xff)
}

func TestBuildGetChannelAuthCapRequest_ReproducesFieldPayload(t *testing.T) {
	// request20=false must reproduce the field-tested discovery payload exactly.
	got := buildGetChannelAuthCapRequest(ipmiPrivAdministrator, false)
	require.Equal(t, capturedGetAuthCapRequest15, got)
}

func TestBuildGetChannelAuthCapRequest_Requesting20IsWellFormed(t *testing.T) {
	got := buildGetChannelAuthCapRequest(ipmiPrivAdministrator, true)

	// The v2.0 extended-data bit must be set on the channel byte.
	channelByte := got[20]
	require.Equal(t, byte(0x8e), channelByte, "0x80 (get v2.0 extended data) | 0x0e (current channel)")
	require.NotZero(t, channelByte&0x80, "bit 7 must ask for v2.0 extended data")

	// Declared message length is the number of IPMI message bytes that follow.
	require.Equal(t, byte(len(got)-14), got[13])

	// Checksum 1 covers rsAddr + netFn/LUN (bytes 14..15).
	require.Equal(t, twosComplementChecksum(got[14:16]), got[16], "checksum 1")
	// Checksum 2 covers rqAddr..data (bytes 17..end-1).
	require.Equal(t, twosComplementChecksum(got[17:len(got)-1]), got[len(got)-1], "checksum 2")

	// The privilege level byte is carried verbatim.
	require.Equal(t, byte(0x04), got[21], "privilege level: administrator")
}

func TestBuildOpenSessionRequest_ReproducesCapturedFraming(t *testing.T) {
	got := buildOpenSessionRequest(ipmiConsoleSessionID, 0x00, 0x00, 0x00)
	require.Equal(t, capturedOpenSessionRequestZero, got)
}

func TestBuildOpenSessionRequest_CipherSuite3(t *testing.T) {
	got := buildOpenSessionRequest(ipmiConsoleSessionID, ipmiAuthAlgHMACSHA1, ipmiIntegAlgHMACSHA1, ipmiConfAlgAESCBC128)

	require.Len(t, got, 48)
	require.Equal(t, byte(0x06), got[4], "RMCP+ authentication format")
	require.Equal(t, byte(0x10), got[5], "payload type: Open Session Request")
	// Payload length (little endian) is 32.
	require.Equal(t, byte(0x20), got[14])
	require.Equal(t, byte(0x00), got[15])

	// The three algorithm numbers land in their payload records.
	require.Equal(t, byte(0x01), got[28], "cipher suite 3 authentication algorithm: RAKP-HMAC-SHA1")
	require.Equal(t, byte(0x01), got[36], "cipher suite 3 integrity algorithm: HMAC-SHA1-96")
	require.Equal(t, byte(0x01), got[44], "cipher suite 3 confidentiality algorithm: AES-CBC-128")

	// Payload record type bytes.
	require.Equal(t, byte(0x00), got[24], "authentication payload type")
	require.Equal(t, byte(0x01), got[32], "integrity payload type")
	require.Equal(t, byte(0x02), got[40], "confidentiality payload type")
}

func TestParseGetChannelAuthCapResponse_DecodesRealBMC(t *testing.T) {
	caps, ok := parseGetChannelAuthCapResponse(capturedGetAuthCapResponse)
	require.True(t, ok)

	require.Equal(t, 1, caps.channel)
	require.Equal(t, byte(0x14), caps.authTypeSupport)
	require.Equal(t, byte(0x04), caps.authStatus)

	require.True(t, caps.authTypeMD5)
	require.True(t, caps.authTypePassword)
	require.False(t, caps.authTypeNone)
	require.False(t, caps.authTypeMD2)
	require.False(t, caps.authTypeOEM)
	require.False(t, caps.ipmi20Claimed, "capability byte bit 7 is clear")

	require.True(t, caps.nonNullUser)
	require.False(t, caps.anonymousLogin)
	require.False(t, caps.nullUser)
	require.False(t, caps.userLevelAuthOff)
	require.False(t, caps.perMessageAuthOff)
	require.False(t, caps.kgDefault)
}

func TestParseGetChannelAuthCapResponse_Rejects(t *testing.T) {
	// Too short.
	_, ok := parseGetChannelAuthCapResponse([]byte{0x06, 0x00, 0xff, 0x07})
	require.False(t, ok)

	// Non-zero completion code.
	bad := append([]byte(nil), capturedGetAuthCapResponse...)
	bad[20] = 0xc1
	_, ok = parseGetChannelAuthCapResponse(bad)
	require.False(t, ok)

	// Wrong RMCP class.
	bad = append([]byte(nil), capturedGetAuthCapResponse...)
	bad[3] = 0x06
	_, ok = parseGetChannelAuthCapResponse(bad)
	require.False(t, ok)
}

func TestParseGetChannelAuthCapResponse_DecodesWeakFlags(t *testing.T) {
	// Synthesize a response with anonymous login + null user + user-level auth
	// disabled + IPMI 2.0 claimed, to exercise every bit.
	weak := append([]byte(nil), capturedGetAuthCapResponse...)
	weak[22] = 0x94 // bit7 (2.0) + bit4 (password) + bit2 (MD5)
	weak[23] = 0x0b // bit0 anon + bit1 null + bit3 user-level-auth-disabled

	caps, ok := parseGetChannelAuthCapResponse(weak)
	require.True(t, ok)
	require.True(t, caps.ipmi20Claimed)
	require.True(t, caps.anonymousLogin)
	require.True(t, caps.nullUser)
	require.False(t, caps.nonNullUser)
	require.True(t, caps.userLevelAuthOff)
	require.False(t, caps.perMessageAuthOff)
}

func TestParseOpenSessionResponse_DecodesRealBMC(t *testing.T) {
	status, ok := parseOpenSessionResponse(capturedOpenSessionResponse)
	require.True(t, ok, "a payload-type 0x11 response is the behavioral 2.0 proof")
	require.Equal(t, 0x11, status, "status 0x11: no matching cipher suite")
}

func TestParseOpenSessionResponse_Rejects(t *testing.T) {
	// Too short.
	_, ok := parseOpenSessionResponse([]byte{0x06, 0x00, 0xff, 0x07})
	require.False(t, ok)

	// Wrong payload type (not an Open Session Response).
	bad := append([]byte(nil), capturedOpenSessionResponse...)
	bad[5] = 0x13 // RAKP Message 1
	_, ok = parseOpenSessionResponse(bad)
	require.False(t, ok)

	// Wrong authentication format byte.
	bad = append([]byte(nil), capturedOpenSessionResponse...)
	bad[4] = 0x00
	_, ok = parseOpenSessionResponse(bad)
	require.False(t, ok)
}

func TestDeriveIPMIFindings(t *testing.T) {
	tests := []struct {
		name         string
		info         IPMIServiceInfo
		wantFindings []string
		wantMismatch bool
	}{
		{
			name: "clean bmc, 2.0 confirmed and claimed",
			info: IPMIServiceInfo{
				IPMI20Confirmed: true,
				IPMI20Claimed:   true,
			},
			wantFindings: []string{ipmiFindingRAKPHashDisclosure},
			wantMismatch: false,
		},
		{
			name: "2.0 confirmed but claim byte says no 2.0",
			info: IPMIServiceInfo{
				IPMI20Confirmed: true,
				IPMI20Claimed:   false,
			},
			wantFindings: []string{ipmiFindingRAKPHashDisclosure, ipmiFindingClaimBehaviorMismatch},
			wantMismatch: true,
		},
		{
			name: "anonymous and null login enabled, no 2.0",
			info: IPMIServiceInfo{
				AnonymousLoginEnabled: true,
				NullUserEnabled:       true,
			},
			wantFindings: []string{ipmiFindingAnonymousLogin, ipmiFindingNullUser},
			wantMismatch: false,
		},
		{
			name: "auth disabled flags",
			info: IPMIServiceInfo{
				UserLevelAuthDisabled:  true,
				PerMessageAuthDisabled: true,
			},
			wantFindings: []string{ipmiFindingUserLevelAuthDisabled, ipmiFindingPerMessageAuthOff},
			wantMismatch: false,
		},
		{
			name:         "nothing weak",
			info:         IPMIServiceInfo{NonNullUserEnabled: true},
			wantFindings: nil,
			wantMismatch: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info := tc.info
			deriveIPMIFindings(&info)
			require.Equal(t, tc.wantFindings, info.Findings)
			require.Equal(t, tc.wantMismatch, info.AuthClaimBehaviorMismatch)
		})
	}
}

func TestIPMICandidatesFromOpenPorts(t *testing.T) {
	// Struct form: only 623 is selected.
	got := ipmiCandidatesFromOpenPorts(discovery.UDPPortDiscoveryResult{
		Target:    "192.0.2.7",
		OpenPorts: []int{161, 623, 5353},
	})
	require.Len(t, got, 1)
	require.Equal(t, "192.0.2.7", got[0].target)
	require.Equal(t, ipmiPort, got[0].port)

	// Map form.
	got = ipmiCandidatesFromOpenPorts(map[string]any{
		"target":     "192.0.2.8",
		"open_ports": []any{float64(623), float64(123)},
	})
	require.Len(t, got, 1)
	require.Equal(t, "192.0.2.8", got[0].target)

	// No 623.
	got = ipmiCandidatesFromOpenPorts(discovery.UDPPortDiscoveryResult{
		Target:    "192.0.2.9",
		OpenPorts: []int{161},
	})
	require.Empty(t, got)
}

func TestIPMINativeProbeModuleExecuteEmitsDetails(t *testing.T) {
	module := newIPMINativeProbeModule()
	require.NoError(t, module.Init("test-ipmi-native-probe", map[string]any{
		"timeout":             "2s",
		"per_attempt_timeout": "700ms",
	}))

	original := probeIPMIDetailsFunc
	probeIPMIDetailsFunc = func(ctx context.Context, target string, port int, opts IPMIProbeOptions) IPMIServiceInfo {
		return IPMIServiceInfo{
			Target:          target,
			Port:            port,
			IPMIProbe:       true,
			IPMI20Confirmed: true,
			Findings:        []string{ipmiFindingRAKPHashDisclosure},
		}
	}
	defer func() { probeIPMIDetailsFunc = original }()

	outputChan := make(chan engine.ModuleOutput, 8)
	err := module.Execute(context.Background(), map[string]any{
		"discovery.open_udp_ports": []any{
			discovery.UDPPortDiscoveryResult{Target: "192.0.2.50", OpenPorts: []int{623}},
		},
	}, outputChan)
	require.NoError(t, err)
	close(outputChan)

	var details []IPMIServiceInfo
	for item := range outputChan {
		if item.DataKey == "service.ipmi.details" {
			detail, ok := item.Data.(IPMIServiceInfo)
			require.True(t, ok)
			details = append(details, detail)
		}
	}
	require.Len(t, details, 1)
	require.True(t, details[0].IPMIProbe)
	require.Equal(t, "192.0.2.50", details[0].Target)
	require.Contains(t, details[0].Findings, ipmiFindingRAKPHashDisclosure)
}

func TestIPMINativeProbeModuleExecuteNoCandidates(t *testing.T) {
	module := newIPMINativeProbeModule()
	require.NoError(t, module.Init("test-ipmi-native-probe", nil))

	outputChan := make(chan engine.ModuleOutput, 4)
	err := module.Execute(context.Background(), map[string]any{
		"discovery.open_udp_ports": []any{
			discovery.UDPPortDiscoveryResult{Target: "192.0.2.50", OpenPorts: []int{161}},
		},
	}, outputChan)
	require.NoError(t, err)
	close(outputChan)

	_, more := <-outputChan
	require.False(t, more, "no 623 candidate means no output")
}

// startFakeBMC runs a UDP listener that answers each received datagram using
// respond, which returns nil to stay silent (simulating a lost datagram).
func startFakeBMC(t *testing.T, respond func(reqIndex int, req []byte) []byte) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, 1024)
		for i := 0; ; i++ {
			n, addr, readErr := conn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			req := append([]byte(nil), buf[:n]...)
			if resp := respond(i, req); resp != nil {
				_, _ = conn.WriteTo(resp, addr)
			}
		}
	}()
	return conn.LocalAddr().String()
}

func probeFakeBMC(t *testing.T, addr string, respond func(int, []byte) []byte) IPMIServiceInfo {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return probeIPMIDetails(context.Background(), host, port, IPMIProbeOptions{
		TotalTimeout:      2 * time.Second,
		PerAttemptTimeout: 300 * time.Millisecond,
	})
}

// The live BMC lost the Get Channel Auth Capabilities datagram while still
// answering the RMCP+ path. A dropped phase 1 must not hide the host.
func TestProbeIPMIDetails_AuthCapLostButOpenSessionAnswers(t *testing.T) {
	var respond func(int, []byte) []byte
	respond = func(i int, req []byte) []byte {
		if req[5] == rmcpPlusPayloadOpenSessionReq {
			return capturedOpenSessionResponse
		}
		return nil // drop the authcap request
	}
	addr := startFakeBMC(t, respond)

	info := probeFakeBMC(t, addr, respond)
	require.True(t, info.IPMIProbe, "the host is a BMC even though phase 1 was lost")
	require.False(t, info.ChannelAuthReceived)
	require.True(t, info.OpenSessionResponded)
	require.True(t, info.IPMI20Confirmed)
	require.Contains(t, info.Findings, ipmiFindingRAKPHashDisclosure)
	require.Empty(t, info.ErrorClass)
}

func TestProbeIPMIDetails_BothPhasesAnswer(t *testing.T) {
	respond := func(i int, req []byte) []byte {
		if req[5] == rmcpPlusPayloadOpenSessionReq {
			return capturedOpenSessionResponse
		}
		return capturedGetAuthCapResponse
	}
	addr := startFakeBMC(t, respond)

	info := probeFakeBMC(t, addr, respond)
	require.True(t, info.IPMIProbe)
	require.True(t, info.ChannelAuthReceived)
	require.True(t, info.AuthTypeMD5)
	require.True(t, info.NonNullUserEnabled)
	require.True(t, info.IPMI20Confirmed)
	// The captured authcap reply has bit 7 clear, so claim and behavior disagree.
	require.False(t, info.IPMI20Claimed)
	require.True(t, info.AuthClaimBehaviorMismatch)
	require.Contains(t, info.Findings, ipmiFindingClaimBehaviorMismatch)
}

func TestProbeIPMIDetails_SilentHost(t *testing.T) {
	respond := func(i int, req []byte) []byte { return nil }
	addr := startFakeBMC(t, respond)

	info := probeFakeBMC(t, addr, respond)
	require.False(t, info.IPMIProbe)
	require.Equal(t, "timeout", info.ErrorClass)
	require.Empty(t, info.Findings)
}
