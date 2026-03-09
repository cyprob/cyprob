package scan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	rpcEpmapperUUID = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"
	rpcMgmtUUID     = "afa8bd80-7d8a-11c9-bef4-08002b102989"
	rpcNDRUUID      = "8a885d04-1ceb-11c9-9fe8-08002b104860"
)

var (
	rpcUUIDPattern = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	rpcPortPattern = regexp.MustCompile(`\[(\d{2,5})\]`)
	rpcPipePattern = regexp.MustCompile(`(?i)\\(?:pipe|PIPE)\\[a-z0-9_\-\.]+`)
	rpcIPPattern   = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b`)
)

// RPCProbeAttempt represents one RPC probe strategy attempt.
type RPCProbeAttempt struct {
	Strategy   string `json:"strategy"`
	Transport  string `json:"transport"`
	Success    bool   `json:"success"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

// RPCDynamicEndpoint represents dynamic RPC endpoint metadata from epmapper output.
type RPCDynamicEndpoint struct {
	Port           int      `json:"port"`
	InterfaceCount int      `json:"interface_count,omitempty"`
	InterfaceUUIDs []string `json:"interface_uuids,omitempty"`
}

// RPCEpmapperInfo is structured epmapper output consumed by follow-up module.
type RPCEpmapperInfo struct {
	Target           string               `json:"target"`
	Port             int                  `json:"port"`
	RPCProbe         bool                 `json:"rpc_probe"`
	AnonymousBind    bool                 `json:"anonymous_bind"`
	EndpointCount    int                  `json:"endpoint_count,omitempty"`
	DynamicPorts     []int                `json:"dynamic_ports,omitempty"`
	DynamicEndpoints []RPCDynamicEndpoint `json:"dynamic_endpoints,omitempty"`
	InterfaceUUIDs   []string             `json:"interface_uuids,omitempty"`
	NamedPipes       []string             `json:"named_pipes,omitempty"`
	InternalIPs      []string             `json:"internal_ips,omitempty"`
	ProbeError       string               `json:"probe_error,omitempty"`
	Attempts         []RPCProbeAttempt    `json:"attempts,omitempty"`
}

// RPCServiceInfo is canonical RPC follow-up output.
type RPCServiceInfo struct {
	Target            string            `json:"target"`
	Port              int               `json:"port"`
	RPCProbe          bool              `json:"rpc_probe"`
	DerivedFromPort   int               `json:"derived_from_port,omitempty"`
	AnonymousBind     bool              `json:"anonymous_bind,omitempty"`
	IsServerListening bool              `json:"is_server_listening,omitempty"`
	PrincipalName     string            `json:"principal_name,omitempty"`
	InterfaceCount    int               `json:"interface_count,omitempty"`
	InterfaceUUIDs    []string          `json:"interface_uuids,omitempty"`
	NamedPipes        []string          `json:"named_pipes,omitempty"`
	InternalIPs       []string          `json:"internal_ips,omitempty"`
	RPCStats          []int             `json:"rpc_stats,omitempty"`
	ProbeError        string            `json:"probe_error,omitempty"`
	Attempts          []RPCProbeAttempt `json:"attempts,omitempty"`
}

func toAnySliceRPC(raw any) []any {
	switch v := raw.(type) {
	case []any:
		return v
	case []RPCEpmapperInfo:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, item)
		}
		return out
	case []RPCServiceInfo:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, item)
		}
		return out
	default:
		return nil
	}
}

func classifyRPCProbeError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "budget_exceeded"):
		return "budget_exceeded"
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"), strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case strings.Contains(msg, "connection refused"):
		return "refused"
	case strings.Contains(msg, "lookup_failed"):
		return "lookup_failed"
	case strings.Contains(msg, "mgmt_failed"):
		return "mgmt_failed"
	case strings.Contains(msg, "bind_failed"):
		return "bind_failed"
	default:
		return "probe_failed"
	}
}

func encodeUUIDLittleEndian(uuidStr string) ([]byte, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(uuidStr))
	if err != nil {
		return nil, err
	}
	b := parsed
	out := make([]byte, 16)
	out[0] = b[3]
	out[1] = b[2]
	out[2] = b[1]
	out[3] = b[0]
	out[4] = b[5]
	out[5] = b[4]
	out[6] = b[7]
	out[7] = b[6]
	copy(out[8:], b[8:])
	return out, nil
}

func buildRPCBindRequest(callID uint32, interfaceUUID string, majorVersion, minorVersion uint16) ([]byte, error) {
	abstractUUID, err := encodeUUIDLittleEndian(interfaceUUID)
	if err != nil {
		return nil, err
	}
	transferUUID, err := encodeUUIDLittleEndian(rpcNDRUUID)
	if err != nil {
		return nil, err
	}

	body := bytes.NewBuffer(nil)
	_ = binary.Write(body, binary.LittleEndian, uint16(4280))
	_ = binary.Write(body, binary.LittleEndian, uint16(4280))
	_ = binary.Write(body, binary.LittleEndian, uint32(0))
	_ = body.WriteByte(1)
	_, _ = body.Write([]byte{0x00, 0x00, 0x00})
	_ = binary.Write(body, binary.LittleEndian, uint16(0))
	_ = body.WriteByte(1)
	_ = body.WriteByte(0)
	_, _ = body.Write(abstractUUID)
	_ = binary.Write(body, binary.LittleEndian, majorVersion)
	_ = binary.Write(body, binary.LittleEndian, minorVersion)
	_, _ = body.Write(transferUUID)
	_ = binary.Write(body, binary.LittleEndian, uint32(2))

	fragLength := uint16(16 + body.Len())
	header := bytes.NewBuffer(nil)
	_, _ = header.Write([]byte{0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00})
	_ = binary.Write(header, binary.LittleEndian, fragLength)
	_ = binary.Write(header, binary.LittleEndian, uint16(0))
	_ = binary.Write(header, binary.LittleEndian, callID)

	return append(header.Bytes(), body.Bytes()...), nil
}

func buildRPCRequestPDU(callID uint32, contextID uint16, opnum uint16, stub []byte) []byte {
	if stub == nil {
		stub = []byte{}
	}
	body := bytes.NewBuffer(nil)
	_ = binary.Write(body, binary.LittleEndian, uint32(len(stub)))
	_ = binary.Write(body, binary.LittleEndian, contextID)
	_ = binary.Write(body, binary.LittleEndian, opnum)
	_, _ = body.Write(stub)

	fragLength := uint16(16 + body.Len())
	header := bytes.NewBuffer(nil)
	_, _ = header.Write([]byte{0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00})
	_ = binary.Write(header, binary.LittleEndian, fragLength)
	_ = binary.Write(header, binary.LittleEndian, uint16(0))
	_ = binary.Write(header, binary.LittleEndian, callID)

	return append(header.Bytes(), body.Bytes()...)
}

func validateRPCBindAck(resp []byte) error {
	if len(resp) < 16 {
		return errors.New("bind_failed: short_response")
	}
	if resp[0] != 0x05 {
		return errors.New("bind_failed: invalid_rpc_version")
	}
	if resp[2] != 0x0c {
		return fmt.Errorf("bind_failed: unexpected_packet_type_%d", resp[2])
	}
	return nil
}

func buildEPMLookupStub(maxEntries int) []byte {
	if maxEntries <= 0 {
		maxEntries = 8
	}
	stub := make([]byte, 40)
	binary.LittleEndian.PutUint32(stub[0:4], 0)
	binary.LittleEndian.PutUint32(stub[4:8], 0)
	binary.LittleEndian.PutUint32(stub[8:12], 0)
	binary.LittleEndian.PutUint32(stub[12:16], 1)
	binary.LittleEndian.PutUint32(stub[36:40], uint32(maxEntries))
	return stub
}

func parseRPCResponseMetadata(payload []byte) (uuids []string, namedPipes []string, internalIPs []string, dynamicPorts []int) {
	text := normalizeRPCText(payload)
	uuids = uniqueSortedStrings(rpcUUIDPattern.FindAllString(text, -1))
	namedPipes = uniqueSortedStrings(rpcPipePattern.FindAllString(text, -1))
	internalIPs = uniqueSortedStrings(rpcIPPattern.FindAllString(text, -1))

	portMatches := rpcPortPattern.FindAllStringSubmatch(text, -1)
	portSet := make(map[int]struct{})
	for _, match := range portMatches {
		if len(match) < 2 {
			continue
		}
		value, err := strconv.Atoi(match[1])
		if err != nil || value <= 0 || value > 65535 {
			continue
		}
		portSet[value] = struct{}{}
	}
	dynamicPorts = make([]int, 0, len(portSet))
	for port := range portSet {
		dynamicPorts = append(dynamicPorts, port)
	}
	sort.Ints(dynamicPorts)
	return
}

func parseRPCStats(payload []byte) []int {
	if len(payload) < 32 {
		return nil
	}
	stats := make([]int, 0, 4)
	for i := 0; i+4 <= len(payload) && len(stats) < 4; i += 4 {
		value := int(binary.LittleEndian.Uint32(payload[i : i+4]))
		if value > 0 && value < 1_000_000_000 {
			stats = append(stats, value)
		}
	}
	if len(stats) == 0 {
		return nil
	}
	return stats
}

func extractPrincipalName(payload []byte) string {
	text := normalizeRPCText(payload)
	candidates := []string{}
	if match := regexp.MustCompile(`(?i)nt authority\\[a-z0-9 _\-]+`).FindString(text); match != "" {
		candidates = append(candidates, match)
	}
	if match := regexp.MustCompile(`(?i)host/[a-z0-9\.\-]+`).FindString(text); match != "" {
		candidates = append(candidates, match)
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Strings(candidates)
	return candidates[0]
}

func normalizeRPCText(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	builder := strings.Builder{}
	builder.Grow(len(payload))
	for _, b := range payload {
		switch {
		case b >= 32 && b <= 126:
			builder.WriteByte(byte(strings.ToLower(string([]byte{b}))[0]))
		case b == '\n' || b == '\r' || b == '\t':
			builder.WriteByte(' ')
		default:
			builder.WriteByte(' ')
		}
	}
	return builder.String()
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uniqueSortedInt(values []int) []int {
	if len(values) == 0 {
		return nil
	}
	set := make(map[int]struct{}, len(values))
	for _, value := range values {
		if value <= 0 || value > 65535 {
			continue
		}
		set[value] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]int, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Ints(out)
	return out
}

func readRPCResponse(conn net.Conn, ioTimeout time.Duration) ([]byte, error) {
	if ioTimeout <= 0 {
		ioTimeout = 800 * time.Millisecond
	}
	if err := conn.SetReadDeadline(time.Now().Add(ioTimeout)); err != nil {
		return nil, err
	}
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	if n <= 0 {
		return nil, errors.New("short_response")
	}
	return append([]byte(nil), buf[:n]...), nil
}

func writeRPCRequest(conn net.Conn, payload []byte, ioTimeout time.Duration) error {
	if ioTimeout <= 0 {
		ioTimeout = 800 * time.Millisecond
	}
	if err := conn.SetWriteDeadline(time.Now().Add(ioTimeout)); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}
