package scan

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/macvendor"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

const (
	nbnsProbeModuleID          = "nbns-probe-instance"
	nbnsProbeModuleName        = "nbns-probe"
	nbnsProbeModuleDescription = "Runs unicast NetBIOS node status queries against UDP/137 and emits host name, domain and adapter identity."

	nbnsPort = 137

	// nbnsNodeStatusType is NBSTAT, the query that asks a host to list every
	// NetBIOS name it has registered.
	nbnsNodeStatusType = 0x0021
	nbnsClassIN        = 0x0001

	nbnsHeaderLen = 12
	// nbnsEncodedNameLen is a length byte, 32 half-ASCII characters and a
	// terminating null.
	nbnsEncodedNameLen = 34
	// nbnsNameEntryLen is a 15-byte name, a 1-byte suffix and 2 flag bytes.
	nbnsNameEntryLen = 18

	nbnsResponseMaxBytes = 4096

	// nbnsGroupFlag marks a name as a group (domain/workgroup) rather than a
	// name unique to this host.
	nbnsGroupFlag = 0x8000
)

// NetBIOS name suffixes that identify what a registered name means. Only the
// ones that carry identity or a security-relevant role are interpreted; the
// rest are still reported verbatim.
const (
	nbnsSuffixWorkstation = 0x00
	nbnsSuffixMessenger   = 0x03
	nbnsSuffixDomainMBrow = 0x1b
	nbnsSuffixDomainCtrl  = 0x1c
	nbnsSuffixFileServer  = 0x20
)

// NBNSProbeOptions configures the NetBIOS node status probe.
type NBNSProbeOptions struct {
	TotalTimeout time.Duration `json:"total_timeout"`
	IOTimeout    time.Duration `json:"io_timeout"`
}

// NBNSName is one name a host reports as registered.
type NBNSName struct {
	Name    string `json:"name"`
	Suffix  byte   `json:"suffix"`
	IsGroup bool   `json:"is_group"`
}

// NBNSNodeInfo is the structured output of the NetBIOS node status probe.
//
// NetBIOS answers this query without credentials, and it is often the only
// source that names a Windows, Samba or NAS host: such hosts frequently publish
// no mDNS and present no banner that carries a hostname. The reply also carries
// the adapter's own MAC address, which yields a vendor even for a target the
// local neighbor table has no entry for.
type NBNSNodeInfo struct {
	Target             string     `json:"target"`
	Port               int        `json:"port"`
	NBNSProbe          bool       `json:"nbns_probe"`
	ComputerName       string     `json:"computer_name,omitempty"`
	Domain             string     `json:"domain,omitempty"`
	UserName           string     `json:"user_name,omitempty"`
	MACAddress         string     `json:"mac_address,omitempty"`
	VendorHint         string     `json:"vendor_hint,omitempty"`
	ServesSMB          bool       `json:"serves_smb,omitempty"`
	IsDomainController bool       `json:"is_domain_controller,omitempty"`
	Names              []NBNSName `json:"names,omitempty"`
	ProbeError         string     `json:"probe_error,omitempty"`
}

type nbnsProbeModule struct {
	meta    engine.ModuleMetadata
	options NBNSProbeOptions
}

type nbnsProbeCandidate struct {
	target string
	port   int
}

var (
	probeNBNSDetailsFunc = probeNBNSDetails
	nbnsExchangeFunc     = exchangeNBNS
)

func newNBNSProbeModule() *nbnsProbeModule {
	return &nbnsProbeModule{
		meta: engine.ModuleMetadata{
			ID:          nbnsProbeModuleID,
			Name:        nbnsProbeModuleName,
			Description: nbnsProbeModuleDescription,
			Version:     "0.1.0",
			Type:        engine.ScanModuleType,
			Author:      "Vulntor Team",
			Tags:        []string{"scan", "netbios", "nbns", "udp", "native_probe", "enrichment"},
			Consumes: []engine.DataContractEntry{
				{
					Key:          "discovery.open_udp_ports",
					DataTypeName: "discovery.UDPPortDiscoveryResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   false,
					Description:  "Open UDP ports used to identify NetBIOS name service candidates.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key:          "service.nbns.details",
					DataTypeName: "scan.NBNSNodeInfo",
					Cardinality:  engine.CardinalityList,
					Description:  "Structured NetBIOS node status output per target.",
				},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				"timeout": {
					Description: "Total timeout budget per target (e.g. 2s).",
					Type:        "duration",
					Required:    false,
					Default:     "2s",
				},
				"io_timeout": {
					Description: "Timeout for the node status query.",
					Type:        "duration",
					Required:    false,
					Default:     "700ms",
				},
			},
			EstimatedCost: 1,
		},
		options: defaultNBNSProbeOptions(),
	}
}

func defaultNBNSProbeOptions() NBNSProbeOptions {
	return NBNSProbeOptions{
		TotalTimeout: 2 * time.Second,
		IOTimeout:    700 * time.Millisecond,
	}
}

func (m *nbnsProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *nbnsProbeModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	opts := defaultNBNSProbeOptions()
	if configMap != nil {
		if d, ok := parseDurationConfig(configMap["timeout"]); ok && d > 0 {
			opts.TotalTimeout = d
		}
		if d, ok := parseDurationConfig(configMap["io_timeout"]); ok && d > 0 {
			opts.IOTimeout = d
		}
	}
	m.options = opts
	return nil
}

func (m *nbnsProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	rawOpenPorts, ok := inputs["discovery.open_udp_ports"]
	if !ok {
		return nil
	}

	candidateMap := map[string]nbnsProbeCandidate{}
	for _, item := range toAnySlice(rawOpenPorts) {
		for _, candidate := range nbnsCandidatesFromOpenPorts(item) {
			candidateMap[fmt.Sprintf("%s:%d", candidate.target, candidate.port)] = candidate
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
		result := probeNBNSDetailsFunc(ctx, candidate.target, candidate.port, m.options)
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "service.nbns.details",
			Data:           result,
			Timestamp:      time.Now(),
			Target:         candidate.target,
		}
	}

	return nil
}

func nbnsCandidatesFromOpenPorts(item any) []nbnsProbeCandidate {
	candidates := make([]nbnsProbeCandidate, 0, 1)
	appendCandidate := func(target string, port int) {
		target = strings.TrimSpace(target)
		if target == "" || port != nbnsPort {
			return
		}
		candidates = append(candidates, nbnsProbeCandidate{target: target, port: port})
	}

	switch typed := item.(type) {
	case discovery.UDPPortDiscoveryResult:
		for _, port := range typed.OpenPorts {
			appendCandidate(typed.Target, port)
		}
	case *discovery.UDPPortDiscoveryResult:
		if typed != nil {
			for _, port := range typed.OpenPorts {
				appendCandidate(typed.Target, port)
			}
		}
	}
	return candidates
}

// probeNBNSDetails asks a host to list its registered NetBIOS names.
func probeNBNSDetails(ctx context.Context, target string, port int, opts NBNSProbeOptions) NBNSNodeInfo {
	info := NBNSNodeInfo{Target: target, Port: port}

	ctx, cancel := context.WithTimeout(ctx, opts.TotalTimeout)
	defer cancel()

	response, err := nbnsExchangeFunc(ctx, target, port, buildNBNSNodeStatusRequest(), opts.IOTimeout)
	if err != nil {
		info.ProbeError = err.Error()
		return info
	}
	info.NBNSProbe = true

	names, mac, err := parseNBNSNodeStatus(response)
	if err != nil {
		info.ProbeError = err.Error()
		return info
	}
	info.Names = names
	info.MACAddress = mac
	if mac != "" {
		if vendor, found := macvendor.Lookup(mac); found {
			info.VendorHint = vendor
		}
	}
	applyNBNSRoles(&info)
	return info
}

// buildNBNSNodeStatusRequest builds the wildcard node status query. The "*"
// name asks for every name the host has registered, which is what makes this a
// single-packet identity source.
func buildNBNSNodeStatusRequest() []byte {
	packet := make([]byte, 0, nbnsHeaderLen+nbnsEncodedNameLen+4)
	header := make([]byte, nbnsHeaderLen)
	// A fixed transaction ID is safe here: the socket is connected and reads
	// exactly one reply, so there is no other response to disambiguate from.
	binary.BigEndian.PutUint16(header[0:2], 0x1337)
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCOUNT
	packet = append(packet, header...)

	// The wildcard name is "*" padded with nulls, not spaces.
	var name [16]byte
	name[0] = '*'
	packet = append(packet, encodeNetBIOSName(name)...)

	suffix := make([]byte, 4)
	binary.BigEndian.PutUint16(suffix[0:2], nbnsNodeStatusType)
	binary.BigEndian.PutUint16(suffix[2:4], nbnsClassIN)
	return append(packet, suffix...)
}

// encodeNetBIOSName applies the first-level encoding from RFC 1001: each byte
// becomes two characters, its nibbles offset from 'A'.
func encodeNetBIOSName(name [16]byte) []byte {
	encoded := make([]byte, 0, nbnsEncodedNameLen)
	encoded = append(encoded, 0x20)
	for _, b := range name {
		encoded = append(encoded, 'A'+(b>>4), 'A'+(b&0x0f))
	}
	return append(encoded, 0x00)
}

// parseNBNSNodeStatus extracts the registered names and the adapter MAC from a
// node status response.
func parseNBNSNodeStatus(response []byte) ([]NBNSName, string, error) {
	if len(response) < nbnsHeaderLen {
		return nil, "", fmt.Errorf("nbns response too short: %d bytes", len(response))
	}
	if binary.BigEndian.Uint16(response[6:8]) == 0 {
		return nil, "", fmt.Errorf("nbns response carries no answer")
	}

	offset := nbnsHeaderLen
	nameLen, err := nbnsAnswerNameLen(response, offset)
	if err != nil {
		return nil, "", err
	}
	// Skip the answer name, then TYPE, CLASS, TTL and RDLENGTH.
	offset += nameLen + 10
	if offset >= len(response) {
		return nil, "", fmt.Errorf("nbns response truncated before name list")
	}

	numNames := int(response[offset])
	offset++
	if numNames == 0 {
		return nil, "", fmt.Errorf("nbns response lists no names")
	}
	if offset+numNames*nbnsNameEntryLen > len(response) {
		return nil, "", fmt.Errorf("nbns name list truncated: %d names do not fit", numNames)
	}

	names := make([]NBNSName, 0, numNames)
	for i := 0; i < numNames; i++ {
		entry := response[offset : offset+nbnsNameEntryLen]
		offset += nbnsNameEntryLen
		name := strings.TrimSpace(string(entry[0:15]))
		if name == "" {
			continue
		}
		names = append(names, NBNSName{
			Name:    sanitizeNetBIOSName(name),
			Suffix:  entry[15],
			IsGroup: binary.BigEndian.Uint16(entry[16:18])&nbnsGroupFlag != 0,
		})
	}

	// The statistics section that follows opens with the adapter's MAC. It is
	// absent or zeroed on some implementations, which is not an error.
	var mac string
	if offset+6 <= len(response) {
		hw := net.HardwareAddr(response[offset : offset+6])
		if !isZeroMAC(hw) {
			mac = hw.String()
		}
	}
	return names, mac, nil
}

// nbnsAnswerNameLen returns how many bytes the answer's name field occupies,
// which is either a compression pointer or a length-prefixed encoded name.
func nbnsAnswerNameLen(response []byte, offset int) (int, error) {
	if offset >= len(response) {
		return 0, fmt.Errorf("nbns response truncated before answer name")
	}
	if response[offset]&0xc0 == 0xc0 {
		return 2, nil
	}
	if offset+nbnsEncodedNameLen > len(response) {
		return 0, fmt.Errorf("nbns answer name truncated")
	}
	return nbnsEncodedNameLen, nil
}

// sanitizeNetBIOSName strips control characters so a hostile or corrupt reply
// cannot inject terminal escapes into a report.
func sanitizeNetBIOSName(name string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
}

func isZeroMAC(hw net.HardwareAddr) bool {
	for _, b := range hw {
		if b != 0 {
			return false
		}
	}
	return true
}

// applyNBNSRoles interprets the name suffixes. A name unique to the host is its
// own identity; a group name is the workgroup or domain it belongs to.
func applyNBNSRoles(info *NBNSNodeInfo) {
	for _, entry := range info.Names {
		switch {
		case entry.Suffix == nbnsSuffixWorkstation && !entry.IsGroup:
			if info.ComputerName == "" {
				info.ComputerName = entry.Name
			}
		case entry.Suffix == nbnsSuffixWorkstation && entry.IsGroup:
			if info.Domain == "" {
				info.Domain = entry.Name
			}
		case entry.Suffix == nbnsSuffixFileServer && !entry.IsGroup:
			info.ServesSMB = true
		case entry.Suffix == nbnsSuffixDomainCtrl && entry.IsGroup:
			// Only domain controllers register the <1C> group name.
			info.IsDomainController = true
			if info.Domain == "" {
				info.Domain = entry.Name
			}
		case entry.Suffix == nbnsSuffixDomainMBrow && !entry.IsGroup:
			if info.Domain == "" {
				info.Domain = entry.Name
			}
		}
	}

	// The messenger name equals the computer name unless a user is logged on,
	// in which case it is that user. Reporting it otherwise would just repeat
	// the hostname.
	for _, entry := range info.Names {
		if entry.Suffix == nbnsSuffixMessenger && !entry.IsGroup &&
			!strings.EqualFold(entry.Name, info.ComputerName) {
			info.UserName = entry.Name
			break
		}
	}
}

// exchangeNBNS sends the query and reads a single reply.
func exchangeNBNS(ctx context.Context, target string, port int, request []byte, ioTimeout time.Duration) ([]byte, error) {
	dialer := net.Dialer{Timeout: ioTimeout}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(target, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck // read-only best-effort cleanup

	deadline := time.Now().Add(ioTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}

	buf := make([]byte, nbnsResponseMaxBytes)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func init() {
	engine.RegisterModuleFactory(nbnsProbeModuleName, func() engine.Module {
		return newNBNSProbeModule()
	})
}
