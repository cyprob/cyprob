package scan

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/stringutil"
)

const (
	mndpProbeModuleID          = "mndp-probe-instance"
	mndpProbeModuleName        = "mndp-probe"
	mndpProbeModuleDescription = "Collects MikroTik Neighbor Discovery announcements on UDP/5678 and emits board, version and identity."

	mndpPort = 5678

	mndpResponseMaxBytes = 4096
	// mndpHeaderLen is the fixed prefix before the first field.
	mndpHeaderLen = 4
	// mndpBursts is how many requests are sent. UDP loses packets and a device
	// answers a request once, so a single datagram under-reports.
	mndpBursts = 3
)

// MNDP field types, as observed on a live RouterOS device and consistent with
// the published field numbering. Only the ones carrying identity are read; the
// rest are skipped rather than guessed at.
const (
	mndpFieldMACAddress = 1
	mndpFieldIdentity   = 5
	mndpFieldVersion    = 7
	mndpFieldPlatform   = 8
	mndpFieldSoftwareID = 11
	mndpFieldBoard      = 12
	mndpFieldInterface  = 16
)

// mndpVersionPrefix captures the numeric release from a version string such as
// "6.49.10 (long-term)", which is the part version-based CVE matching needs.
var mndpVersionPrefix = regexp.MustCompile(`^\d+(?:\.\d+)*`)

// MNDPProbeOptions configures the MNDP probe.
type MNDPProbeOptions struct {
	TotalTimeout  time.Duration `json:"total_timeout"`
	ListenTimeout time.Duration `json:"listen_timeout"`
}

// MNDPNeighborInfo is the structured output of the MNDP probe.
//
// RouterOS devices announce their own board, firmware version and configured
// name without credentials. That combination is unusually complete for a
// credential-free source: it names the exact hardware and gives a version that
// feeds version-based CVE matching, not just inventory.
type MNDPNeighborInfo struct {
	Target string `json:"target"`
	Port   int    `json:"port"`
	// MNDPProbe reports whether the host answered at all.
	MNDPProbe bool `json:"mndp_probe"`
	// Identity is the operator-assigned name of the device.
	Identity string `json:"identity,omitempty"`
	// Platform is the vendor as the device states it, e.g. "MikroTik".
	Platform string `json:"platform,omitempty"`
	// Board is the exact hardware model, e.g. "RB3011UiAS".
	Board string `json:"board,omitempty"`
	// Version is the firmware release as announced, e.g. "6.49.10 (long-term)".
	Version string `json:"version,omitempty"`
	// VersionNumber is the numeric part of Version, for version comparison.
	VersionNumber string `json:"version_number,omitempty"`
	// SoftwareID identifies the license, not the unit; it is not a serial.
	SoftwareID string `json:"software_id,omitempty"`
	Interface  string `json:"interface,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
	ProbeError string `json:"probe_error,omitempty"`
}

type mndpProbeModule struct {
	meta    engine.ModuleMetadata
	options MNDPProbeOptions
}

var mndpCollectFunc = collectMNDPAnnouncements

func newMNDPProbeModule() *mndpProbeModule {
	return &mndpProbeModule{
		meta: engine.ModuleMetadata{
			ID:          mndpProbeModuleID,
			Name:        mndpProbeModuleName,
			Description: mndpProbeModuleDescription,
			Version:     "0.1.0",
			Type:        engine.ScanModuleType,
			Author:      "Vulntor Team",
			Tags:        []string{"scan", "mndp", "mikrotik", "udp", "native_probe", "enrichment"},
			Consumes: []engine.DataContractEntry{
				{
					Key:          "discovery.open_udp_ports",
					DataTypeName: "discovery.UDPPortDiscoveryResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   false,
					Description:  "Scanned hosts that bound which announcements are in scope.",
				},
				{
					Key:          "discovery.live_hosts",
					DataTypeName: "discovery.ICMPPingDiscoveryResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   true,
					Description:  "Live hosts, when host discovery ran, widening the in-scope set.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key:          "service.mndp.details",
					DataTypeName: "scan.MNDPNeighborInfo",
					Cardinality:  engine.CardinalityList,
					Description:  "Structured MikroTik neighbor announcement per target.",
				},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				"timeout": {
					Description: "Total timeout budget for the probe (e.g. 6s).",
					Type:        "duration",
					Required:    false,
					Default:     "6s",
				},
				"listen_timeout": {
					Description: "How long to collect announcements.",
					Type:        "duration",
					Required:    false,
					Default:     "4s",
				},
			},
			EstimatedCost: 1,
		},
		options: defaultMNDPProbeOptions(),
	}
}

func defaultMNDPProbeOptions() MNDPProbeOptions {
	return MNDPProbeOptions{
		TotalTimeout:  6 * time.Second,
		ListenTimeout: 4 * time.Second,
	}
}

func (m *mndpProbeModule) Metadata() engine.ModuleMetadata { return m.meta }

func (m *mndpProbeModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	opts := defaultMNDPProbeOptions()
	if configMap != nil {
		if d, ok := parseDurationConfig(configMap["timeout"]); ok && d > 0 {
			opts.TotalTimeout = d
		}
		if d, ok := parseDurationConfig(configMap["listen_timeout"]); ok && d > 0 {
			opts.ListenTimeout = d
		}
	}
	m.options = opts
	return nil
}

func (m *mndpProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	targets := ssdpTargetsInScope(inputs)
	if len(targets) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, m.options.TotalTimeout)
	defer cancel()

	inScope := make(map[string]bool, len(targets))
	for _, target := range targets {
		inScope[strings.TrimSpace(target)] = true
	}

	announcements := mndpCollectFunc(ctx, m.options)

	hosts := make([]string, 0, len(announcements))
	for host := range announcements {
		// The request goes to the broadcast address, so devices nobody asked to
		// scan will answer. Reporting them would invent assets the operator
		// never requested.
		if inScope[host] {
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)

	for _, host := range hosts {
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "service.mndp.details",
			Data:           announcements[host],
			Timestamp:      time.Now(),
			Target:         host,
		}
	}
	return nil
}

// collectMNDPAnnouncements broadcasts a request and gathers the replies.
//
// The protocol is broadcast-only in practice: a unicast datagram to a RouterOS
// device's port 5678 is refused, so there is nothing to probe per target. What
// bounds the result is the in-scope filter applied by the caller, not the
// addressing.
func collectMNDPAnnouncements(ctx context.Context, opts MNDPProbeOptions) map[string]MNDPNeighborInfo {
	results := map[string]MNDPNeighborInfo{}

	// The port has to be the protocol's own. Unlike mDNS and SSDP, a RouterOS
	// device sends its announcement to port 5678 rather than back to whatever
	// port asked, so a probe listening on an ephemeral port receives nothing —
	// verified against a live device, which is what caught the assumption.
	conn, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", mndpPort))
	if err != nil {
		return results
	}
	defer conn.Close() //nolint:errcheck // read-only best-effort cleanup

	request := make([]byte, mndpHeaderLen)
	broadcast := &net.UDPAddr{IP: net.IPv4bcast, Port: mndpPort}
	for i := 0; i < mndpBursts; i++ {
		_, _ = conn.WriteTo(request, broadcast)
	}

	deadline := time.Now().Add(opts.ListenTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return results
	}

	buf := make([]byte, mndpResponseMaxBytes)
	for {
		n, addr, readErr := conn.ReadFrom(buf)
		if readErr != nil {
			break
		}
		host, _, splitErr := net.SplitHostPort(addr.String())
		if splitErr != nil {
			continue
		}
		info := parseMNDPAnnouncement(buf[:n])
		if !info.MNDPProbe {
			continue
		}
		info.Target = host
		info.Port = mndpPort
		results[host] = info
	}
	return results
}

// parseMNDPAnnouncement reads the type-length-value fields of an announcement.
func parseMNDPAnnouncement(packet []byte) MNDPNeighborInfo {
	var info MNDPNeighborInfo
	if len(packet) <= mndpHeaderLen {
		return info
	}

	offset := mndpHeaderLen
	for offset+4 <= len(packet) {
		fieldType := binary.BigEndian.Uint16(packet[offset : offset+2])
		length := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		offset += 4
		if length < 0 || offset+length > len(packet) {
			break
		}
		value := packet[offset : offset+length]
		offset += length

		switch fieldType {
		case mndpFieldMACAddress:
			if len(value) == 6 {
				info.MACAddress = net.HardwareAddr(value).String()
			}
		case mndpFieldIdentity:
			info.Identity = sanitizeMNDPText(value)
		case mndpFieldVersion:
			info.Version = sanitizeMNDPText(value)
			info.VersionNumber = mndpVersionPrefix.FindString(info.Version)
		case mndpFieldPlatform:
			info.Platform = sanitizeMNDPText(value)
		case mndpFieldSoftwareID:
			info.SoftwareID = sanitizeMNDPText(value)
		case mndpFieldBoard:
			info.Board = sanitizeMNDPText(value)
		case mndpFieldInterface:
			info.Interface = sanitizeMNDPText(value)
		}
	}

	// An announcement that named nothing is not an identity. The request this
	// probe broadcasts is itself a four-byte packet, and it arrives back from
	// the local interface.
	if info.Identity != "" || info.Board != "" || info.Platform != "" || info.Version != "" {
		info.MNDPProbe = true
	}
	return info
}

// sanitizeMNDPText makes an announcement field safe to report.
//
// The announcement is whatever the device chose to broadcast. The shared
// implementation removes what a control-character check misses -- C1,
// bidirectional overrides, zero-width characters -- and bounds by runes, so a
// device cannot have its name cut into invalid UTF-8.
func sanitizeMNDPText(value []byte) string {
	return stringutil.SanitizeUntrusted(string(value), 128)
}

func init() {
	engine.RegisterModuleFactory(mndpProbeModuleName, func() engine.Module {
		return newMNDPProbeModule()
	})
}
