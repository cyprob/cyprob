package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

const (
	ssdpProbeModuleID          = "ssdp-probe-instance"
	ssdpProbeModuleName        = "ssdp-probe"
	ssdpProbeModuleDescription = "Discovers UPnP devices over SSDP and reads the manufacturer, model and serial they publish."

	ssdpPort         = 1900
	ssdpMulticastIP  = "239.255.255.250"
	ssdpResponseMax  = 8192
	ssdpDescMaxBytes = 128 * 1024

	// ssdpMulticastBursts is how many M-SEARCH datagrams are sent. UDP loses
	// packets and some devices answer only one of a burst, so a single query
	// under-reports; three is enough without flooding the segment.
	ssdpMulticastBursts = 3
)

// SSDPProbeOptions configures the SSDP probe.
type SSDPProbeOptions struct {
	TotalTimeout   time.Duration `json:"total_timeout"`
	ListenTimeout  time.Duration `json:"listen_timeout"`
	RequestTimeout time.Duration `json:"request_timeout"`
	// MulticastEnabled controls the segment-wide M-SEARCH. Devices that ignore
	// unicast queries answer it, but it puts one query on the local segment
	// rather than addressing a single target.
	MulticastEnabled bool `json:"multicast_enabled"`
}

// SSDPDeviceInfo is the structured output of the SSDP probe.
//
// UPnP device descriptions are the richest credential-free identity a consumer
// device gives: manufacturer, model and often a serial number, stated by the
// device about itself.
type SSDPDeviceInfo struct {
	Target       string `json:"target"`
	Port         int    `json:"port"`
	SSDPProbe    bool   `json:"ssdp_probe"`
	Server       string `json:"server,omitempty"`
	Location     string `json:"location,omitempty"`
	FriendlyName string `json:"friendly_name,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	ModelName    string `json:"model_name,omitempty"`
	ModelNumber  string `json:"model_number,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	UDN          string `json:"udn,omitempty"`
	ProbeError   string `json:"probe_error,omitempty"`
}

type ssdpProbeModule struct {
	meta    engine.ModuleMetadata
	options SSDPProbeOptions
}

var (
	ssdpCollectFunc = collectSSDPReplies
	ssdpDescribeFn  = fetchSSDPDescription

	// ssdpDescTag matches the identity elements of a UPnP device description.
	ssdpDescTag = regexp.MustCompile(`(?is)<(friendlyName|manufacturer|modelName|modelNumber|serialNumber|UDN)>(.*?)</`)
	// ssdpHeader splits an SSDP reply header from its value.
	ssdpHeader = regexp.MustCompile(`(?i)^([A-Za-z0-9-]+)\s*:\s*(.*)$`)
)

func newSSDPProbeModule() *ssdpProbeModule {
	return &ssdpProbeModule{
		meta: engine.ModuleMetadata{
			ID:          ssdpProbeModuleID,
			Name:        ssdpProbeModuleName,
			Description: ssdpProbeModuleDescription,
			Version:     "0.1.0",
			Type:        engine.ScanModuleType,
			Author:      "Vulntor Team",
			Tags:        []string{"scan", "ssdp", "upnp", "udp", "native_probe", "enrichment"},
			Consumes: []engine.DataContractEntry{
				{
					Key:          "discovery.open_udp_ports",
					DataTypeName: "discovery.UDPPortDiscoveryResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   false,
					Description:  "Scanned hosts that bound which SSDP responders are in scope.",
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
					Key:          "service.ssdp.details",
					DataTypeName: "scan.SSDPDeviceInfo",
					Cardinality:  engine.CardinalityList,
					Description:  "Structured UPnP device description per target.",
				},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				"timeout": {
					Description: "Total timeout budget for the probe (e.g. 8s).",
					Type:        "duration",
					Required:    false,
					Default:     "8s",
				},
				"listen_timeout": {
					Description: "How long to collect SSDP replies.",
					Type:        "duration",
					Required:    false,
					Default:     "4s",
				},
				"request_timeout": {
					Description: "Timeout for fetching a device description.",
					Type:        "duration",
					Required:    false,
					Default:     "4s",
				},
				"multicast_enabled": {
					Description: "Send a segment-wide M-SEARCH as well as unicast queries.",
					Type:        "boolean",
					Required:    false,
					Default:     true,
				},
			},
			EstimatedCost: 2,
		},
		options: defaultSSDPProbeOptions(),
	}
}

func defaultSSDPProbeOptions() SSDPProbeOptions {
	return SSDPProbeOptions{
		TotalTimeout:     8 * time.Second,
		ListenTimeout:    4 * time.Second,
		RequestTimeout:   4 * time.Second,
		MulticastEnabled: true,
	}
}

func (m *ssdpProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *ssdpProbeModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	opts := defaultSSDPProbeOptions()
	if configMap != nil {
		if d, ok := parseDurationConfig(configMap["timeout"]); ok && d > 0 {
			opts.TotalTimeout = d
		}
		if d, ok := parseDurationConfig(configMap["listen_timeout"]); ok && d > 0 {
			opts.ListenTimeout = d
		}
		if d, ok := parseDurationConfig(configMap["request_timeout"]); ok && d > 0 {
			opts.RequestTimeout = d
		}
		if enabled, ok := configMap["multicast_enabled"].(bool); ok {
			opts.MulticastEnabled = enabled
		}
	}
	m.options = opts
	return nil
}

func (m *ssdpProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
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

	replies := ssdpCollectFunc(ctx, targets, m.options)

	hosts := make([]string, 0, len(replies))
	for host := range replies {
		// A multicast query reaches the whole segment. Reporting a responder
		// that was never a target would invent an asset the operator did not
		// ask to scan.
		if inScope[host] {
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)

	for _, host := range hosts {
		info := replies[host]
		if info.Location != "" {
			ssdpDescribeFn(ctx, &info, m.options.RequestTimeout)
		}
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "service.ssdp.details",
			Data:           info,
			Timestamp:      time.Now(),
			Target:         host,
		}
	}
	return nil
}

// ssdpTargetsInScope collects the hosts this scan asked about.
//
// It is deliberately not tied to host discovery alone: a scan of explicitly
// named targets does not run a ping sweep, so a module that required
// discovery.live_hosts would be silently dropped from the plan for exactly the
// scans an operator aims at known devices. The port-scan target list is always
// produced, and live hosts widen it when a sweep did run.
func ssdpTargetsInScope(inputs map[string]any) []string {
	seen := map[string]bool{}
	targets := make([]string, 0, 8)
	add := func(host string) {
		host = strings.TrimSpace(host)
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		targets = append(targets, host)
	}

	for _, host := range discovery.ExtractLiveHosts(inputs["discovery.live_hosts"]) {
		add(host)
	}
	for _, item := range toAnySlice(inputs["discovery.open_udp_ports"]) {
		switch typed := item.(type) {
		case discovery.UDPPortDiscoveryResult:
			add(typed.Target)
		case *discovery.UDPPortDiscoveryResult:
			if typed != nil {
				add(typed.Target)
			}
		}
	}
	sort.Strings(targets)
	return targets
}

// collectSSDPReplies queries every target directly and, when enabled, the
// multicast group as well.
//
// The two reach different devices: some answer only a unicast query addressed
// to them, others only the segment-wide one. Both replies are collected on a
// single socket so a device answering either way is recorded once.
func collectSSDPReplies(ctx context.Context, targets []string, opts SSDPProbeOptions) map[string]SSDPDeviceInfo {
	results := map[string]SSDPDeviceInfo{}

	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return results
	}
	defer conn.Close() //nolint:errcheck // read-only best-effort cleanup

	request := []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: " + ssdpMulticastIP + ":1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: ssdp:all\r\n\r\n")

	multicastAddr := &net.UDPAddr{IP: net.ParseIP(ssdpMulticastIP), Port: ssdpPort}
	if opts.MulticastEnabled {
		for i := 0; i < ssdpMulticastBursts; i++ {
			_, _ = conn.WriteTo(request, multicastAddr)
		}
	}
	for _, target := range targets {
		ip := net.ParseIP(strings.TrimSpace(target))
		if ip == nil || ip.To4() == nil {
			continue
		}
		_, _ = conn.WriteTo(request, &net.UDPAddr{IP: ip, Port: ssdpPort})
	}

	deadline := time.Now().Add(opts.ListenTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return results
	}

	buf := make([]byte, ssdpResponseMax)
	for {
		n, addr, readErr := conn.ReadFrom(buf)
		if readErr != nil {
			break
		}
		host, _, splitErr := net.SplitHostPort(addr.String())
		if splitErr != nil {
			continue
		}
		info := parseSSDPReply(string(buf[:n]))
		info.Target = host
		info.Port = ssdpPort
		info.SSDPProbe = true
		// A device answers the burst several times; keep the reply that names a
		// description, since that is the one worth following.
		if existing, seen := results[host]; seen && existing.Location != "" {
			continue
		}
		results[host] = info
	}
	return results
}

// parseSSDPReply reads the headers of an M-SEARCH response.
func parseSSDPReply(reply string) SSDPDeviceInfo {
	var info SSDPDeviceInfo
	for _, line := range strings.Split(reply, "\n") {
		match := ssdpHeader.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if match == nil {
			continue
		}
		value := strings.TrimSpace(match[2])
		switch strings.ToUpper(match[1]) {
		case "SERVER":
			info.Server = sanitizeSSDPValue(value)
		case "LOCATION":
			info.Location = value
		case "USN":
			if udn, _, found := strings.Cut(value, "::"); found {
				info.UDN = sanitizeSSDPValue(udn)
			}
		}
	}
	return info
}

// fetchSSDPDescription reads the UPnP device description the reply points at.
//
// The description is fetched only from the host that advertised it: a LOCATION
// naming a different host would make the scanner follow a redirect of the
// device's choosing, which is not something a target gets to decide.
func fetchSSDPDescription(ctx context.Context, info *SSDPDeviceInfo, timeout time.Duration) {
	if !ssdpLocationBelongsToTarget(info.Location, info.Target) {
		info.ProbeError = "description location does not belong to the target"
		info.Location = ""
		return
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // identification, not a trust decision
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, info.Location, nil)
	if err != nil {
		info.ProbeError = "description request rejected"
		return
	}
	response, err := client.Do(request)
	if err != nil {
		info.ProbeError = "description unreachable"
		return
	}
	defer response.Body.Close() //nolint:errcheck // read-only best-effort cleanup
	if response.StatusCode != http.StatusOK {
		info.ProbeError = fmt.Sprintf("description status_%d", response.StatusCode)
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, ssdpDescMaxBytes))
	if err != nil {
		info.ProbeError = "description unreadable"
		return
	}
	applySSDPDescription(info, string(body))
}

// applySSDPDescription folds the device description into the reply.
func applySSDPDescription(info *SSDPDeviceInfo, body string) {
	for _, match := range ssdpDescTag.FindAllStringSubmatch(body, -1) {
		value := sanitizeSSDPValue(match[2])
		if value == "" {
			continue
		}
		switch strings.ToLower(match[1]) {
		case "friendlyname":
			if info.FriendlyName == "" {
				info.FriendlyName = value
			}
		case "manufacturer":
			if info.Manufacturer == "" {
				info.Manufacturer = value
			}
		case "modelname":
			if info.ModelName == "" {
				info.ModelName = value
			}
		case "modelnumber":
			if info.ModelNumber == "" {
				info.ModelNumber = value
			}
		case "serialnumber":
			if info.SerialNumber == "" {
				info.SerialNumber = value
			}
		case "udn":
			if info.UDN == "" {
				info.UDN = value
			}
		}
	}
}

// ssdpLocationBelongsToTarget reports whether a description URL points back at
// the host that sent the reply.
func ssdpLocationBelongsToTarget(location, target string) bool {
	if location == "" || target == "" {
		return false
	}
	if !strings.HasPrefix(strings.ToLower(location), "http://") &&
		!strings.HasPrefix(strings.ToLower(location), "https://") {
		return false
	}
	rest := location[strings.Index(location, "://")+3:]
	if slash := strings.IndexAny(rest, "/?#"); slash >= 0 {
		rest = rest[:slash]
	}
	host := rest
	if h, _, err := net.SplitHostPort(rest); err == nil {
		host = h
	}
	return strings.EqualFold(strings.Trim(host, "[]"), target)
}

// sanitizeSSDPValue strips control characters so a hostile reply cannot inject
// terminal escapes into a report, and bounds the length a device can claim.
func sanitizeSSDPValue(value string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(value))
	if len(cleaned) > 256 {
		cleaned = cleaned[:256]
	}
	return cleaned
}

func init() {
	engine.RegisterModuleFactory(ssdpProbeModuleName, func() engine.Module {
		return newSSDPProbeModule()
	})
}
