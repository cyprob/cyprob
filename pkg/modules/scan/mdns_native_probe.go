package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

const (
	mdnsNativeProbeModuleID          = "mdns-native-probe-instance"
	mdnsNativeProbeModuleName        = "mdns-native-probe"
	mdnsNativeProbeModuleDescription = "Runs bounded unicast mDNS (DNS-SD) probes against UDP/5353 and emits device identity metadata."

	mdnsPort = 5353

	// mdnsServiceEnumeration is the DNS-SD meta-query that lists the service
	// types a host advertises.
	mdnsServiceEnumeration = "_services._dns-sd._udp.local."
	// mdnsDeviceInfo is the canonical Bonjour record carrying a device model.
	mdnsDeviceInfo = "_device-info._tcp.local."

	mdnsResponseMaxBytes = 9000
	// mdnsMaxFollowUpQueries bounds the per-target work: one enumeration query
	// plus at most this many service-type queries.
	mdnsMaxFollowUpQueries = 4
)

// MDNSProbeOptions configures the mDNS native probe.
type MDNSProbeOptions struct {
	TotalTimeout time.Duration `json:"total_timeout"`
	IOTimeout    time.Duration `json:"io_timeout"`
}

// MDNSServiceInfo is the structured output of the mDNS native probe.
//
// mDNS is a credential-free identity source: hosts that answer it typically
// publish an exact hardware model and OS version, which feeds both the device
// inventory and version-based CVE correlation.
type MDNSServiceInfo struct {
	Target       string            `json:"target"`
	Port         int               `json:"port"`
	MDNSProbe    bool              `json:"mdns_probe"`
	Hostname     string            `json:"hostname,omitempty"`
	InstanceName string            `json:"instance_name,omitempty"`
	ServiceTypes []string          `json:"service_types,omitempty"`
	VendorHint   string            `json:"vendor_hint,omitempty"`
	ProductHint  string            `json:"product_hint,omitempty"`
	VersionHint  string            `json:"version_hint,omitempty"`
	Model        string            `json:"model,omitempty"`
	DeviceType   string            `json:"device_type,omitempty"`
	TXTAttrs     map[string]string `json:"txt_attrs,omitempty"`
	ProbeError   string            `json:"probe_error,omitempty"`
}

type mdnsNativeProbeModule struct {
	meta    engine.ModuleMetadata
	options MDNSProbeOptions
}

type mdnsProbeCandidate struct {
	target string
	port   int
}

var (
	probeMDNSDetailsFunc = probeMDNSDetails
	mdnsQueryFunc        = executeMDNSQuery

	errMDNSNoResponse = errors.New("mdns no response")
)

// mdnsIdentityServiceTypes are the service types worth a follow-up query,
// ordered by how reliably they carry model/version metadata.
var mdnsIdentityServiceTypes = []string{
	mdnsDeviceInfo,
	"_airplay._tcp.local.",
	"_hap._tcp.local.",
	"_ipp._tcp.local.",
	"_printer._tcp.local.",
	"_googlecast._tcp.local.",
	"_raop._tcp.local.",
}

func newMDNSNativeProbeModule() *mdnsNativeProbeModule {
	return &mdnsNativeProbeModule{
		meta: engine.ModuleMetadata{
			ID:          mdnsNativeProbeModuleID,
			Name:        mdnsNativeProbeModuleName,
			Description: mdnsNativeProbeModuleDescription,
			Version:     "0.1.0",
			Type:        engine.ScanModuleType,
			Author:      "Vulntor Team",
			Tags:        []string{"scan", "mdns", "dns-sd", "udp", "native_probe", "enrichment"},
			Consumes: []engine.DataContractEntry{
				{
					Key:          "discovery.open_udp_ports",
					DataTypeName: "discovery.UDPPortDiscoveryResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   false,
					Description:  "Open UDP ports used to identify mDNS candidates.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key:          "service.mdns.details",
					DataTypeName: "scan.MDNSServiceInfo",
					Cardinality:  engine.CardinalityList,
					Description:  "Structured mDNS native probe output per target and port.",
				},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				"timeout": {
					Description: "Total timeout budget per target (e.g. 3s).",
					Type:        "duration",
					Required:    false,
					Default:     "3s",
				},
				"io_timeout": {
					Description: "Timeout for each mDNS query.",
					Type:        "duration",
					Required:    false,
					Default:     "700ms",
				},
			},
			EstimatedCost: 1,
		},
		options: defaultMDNSProbeOptions(),
	}
}

func (m *mdnsNativeProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *mdnsNativeProbeModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	opts := defaultMDNSProbeOptions()
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

func (m *mdnsNativeProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	rawOpenPorts, ok := inputs["discovery.open_udp_ports"]
	if !ok {
		return nil
	}

	candidateMap := map[string]mdnsProbeCandidate{}
	for _, item := range toAnySlice(rawOpenPorts) {
		for _, candidate := range mdnsCandidatesFromOpenPorts(item) {
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
		result := probeMDNSDetailsFunc(ctx, candidate.target, candidate.port, m.options)
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "service.mdns.details",
			Data:           result,
			Timestamp:      time.Now(),
			Target:         candidate.target,
		}
	}

	return nil
}

func defaultMDNSProbeOptions() MDNSProbeOptions {
	return MDNSProbeOptions{
		TotalTimeout: 3 * time.Second,
		IOTimeout:    700 * time.Millisecond,
	}
}

func mdnsCandidatesFromOpenPorts(item any) []mdnsProbeCandidate {
	candidates := make([]mdnsProbeCandidate, 0, 1)
	appendCandidate := func(target string, port int) {
		target = strings.TrimSpace(target)
		if target == "" || port != mdnsPort {
			return
		}
		candidates = append(candidates, mdnsProbeCandidate{target: target, port: port})
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

// probeMDNSDetails performs a bounded unicast mDNS conversation: one service
// enumeration query, then follow-up queries for the identity-bearing service
// types the host advertised.
func probeMDNSDetails(ctx context.Context, target string, port int, opts MDNSProbeOptions) MDNSServiceInfo {
	if port <= 0 {
		port = mdnsPort
	}
	if opts.TotalTimeout <= 0 {
		opts.TotalTimeout = 3 * time.Second
	}
	if opts.IOTimeout <= 0 {
		opts.IOTimeout = 700 * time.Millisecond
	}

	probeCtx, cancel := context.WithTimeout(ctx, opts.TotalTimeout)
	defer cancel()

	result := MDNSServiceInfo{Target: target, Port: port, TXTAttrs: map[string]string{}}

	// Step 1: enumerate advertised service types.
	packet, err := mdnsQueryFunc(probeCtx, target, port, opts, mdnsServiceEnumeration, dnsmessage.TypePTR)
	if err != nil {
		result.ProbeError = classifyMDNSError(err)
		return result
	}
	result.MDNSProbe = true
	collectMDNSRecords(packet, &result)

	// Step 2: follow up on the identity-bearing types this host advertises.
	queries := 0
	for _, svc := range mdnsIdentityServiceTypes {
		if queries >= mdnsMaxFollowUpQueries {
			break
		}
		if svc != mdnsDeviceInfo && !mdnsAdvertises(result.ServiceTypes, svc) {
			continue
		}
		if probeCtx.Err() != nil {
			break
		}
		queries++
		followUp, followErr := mdnsQueryFunc(probeCtx, target, port, opts, svc, dnsmessage.TypePTR)
		if followErr != nil {
			continue
		}
		collectMDNSRecords(followUp, &result)
	}

	deriveMDNSIdentity(&result)
	if len(result.TXTAttrs) == 0 {
		result.TXTAttrs = nil
	}
	return result
}

func mdnsAdvertises(advertised []string, service string) bool {
	target := strings.TrimSuffix(strings.ToLower(service), ".")
	for _, entry := range advertised {
		if strings.TrimSuffix(strings.ToLower(entry), ".") == target {
			return true
		}
	}
	return false
}

// executeMDNSQuery sends a unicast mDNS query. Unicast (rather than multicast)
// keeps the probe inside the per-target model the engine already uses, and
// hosts that implement DNS-SD answer it directly.
func executeMDNSQuery(
	ctx context.Context,
	target string,
	port int,
	opts MDNSProbeOptions,
	name string,
	qtype dnsmessage.Type,
) ([]byte, error) {
	query, err := buildMDNSQuery(name, qtype)
	if err != nil {
		return nil, err
	}

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(target, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck // best-effort cleanup

	deadline := time.Now().Add(opts.IOTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	response := make([]byte, mdnsResponseMaxBytes)
	n, err := conn.Read(response)
	if err != nil {
		if isTimeoutError(err) {
			return nil, errMDNSNoResponse
		}
		return nil, err
	}
	return response[:n], nil
}

func buildMDNSQuery(name string, qtype dnsmessage.Type) ([]byte, error) {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0, RecursionDesired: false})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  qname,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

// collectMDNSRecords parses every section of an mDNS response. mDNS servers
// bundle SRV/TXT alongside the PTR answer, so the additional sections carry
// most of the identity data.
func collectMDNSRecords(packet []byte, result *MDNSServiceInfo) {
	var parser dnsmessage.Parser
	if _, err := parser.Start(packet); err != nil {
		return
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return
	}

	sections := []func() (dnsmessage.Resource, error){
		parser.Answer, parser.Authority, parser.Additional,
	}
	skips := []func() error{
		parser.SkipAllAnswers, parser.SkipAllAuthorities, parser.SkipAllAdditionals,
	}

	for i, next := range sections {
		for {
			resource, err := next()
			if err != nil {
				break
			}
			applyMDNSResource(resource, result)
		}
		if i+1 < len(skips) {
			_ = skips[i]()
		}
	}
}

func applyMDNSResource(resource dnsmessage.Resource, result *MDNSServiceInfo) {
	switch body := resource.Body.(type) {
	case *dnsmessage.PTRResource:
		value := strings.TrimSpace(body.PTR.String())
		if value == "" {
			return
		}
		if strings.HasPrefix(strings.ToLower(resource.Header.Name.String()), "_services._dns-sd._udp") {
			result.ServiceTypes = appendUniqueSorted(result.ServiceTypes, value)
			return
		}
		if result.InstanceName == "" {
			result.InstanceName = mdnsInstanceLabel(value)
		}
	case *dnsmessage.SRVResource:
		if result.Hostname == "" {
			result.Hostname = strings.TrimSuffix(strings.TrimSpace(body.Target.String()), ".")
		}
	case *dnsmessage.TXTResource:
		for _, entry := range body.TXT {
			key, value, found := strings.Cut(entry, "=")
			if !found {
				continue
			}
			key = strings.ToLower(strings.TrimSpace(key))
			value = strings.TrimSpace(value)
			if key == "" || value == "" {
				continue
			}
			if _, exists := result.TXTAttrs[key]; !exists {
				result.TXTAttrs[key] = value
			}
		}
	}
}

// mdnsInstanceLabel extracts the human-readable instance label from a DNS-SD
// instance name ("Living Room._airplay._tcp.local." -> "Living Room").
func mdnsInstanceLabel(name string) string {
	label, _, found := strings.Cut(name, "._")
	if !found {
		return strings.TrimSuffix(name, ".")
	}
	return strings.TrimSpace(strings.ReplaceAll(label, `\032`, " "))
}

func appendUniqueSorted(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if strings.EqualFold(existing, value) {
			return values
		}
	}
	values = append(values, value)
	sort.Strings(values)
	return values
}

func init() {
	engine.RegisterModuleFactory(mdnsNativeProbeModuleName, func() engine.Module {
		return newMDNSNativeProbeModule()
	})
}
