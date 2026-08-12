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
	mdnsNativeProbeModuleDescription = "Runs bounded mDNS (DNS-SD) probes over unicast and multicast and emits device identity metadata."

	mdnsPort        = 5353
	mdnsMulticastIP = "224.0.0.251"

	// mdnsMulticastBursts is how many times the query set is repeated. UDP loses
	// packets and a responder answers a given question once, so a single pass
	// under-reports.
	mdnsMulticastBursts = 2

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
	// ListenTimeout bounds the multicast collection window.
	ListenTimeout time.Duration `json:"listen_timeout"`
	// MulticastEnabled controls the segment-wide query. Some devices publish a
	// record only in answer to multicast, and a host whose UDP/5353 was never
	// detected as open is never probed by unicast at all.
	MulticastEnabled bool `json:"multicast_enabled"`
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
	probeMDNSDetailsFunc  = probeMDNSDetails
	mdnsQueryFunc         = executeMDNSQuery
	mdnsMulticastCollectF = collectMDNSMulticast

	errMDNSNoResponse = errors.New("mdns no response")
)

// mdnsIdentityServiceTypes are the service types worth a follow-up query,
// ordered by how reliably they carry model/version metadata.
var mdnsIdentityServiceTypes = []string{
	mdnsDeviceInfo,
	"_airplay._tcp.local.",
	"_androidtvremote2._tcp.local.",
	"_googlecast._tcp.local.",
	"_hap._tcp.local.",
	"_ipp._tcp.local.",
	"_printer._tcp.local.",
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
					Description:  "Open UDP ports used to identify unicast mDNS candidates, and the hosts that bound which multicast responders are in scope.",
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
					Description: "Timeout for each unicast mDNS query.",
					Type:        "duration",
					Required:    false,
					Default:     "700ms",
				},
				"listen_timeout": {
					Description: "How long to collect answers to the multicast query.",
					Type:        "duration",
					Required:    false,
					Default:     "3s",
				},
				"multicast_enabled": {
					Description: "Send a segment-wide DNS-SD query as well as unicast queries.",
					Type:        "boolean",
					Required:    false,
					Default:     true,
				},
			},
			// The multicast pass is one segment-wide conversation on top of the
			// per-target queries, so the module costs more than a plain probe.
			EstimatedCost: 2,
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
		if d, ok := parseDurationConfig(configMap["listen_timeout"]); ok && d > 0 {
			opts.ListenTimeout = d
		}
		if enabled, ok := configMap["multicast_enabled"].(bool); ok {
			opts.MulticastEnabled = enabled
		}
	}
	m.options = opts
	return nil
}

func (m *mdnsNativeProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	inScope := map[string]bool{}
	for _, target := range ssdpTargetsInScope(inputs) {
		inScope[strings.TrimSpace(target)] = true
	}

	// Unicast candidates are the hosts whose UDP/5353 was detected as open.
	candidates := map[string]mdnsProbeCandidate{}
	for _, item := range toAnySlice(inputs["discovery.open_udp_ports"]) {
		for _, candidate := range mdnsCandidatesFromOpenPorts(item) {
			candidates[candidate.target] = candidate
		}
	}

	// The multicast query reaches hosts the unicast candidate list never
	// contains: a device that answers only multicast, and any device whose
	// UDP/5353 the port scan did not report open. It is sent once for the
	// segment rather than per target.
	multicast := map[string]MDNSServiceInfo{}
	if m.options.MulticastEnabled && len(inScope) > 0 {
		multicast = mdnsMulticastCollectF(ctx, m.options)
	}

	hosts := make([]string, 0, len(candidates)+len(multicast))
	seen := map[string]bool{}
	for target := range candidates {
		seen[target] = true
		hosts = append(hosts, target)
	}
	for host := range multicast {
		// A multicast query reaches the whole segment, so hosts nobody asked to
		// scan will answer. Reporting one would invent an asset the operator
		// never requested.
		if !inScope[host] || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	if len(hosts) == 0 {
		return nil
	}
	sort.Strings(hosts)

	for _, host := range hosts {
		result := MDNSServiceInfo{Target: host, Port: mdnsPort, TXTAttrs: map[string]string{}}
		if candidate, ok := candidates[host]; ok {
			result = probeMDNSDetailsFunc(ctx, candidate.target, candidate.port, m.options)
		}
		if answer, ok := multicast[host]; ok {
			mergeMDNSInfo(&result, answer)
			// A multicast answer is a response, whatever unicast reported.
			result.MDNSProbe = true
			result.ProbeError = ""
			// The merge may have supplied records the unicast pass never saw, so
			// the identity is derived again over the union. The derived fields are
			// cleared first: keeping them would pair a model taken from one pass
			// with a product string built from the other.
			result.Model, result.VendorHint, result.ProductHint = "", "", ""
			result.VersionHint, result.DeviceType = "", ""
			deriveMDNSIdentity(&result)
		}
		if len(result.TXTAttrs) == 0 {
			result.TXTAttrs = nil
		}
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "service.mdns.details",
			Data:           result,
			Timestamp:      time.Now(),
			Target:         host,
		}
	}

	return nil
}

// mergeMDNSInfo folds collected records into an existing result, filling only
// what is missing. Unicast and multicast reach different devices and neither is
// authoritative over the other, so the first answer to state a field keeps it.
func mergeMDNSInfo(dst *MDNSServiceInfo, src MDNSServiceInfo) {
	if dst.Hostname == "" {
		dst.Hostname = src.Hostname
	}
	if dst.InstanceName == "" {
		dst.InstanceName = src.InstanceName
	}
	for _, service := range src.ServiceTypes {
		dst.ServiceTypes = appendUniqueSorted(dst.ServiceTypes, service)
	}
	if len(src.TXTAttrs) == 0 {
		return
	}
	if dst.TXTAttrs == nil {
		dst.TXTAttrs = map[string]string{}
	}
	for key, value := range src.TXTAttrs {
		if _, exists := dst.TXTAttrs[key]; !exists {
			dst.TXTAttrs[key] = value
		}
	}
}

func defaultMDNSProbeOptions() MDNSProbeOptions {
	return MDNSProbeOptions{
		TotalTimeout:     3 * time.Second,
		IOTimeout:        700 * time.Millisecond,
		ListenTimeout:    3 * time.Second,
		MulticastEnabled: true,
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

// collectMDNSMulticast sends the DNS-SD queries to the multicast group and
// gathers whatever answers inside a bounded window, keyed by responder.
//
// Unlike the unicast path this is one conversation for the whole segment, so it
// costs the same whether the scan covers one host or a /24.
func collectMDNSMulticast(ctx context.Context, opts MDNSProbeOptions) map[string]MDNSServiceInfo {
	results := map[string]MDNSServiceInfo{}

	if opts.ListenTimeout <= 0 {
		opts.ListenTimeout = 3 * time.Second
	}

	// The socket deliberately does not bind UDP/5353. On any host running a
	// system mDNS responder that port is already taken, and a probe requiring it
	// would fail to start. Querying from an ephemeral port instead makes this a
	// legacy query under RFC 6762 §6.7, which responders answer by unicast
	// straight back to the source port — verified on a live segment against both
	// a Sony TV and macOS.
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return results
	}
	defer conn.Close() //nolint:errcheck // read-only best-effort cleanup

	group := &net.UDPAddr{IP: net.ParseIP(mdnsMulticastIP), Port: mdnsPort}
	names := make([]string, 0, len(mdnsIdentityServiceTypes)+1)
	names = append(names, mdnsServiceEnumeration)
	names = append(names, mdnsIdentityServiceTypes...)

	for burst := 0; burst < mdnsMulticastBursts; burst++ {
		for _, name := range names {
			query, buildErr := buildMDNSQuery(name, dnsmessage.TypePTR)
			if buildErr != nil {
				continue
			}
			_, _ = conn.WriteTo(query, group)
		}
	}

	deadline := time.Now().Add(opts.ListenTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return results
	}

	buf := make([]byte, mdnsResponseMaxBytes)
	for {
		n, addr, readErr := conn.ReadFrom(buf)
		if readErr != nil {
			break
		}
		host, _, splitErr := net.SplitHostPort(addr.String())
		if splitErr != nil {
			continue
		}
		// A responder answers each question separately, so its records arrive
		// spread over several datagrams and are accumulated per host.
		info, ok := results[host]
		if !ok {
			info = MDNSServiceInfo{Target: host, Port: mdnsPort, MDNSProbe: true, TXTAttrs: map[string]string{}}
		}
		collectMDNSRecords(buf[:n], &info)
		results[host] = info
	}
	return results
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
