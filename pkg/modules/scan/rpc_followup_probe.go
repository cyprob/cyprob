package scan

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cyprob/cyprob/pkg/engine"
)

const (
	rpcFollowupProbeModuleID          = "rpc-followup-probe-instance"
	rpcFollowupProbeModuleName        = "rpc-followup-probe"
	rpcFollowupProbeModuleDescription = "Runs bounded RPC follow-up probes against epmapper-discovered dynamic ports."
)

// RPCFollowupProbeOptions controls bounded follow-up behavior.
type RPCFollowupProbeOptions struct {
	Enabled          bool          `json:"rpc_followup_enabled"`
	DerivedPorts     bool          `json:"rpc_derived_ports_enabled"`
	HostTotalTimeout time.Duration `json:"host_total_timeout"`
	PerPortTimeout   time.Duration `json:"per_port_total_timeout"`
	ConnectTimeout   time.Duration `json:"connect_timeout"`
	IOTimeout        time.Duration `json:"io_timeout"`
	Retries          int           `json:"retries"`
	MaxDynamicPorts  int           `json:"max_dynamic_ports"`
	MaxInterfaces    int           `json:"max_interfaces_per_port"`
	MaxNamedPipes    int           `json:"max_named_pipes"`
}

type rpcFollowupProbeModule struct {
	meta    engine.ModuleMetadata
	options RPCFollowupProbeOptions
}

var probeRPCFollowupDetailsFunc = probeRPCFollowupDetails

func newRPCFollowupProbeModule() *rpcFollowupProbeModule {
	return &rpcFollowupProbeModule{
		meta: engine.ModuleMetadata{
			ID:          rpcFollowupProbeModuleID,
			Name:        rpcFollowupProbeModuleName,
			Description: rpcFollowupProbeModuleDescription,
			Version:     "0.1.0",
			Type:        engine.ScanModuleType,
			Author:      "Vulntor Team",
			Tags:        []string{"scan", "rpc", "enrichment", "native_probe"},
			Consumes: []engine.DataContractEntry{
				{Key: "service.rpc.epmapper", DataTypeName: "scan.RPCEpmapperInfo", Cardinality: engine.CardinalityList, IsOptional: true},
			},
			Produces: []engine.DataContractEntry{
				{Key: "service.rpc.details", DataTypeName: "scan.RPCServiceInfo", Cardinality: engine.CardinalityList},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				"rpc_followup_enabled": {
					Description: "Feature gate for RPC follow-up probe module.",
					Type:        "bool",
					Required:    false,
					Default:     true,
				},
				"rpc_derived_ports_enabled": {
					Description: "Enable probing of dynamic ports discovered from endpoint mapper.",
					Type:        "bool",
					Required:    false,
					Default:     true,
				},
				"host_total_timeout": {
					Description: "Total timeout budget per host for follow-up probes.",
					Type:        "duration",
					Required:    false,
					Default:     "4s",
				},
				"per_port_total_timeout": {
					Description: "Total timeout per dynamic port follow-up attempt.",
					Type:        "duration",
					Required:    false,
					Default:     "1200ms",
				},
				"connect_timeout": {
					Description: "TCP connect timeout per follow-up attempt.",
					Type:        "duration",
					Required:    false,
					Default:     "600ms",
				},
				"io_timeout": {
					Description: "Read/write timeout per follow-up attempt.",
					Type:        "duration",
					Required:    false,
					Default:     "600ms",
				},
				"retries": {
					Description: "Retry count per dynamic port.",
					Type:        "int",
					Required:    false,
					Default:     0,
				},
				"max_dynamic_ports": {
					Description: "Maximum number of dynamic ports to probe per host.",
					Type:        "int",
					Required:    false,
					Default:     4,
				},
				"max_interfaces_per_port": {
					Description: "Maximum interfaces to keep per dynamic port.",
					Type:        "int",
					Required:    false,
					Default:     16,
				},
				"max_named_pipes": {
					Description: "Maximum named pipes to retain per port.",
					Type:        "int",
					Required:    false,
					Default:     8,
				},
			},
		},
		options: defaultRPCFollowupProbeOptions(),
	}
}

func defaultRPCFollowupProbeOptions() RPCFollowupProbeOptions {
	return RPCFollowupProbeOptions{
		Enabled:          true,
		DerivedPorts:     true,
		HostTotalTimeout: 4 * time.Second,
		PerPortTimeout:   1200 * time.Millisecond,
		ConnectTimeout:   600 * time.Millisecond,
		IOTimeout:        600 * time.Millisecond,
		Retries:          0,
		MaxDynamicPorts:  4,
		MaxInterfaces:    16,
		MaxNamedPipes:    8,
	}
}

func (m *rpcFollowupProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *rpcFollowupProbeModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	opts := defaultRPCFollowupProbeOptions()
	if configMap != nil {
		if enabled, ok := configMap["rpc_followup_enabled"].(bool); ok {
			opts.Enabled = enabled
		}
		if enabled, ok := configMap["rpc_derived_ports_enabled"].(bool); ok {
			opts.DerivedPorts = enabled
		}
		if d, ok := parseDurationConfig(configMap["host_total_timeout"]); ok && d > 0 {
			opts.HostTotalTimeout = d
		}
		if d, ok := parseDurationConfig(configMap["per_port_total_timeout"]); ok && d > 0 {
			opts.PerPortTimeout = d
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
		if maxPorts, ok := configMap["max_dynamic_ports"].(int); ok && maxPorts > 0 {
			opts.MaxDynamicPorts = maxPorts
		}
		if maxPorts, ok := configMap["max_dynamic_ports"].(float64); ok && maxPorts > 0 {
			opts.MaxDynamicPorts = int(maxPorts)
		}
		if maxIfaces, ok := configMap["max_interfaces_per_port"].(int); ok && maxIfaces > 0 {
			opts.MaxInterfaces = maxIfaces
		}
		if maxIfaces, ok := configMap["max_interfaces_per_port"].(float64); ok && maxIfaces > 0 {
			opts.MaxInterfaces = int(maxIfaces)
		}
		if maxPipes, ok := configMap["max_named_pipes"].(int); ok && maxPipes > 0 {
			opts.MaxNamedPipes = maxPipes
		}
		if maxPipes, ok := configMap["max_named_pipes"].(float64); ok && maxPipes > 0 {
			opts.MaxNamedPipes = int(maxPipes)
		}
	}
	m.options = opts
	return nil
}

func (m *rpcFollowupProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	if !m.options.Enabled {
		return nil
	}

	rawEpmapper, ok := inputs["service.rpc.epmapper"]
	if !ok {
		return nil
	}

	epmappers := make([]RPCEpmapperInfo, 0)
	for _, item := range toAnySliceRPC(rawEpmapper) {
		switch typed := item.(type) {
		case RPCEpmapperInfo:
			epmappers = append(epmappers, typed)
		case map[string]any:
			epmappers = append(epmappers, mapToRPCEpmapperInfo(typed))
		}
	}
	if len(epmappers) == 0 {
		return nil
	}

	hostBuckets := bucketRPCEpmapperByTarget(epmappers)
	hosts := make([]string, 0, len(hostBuckets))
	for host := range hostBuckets {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	attempted := 0
	success := 0
	failed := 0
	discovered := 0
	probed := 0
	budgetExceeded := 0

	for _, host := range hosts {
		entries := hostBuckets[host]
		selected := selectRPCDynamicPorts(entries, m.options.MaxDynamicPorts, m.options.DerivedPorts)
		discovered += len(selected)

		for _, entry := range entries {
			base := RPCServiceInfo{
				Target:            entry.Target,
				Port:              entry.Port,
				RPCProbe:          entry.RPCProbe,
				DerivedFromPort:   0,
				AnonymousBind:     entry.AnonymousBind,
				IsServerListening: entry.RPCProbe,
				InterfaceCount:    len(entry.InterfaceUUIDs),
				InterfaceUUIDs:    truncateStringSlice(entry.InterfaceUUIDs, m.options.MaxInterfaces),
				NamedPipes:        truncateStringSlice(entry.NamedPipes, m.options.MaxNamedPipes),
				InternalIPs:       entry.InternalIPs,
				ProbeError:        entry.ProbeError,
			}
			outputChan <- engine.ModuleOutput{
				FromModuleName: m.meta.ID,
				DataKey:        "service.rpc.details",
				Data:           base,
				Timestamp:      time.Now(),
				Target:         entry.Target,
			}
		}

		hostCtx, cancel := context.WithTimeout(ctx, m.options.HostTotalTimeout)
		for _, portChoice := range selected {
			if hostCtx.Err() != nil {
				budgetExceeded++
				break
			}
			probed++
			result := probeRPCFollowupDetailsFunc(hostCtx, host, portChoice.port, portChoice.derivedFromPort, m.options)
			attempted++
			if result.RPCProbe {
				success++
			} else {
				failed++
			}

			outputChan <- engine.ModuleOutput{
				FromModuleName: m.meta.ID,
				DataKey:        "service.rpc.details",
				Data:           result,
				Timestamp:      time.Now(),
				Target:         host,
			}
		}
		cancel()
	}

	log.Info().
		Str("module", rpcFollowupProbeModuleName).
		Int("rpc_followup_attempted", attempted).
		Int("rpc_followup_success", success).
		Int("rpc_followup_failed", failed).
		Int("rpc_dynamic_ports_discovered", discovered).
		Int("rpc_dynamic_ports_probed", probed).
		Int("rpc_budget_exhausted", budgetExceeded).
		Msg("RPC follow-up probe completed")

	return nil
}

type rpcPortChoice struct {
	port            int
	interfaceCount  int
	derivedFromPort int
}

func bucketRPCEpmapperByTarget(items []RPCEpmapperInfo) map[string][]RPCEpmapperInfo {
	out := make(map[string][]RPCEpmapperInfo)
	for _, item := range items {
		target := strings.TrimSpace(item.Target)
		if target == "" || item.Port <= 0 {
			continue
		}
		out[target] = append(out[target], item)
	}
	return out
}

func selectRPCDynamicPorts(entries []RPCEpmapperInfo, maxDynamicPorts int, enabled bool) []rpcPortChoice {
	if !enabled || len(entries) == 0 {
		return nil
	}
	if maxDynamicPorts <= 0 {
		maxDynamicPorts = 4
	}

	best := make(map[int]rpcPortChoice)
	for _, entry := range entries {
		for _, endpoint := range entry.DynamicEndpoints {
			if endpoint.Port <= 0 || endpoint.Port > 65535 {
				continue
			}
			candidate := rpcPortChoice{port: endpoint.Port, interfaceCount: endpoint.InterfaceCount, derivedFromPort: entry.Port}
			current, exists := best[endpoint.Port]
			if !exists || candidate.interfaceCount > current.interfaceCount {
				best[endpoint.Port] = candidate
			}
		}
		for _, p := range entry.DynamicPorts {
			if p <= 0 || p > 65535 {
				continue
			}
			if _, exists := best[p]; !exists {
				best[p] = rpcPortChoice{port: p, interfaceCount: 0, derivedFromPort: entry.Port}
			}
		}
	}

	choices := make([]rpcPortChoice, 0, len(best))
	for _, choice := range best {
		choices = append(choices, choice)
	}
	sort.Slice(choices, func(i, j int) bool {
		if choices[i].interfaceCount == choices[j].interfaceCount {
			return choices[i].port < choices[j].port
		}
		return choices[i].interfaceCount > choices[j].interfaceCount
	})
	if len(choices) > maxDynamicPorts {
		choices = choices[:maxDynamicPorts]
	}
	return choices
}

func mapToRPCEpmapperInfo(m map[string]any) RPCEpmapperInfo {
	result := RPCEpmapperInfo{}
	if value, ok := m["target"].(string); ok {
		result.Target = strings.TrimSpace(value)
	}
	if value, ok := m["port"].(float64); ok {
		result.Port = int(value)
	}
	if value, ok := m["port"].(int); ok {
		result.Port = value
	}
	if value, ok := m["rpc_probe"].(bool); ok {
		result.RPCProbe = value
	}
	if value, ok := m["anonymous_bind"].(bool); ok {
		result.AnonymousBind = value
	}
	if value, ok := m["probe_error"].(string); ok {
		result.ProbeError = strings.TrimSpace(value)
	}
	if value, ok := m["dynamic_ports"].([]any); ok {
		for _, raw := range value {
			switch p := raw.(type) {
			case int:
				result.DynamicPorts = append(result.DynamicPorts, p)
			case float64:
				result.DynamicPorts = append(result.DynamicPorts, int(p))
			}
		}
	}
	if value, ok := m["interface_uuids"].([]any); ok {
		for _, raw := range value {
			if str, ok := raw.(string); ok {
				result.InterfaceUUIDs = append(result.InterfaceUUIDs, strings.TrimSpace(str))
			}
		}
	}
	if value, ok := m["named_pipes"].([]any); ok {
		for _, raw := range value {
			if str, ok := raw.(string); ok {
				result.NamedPipes = append(result.NamedPipes, strings.TrimSpace(str))
			}
		}
	}
	if value, ok := m["internal_ips"].([]any); ok {
		for _, raw := range value {
			if str, ok := raw.(string); ok {
				result.InternalIPs = append(result.InternalIPs, strings.TrimSpace(str))
			}
		}
	}
	if value, ok := m["dynamic_endpoints"].([]any); ok {
		for _, raw := range value {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			endpoint := RPCDynamicEndpoint{}
			if p, ok := entry["port"].(float64); ok {
				endpoint.Port = int(p)
			}
			if p, ok := entry["port"].(int); ok {
				endpoint.Port = p
			}
			if ic, ok := entry["interface_count"].(float64); ok {
				endpoint.InterfaceCount = int(ic)
			}
			if ic, ok := entry["interface_count"].(int); ok {
				endpoint.InterfaceCount = ic
			}
			if ids, ok := entry["interface_uuids"].([]any); ok {
				for _, rawID := range ids {
					if str, ok := rawID.(string); ok {
						endpoint.InterfaceUUIDs = append(endpoint.InterfaceUUIDs, strings.TrimSpace(str))
					}
				}
			}
			result.DynamicEndpoints = append(result.DynamicEndpoints, endpoint)
		}
	}
	result.DynamicPorts = uniqueSortedInt(result.DynamicPorts)
	result.InterfaceUUIDs = uniqueSortedStrings(result.InterfaceUUIDs)
	result.NamedPipes = uniqueSortedStrings(result.NamedPipes)
	result.InternalIPs = uniqueSortedStrings(result.InternalIPs)
	return result
}

func truncateStringSlice(values []string, max int) []string {
	if len(values) == 0 {
		return nil
	}
	if max <= 0 || len(values) <= max {
		return values
	}
	return values[:max]
}

func probeRPCFollowupDetails(ctx context.Context, target string, port int, derivedFromPort int, opts RPCFollowupProbeOptions) RPCServiceInfo {
	if opts.PerPortTimeout <= 0 {
		opts.PerPortTimeout = 1200 * time.Millisecond
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = 600 * time.Millisecond
	}
	if opts.IOTimeout <= 0 {
		opts.IOTimeout = 600 * time.Millisecond
	}
	if opts.Retries < 0 {
		opts.Retries = 0
	}

	result := RPCServiceInfo{
		Target:          target,
		Port:            port,
		DerivedFromPort: derivedFromPort,
		Attempts:        make([]RPCProbeAttempt, 0, opts.Retries+1),
	}

	bestUUIDs := []string{}
	bestPipes := []string{}
	bestIPs := []string{}
	bestStats := []int{}
	bestPrincipal := ""
	bestListening := false
	bestAnonymous := false
	allErrors := make([]string, 0, opts.Retries+1)

	for attempt := 0; attempt <= opts.Retries; attempt++ {
		portCtx, cancel := context.WithTimeout(ctx, opts.PerPortTimeout)
		start := time.Now()
		anonymous, listening, principal, uuids, pipes, ips, stats, err := probeSingleRPCFollowupAttempt(portCtx, target, port, opts)
		cancel()
		dur := time.Since(start)
		if err != nil {
			code := classifyRPCProbeError(err)
			allErrors = append(allErrors, code)
			result.Attempts = append(result.Attempts, RPCProbeAttempt{
				Strategy:   "rpc-mgmt-bind",
				Transport:  strconv.Itoa(port),
				Success:    false,
				DurationMS: dur.Milliseconds(),
				Error:      code,
			})
			continue
		}

		result.Attempts = append(result.Attempts, RPCProbeAttempt{
			Strategy:   "rpc-mgmt-bind",
			Transport:  strconv.Itoa(port),
			Success:    true,
			DurationMS: dur.Milliseconds(),
		})
		if len(uuids) > len(bestUUIDs) {
			bestUUIDs = uuids
		}
		if len(pipes) > len(bestPipes) {
			bestPipes = pipes
		}
		if len(ips) > len(bestIPs) {
			bestIPs = ips
		}
		if len(stats) > len(bestStats) {
			bestStats = stats
		}
		if principal != "" {
			bestPrincipal = principal
		}
		if listening {
			bestListening = true
		}
		if anonymous {
			bestAnonymous = true
		}
	}

	result.RPCProbe = bestAnonymous || len(bestUUIDs) > 0 || bestListening
	result.AnonymousBind = bestAnonymous
	result.IsServerListening = bestListening
	result.PrincipalName = bestPrincipal
	result.InterfaceUUIDs = truncateStringSlice(bestUUIDs, opts.MaxInterfaces)
	result.InterfaceCount = len(result.InterfaceUUIDs)
	result.NamedPipes = truncateStringSlice(bestPipes, opts.MaxNamedPipes)
	result.InternalIPs = bestIPs
	result.RPCStats = bestStats

	if !result.RPCProbe {
		if len(allErrors) == 0 {
			result.ProbeError = "probe_failed"
		} else {
			result.ProbeError = allErrors[0]
		}
	}

	return result
}

func probeSingleRPCFollowupAttempt(
	ctx context.Context,
	target string,
	port int,
	opts RPCFollowupProbeOptions,
) (anonymous bool, isListening bool, principal string, uuids []string, pipes []string, ips []string, stats []int, err error) {
	if ctx.Err() != nil {
		return false, false, "", nil, nil, nil, nil, errors.New("budget_exceeded")
	}

	address := net.JoinHostPort(target, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: opts.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false, false, "", nil, nil, nil, nil, err
	}
	defer func() {
		_ = conn.Close()
	}()

	bindReq, err := buildRPCBindRequest(1, rpcMgmtUUID, 1, 0)
	if err != nil {
		return false, false, "", nil, nil, nil, nil, err
	}
	if err := writeRPCRequest(conn, bindReq, opts.IOTimeout); err != nil {
		return false, false, "", nil, nil, nil, nil, err
	}
	bindResp, err := readRPCResponse(conn, opts.IOTimeout)
	if err != nil {
		return false, false, "", nil, nil, nil, nil, err
	}
	if err := validateRPCBindAck(bindResp); err != nil {
		return false, false, "", nil, nil, nil, nil, err
	}
	anonymous = true

	inqIfIDsReq := buildRPCRequestPDU(2, 0, 0, nil)
	if err := writeRPCRequest(conn, inqIfIDsReq, opts.IOTimeout); err != nil {
		return anonymous, false, "", nil, nil, nil, nil, errors.New("mgmt_failed")
	}
	inqIfIDsResp, err := readRPCResponse(conn, opts.IOTimeout)
	if err != nil {
		return anonymous, false, "", nil, nil, nil, nil, errors.New("mgmt_failed")
	}

	uuidList, namedPipes, internalIPs, _ := parseRPCResponseMetadata(inqIfIDsResp)
	principal = extractPrincipalName(inqIfIDsResp)
	stats = parseRPCStats(inqIfIDsResp)
	isListening = len(inqIfIDsResp) > 0

	if len(uuidList) == 0 {
		uuidList, namedPipes, internalIPs, _ = parseRPCResponseMetadata(bindResp)
		if principal == "" {
			principal = extractPrincipalName(bindResp)
		}
		if len(stats) == 0 {
			stats = parseRPCStats(bindResp)
		}
	}

	return anonymous, isListening, principal, uuidList, namedPipes, internalIPs, stats, nil
}

func rpcFollowupProbeModuleFactory() engine.Module {
	return newRPCFollowupProbeModule()
}

func init() {
	engine.RegisterModuleFactory(rpcFollowupProbeModuleName, rpcFollowupProbeModuleFactory)
}
