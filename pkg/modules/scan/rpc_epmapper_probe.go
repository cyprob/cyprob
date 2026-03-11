package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

const (
	rpcEpmapperProbeModuleID          = "rpc-epmapper-probe-instance"
	rpcEpmapperProbeModuleName        = "rpc-epmapper-probe"
	rpcEpmapperProbeModuleDescription = "Runs RPC endpoint mapper probe on port 135 and emits structured endpoint metadata."
)

// RPCEpmapperProbeOptions controls timeout and feature gate behavior.
type RPCEpmapperProbeOptions struct {
	Enabled        bool          `json:"rpc_epmapper_enabled"`
	TotalTimeout   time.Duration `json:"total_timeout"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	IOTimeout      time.Duration `json:"io_timeout"`
	Retries        int           `json:"retries"`
}

type rpcEpmapperProbeModule struct {
	meta    engine.ModuleMetadata
	options RPCEpmapperProbeOptions
}

var probeRPCEpmapperDetailsFunc = probeRPCEpmapperDetails

func newRPCEpmapperProbeModuleWithSpec(moduleID string, moduleName string, description string, outputKey string, tags []string) *rpcEpmapperProbeModule {
	return &rpcEpmapperProbeModule{
		meta: engine.ModuleMetadata{
			ID:          moduleID,
			Name:        moduleName,
			Description: description,
			Version:     "0.1.0",
			Type:        engine.ScanModuleType,
			Author:      "Vulntor Team",
			Tags:        tags,
			Consumes: []engine.DataContractEntry{
				{Key: "discovery.open_tcp_ports", DataTypeName: "discovery.TCPPortDiscoveryResult", Cardinality: engine.CardinalityList, IsOptional: true},
			},
			Produces: []engine.DataContractEntry{
				{Key: outputKey, DataTypeName: "scan.RPCEpmapperInfo", Cardinality: engine.CardinalityList},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				"rpc_epmapper_enabled": {
					Description: "Feature gate for RPC epmapper probe module.",
					Type:        "bool",
					Required:    false,
					Default:     true,
				},
				"timeout": {
					Description: "Total timeout budget per host for epmapper probe.",
					Type:        "duration",
					Required:    false,
					Default:     "2s",
				},
				"connect_timeout": {
					Description: "TCP connect timeout per attempt.",
					Type:        "duration",
					Required:    false,
					Default:     "800ms",
				},
				"io_timeout": {
					Description: "Read/write timeout per attempt.",
					Type:        "duration",
					Required:    false,
					Default:     "800ms",
				},
				"retries": {
					Description: "Retry count per strategy.",
					Type:        "int",
					Required:    false,
					Default:     0,
				},
			},
		},
		options: defaultRPCEpmapperProbeOptions(),
	}
}

func newRPCEpmapperProbeModule() *rpcEpmapperProbeModule {
	return newRPCEpmapperProbeModuleWithSpec(
		rpcEpmapperProbeModuleID,
		rpcEpmapperProbeModuleName,
		rpcEpmapperProbeModuleDescription,
		"service.rpc.epmapper",
		[]string{"scan", "rpc", "enrichment", "native_probe"},
	)
}

func defaultRPCEpmapperProbeOptions() RPCEpmapperProbeOptions {
	return RPCEpmapperProbeOptions{
		Enabled:        true,
		TotalTimeout:   2 * time.Second,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
		Retries:        0,
	}
}

func (m *rpcEpmapperProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *rpcEpmapperProbeModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	opts := defaultRPCEpmapperProbeOptions()
	if configMap != nil {
		if enabled, ok := configMap["rpc_epmapper_enabled"].(bool); ok {
			opts.Enabled = enabled
		}
		if d, ok := parseDurationConfig(configMap["timeout"]); ok && d > 0 {
			opts.TotalTimeout = d
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
	}
	m.options = opts
	return nil
}

func (m *rpcEpmapperProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	if !m.options.Enabled {
		return nil
	}

	rawOpenPorts, ok := inputs["discovery.open_tcp_ports"]
	if !ok {
		return nil
	}

	candidates := make(map[string]discovery.TCPPortDiscoveryResult)
	for _, item := range toAnySlice(rawOpenPorts) {
		for _, candidate := range rpcEpmapperCandidatesFromOpenPorts(item) {
			key := fmt.Sprintf("%s:%d", candidate.Target, 135)
			candidates[key] = candidate
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	keys := make([]string, 0, len(candidates))
	for key := range candidates {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	attempted := 0
	success := 0
	failed := 0

	for _, key := range keys {
		candidate := candidates[key]
		result := probeRPCEpmapperDetailsFunc(ctx, candidate.Target, 135, m.options)
		attempted++
		if result.RPCProbe {
			success++
		} else {
			failed++
		}

		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        m.meta.Produces[0].Key,
			Data:           result,
			Timestamp:      time.Now(),
			Target:         candidate.Target,
		}
	}

	log.Info().
		Str("module", rpcEpmapperProbeModuleName).
		Int("rpc_epmapper_attempted", attempted).
		Int("rpc_epmapper_success", success).
		Int("rpc_epmapper_failed", failed).
		Msg("RPC epmapper probe completed")

	return nil
}

func rpcEpmapperCandidatesFromOpenPorts(item any) []discovery.TCPPortDiscoveryResult {
	out := make([]discovery.TCPPortDiscoveryResult, 0, 1)
	appendCandidate := func(target, hostname string, openPorts []int) {
		if strings.TrimSpace(target) == "" {
			return
		}
		has135 := false
		for _, port := range openPorts {
			if port == 135 {
				has135 = true
				break
			}
		}
		if !has135 {
			return
		}
		out = append(out, discovery.TCPPortDiscoveryResult{Target: strings.TrimSpace(target), Hostname: strings.TrimSpace(hostname), OpenPorts: []int{135}})
	}

	switch v := item.(type) {
	case discovery.TCPPortDiscoveryResult:
		appendCandidate(v.Target, v.Hostname, v.OpenPorts)
	case map[string]any:
		target, _ := v["target"].(string)
		hostname, _ := v["hostname"].(string)
		ports := []int{}
		switch rawPorts := v["open_ports"].(type) {
		case []int:
			ports = append(ports, rawPorts...)
		case []any:
			for _, rawPort := range rawPorts {
				switch p := rawPort.(type) {
				case int:
					ports = append(ports, p)
				case float64:
					ports = append(ports, int(p))
				}
			}
		}
		appendCandidate(target, hostname, ports)
	}

	return out
}

func probeRPCEpmapperDetails(ctx context.Context, target string, port int, opts RPCEpmapperProbeOptions) RPCEpmapperInfo {
	if opts.TotalTimeout <= 0 {
		opts.TotalTimeout = 2 * time.Second
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = 800 * time.Millisecond
	}
	if opts.IOTimeout <= 0 {
		opts.IOTimeout = 800 * time.Millisecond
	}
	if opts.Retries < 0 {
		opts.Retries = 0
	}

	probeCtx, cancel := context.WithTimeout(ctx, opts.TotalTimeout)
	defer cancel()

	result := RPCEpmapperInfo{
		Target:   target,
		Port:     port,
		Attempts: make([]RPCProbeAttempt, 0, opts.Retries+1),
	}

	bestDynamicPorts := []int{}
	bestUUIDs := []string{}
	bestPipes := []string{}
	bestInternalIPs := []string{}
	bestEndpoints := []RPCDynamicEndpoint{}
	bestAnonymous := false
	allErrors := make([]string, 0, opts.Retries+1)

	for attempt := 0; attempt <= opts.Retries; attempt++ {
		start := time.Now()
		anonymousBind, dynamicPorts, endpoints, uuids, namedPipes, internalIPs, err := probeSingleRPCEpmapperAttempt(probeCtx, target, port, opts)
		dur := time.Since(start)
		if err != nil {
			code := classifyRPCProbeError(err)
			allErrors = append(allErrors, code)
			result.Attempts = append(result.Attempts, RPCProbeAttempt{
				Strategy:   "epmapper-bind-lookup",
				Transport:  strconv.Itoa(port),
				Success:    false,
				DurationMS: dur.Milliseconds(),
				Error:      code,
			})
			continue
		}

		result.Attempts = append(result.Attempts, RPCProbeAttempt{
			Strategy:   "epmapper-bind-lookup",
			Transport:  strconv.Itoa(port),
			Success:    true,
			DurationMS: dur.Milliseconds(),
		})

		if len(dynamicPorts) > len(bestDynamicPorts) {
			bestDynamicPorts = dynamicPorts
			bestUUIDs = uuids
			bestPipes = namedPipes
			bestInternalIPs = internalIPs
			bestEndpoints = endpoints
		}
		if anonymousBind {
			bestAnonymous = true
		}
	}

	result.RPCProbe = bestAnonymous || len(bestDynamicPorts) > 0
	result.AnonymousBind = bestAnonymous
	result.DynamicPorts = uniqueSortedInt(bestDynamicPorts)
	result.DynamicEndpoints = bestEndpoints
	result.EndpointCount = len(result.DynamicPorts)
	result.InterfaceUUIDs = bestUUIDs
	result.NamedPipes = bestPipes
	result.InternalIPs = bestInternalIPs

	if !result.RPCProbe {
		if len(allErrors) == 0 {
			result.ProbeError = "probe_failed"
		} else {
			result.ProbeError = allErrors[0]
		}
	}

	return result
}

func probeSingleRPCEpmapperAttempt(
	ctx context.Context,
	target string,
	port int,
	opts RPCEpmapperProbeOptions,
) (anonymousBind bool, dynamicPorts []int, endpoints []RPCDynamicEndpoint, uuids []string, namedPipes []string, internalIPs []string, err error) {
	address := net.JoinHostPort(target, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: opts.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false, nil, nil, nil, nil, nil, err
	}
	defer func() {
		_ = conn.Close()
	}()

	bindReq, err := buildRPCBindRequest(1, rpcEpmapperUUID, 3, 0)
	if err != nil {
		return false, nil, nil, nil, nil, nil, err
	}
	if err := writeRPCRequest(conn, bindReq, opts.IOTimeout); err != nil {
		return false, nil, nil, nil, nil, nil, err
	}
	bindResp, err := readRPCResponse(conn, opts.IOTimeout)
	if err != nil {
		return false, nil, nil, nil, nil, nil, err
	}
	if err := validateRPCBindAck(bindResp); err != nil {
		return false, nil, nil, nil, nil, nil, err
	}
	anonymousBind = true

	lookupReq := buildRPCRequestPDU(2, 0, 2, buildEPMLookupStub(16))
	if err := writeRPCRequest(conn, lookupReq, opts.IOTimeout); err != nil {
		return anonymousBind, nil, nil, nil, nil, nil, errors.New("lookup_failed")
	}
	lookupResp, err := readRPCResponse(conn, opts.IOTimeout)
	if err != nil {
		return anonymousBind, nil, nil, nil, nil, nil, errors.New("lookup_failed")
	}

	uuidList, pipes, ips, ports := parseRPCResponseMetadata(lookupResp)
	if len(ports) == 0 {
		// Keep a conservative fallback from bind response for observability only.
		uuidList, pipes, ips, ports = parseRPCResponseMetadata(bindResp)
	}
	endpointMap := make(map[int]map[string]struct{})
	for _, p := range ports {
		if _, ok := endpointMap[p]; !ok {
			endpointMap[p] = map[string]struct{}{}
		}
		for _, id := range uuidList {
			endpointMap[p][id] = struct{}{}
		}
	}
	endpoints = make([]RPCDynamicEndpoint, 0, len(endpointMap))
	for p, ids := range endpointMap {
		list := make([]string, 0, len(ids))
		for id := range ids {
			list = append(list, id)
		}
		sort.Strings(list)
		endpoints = append(endpoints, RPCDynamicEndpoint{Port: p, InterfaceCount: len(list), InterfaceUUIDs: list})
	}
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].Port < endpoints[j].Port })

	return anonymousBind, uniqueSortedInt(ports), endpoints, uuidList, pipes, ips, nil
}

func rpcEpmapperProbeModuleFactory() engine.Module {
	return newRPCEpmapperProbeModule()
}

func init() {
	engine.RegisterModuleFactory(rpcEpmapperProbeModuleName, rpcEpmapperProbeModuleFactory)
}
