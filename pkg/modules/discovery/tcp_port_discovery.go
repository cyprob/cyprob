// pkg/modules/discovery/tcp_port_discovery.go
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	// Utilities like target and port parsing
	"github.com/rs/zerolog/log"
	"github.com/spf13/cast"

	"github.com/cyprob/cyprob/pkg/engine" // Engine interfaces
	"github.com/cyprob/cyprob/pkg/netutil"
	"github.com/cyprob/cyprob/pkg/output"
)

// TCPPortDiscoveryResult stores the outcome of the TCP port discovery for a single target.
type TCPPortDiscoveryResult struct {
	Target          string `json:"target"`   // IP address
	Hostname        string `json:"hostname"` // Original hostname (if target was a domain)
	OpenPorts       []int  `json:"open_ports"`
	TimedOutPorts   []int  `json:"timed_out_ports,omitempty"`
	RefusedPorts    []int  `json:"refused_ports,omitempty"`
	OtherErrorPorts []int  `json:"other_error_ports,omitempty"`
}

// TCPPortDiscoveryConfig holds configuration for the TCP port discovery module.
type TCPPortDiscoveryConfig struct {
	Targets                 []string              `json:"targets"`
	Ports                   []string              `json:"ports"`   // Port ranges and lists (e.g., "1-1024", "80,443,8080")
	Timeout                 time.Duration         `json:"timeout"` // Connection timeout for each port
	PortTimeoutOverrides    map[int]time.Duration `json:"port_timeout_overrides,omitempty"`
	Concurrency             int                   `json:"concurrency"`
	Retries                 int                   `json:"retries"`
	StopOnFirstOpen         bool                  `json:"stop_on_first_open"`
	VerificationPassEnabled bool                  `json:"verification_pass_enabled"`
}

// TCPPortDiscoveryModule implements the engine.Module interface for TCP port discovery.
type TCPPortDiscoveryModule struct {
	meta   engine.ModuleMetadata
	config TCPPortDiscoveryConfig
}

const (
	tcpPortDiscoveryModuleTypeName = "tcp-port-discovery"
	defaultTCPPortDiscoveryTimeout = 1 * time.Second
	defaultTCPConcurrency          = 100
	defaultTCPPorts                = "1-1024" // Default common ports or a well-known range
	experimentalInterProbeDelay    = 0 * time.Millisecond
)

var (
	lookupHost               = net.LookupHost
	dialTimeout              = net.DialTimeout
	experimentalGlobalPPSCap = 0
	globalProbeTicker        = newGlobalProbeTicker()
)

func newGlobalProbeTicker() *time.Ticker {
	if experimentalGlobalPPSCap > 0 {
		return time.NewTicker(time.Second / time.Duration(experimentalGlobalPPSCap))
	}
	return nil
}

// newTCPPortDiscoveryModule is the internal constructor for the module.
// It sets up metadata and initializes the config with default values.
//
//nolint:dupl // TCP/UDP discovery module metadata is intentionally parallel for maintainability.
func newTCPPortDiscoveryModule() *TCPPortDiscoveryModule {
	defaultConfig := TCPPortDiscoveryConfig{
		Ports:                   []string{defaultTCPPorts},
		Timeout:                 defaultTCPPortDiscoveryTimeout,
		Concurrency:             defaultTCPConcurrency,
		Retries:                 0,
		StopOnFirstOpen:         false,
		VerificationPassEnabled: true,
	}
	return &TCPPortDiscoveryModule{
		meta: engine.ModuleMetadata{
			ID:          "tcp-port-discovery-instance",  // Unique ID for this module instance, can be generated dynamically
			Name:        tcpPortDiscoveryModuleTypeName, // Type name for factory registration
			Version:     "0.1.0",
			Description: "Discovers open TCP ports on target hosts based on a list or range.",
			Type:        engine.DiscoveryModuleType,
			Author:      "Vulntor Team",
			Tags:        []string{"discovery", "port", "tcp"},
			Consumes: []engine.DataContractEntry{
				{
					Key: "config.targets",
					// DataTypeName: "[]string", // This is an initial input, stored directly
					// Cardinality: engine.CardinalitySingle, // Expects a single []string list
					DataTypeName: "[]string",               // The type of the data itself
					Cardinality:  engine.CardinalitySingle, // "config.targets" itself is a single list of strings
					IsOptional:   true,                     // Can also get targets from discovery.live_hosts
					Description:  "List of initial target strings (IPs, CIDRs, hostnames) to scan.",
				},
				{
					Key: "discovery.live_hosts",
					// DataTypeName: "discovery.ICMPPingDiscoveryResult", // This is what's inside the []interface{} list
					// Cardinality: engine.CardinalityList, // Expects a list of ICMPPingDiscoveryResult from DataContext
					DataTypeName: "discovery.ICMPPingDiscoveryResult", // The type of each item in the list
					Cardinality:  engine.CardinalityList,              // Expects a list of these items
					IsOptional:   true,
					Description:  "List of live hosts (as ICMPPingDiscoveryResult) from ICMP ping module.",
				},
				{
					Key:          "config.ports", // Optional: specific ports can also be an input
					DataTypeName: "string",       // e.g., "80,443,1000-1024"
					Cardinality:  engine.CardinalitySingle,
					IsOptional:   true,
					Description:  "Port string to scan, can override module's static config.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key:          "discovery.open_tcp_ports",
					DataTypeName: "discovery.TCPPortDiscoveryResult",
					Cardinality:  engine.CardinalityList, // Indicates this DataKey will hold a list of results
					Description:  "List of results, each detailing open TCP ports for a specific target.",
				},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				"targets": {
					Description: "List of IPs, CIDRs, or hostnames to scan. Can be inherited from global config or previous modules.",
					Type:        "[]string",
					Required:    false, // Can be provided by 'discovery.live_hosts' input
				},
				"ports": {
					Description: "Comma-separated list or ranges of ports (e.g., '22,80,443', '1-1024').",
					Type:        "[]string", // Array of strings, each can be a port, a list, or a range
					Required:    false,
					Default:     []string{defaultTCPPorts},
				},
				"timeout": {
					Description: "Timeout for each port connection attempt (e.g., '1s', '500ms').",
					Type:        "duration",
					Required:    false,
					Default:     defaultTCPPortDiscoveryTimeout.String(),
				},
				"port_timeout_overrides": {
					Description: "Per-port timeout overrides keyed by port number (e.g., {\"445\":\"8s\"}).",
					Type:        "map",
					Required:    false,
					Default:     map[string]string{},
				},
				"concurrency": {
					Description: "Number of concurrent port scanning goroutines.",
					Type:        "int",
					Required:    false,
					Default:     defaultTCPConcurrency,
				},
				"retries": {
					Description: "Number of additional connection attempts per port before giving up.",
					Type:        "int",
					Required:    false,
					Default:     0,
				},
				"stop_on_first_open": {
					Description: "Stop scanning remaining ports for a target after the first open port is found.",
					Type:        "bool",
					Required:    false,
					Default:     true,
				},
				"verification_pass_enabled": {
					Description: "Run a targeted verification pass only for ports not found open in the first pass.",
					Type:        "bool",
					Required:    false,
					Default:     false,
				},
			},
			// ActivationTriggers: Usually none for a primary discovery module, unless it depends on a very specific prior state.
			// IsDynamic: false,
			EstimatedCost: 2, // 1-5 scale, TCP port scan is generally a bit more involved than ICMP.
		},
		config: defaultConfig,
	}
}

// Metadata returns the module's metadata.
func (m *TCPPortDiscoveryModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

// Init initializes the module with the given configuration map.
// It parses the map and populates the module's config struct, overriding defaults.
func (m *TCPPortDiscoveryModule) Init(instanceID string, moduleConfig map[string]any) error {
	cfg := m.config // Start with default config values

	m.meta.ID = instanceID // Set the unique ID for this module instance

	if targetsVal, ok := moduleConfig["targets"]; ok {
		cfg.Targets = cast.ToStringSlice(targetsVal)
	}
	if portsVal, ok := moduleConfig["ports"]; ok {
		cfg.Ports = cast.ToStringSlice(portsVal)
	}
	if timeoutStr, ok := moduleConfig["timeout"].(string); ok {
		if dur, err := time.ParseDuration(timeoutStr); err == nil {
			cfg.Timeout = dur
		} else {
			// Use fmt.Fprintf(os.Stderr, ...) for warnings/errors in production code for better logging control
			fmt.Printf("[WARN] Module '%s': Invalid 'timeout' format in config: '%s'. Using default: %s\n", m.meta.Name, timeoutStr, cfg.Timeout)
		}
	}
	if timeoutOverrides, ok := parsePortTimeoutOverrides(moduleConfig["port_timeout_overrides"]); ok {
		cfg.PortTimeoutOverrides = timeoutOverrides
	}
	if concurrencyVal, ok := moduleConfig["concurrency"]; ok {
		cfg.Concurrency = cast.ToInt(concurrencyVal)
		if cfg.Concurrency < 1 {
			fmt.Printf("[WARN] Module '%s': Concurrency in config is < 1 (%d). Setting to default: %d.\n", m.meta.Name, cfg.Concurrency, defaultTCPConcurrency)
			cfg.Concurrency = defaultTCPConcurrency
		}
	}
	if retriesVal, ok := moduleConfig["retries"]; ok {
		cfg.Retries = cast.ToInt(retriesVal)
		if cfg.Retries < 0 {
			fmt.Printf("[WARN] Module '%s': Retries in config is < 0 (%d). Setting to default: 0.\n", m.meta.Name, cfg.Retries)
			cfg.Retries = 0
		}
	}
	if stopVal, ok := moduleConfig["stop_on_first_open"]; ok {
		cfg.StopOnFirstOpen = cast.ToBool(stopVal)
	}
	if verificationPassEnabled, ok := moduleConfig["verification_pass_enabled"]; ok {
		cfg.VerificationPassEnabled = cast.ToBool(verificationPassEnabled)
	}

	// Sanitize final values
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTCPPortDiscoveryTimeout
		fmt.Printf("[WARN] Module '%s': Invalid 'timeout' value. Setting to default: %s\n", m.meta.Name, cfg.Timeout)
	}
	if len(cfg.Ports) == 0 || (len(cfg.Ports) == 1 && strings.TrimSpace(cfg.Ports[0]) == "") {
		cfg.Ports = []string{defaultTCPPorts}
		fmt.Printf("[WARN] Module '%s': No ports specified. Using default: %s\n", m.meta.Name, defaultTCPPorts)
	}

	m.config = cfg
	// For debugging during development; consider a proper logging framework for production.
	log.Debug().
		Str("module", m.meta.Name).
		Str("instance_id", m.meta.ID).Interface("config", m.config).Msg("Module configuration initialized with config.")
	return nil
}

func parsePortTimeoutOverrides(raw any) (map[int]time.Duration, bool) {
	if raw == nil {
		return nil, false
	}

	rawMap, ok := raw.(map[string]any)
	if !ok {
		if stringMap, stringOK := raw.(map[string]string); stringOK {
			rawMap = make(map[string]any, len(stringMap))
			for port, timeout := range stringMap {
				rawMap[port] = timeout
			}
			ok = true
		}
	}
	if !ok {
		return nil, false
	}

	overrides := make(map[int]time.Duration, len(rawMap))
	for portKey, timeoutValue := range rawMap {
		port, err := strconv.Atoi(strings.TrimSpace(portKey))
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		timeoutStr := strings.TrimSpace(cast.ToString(timeoutValue))
		if timeoutStr == "" {
			continue
		}
		timeout, err := time.ParseDuration(timeoutStr)
		if err != nil || timeout <= 0 {
			continue
		}
		overrides[port] = timeout
	}
	return overrides, true
}

func (m *TCPPortDiscoveryModule) timeoutForPort(port int) time.Duration {
	if timeout, ok := m.config.PortTimeoutOverrides[port]; ok && timeout > 0 {
		return timeout
	}
	return m.config.Timeout
}

// Execute performs the TCP port discovery.
//
//nolint:gocyclo // Complexity inherited from existing implementation
func (m *TCPPortDiscoveryModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	var targetsToScan []string
	hostnameByIP := make(map[string]string)

	logger := log.With().Str("module", m.meta.Name).Str("instance_id", m.meta.ID).Logger()

	// Determine targets: prefer 'discovery.live_hosts' from input, then 'config.targets' from input, then module's own config.
	if liveHosts := extractLiveHostsInput(inputs["discovery.live_hosts"]); len(liveHosts) > 0 {
		targetsToScan = append(targetsToScan, liveHosts...)
		logger.Debug().Msgf("Using %d live hosts from input 'discovery.live_hosts'.", len(targetsToScan))
	} else if configTargets, ok := inputs["config.targets"].([]string); ok && len(configTargets) > 0 {
		targetsToScan = netutil.ParseAndExpandTargets(configTargets)
		hostnameByIP = buildHostnameByIPMap(configTargets)
		logger.Debug().Msgf("Using %d targets from input 'config.targets', expanded to %d IPs.", len(configTargets), len(targetsToScan))
	} else if len(m.config.Targets) > 0 {
		targetsToScan = netutil.ParseAndExpandTargets(m.config.Targets)
		hostnameByIP = buildHostnameByIPMap(m.config.Targets)
		fmt.Printf("[DEBUG] Module '%s': Using %d targets from module config, expanded to %d IPs.\n", m.meta.Name, len(m.config.Targets), len(targetsToScan))
	} else {
		err := fmt.Errorf("module '%s': no targets specified through inputs or module configuration", m.meta.Name)
		outputChan <- engine.ModuleOutput{FromModuleName: m.meta.ID, Error: err, Timestamp: time.Now()}
		return err
	}

	portsToScanStr := strings.Join(m.config.Ports, ",")
	parsedPorts, err := netutil.ParsePortString(portsToScanStr)
	if err != nil {
		err = fmt.Errorf("module '%s': invalid port configuration '%s': %w", m.meta.Name, portsToScanStr, err)
		outputChan <- engine.ModuleOutput{FromModuleName: m.meta.ID, Error: err, Timestamp: time.Now()}
		return err
	}

	if len(targetsToScan) == 0 {
		fmt.Printf("[INFO] Module '%s': Effective target list is empty. Nothing to scan.\n", m.meta.Name)
		// Send an empty result to indicate completion without error but no data
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        m.meta.Produces[0].Key, // "discovery.open_tcp_ports"
			Data:           []TCPPortDiscoveryResult{},
			Timestamp:      time.Now(),
		}
		return nil
	}
	if len(parsedPorts) == 0 {
		fmt.Printf("[INFO] Module '%s': Effective port list is empty. Nothing to scan.\n", m.meta.Name)
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        m.meta.Produces[0].Key, // "discovery.open_tcp_ports"
			Data:           []TCPPortDiscoveryResult{},
			Timestamp:      time.Now(),
		}
		return nil
	}

	logger.Info().Msgf(
		"Starting TCP Port Discovery for %d targets on %d unique ports. Concurrency: %d, Timeout per port: %s, Retries: %d, stop_on_first_open: %t",
		len(targetsToScan), len(parsedPorts), m.config.Concurrency, m.config.Timeout, m.config.Retries, m.config.StopOnFirstOpen,
	)

	var wg sync.WaitGroup
	sem := make(chan struct{}, m.config.Concurrency) // Semaphore to limit concurrency

	// Group results by target
	openPortsByTarget := make(map[string][]int)
	timedOutPortsByTarget := make(map[string][]int)
	refusedPortsByTarget := make(map[string][]int)
	otherErrorPortsByTarget := make(map[string][]int)
	var mapMutex sync.Mutex // To protect openPortsByTarget map

	// Per-target streaming: Launch goroutine for each IP (no batch waiting)
	for _, targetIP := range targetsToScan {
		// Check for context cancellation before starting new target
		select {
		case <-ctx.Done():
			fmt.Printf("[INFO] Module '%s' (instance: %s): Context canceled. Aborting further port scans.\n", m.meta.Name, m.meta.ID)
			goto endLoops
		default:
		}

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()

			startTime := time.Now()
			logger.Debug().Msgf("Scanning target: %s", ip)

			// Streaming event: Target started
			engine.PublishEvent(ctx, engine.NewTargetStartedEvent(ip, "port_scan"))

			ipPorts := m.scanTargetPorts(
				ctx,
				ip,
				parsedPorts,
				sem,
				&mapMutex,
				openPortsByTarget,
				timedOutPortsByTarget,
				refusedPortsByTarget,
				otherErrorPortsByTarget,
			)

			duration := time.Since(startTime)
			logger.Debug().Msgf("Completed target: %s (duration: %v, open ports: %d)", ip, duration, len(ipPorts))

			// Streaming event: Target completed (IP-level!)
			engine.PublishEvent(ctx, engine.NewTargetCompletedEvent(ip, "port_scan", ipPorts, duration))
		}(targetIP)
	}

endLoops:
	wg.Wait() // Wait for all targets to complete or be canceled
	// Send aggregated results per target
	for _, target := range targetsToScan {
		openPorts := openPortsByTarget[target]
		timedOutPorts := timedOutPortsByTarget[target]
		refusedPorts := refusedPortsByTarget[target]
		otherErrorPorts := otherErrorPortsByTarget[target]
		if len(openPorts) == 0 && len(timedOutPorts) == 0 && len(refusedPorts) == 0 && len(otherErrorPorts) == 0 {
			continue
		}

		result := TCPPortDiscoveryResult{
			Target:          target,
			Hostname:        hostnameByIP[target],
			OpenPorts:       openPorts,
			TimedOutPorts:   timedOutPorts,
			RefusedPorts:    refusedPorts,
			OtherErrorPorts: otherErrorPorts,
		}
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        m.meta.Produces[0].Key, // "discovery.open_tcp_ports"
			Data:           result,
			Timestamp:      time.Now(),
			Target:         target,
		}
		logger.Info().
			Str("target", target).
			Ints("open_ports", openPorts).
			Ints("timed_out_ports", timedOutPorts).
			Ints("refused_ports", refusedPorts).
			Ints("other_error_ports", otherErrorPorts).
			Msgf(
				"Target %s - Open TCP Ports: %v, Timed Out TCP Ports: %v, Refused TCP Ports: %v, Other Error TCP Ports: %v",
				target,
				openPorts,
				timedOutPorts,
				refusedPorts,
				otherErrorPorts,
			)
	}
	// If no open ports were found for any target, we might still want to send an empty aggregate or signal completion.
	// The current logic sends per-target results, so if all targets have no open ports, nothing is sent from this loop.
	// Consider if an explicit "no open ports found for any target" message is needed.
	log.Info().Msg("TCP Port Discovery completed.")
	return nil // Indicate successful completion of the module's execution logic
}

func (m *TCPPortDiscoveryModule) scanTargetPorts(
	ctx context.Context,
	ip string,
	parsedPorts []int,
	sem chan struct{},
	mapMutex *sync.Mutex,
	openPortsByTarget map[string][]int,
	timedOutPortsByTarget map[string][]int,
	refusedPortsByTarget map[string][]int,
	otherErrorPortsByTarget map[string][]int,
) []int {
	if m.config.StopOnFirstOpen {
		return m.scanTargetPortsStopOnFirstOpen(
			ctx,
			ip,
			parsedPorts,
			sem,
			mapMutex,
			openPortsByTarget,
			timedOutPortsByTarget,
			refusedPortsByTarget,
			otherErrorPortsByTarget,
		)
	}
	return m.scanTargetPortsAll(
		ctx,
		ip,
		parsedPorts,
		sem,
		mapMutex,
		openPortsByTarget,
		timedOutPortsByTarget,
		refusedPortsByTarget,
		otherErrorPortsByTarget,
	)
}

func (m *TCPPortDiscoveryModule) scanTargetPortsStopOnFirstOpen(
	ctx context.Context,
	ip string,
	parsedPorts []int,
	sem chan struct{},
	mapMutex *sync.Mutex,
	openPortsByTarget map[string][]int,
	timedOutPortsByTarget map[string][]int,
	refusedPortsByTarget map[string][]int,
	otherErrorPortsByTarget map[string][]int,
) []int {
	ipPorts := make([]int, 0, 1)

	for _, p := range parsedPorts {
		select {
		case <-ctx.Done():
			return ipPorts
		default:
		}

		sem <- struct{}{}
		address := net.JoinHostPort(ip, strconv.Itoa(p))
		conn, err := m.dialWithRetries(ctx, address, p)
		<-sem
		if err != nil {
			recordNegativeOutcome(mapMutex, ip, p, err, timedOutPortsByTarget, refusedPortsByTarget, otherErrorPortsByTarget)
			continue
		}
		_ = conn.Close()

		ipPorts = append(ipPorts, p)

		mapMutex.Lock()
		openPortsByTarget[ip] = append(openPortsByTarget[ip], p)
		mapMutex.Unlock()

		if out, ok := ctx.Value(output.OutputKey).(output.Output); ok {
			out.Diag(output.LevelNormal, fmt.Sprintf("Open port: %s:%d/tcp", ip, p), nil)
		}
		engine.PublishEvent(ctx, engine.NewPortOpenEvent(ip, p, "tcp"))
		break
	}

	return ipPorts
}

func (m *TCPPortDiscoveryModule) scanTargetPortsAll(
	ctx context.Context,
	ip string,
	parsedPorts []int,
	sem chan struct{},
	mapMutex *sync.Mutex,
	openPortsByTarget map[string][]int,
	timedOutPortsByTarget map[string][]int,
	refusedPortsByTarget map[string][]int,
	otherErrorPortsByTarget map[string][]int,
) []int {
	outcomes := newTCPPortScanOutcomes()
	m.scanPortBatch(ctx, ip, parsedPorts, sem, outcomes)

	if m.config.VerificationPassEnabled {
		missedPorts := outcomes.missedPorts(parsedPorts)
		if len(missedPorts) > 0 {
			m.scanPortBatch(ctx, ip, missedPorts, sem, outcomes)
		}
	}

	openPorts := outcomes.openPorts()
	timedOutPorts := outcomes.timedOutPorts()
	refusedPorts := outcomes.refusedPorts()
	otherErrorPorts := outcomes.otherErrorPorts()

	mapMutex.Lock()
	if len(openPorts) > 0 {
		openPortsByTarget[ip] = openPorts
	}
	if len(timedOutPorts) > 0 {
		timedOutPortsByTarget[ip] = timedOutPorts
	}
	if len(refusedPorts) > 0 {
		refusedPortsByTarget[ip] = refusedPorts
	}
	if len(otherErrorPorts) > 0 {
		otherErrorPortsByTarget[ip] = otherErrorPorts
	}
	mapMutex.Unlock()

	return openPorts
}

func (m *TCPPortDiscoveryModule) scanPortBatch(
	ctx context.Context,
	ip string,
	ports []int,
	sem chan struct{},
	outcomes *tcpPortScanOutcomes,
) {
	var portWg sync.WaitGroup

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return
		default:
		}

		portWg.Add(1)
		go func(p int) {
			defer portWg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			address := net.JoinHostPort(ip, strconv.Itoa(p))
			conn, err := m.dialWithRetries(ctx, address, p)
			if err != nil {
				outcomes.recordNegative(p, err)
				return
			}
			_ = conn.Close()

			outcomes.recordOpen(p)

			if out, ok := ctx.Value(output.OutputKey).(output.Output); ok {
				out.Diag(output.LevelNormal, fmt.Sprintf("Open port: %s:%d/tcp", ip, p), nil)
			}
			engine.PublishEvent(ctx, engine.NewPortOpenEvent(ip, p, "tcp"))
		}(port)
	}

	portWg.Wait()
}

func (m *TCPPortDiscoveryModule) dialWithRetries(ctx context.Context, address string, port int) (net.Conn, error) {
	attempts := m.config.Retries + 1
	var lastErr error
	timeout := m.timeoutForPort(port)

	for attempt := 0; attempt < attempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if experimentalInterProbeDelay > 0 {
			timer := time.NewTimer(experimentalInterProbeDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}

		if globalProbeTicker != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-globalProbeTicker.C:
			}
		}

		conn, err := dialTimeout("tcp", address, timeout)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	return nil, lastErr
}

func isTimeoutLikeError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isRefusedLikeError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

func recordNegativeOutcome(
	mapMutex *sync.Mutex,
	ip string,
	port int,
	err error,
	timedOutPortsByTarget map[string][]int,
	refusedPortsByTarget map[string][]int,
	otherErrorPortsByTarget map[string][]int,
) {
	mapMutex.Lock()
	defer mapMutex.Unlock()

	switch {
	case isTimeoutLikeError(err):
		timedOutPortsByTarget[ip] = append(timedOutPortsByTarget[ip], port)
	case isRefusedLikeError(err):
		refusedPortsByTarget[ip] = append(refusedPortsByTarget[ip], port)
	default:
		otherErrorPortsByTarget[ip] = append(otherErrorPortsByTarget[ip], port)
	}
}

type tcpPortScanOutcomes struct {
	mu          sync.Mutex
	open        map[int]struct{}
	timedOut    map[int]struct{}
	refused     map[int]struct{}
	otherErrors map[int]struct{}
}

func newTCPPortScanOutcomes() *tcpPortScanOutcomes {
	return &tcpPortScanOutcomes{
		open:        make(map[int]struct{}),
		timedOut:    make(map[int]struct{}),
		refused:     make(map[int]struct{}),
		otherErrors: make(map[int]struct{}),
	}
}

func (o *tcpPortScanOutcomes) recordOpen(port int) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.open[port] = struct{}{}
	delete(o.timedOut, port)
	delete(o.refused, port)
	delete(o.otherErrors, port)
}

func (o *tcpPortScanOutcomes) recordNegative(port int, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if _, ok := o.open[port]; ok {
		return
	}

	delete(o.timedOut, port)
	delete(o.refused, port)
	delete(o.otherErrors, port)

	switch {
	case isTimeoutLikeError(err):
		o.timedOut[port] = struct{}{}
	case isRefusedLikeError(err):
		o.refused[port] = struct{}{}
	default:
		o.otherErrors[port] = struct{}{}
	}
}

func (o *tcpPortScanOutcomes) missedPorts(parsedPorts []int) []int {
	o.mu.Lock()
	defer o.mu.Unlock()

	missed := make([]int, 0, len(parsedPorts))
	for _, port := range parsedPorts {
		if _, ok := o.open[port]; ok {
			continue
		}
		missed = append(missed, port)
	}
	return missed
}

func (o *tcpPortScanOutcomes) openPorts() []int {
	return sortedPortsFromSet(o.open)
}

func (o *tcpPortScanOutcomes) timedOutPorts() []int {
	return sortedPortsFromSet(o.timedOut)
}

func (o *tcpPortScanOutcomes) refusedPorts() []int {
	return sortedPortsFromSet(o.refused)
}

func (o *tcpPortScanOutcomes) otherErrorPorts() []int {
	return sortedPortsFromSet(o.otherErrors)
}

func sortedPortsFromSet(set map[int]struct{}) []int {
	if len(set) == 0 {
		return nil
	}
	ports := make([]int, 0, len(set))
	for port := range set {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

// TCPPortDiscoveryModuleFactory creates a new TCPPortDiscoveryModule instance.
// This factory function is what's registered with the core engine.
func TCPPortDiscoveryModuleFactory() engine.Module {
	return newTCPPortDiscoveryModule()
}

func init() {
	// Register the module factory with Vulntor's core module registry.
	// The name "tcp-port-discovery" will be used in DAG definitions to instantiate this module.
	engine.RegisterModuleFactory(tcpPortDiscoveryModuleTypeName, TCPPortDiscoveryModuleFactory)
}

func buildHostnameByIPMap(targets []string) map[string]string {
	out := make(map[string]string)
	for _, raw := range targets {
		target := strings.TrimSpace(raw)
		if target == "" {
			continue
		}
		// Keep existing behavior for CIDR/range/IP targets.
		if strings.Contains(target, "/") || strings.Contains(target, "-") {
			continue
		}
		if net.ParseIP(target) != nil {
			continue
		}

		ips, err := lookupHost(target)
		if err != nil {
			continue
		}

		for _, ipRaw := range ips {
			parsed := net.ParseIP(ipRaw)
			if parsed == nil {
				continue
			}
			ip := parsed.String()
			if _, exists := out[ip]; !exists {
				out[ip] = target
			}
		}
	}
	return out
}
