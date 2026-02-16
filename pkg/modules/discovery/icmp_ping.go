// pkg/modules/discovery/icmp_ping.go
// Package discovery provides various host discovery modules.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	// TODO: Replace with your actual ping library import path
	//nolint:staticcheck // Ignore staticcheck warning for this import
	"github.com/go-ping/ping"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cast"

	"github.com/cyprob/cyprob/pkg/engine" // Assuming your core module interfaces are in pkg/engine
	"github.com/cyprob/cyprob/pkg/netutil"
	"github.com/cyprob/cyprob/pkg/output"
)

// ICMPPingDiscoveryResult stores the outcome of the ping discovery.
type ICMPPingDiscoveryResult struct {
	LiveHosts []string `json:"live_hosts"`
}

// ICMPPingDiscoveryConfig holds configuration for the ICMP ping module.
type ICMPPingDiscoveryConfig struct {
	Targets       []string      `json:"targets"`
	Timeout       time.Duration `json:"timeout"`        // Overall timeout for all pings to a single host
	Count         int           `json:"count"`          // Number of echo requests per host
	Interval      time.Duration `json:"interval"`       // Interval between sending each echo request
	PacketTimeout time.Duration `json:"packet_timeout"` // Timeout for receiving a reply for each packet (used by go-ping Pinger.Timeout)
	Privileged    bool          `json:"privileged"`
	Concurrency   int           `json:"concurrency"`
	AllowLoopback bool          `json:"allow_loopback"`
}

// Pinger is an interface for the ping library.
type Pinger interface {
	Run() error
	Stop()
	Statistics() *ping.Statistics

	SetPrivileged(bool)
	SetNetwork(string)
	SetAddr(string)
	SetCount(int)
	SetInterval(time.Duration)
	SetTimeout(time.Duration)
	GetTimeout() time.Duration
}

// Pinger is an interface for the ping library.
type pingerFactoryFunc func(ip string) (Pinger, error)

// ICMPPingDiscoveryModule implements the engine.Module interface for ICMP host discovery.
type ICMPPingDiscoveryModule struct {
	meta          engine.ModuleMetadata
	config        ICMPPingDiscoveryConfig
	pingerFactory pingerFactoryFunc
}

// newICMPPingDiscoveryModule is the internal constructor for the module.
// It sets up metadata and initializes the config with default values.
func newICMPPingDiscoveryModule() *ICMPPingDiscoveryModule {
	// Default configuration values are set here.
	// These will be used if not overridden by the Init method.
	defaultConfig := ICMPPingDiscoveryConfig{
		Timeout:       3 * time.Second,
		Count:         1,
		Interval:      1 * time.Second,
		PacketTimeout: 1 * time.Second, // This will be used for pinger.Timeout
		Privileged:    false,
		Concurrency:   50,
		AllowLoopback: true,
	}

	return &ICMPPingDiscoveryModule{
		meta: engine.ModuleMetadata{
			ID:          "icmp-ping-discovery-instance", // Placeholder; actual instance ID is set by orchestrator/DAG
			Name:        "icmp-ping-discovery",          // Module type name, used by the factory
			Version:     "0.1.0",                        // Incremented version for clarity
			Description: "Detects live hosts using ICMP echo requests via the go-ping library.",
			Type:        engine.DiscoveryModuleType,
			Author:      "Vulntor Team",
			Tags:        []string{"discovery", "host", "icmp", "ping"},
			Consumes: []engine.DataContractEntry{
				{
					Key:          "config.targets",
					DataTypeName: "[]string", // Beklenen Go tipinin string temsili
					// DataType:    reflect.TypeOf(([]string)(nil)), // reflect.Type kullanımı opsiyonel
					Cardinality: engine.CardinalitySingle, // config.targets tek bir []string listesi olarak gelir
					IsOptional:  false,                    // Ya bu ya da module.config.Targets dolu olmalı
					Description: "List of initial targets (IPs, CIDRs, hostnames) to ping.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key:          "discovery.live_hosts",
					DataTypeName: "discovery.ICMPPingDiscoveryResult", // Üretilen ModuleOutput.Data'nın tipi
					Cardinality:  engine.CardinalitySingle,            // ICMPPingDiscoveryResult tek bir struct'tır
					Description:  "A single result object containing a list of live hosts found.",
				},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				"targets":        {Description: "List of IPs, CIDRs, or ranges to ping.", Type: "[]string", Required: false /* Can be provided by input */},
				"timeout":        {Description: "Overall timeout for all ping attempts to a single host (e.g., '3s'). This is for the module's management of the ping operation.", Type: "duration", Required: false, Default: defaultConfig.Timeout.String()},
				"count":          {Description: "Number of echo requests to send to each host.", Type: "int", Required: false, Default: defaultConfig.Count},
				"interval":       {Description: "Interval between sending each echo request (e.g., '1s').", Type: "duration", Required: false, Default: defaultConfig.Interval.String()},
				"packet_timeout": {Description: "Timeout for receiving a reply for each ping packet (e.g., '1s'). Used for Pinger.Timeout.", Type: "duration", Required: false, Default: defaultConfig.PacketTimeout.String()},
				"privileged":     {Description: "Set to true to attempt to use raw sockets (requires root/admin privileges).", Type: "bool", Required: false, Default: defaultConfig.Privileged},
				"concurrency":    {Description: "Number of concurrent ping operations.", Type: "int", Required: false, Default: defaultConfig.Concurrency},
				"allow_loopback": {Description: "Set to true to allow pinging loopback addresses (e.g., 127.0.0.1).", Type: "bool", Required: false, Default: defaultConfig.AllowLoopback},
			},
			EstimatedCost: 1,
		},
		config: defaultConfig, // Initialize with defaults
		pingerFactory: func(ip string) (Pinger, error) {
			p, err := ping.NewPinger(ip)
			if err != nil {
				return nil, err
			}
			return &realPingerAdapter{p: p}, nil
		},
	}
}

// Metadata returns the module's metadata.
func (m *ICMPPingDiscoveryModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

// Init initializes the module with the given configuration map.
// It parses the map and populates the module's config struct, overriding defaults.
func (m *ICMPPingDiscoveryModule) Init(instanceID string, configMap map[string]any) error {
	// Start with default config values already set by newICMPPingDiscoveryModule
	cfg := m.config

	logger := log.With().Str("module", m.meta.Name).Str("instance_id", m.meta.ID).Logger()
	logger.Debug().Interface("received_config_map", configMap).Msg("Initializing module")

	m.meta.ID = instanceID // Set the instance ID for this module

	if targetsVal, ok := configMap["targets"]; ok {
		cfg.Targets = cast.ToStringSlice(targetsVal)
	}
	if timeoutStr, ok := configMap["timeout"].(string); ok {
		if dur, err := time.ParseDuration(timeoutStr); err == nil {
			cfg.Timeout = dur
		} else {
			log.Warn().Msgf("Module '%s': Invalid 'timeout' format in config: '%s'. Using default: %s\n", m.meta.Name, timeoutStr, cfg.Timeout)
		}
	}
	if countVal, ok := configMap["count"]; ok {
		cfg.Count = cast.ToInt(countVal)
	}
	if intervalStr, ok := configMap["interval"].(string); ok {
		if dur, err := time.ParseDuration(intervalStr); err == nil {
			cfg.Interval = dur
		} else {
			log.Warn().Msgf("Module '%s': Invalid 'interval' format in config: '%s'. Using default: %s\n", m.meta.Name, intervalStr, cfg.Interval)
		}
	}
	if packetTimeoutStr, ok := configMap["packet_timeout"].(string); ok {
		if dur, err := time.ParseDuration(packetTimeoutStr); err == nil {
			cfg.PacketTimeout = dur
		} else {
			log.Warn().Msgf("Module '%s': Invalid 'packet_timeout' format in config: '%s'. Using default: %s\n", m.meta.Name, packetTimeoutStr, cfg.PacketTimeout)
		}
	}
	if privilegedVal, ok := configMap["privileged"]; ok {
		cfg.Privileged = cast.ToBool(privilegedVal)
	}
	if concurrencyVal, ok := configMap["concurrency"]; ok {
		cfg.Concurrency = cast.ToInt(concurrencyVal)
	}
	if allowLoopbackVal, ok := configMap["allow_loopback"]; ok {
		cfg.AllowLoopback = cast.ToBool(allowLoopbackVal)
	}

	// Validate and sanitize config values
	if cfg.Count < 1 {
		log.Warn().Msgf("Module '%s': Ping count in config is < 1 (%d). Setting to 1.", m.meta.Name, cfg.Count)
		cfg.Count = 1
	}
	if cfg.Concurrency < 1 {
		log.Warn().Msgf("Module '%s': Concurrency in config is < 1 (%d). Setting to 1.", m.meta.Name, cfg.Concurrency)
		cfg.Concurrency = 1
	}
	if cfg.Timeout <= 0 { // Ensure overall timeout is also positive
		cfg.Timeout = 3 * time.Second // A sensible fallback
		log.Warn().Msgf("Module '%s': Invalid 'timeout'. Setting to default: %s", m.meta.Name, cfg.Timeout)
	}
	if cfg.PacketTimeout <= 0 {
		cfg.PacketTimeout = cfg.Timeout // Fallback if packet_timeout is invalid or not set appropriately
		log.Warn().Msgf("Module '%s': Invalid 'packet_timeout'. Using overall 'timeout' value: %s", m.meta.Name, cfg.PacketTimeout)
	}

	// Handle privileged mode warning/downgrade for non-Windows OS
	if cfg.Privileged && runtime.GOOS != "windows" {
		if os.Geteuid() != 0 {
			log.Warn().Msgf("Module '%s': Privileged ping requested, but process is not running as root. Falling back to unprivileged ping.", m.meta.Name)
			cfg.Privileged = false
		}
	} else if cfg.Privileged && runtime.GOOS == "windows" {
		// Inform the user about Windows behavior with privileged pings
		log.Info().Msgf("Module '%s': Privileged mode for go-ping on Windows may rely on ICMP.DLL rather than raw sockets.", m.meta.Name)
	}

	m.config = cfg // Assign the processed config back to the module
	log.Debug().Msgf("Module '%s' initialized. Final Config: %+v", m.meta.Name, m.config)
	return nil
}

// Execute performs the host discovery using ICMP pings based on the initialized configuration.
//
//nolint:gocyclo // Complexity inherited from existing implementation (target resolution, timeout handling, context management)
func (m *ICMPPingDiscoveryModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	logger := log.With().Str("module", m.meta.Name).Str("instance_id", m.meta.ID).Logger()
	logger.Debug().Interface("received_inputs", inputs).Msg("Executing module")

	var targetsToProcess []string
	targetsInputSource := "module_config_fallback" // To log which source was used

	// "config.targets" is an initial input, assumed to be set directly by DataContext.SetInitial
	if rawTargetsInput, ok := inputs["config.targets"]; ok {
		logger.Debug().Interface("config.targets_input_raw", rawTargetsInput).Type("type", rawTargetsInput).Msg("Found 'config.targets' in inputs")
		if stringSlice, isStringSlice := rawTargetsInput.([]string); isStringSlice {
			targetsToProcess = netutil.ParseAndExpandTargets(stringSlice)
			targetsInputSource = "inputs[\"config.targets\"] (direct []string)"
		} else if rawTargetsInput != nil {
			logger.Error().Type("type", rawTargetsInput).Msg("'config.targets' input has unexpected type, expected []string")
		}
	}

	if len(targetsToProcess) == 0 && len(m.config.Targets) > 0 {
		targetsToProcess = netutil.ParseAndExpandTargets(m.config.Targets)
		targetsInputSource = "module.config.Targets (from Init)"
		logger.Debug().Interface("module_config_targets", m.config.Targets).Msg("Using targets from module's own config as fallback")
	}

	logger.Debug().Strs("parsed_targets", targetsToProcess).Str("source", targetsInputSource).Msg("Targets after attempting to read from all sources")
	if len(targetsToProcess) == 0 {
		err := fmt.Errorf("no targets specified (source evaluated: %s, instance: %s)", targetsInputSource, m.meta.ID)
		logger.Error().Err(err).Msg("Module execution cannot proceed")
		// Send error via ModuleOutput, DataKey can be empty or a specific error key
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "error.input.targets", // More specific error key
			Error:          err,
			Timestamp:      time.Now(),
		}
		return err // Return error to orchestrator to indicate module failure
	}

	logger.Debug().Msgf("[DEBUG-EXEC] Module '%s': Targets after parseAndExpandTargets: %v", m.meta.Name, targetsToProcess)

	// --- Loopback Filtering ---
	finalTargetsToScan := []string{}
	if !m.config.AllowLoopback {
		for _, ipStr := range targetsToProcess {
			ip := net.ParseIP(ipStr)
			if ip != nil && ip.IsLoopback() {
				logger.Debug().Str("ip", ipStr).Msg("Skipping loopback address")
				continue
			}
			finalTargetsToScan = append(finalTargetsToScan, ipStr)
		}
	} else {
		finalTargetsToScan = targetsToProcess
	}
	logger.Debug().Strs("final_targets_to_scan", finalTargetsToScan).Msg("Targets after loopback filtering")

	if len(finalTargetsToScan) == 0 {
		msg := "effective target list is empty after all filters"
		if !m.config.AllowLoopback && len(targetsToProcess) > 0 {
			allWereLoopback := true
			for _, ipStr := range targetsToProcess {
				ip := net.ParseIP(ipStr)
				if ip == nil || !ip.IsLoopback() {
					allWereLoopback = false
					break
				}
			}
			if allWereLoopback {
				msg = "all specified targets were loopback addresses and loopback scanning is disabled"
			}
		}
		logger.Info().Msg(msg + ". No hosts to ping.")
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        m.meta.Produces[0].Key,
			Data:           ICMPPingDiscoveryResult{LiveHosts: []string{}},
			Timestamp:      time.Now(),
			Error:          errors.New("no hosts to ping: " + msg),
		}
		return nil // Module itself didn't fail, just had no work.
	}

	var liveHosts []string
	var mu sync.Mutex // Protects liveHosts
	var wg sync.WaitGroup
	sem := make(chan struct{}, m.config.Concurrency)

	logger.Info().Int("num_targets", len(finalTargetsToScan)).Int("concurrency", m.config.Concurrency).Msg("Starting ICMP Ping scan")

	for _, targetIP := range finalTargetsToScan {
		select {
		case <-ctx.Done():
			logger.Info().Int("live_hosts_found", len(liveHosts)).Msg("Main context canceled. Aborting further pings.")
			return ctx.Err() // Propagate cancellation
		default:
		}

		wg.Add(1)
		sem <- struct{}{} // Acquire a spot in the semaphore

		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }() // Release spot

			select {
			case <-ctx.Done(): // Check parent context again before starting
				return
			default:
			}

			pinger, err := m.pingerFactory(ip)
			if err != nil {
				logger.Warn().Str("target", ip).Err(err).Msg("Failed to create pinger")
				return
			}

			pinger.SetPrivileged(m.config.Privileged)
			pinger.SetCount(m.config.Count)
			pinger.SetInterval(m.config.Interval)
			pinger.SetTimeout(m.config.PacketTimeout)

			opCtx, opCancel := context.WithTimeout(ctx, pinger.GetTimeout()+(500*time.Millisecond))
			defer opCancel()

			go func() {
				<-opCtx.Done()
				if opCtx.Err() != nil { // Could be context.DeadlineExceeded or context.Canceled
					pinger.Stop()
				}
			}()

			err = pinger.Run()           // This is a blocking call.
			stats := pinger.Statistics() // Get stats regardless of error from Run()

			if opCtx.Err() != nil { // Check if our operation context timed out or was canceled
				logger.Debug().Str("target", ip).Err(opCtx.Err()).Msg("Ping operation context done")
				return
			}
			// Error from pinger.Run() itself might indicate network issues other than timeout,
			// or issues setting up the ping (e.g. privilege problems not caught earlier).
			if err != nil {
				// Depending on verbosity, this might be a debug or warn.
				// If stats.PacketsRecv > 0, it's not a complete failure for host discovery.
				logger.Debug().Err(err).Str("target", ip).Msg("Pinger.Run() error")
			}

			if stats != nil && stats.PacketsRecv > 0 {
				mu.Lock()
				liveHosts = append(liveHosts, ip)
				mu.Unlock()
				logger.Debug().Str("target", ip).Msg("Host is live")

				// Real-time output: Emit host discovery to user
				if out, ok := ctx.Value(output.OutputKey).(output.Output); ok {
					out.Diag(output.LevelNormal, fmt.Sprintf("Host discovered: %s", ip), nil)
				}
			} else {
				logger.Debug().Str("target", ip).Int("sent", stats.PacketsSent).Int("recv", stats.PacketsRecv).Msg("Host did not respond")
			}
		}(targetIP)
	}

	wg.Wait()

	resultData := ICMPPingDiscoveryResult{LiveHosts: liveHosts}
	outputChan <- engine.ModuleOutput{
		FromModuleName: m.meta.ID,
		DataKey:        m.meta.Produces[0].Key, // "discovery.live_hosts"
		Data:           resultData,
		Timestamp:      time.Now(),
	}

	logger.Info().Int("live_hosts_found", len(liveHosts)).Int("targets_processed", len(finalTargetsToScan)).Msg("ICMP Ping Discovery completed")
	return nil
}

// ICMPPingModuleFactory creates a new ICMPPingDiscoveryModule instance.
// This factory function is what's registered with the core engine.
func ICMPPingModuleFactory() engine.Module {
	return newICMPPingDiscoveryModule()
}

func init() {
	// Register the module factory with Vulntor's core module registry.
	// The name "icmp-ping-discovery" will be used in DAG definitions to instantiate this module.
	engine.RegisterModuleFactory("icmp-ping-discovery", ICMPPingModuleFactory)
}

// internal adapter: wraps github.com/go-ping/ping.Pinger to implement our Pinger interface
type realPingerAdapter struct {
	p *ping.Pinger
}

func (r *realPingerAdapter) Run() error                   { return r.p.Run() }
func (r *realPingerAdapter) Stop()                        { r.p.Stop() }
func (r *realPingerAdapter) Statistics() *ping.Statistics { return r.p.Statistics() }

func (r *realPingerAdapter) SetPrivileged(v bool)        { r.p.SetPrivileged(v) }
func (r *realPingerAdapter) SetNetwork(n string)         { r.p.SetNetwork(n) }
func (r *realPingerAdapter) SetAddr(a string)            { _ = r.p.SetAddr(a) }
func (r *realPingerAdapter) SetCount(c int)              { r.p.Count = c }
func (r *realPingerAdapter) SetInterval(i time.Duration) { r.p.Interval = i }
func (r *realPingerAdapter) SetTimeout(t time.Duration)  { r.p.Timeout = t }
func (r *realPingerAdapter) GetTimeout() time.Duration   { return r.p.Timeout }
