// pkg/modules/discovery/udp_port_discovery.go
package discovery

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cast"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/netutil"
	"github.com/cyprob/cyprob/pkg/output"
)

// UDPPortDiscoveryResult stores the outcome of UDP port discovery for a single target.
type UDPPortDiscoveryResult struct {
	Target        string         `json:"target"`
	OpenPorts     []int          `json:"open_ports"`
	FilteredPorts []int          `json:"filtered_ports"` // Ports with ICMP unreachable
	Responses     map[int]string `json:"responses"`      // Port → response data
}

// UDPPortDiscoveryConfig holds configuration for the UDP port discovery module.
type UDPPortDiscoveryConfig struct {
	Targets        []string       `json:"targets"`
	Ports          []string       `json:"ports"`   // Port ranges and lists (e.g., "53,161,123")
	Timeout        time.Duration  `json:"timeout"` // Response timeout per port
	Concurrency    int            `json:"concurrency"`
	MaxRetries     int            `json:"max_retries"` // Retry count for ambiguous responses
	PayloadCatalog map[int][]byte `json:"-"`           // Port-specific payloads
}

// UDPPortDiscoveryModule implements the engine.Module interface for UDP port discovery.
type UDPPortDiscoveryModule struct {
	meta   engine.ModuleMetadata
	config UDPPortDiscoveryConfig
}

const (
	udpPortDiscoveryModuleTypeName = "udp-port-discovery"
	defaultUDPPortDiscoveryTimeout = 2 * time.Second
	defaultUDPConcurrency          = 50                    // Lower than TCP (UDP slower)
	defaultUDPPorts                = "53,161,123,514,1900" // DNS, SNMP, NTP, Syslog, UPnP
	defaultUDPMaxRetries           = 2
)

// newUDPPortDiscoveryModule is the internal constructor for the module.
//
//nolint:dupl // TCP/UDP discovery module metadata is intentionally parallel for maintainability.
func newUDPPortDiscoveryModule() *UDPPortDiscoveryModule {
	defaultConfig := UDPPortDiscoveryConfig{
		Ports:          []string{defaultUDPPorts},
		Timeout:        defaultUDPPortDiscoveryTimeout,
		Concurrency:    defaultUDPConcurrency,
		MaxRetries:     defaultUDPMaxRetries,
		PayloadCatalog: getDefaultUDPPayloads(),
	}

	return &UDPPortDiscoveryModule{
		meta: engine.ModuleMetadata{
			ID:          "udp-port-discovery-instance",
			Name:        udpPortDiscoveryModuleTypeName,
			Version:     "0.1.0",
			Description: "Discovers open UDP ports on target hosts using protocol-specific payloads.",
			Type:        engine.DiscoveryModuleType,
			Author:      "Vulntor Team",
			Tags:        []string{"discovery", "port", "udp"},
			Consumes: []engine.DataContractEntry{
				{
					Key:          "config.targets",
					DataTypeName: "[]string",
					Cardinality:  engine.CardinalitySingle,
					IsOptional:   true,
					Description:  "List of initial target strings (IPs, CIDRs, hostnames) to scan.",
				},
				{
					Key:          "discovery.live_hosts",
					DataTypeName: "discovery.ICMPPingDiscoveryResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   false,
					Description:  "List of live hosts from ICMP ping module.",
				},
				{
					Key:          "config.ports",
					DataTypeName: "string",
					Cardinality:  engine.CardinalitySingle,
					IsOptional:   true,
					Description:  "Port string to scan (e.g., '53,161,123').",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key:          "discovery.open_udp_ports",
					DataTypeName: "discovery.UDPPortDiscoveryResult",
					Cardinality:  engine.CardinalityList,
					Description:  "List of UDP port discovery results per target.",
				},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				"targets": {
					Description: "List of IPs, CIDRs, or hostnames to scan.",
					Type:        "[]string",
					Required:    false,
				},
				"ports": {
					Description: "Comma-separated list of UDP ports (e.g., '53,161,123').",
					Type:        "[]string",
					Required:    false,
					Default:     []string{defaultUDPPorts},
				},
				"timeout": {
					Description: "Timeout for UDP response (e.g., '2s').",
					Type:        "duration",
					Required:    false,
					Default:     defaultUDPPortDiscoveryTimeout.String(),
				},
				"concurrency": {
					Description: "Number of concurrent UDP scanning goroutines.",
					Type:        "int",
					Required:    false,
					Default:     defaultUDPConcurrency,
				},
				"max_retries": {
					Description: "Maximum retry attempts for ambiguous responses.",
					Type:        "int",
					Required:    false,
					Default:     defaultUDPMaxRetries,
				},
			},
			EstimatedCost: 3, // UDP scanning is slower than TCP
		},
		config: defaultConfig,
	}
}

// getDefaultUDPPayloads returns protocol-specific UDP payloads for common services.
func getDefaultUDPPayloads() map[int][]byte {
	return map[int][]byte{
		// DNS (53): Standard DNS query for version.bind TXT
		53: {
			0x00, 0x00, // Transaction ID
			0x01, 0x00, // Flags: Standard query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer/Authority/Additional RRs: 0
			0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, // "version"
			0x04, 0x62, 0x69, 0x6e, 0x64, // "bind"
			0x00,       // Root
			0x00, 0x10, // Type: TXT
			0x00, 0x03, // Class: CHAOS
		},

		// SNMP (161): SNMPv1 GetRequest for sysDescr
		161: {
			0x30, 0x26, // SEQUENCE, length 38
			0x02, 0x01, 0x00, // INTEGER, version 0 (SNMPv1)
			0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // OCTET STRING, "public"
			0xa0, 0x19, // GetRequest PDU
			0x02, 0x01, 0x01, // Request ID: 1
			0x02, 0x01, 0x00, // Error status: 0
			0x02, 0x01, 0x00, // Error index: 0
			0x30, 0x0e, // Variable bindings
			0x30, 0x0c, // Variable binding
			0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
			0x05, 0x00, // NULL
		},

		// NTP (123): NTP version 3 client request
		123: {
			0x1b, // LI=0, VN=3, Mode=3 (client)
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},

		// Syslog (514): Simple syslog message
		514: []byte("<34>1 - - - - - - Test"), // Priority 34, version 1

		// UPnP SSDP (1900): M-SEARCH discovery
		1900: []byte("M-SEARCH * HTTP/1.1\r\n" +
			"HOST: 239.255.255.250:1900\r\n" +
			"MAN: \"ssdp:discover\"\r\n" +
			"MX: 1\r\n" +
			"ST: ssdp:all\r\n\r\n"),
	}
}

// Metadata returns the module's metadata.
func (m *UDPPortDiscoveryModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

// Init initializes the module with the given configuration map.
func (m *UDPPortDiscoveryModule) Init(instanceID string, moduleConfig map[string]any) error {
	cfg := m.config

	m.meta.ID = instanceID

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
			log.Warn().Str("module", m.meta.Name).Msgf("Invalid timeout format '%s', using default: %s", timeoutStr, cfg.Timeout)
		}
	}
	if concurrencyVal, ok := moduleConfig["concurrency"]; ok {
		cfg.Concurrency = cast.ToInt(concurrencyVal)
		if cfg.Concurrency < 1 {
			log.Warn().Str("module", m.meta.Name).Msgf("Concurrency < 1 (%d), using default: %d", cfg.Concurrency, defaultUDPConcurrency)
			cfg.Concurrency = defaultUDPConcurrency
		}
	}
	if retriesVal, ok := moduleConfig["max_retries"]; ok {
		cfg.MaxRetries = cast.ToInt(retriesVal)
		if cfg.MaxRetries < 0 {
			cfg.MaxRetries = defaultUDPMaxRetries
		}
	}

	// Sanitize
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultUDPPortDiscoveryTimeout
	}
	if len(cfg.Ports) == 0 || (len(cfg.Ports) == 1 && strings.TrimSpace(cfg.Ports[0]) == "") {
		cfg.Ports = []string{defaultUDPPorts}
	}

	m.config = cfg
	log.Debug().Str("module", m.meta.Name).Str("instance_id", m.meta.ID).Interface("config", m.config).Msg("UDP module initialized")
	return nil
}

// Execute performs UDP port discovery.
//
//nolint:gocyclo // Complexity inherited from TCP implementation
func (m *UDPPortDiscoveryModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	var targetsToScan []string

	logger := log.With().Str("module", m.meta.Name).Str("instance_id", m.meta.ID).Logger()

	// Determine targets
	if liveHosts, ok := inputs["discovery.live_hosts"].(ICMPPingDiscoveryResult); ok && len(liveHosts.LiveHosts) > 0 {
		targetsToScan = append(targetsToScan, liveHosts.LiveHosts...)
		logger.Debug().Msgf("Using %d live hosts from input", len(targetsToScan))
	} else if configTargets, ok := inputs["config.targets"].([]string); ok && len(configTargets) > 0 {
		targetsToScan = netutil.ParseAndExpandTargets(configTargets)
		logger.Debug().Msgf("Using %d targets from config, expanded to %d IPs", len(configTargets), len(targetsToScan))
	} else if len(m.config.Targets) > 0 {
		targetsToScan = netutil.ParseAndExpandTargets(m.config.Targets)
		logger.Debug().Msgf("Using %d targets from module config, expanded to %d IPs", len(m.config.Targets), len(targetsToScan))
	} else {
		err := fmt.Errorf("module '%s': no targets specified", m.meta.Name)
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
		logger.Info().Msg("Effective target list is empty, nothing to scan")
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        m.meta.Produces[0].Key,
			Data:           []UDPPortDiscoveryResult{},
			Timestamp:      time.Now(),
		}
		return nil
	}
	if len(parsedPorts) == 0 {
		logger.Info().Msg("Effective port list is empty, nothing to scan")
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        m.meta.Produces[0].Key,
			Data:           []UDPPortDiscoveryResult{},
			Timestamp:      time.Now(),
		}
		return nil
	}

	logger.Info().Msgf("Starting UDP Port Discovery for %d targets on %d ports. Concurrency: %d, Timeout: %s",
		len(targetsToScan), len(parsedPorts), m.config.Concurrency, m.config.Timeout)

	var wg sync.WaitGroup
	sem := make(chan struct{}, m.config.Concurrency)

	// Results by target
	resultsByTarget := make(map[string]*UDPPortDiscoveryResult)
	var mapMutex sync.Mutex

	batchSize := 10
	for i := 0; i < len(targetsToScan); i += batchSize {
		end := i + batchSize
		end = min(end, len(targetsToScan))
		ipBatch := targetsToScan[i:end]

		logger.Debug().Msgf("Scanning UDP batch: %v", ipBatch)

		for _, targetIP := range ipBatch {
			for _, port := range parsedPorts {
				// Check context cancellation
				select {
				case <-ctx.Done():
					logger.Info().Msg("Context canceled, aborting UDP scan")
					goto endLoops
				default:
				}

				wg.Add(1)
				go func(ip string, p int) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					// Check context inside goroutine
					select {
					case <-ctx.Done():
						return
					default:
					}

					// Probe UDP port
					response, isOpen := m.probeUDPPort(ctx, ip, p)

					mapMutex.Lock()
					if _, exists := resultsByTarget[ip]; !exists {
						resultsByTarget[ip] = &UDPPortDiscoveryResult{
							Target:        ip,
							OpenPorts:     []int{},
							FilteredPorts: []int{},
							Responses:     make(map[int]string),
						}
					}

					if isOpen {
						resultsByTarget[ip].OpenPorts = append(resultsByTarget[ip].OpenPorts, p)
						if response != "" {
							resultsByTarget[ip].Responses[p] = response
						}

						// Real-time output
						if out, ok := ctx.Value(output.OutputKey).(output.Output); ok {
							out.Diag(output.LevelNormal, fmt.Sprintf("Open UDP port: %s:%d/udp", ip, p), nil)
						}
					} else {
						// Mark as filtered (no response, could be closed or filtered)
						resultsByTarget[ip].FilteredPorts = append(resultsByTarget[ip].FilteredPorts, p)
					}
					mapMutex.Unlock()
				}(targetIP, port)
			}
		}

		wg.Wait()
		logger.Debug().Msgf("Completed UDP batch: %v", ipBatch)
	}

endLoops:
	wg.Wait()

	// Send results
	for target, result := range resultsByTarget {
		if len(result.OpenPorts) > 0 || len(result.FilteredPorts) > 0 {
			outputChan <- engine.ModuleOutput{
				FromModuleName: m.meta.ID,
				DataKey:        m.meta.Produces[0].Key,
				Data:           *result,
				Timestamp:      time.Now(),
				Target:         target,
			}
			logger.Info().
				Str("target", target).
				Ints("open_ports", result.OpenPorts).
				Ints("filtered_ports", result.FilteredPorts).
				Msgf("Target %s - Open: %v, Filtered: %v", target, result.OpenPorts, result.FilteredPorts)
		}
	}

	logger.Info().Msg("UDP Port Discovery completed")
	return nil
}

// probeUDPPort sends protocol-specific payload and waits for response.
// Returns (response_data, is_open).
func (m *UDPPortDiscoveryModule) probeUDPPort(ctx context.Context, ip string, port int) (string, bool) {
	address := net.JoinHostPort(ip, strconv.Itoa(port))

	// Get payload for this port (or use empty payload)
	payload, ok := m.config.PayloadCatalog[port]
	if !ok {
		payload = []byte{} // Empty payload for unknown ports
	}

	// Try multiple times (UDP packet loss)
	for attempt := 0; attempt <= m.config.MaxRetries; attempt++ {
		// Check context
		select {
		case <-ctx.Done():
			return "", false
		default:
		}

		conn, err := net.Dial("udp", address)
		if err != nil {
			return "", false
		}
		defer func() { _ = conn.Close() }() //nolint:errcheck // Best-effort close

		// Set deadline
		if err := conn.SetDeadline(time.Now().Add(m.config.Timeout)); err != nil {
			return "", false
		}

		// Send payload
		if len(payload) > 0 {
			if _, err := conn.Write(payload); err != nil {
				continue // Retry
			}
		}

		// Read response
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			// Got response = port is OPEN
			return string(buf[:n]), true
		}

		// No response, retry
	}

	// After all retries, no response = filtered/closed
	return "", false
}

// UDPPortDiscoveryModuleFactory creates a new UDPPortDiscoveryModule instance.
func UDPPortDiscoveryModuleFactory() engine.Module {
	return newUDPPortDiscoveryModule()
}

func init() {
	engine.RegisterModuleFactory(udpPortDiscoveryModuleTypeName, UDPPortDiscoveryModuleFactory)
}
