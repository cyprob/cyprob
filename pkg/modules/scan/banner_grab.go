// pkg/modules/scan/banner_grab.go
// Package scan provides modules related to active network scanning.
package scan

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cast"

	"github.com/cyprob/cyprob/pkg/engine" // Your engine/core package
	"github.com/cyprob/cyprob/pkg/fingerprint"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"github.com/cyprob/cyprob/pkg/output"
)

// BannerGrabConfig holds configuration for the banner grabbing module.
type BannerGrabConfig struct {
	// Input will typically be PortStatusInfo from PortScanModule
	ReadTimeout           time.Duration `mapstructure:"read_timeout"`             // Timeout for reading banner data from a connection
	ConnectTimeout        time.Duration `mapstructure:"connect_timeout"`          // Timeout for establishing the connection (if re-dialing)
	BufferSize            int           `mapstructure:"buffer_size"`              // Size of the buffer to read banner data
	Concurrency           int           `mapstructure:"concurrency"`              // Number of concurrent banner grabbing operations
	SendProbes            bool          `mapstructure:"send_probes"`              // Whether to send basic probes (e.g., HTTP GET)
	TLSInsecureSkipVerify bool          `mapstructure:"tls_insecure_skip_verify"` // For TLS connections, skip cert verification (not recommended for production)
	// Future: Define specific probes for common ports
	// HTTPProbes     []string      `mapstructure:"http_probes"`  // e.g., ["GET / HTTP/1.1\r\nHost: {HOST}\r\n\r\n", "HEAD / HTTP/1.0\r\n\r\n"]
	// GenericProbes  []string      `mapstructure:"generic_probes"`// e.g., ["\r\n\r\n", "HELP\r\n"]
}

// BannerGrabResult holds the banner information for a specific port.
// This will be the 'Data' in ModuleOutput with DataKey "service.banner.raw".
type BannerGrabResult struct {
	IP                   string                    `json:"ip"`
	ResolvedIP           string                    `json:"resolved_ip,omitempty"`
	ProbeHost            string                    `json:"probe_host,omitempty"`
	SNIServerName        string                    `json:"sni_server_name,omitempty"`
	Port                 int                       `json:"port"`
	Protocol             string                    `json:"protocol"`
	Banner               string                    `json:"banner"`
	IsTLS                bool                      `json:"is_tls"`
	Error                string                    `json:"error,omitempty"`
	ResponseClass        string                    `json:"response_class,omitempty"`
	ProxyResponse        bool                      `json:"proxy_response,omitempty"`
	OriginRetryAttempted bool                      `json:"origin_retry_attempted,omitempty"`
	OriginRetrySuccess   bool                      `json:"origin_retry_success,omitempty"`
	Evidence             []engine.ProbeObservation `json:"evidence,omitempty"`
}

type commandProbeSpec struct {
	ProbeID         string
	Description     string
	Protocol        string
	Commands        []string
	UseTLS          bool
	SkipInitialRead bool
}

// BannerGrabModule attempts to grab banners from open TCP ports.
type BannerGrabModule struct {
	meta   engine.ModuleMetadata
	config BannerGrabConfig
	logger zerolog.Logger
}

type PortInfo struct {
	*discovery.TCPPortDiscoveryResult
}

// newBannerGrabModule is the internal constructor for the BannerGrabModule.
func newBannerGrabModule() *BannerGrabModule {
	defaultConfig := BannerGrabConfig{
		ReadTimeout:           10 * time.Second,
		ConnectTimeout:        5 * time.Second,
		BufferSize:            2048, // Sufficient for binary protocols (SMB/RPC: 256-512 bytes typical)
		Concurrency:           50,
		SendProbes:            true,
		TLSInsecureSkipVerify: true, // Default to skip cert validation for service detection (Phase 1.6)
	}

	return &BannerGrabModule{
		meta: engine.ModuleMetadata{
			ID:          "banner-grab-instance",
			Name:        "banner-grabber",
			Version:     "0.1.0",
			Description: "Grabs banners from open TCP ports, attempting generic and protocol-aware probes.",
			Type:        engine.ScanModuleType,
			Author:      "Vulntor Team",
			Tags:        []string{"scan", "banner", "fingerprint", "tcp"},
			Consumes: []engine.DataContractEntry{
				{
					Key:          "discovery.open_tcp_ports",
					DataTypeName: "discovery.TCPPortDiscoveryResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   false,
					Description:  "List of results, where each item details open TCP ports for a specific target.",
				},
				{
					Key:          "config.original_cli_targets",
					DataTypeName: "[]string",
					Cardinality:  engine.CardinalitySingle,
					IsOptional:   true,
					Description:  "Original CLI targets used to preserve hostname for HTTP Host header during probes.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key:          "service.banner.tcp",
					DataTypeName: "scan.BannerGrabResult",
					Cardinality:  engine.CardinalityList,
					Description:  "List of banners (or errors) captured from TCP services, one result per target/port.",
				},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				"read_timeout":    {Description: "Timeout for reading banner data from an open port (e.g., '3s').", Type: "duration", Required: false, Default: defaultConfig.ReadTimeout.String()},
				"connect_timeout": {Description: "Timeout for establishing connection if re-dialing (e.g., '2s').", Type: "duration", Required: false, Default: defaultConfig.ConnectTimeout.String()},
				"buffer_size":     {Description: "Size of the buffer (in bytes) for reading banner data.", Type: "int", Required: false, Default: defaultConfig.BufferSize},
				"concurrency":     {Description: "Number of concurrent banner grabbing operations.", Type: "int", Required: false, Default: defaultConfig.Concurrency},
				"send_probes":     {Description: "Whether to send protocol-specific probes after passive banner capture.", Type: "bool", Required: false, Default: defaultConfig.SendProbes},
			},
			EstimatedCost: 2,
		},
		config: defaultConfig,
	}
}

// Metadata returns the module's descriptive metadata.
func (m *BannerGrabModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

// Init initializes the module with the given configuration map.
func (m *BannerGrabModule) Init(instanceID string, configMap map[string]any) error {
	m.logger = log.With().Str("module", m.meta.Name).Str("instance_id", m.meta.ID).Logger()

	cfg := m.config

	if readTimeoutStr, ok := configMap["read_timeout"].(string); ok {
		if dur, err := time.ParseDuration(readTimeoutStr); err == nil {
			cfg.ReadTimeout = dur
		} else {
			fmt.Fprintf(os.Stderr, "[WARN] Module '%s': Invalid 'read_timeout': '%s'. Using default: %s\n", m.meta.Name, readTimeoutStr, cfg.ReadTimeout)
		}
	}
	if connectTimeoutStr, ok := configMap["connect_timeout"].(string); ok {
		if dur, err := time.ParseDuration(connectTimeoutStr); err == nil {
			cfg.ConnectTimeout = dur
		} else {
			fmt.Fprintf(os.Stderr, "[WARN] Module '%s': Invalid 'connect_timeout': '%s'. Using default: %s\n", m.meta.Name, connectTimeoutStr, cfg.ConnectTimeout)
		}
	}
	if bufferSizeVal, ok := configMap["buffer_size"]; ok {
		cfg.BufferSize = cast.ToInt(bufferSizeVal)
	}
	if concurrencyVal, ok := configMap["concurrency"]; ok {
		cfg.Concurrency = cast.ToInt(concurrencyVal)
	}
	if sendProbesVal, ok := configMap["send_probes"]; ok {
		cfg.SendProbes = cast.ToBool(sendProbesVal)
	}
	if tlsInsecureSkipVerify, ok := configMap["tls_insecure_skip_verify"].(bool); ok {
		cfg.TLSInsecureSkipVerify = cast.ToBool(tlsInsecureSkipVerify)
	}

	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 10 * time.Second
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 5 * time.Second
	}
	if cfg.BufferSize <= 0 || cfg.BufferSize > 16384 {
		cfg.BufferSize = 2048
	}
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}

	m.config = cfg
	m.logger.Debug().Interface("final_config", m.config).Msgf("Module initialized.")
	return nil
}

// TargetPortData represents a target IP and a port to scan.
type TargetPortData struct {
	Target     string
	ProbeHost  string
	OriginHost string
	Port       int
}

// Execute attempts to grab banners from open ports.
// It consumes 'discovery.open_tcp_ports' which should be of type PortStatusInfo.
//
//nolint:gocyclo // Complexity inherited from existing implementation
func (m *BannerGrabModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	m.logger.Debug().Interface("received_inputs", inputs).Msg("Executing module")

	var scanTasks []TargetPortData
	originalTargets := readOriginalTargets(inputs)
	originHostOverride := resolveProbeHostOverride(originalTargets)

	if rawOpenTCPPorts, ok := inputs["discovery.open_tcp_ports"]; ok {
		m.logger.Debug().Type("type", rawOpenTCPPorts).Msg("Found 'discovery.open_tcp_ports' in inputs")
		if openTCPPortsList, listOk := rawOpenTCPPorts.([]any); listOk {
			for _, item := range openTCPPortsList {
				if portResult, castOk := item.(discovery.TCPPortDiscoveryResult); castOk {
					originHost := normalizeNonIPHostname(portResult.Hostname)
					if originHost == "" {
						originHost = originHostOverride
					}
					probeHost := portResult.Target
					if originHost != "" {
						probeHost = originHost
					}
					for _, port := range portResult.OpenPorts {
						scanTasks = append(scanTasks, TargetPortData{
							Target:     portResult.Target,
							ProbeHost:  probeHost,
							OriginHost: originHost,
							Port:       port,
						})
					}
				} else {
					m.logger.Warn().Type("item_type", item).Msg("Item in 'discovery.open_tcp_ports' list is not of expected type discovery.TCPPortDiscoveryResult")
				}
			}
			m.logger.Info().Int("num_target_port_pairs", len(scanTasks)).Msg("Targets and ports loaded from 'discovery.open_tcp_ports' input")
		} else {
			m.logger.Warn().Type("type", rawOpenTCPPorts).Msg("'discovery.open_tcp_ports' input is not a list as expected")
		}
	} else {
		m.logger.Warn().Msg("'discovery.open_tcp_ports' not found in inputs. Banner grabbing will be limited or skipped unless targets/ports provided via other means (not fully implemented in this example).")
	}

	if len(scanTasks) == 0 {
		m.logger.Info().Msg("No target/port pairs to grab banners from. Module execution complete.")
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        m.meta.Produces[0].Key,
			Data:           []BannerGrabResult{},
			Timestamp:      time.Now(),
		}
		return nil
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, m.config.Concurrency)
	var resultsMu sync.Mutex
	grabbedBanners := make([]BannerGrabResult, 0, len(scanTasks))

	m.logger.Info().Int("tasks", len(scanTasks)).Int("concurrency", m.config.Concurrency).Msg("Starting banner grabbing")

	for _, task := range scanTasks {
		select {
		case <-ctx.Done():
			m.logger.Info().Msg("Context canceled. Aborting further banner grabbing.")
			goto endLoop
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(currentTarget string, currentProbeHost string, currentOriginHost string, currentPort int) {
			defer wg.Done()
			defer func() { <-sem }()

			result := m.runProbes(ctx, currentTarget, currentProbeHost, currentOriginHost, currentPort)

			// Real-time output: Emit banner grab result to user
			if out, ok := ctx.Value(output.OutputKey).(output.Output); ok && result.Banner != "" {
				// Success case: banner captured
				message := fmt.Sprintf("Banner captured: %s:%d -> %s",
					currentTarget, currentPort, strings.TrimSpace(result.Banner[:min(60, len(result.Banner))]))
				if len(result.Banner) > 60 {
					message += "..."
				}
				out.Diag(output.LevelVerbose, message, nil)
			} else if out != nil && result.Error != "" {
				// Error case: banner grab failed
				out.Diag(output.LevelVerbose, fmt.Sprintf("Banner grab failed: %s:%d - %s",
					currentTarget, currentPort, result.Error), nil)
			}

			resultsMu.Lock()
			grabbedBanners = append(grabbedBanners, result)
			resultsMu.Unlock()

			select {
			case outputChan <- engine.ModuleOutput{
				FromModuleName: m.meta.ID,
				DataKey:        m.meta.Produces[0].Key,
				Target:         currentTarget,
				Data:           result,
				Timestamp:      time.Now(),
			}:
			case <-ctx.Done():
				return
			}
		}(task.Target, task.ProbeHost, task.OriginHost, task.Port)
	}

endLoop:
	wg.Wait()
	m.logger.Info().Int("results", len(grabbedBanners)).Msg("Service banner scanning completed.")

	return nil
}

// runActiveProbes executes active probes against the target port.
// Extracted from runProbes to reduce cyclomatic complexity.
func (m *BannerGrabModule) runActiveProbes(
	ctx context.Context,
	target string,
	probeHost string,
	originHost string,
	port int,
	catalog *fingerprint.ProbeCatalog,
	observations *[]engine.ProbeObservation,
	lastError *string,
	hintAcc *hintAccumulator,
) {
	candidateProbes := catalog.ProbesFor(port, hintAcc.slice())

	// Phase 1.5: Probe Fallback for non-standard ports
	// If no port-specific probes matched AND we still do not have a usable primary banner,
	// try fallback probes for non-standard ports.
	if len(candidateProbes) == 0 && selectPrimaryBannerObservation(*observations).Banner == "" {
		candidateProbes = catalog.FallbackProbes()
		if len(candidateProbes) > 0 {
			m.logger.Debug().
				Int("port", port).
				Int("fallback_probes", len(candidateProbes)).
				Msg("No port-specific probes found, trying fallback probes for non-standard port")
		}
	}

	seen := make(map[string]struct{}, len(candidateProbes))
	originRetryDone := false
	connectRetryDone := false

	for _, spec := range candidateProbes {
		if ctx.Err() != nil {
			break
		}
		if _, exists := seen[spec.ID]; exists {
			continue
		}
		seen[spec.ID] = struct{}{}

		obs := m.executeProbeSpec(ctx, target, probeHost, port, spec)
		if respHint := protocolHintFromBanner(obs.Response); respHint != "" {
			hintAcc.add(respHint)
		}
		classifyHTTPProbeObservation(&obs)

		if !originRetryDone && shouldAttemptOriginRetry(spec, obs, originHost, port) {
			obs.OriginRetryAttempted = true
			retryObs := m.runOriginRetry(ctx, target, originHost, port, spec)
			retryObs.OriginRetryAttempted = true
			if respHint := protocolHintFromBanner(retryObs.Response); respHint != "" {
				hintAcc.add(respHint)
			}
			classifyHTTPProbeObservation(&retryObs)
			if retryObs.Response != "" && !retryObs.ProxyResponse {
				obs.OriginRetrySuccess = true
				retryObs.OriginRetrySuccess = true
				obs.ResponseClass = "proxy"
				if retryObs.ProxyResponse {
					retryObs.ResponseClass = "proxy"
				}
				m.collectObservation(observations, obs, lastError)
				m.collectObservation(observations, retryObs, lastError)
			} else if !connectRetryDone && shouldAttemptConnectTunnelRetry(spec, obs, retryObs, originHost, port) {
				connectObs := m.runConnectTunnelOriginRetry(ctx, target, originHost, port)
				connectObs.OriginRetryAttempted = true
				if respHint := protocolHintFromBanner(connectObs.Response); respHint != "" {
					hintAcc.add(respHint)
				}
				classifyHTTPProbeObservation(&connectObs)
				if connectObs.Response != "" && !connectObs.ProxyResponse && connectObs.Error == "" {
					obs.OriginRetrySuccess = true
					retryObs.OriginRetrySuccess = true
					connectObs.OriginRetrySuccess = true
					obs.ResponseClass = "proxy"
					if retryObs.ProxyResponse {
						retryObs.ResponseClass = "proxy"
					}
				} else {
					obs.ResponseClass = "proxy_only"
					if retryObs.ProxyResponse {
						retryObs.ResponseClass = "proxy_only"
					}
				}
				m.collectObservation(observations, obs, lastError)
				m.collectObservation(observations, retryObs, lastError)
				m.collectObservation(observations, connectObs, lastError)
				connectRetryDone = true
			} else {
				obs.ResponseClass = "proxy_only"
				if retryObs.ProxyResponse {
					retryObs.ResponseClass = "proxy_only"
				}
				m.collectObservation(observations, obs, lastError)
				m.collectObservation(observations, retryObs, lastError)
			}
			originRetryDone = true
		} else {
			m.collectObservation(observations, obs, lastError)
		}

		// Phase 1.9: Early exit optimization
		// If we got a usable banner with no error, stop probing
		if selection := selectPrimaryBannerObservation(*observations); selection.Banner != "" && *lastError == "" && !shouldKeepTLSFallbackProbing(port, selection) {
			m.logger.Debug().
				Str("probe_id", obs.ProbeID).
				Int("port", port).
				Int("remaining_probes", len(candidateProbes)-len(seen)).
				Msg("Early exit: usable banner found, skipping remaining probes")
			break
		}
	}
}

func (m *BannerGrabModule) runProbes(ctx context.Context, target string, probeHost string, originHost string, port int) BannerGrabResult {
	observations := make([]engine.ProbeObservation, 0, 8)
	var lastError string

	passive := m.runPassiveProbe(ctx, target, port)
	hintAcc := newHintAccumulator()

	catalog, catalogErr := fingerprint.GetProbeCatalog()
	if catalogErr != nil {
		m.logger.Warn().Err(catalogErr).Msg("failed to load probe catalog; continuing with passive banner only")
	} else {
		hintAcc.addAll(portHintsFromCatalog(catalog, port))
	}

	if respHint := protocolHintFromBanner(passive.Response); respHint != "" {
		hintAcc.add(respHint)
	}

	classifyHTTPProbeObservation(&passive)
	m.collectObservation(&observations, passive, &lastError)

	if m.config.SendProbes && ctx.Err() == nil && catalogErr == nil {
		m.runActiveProbes(ctx, target, probeHost, originHost, port, catalog, &observations, &lastError, &hintAcc)
	}
	selection := selectPrimaryBannerObservation(observations)

	result := BannerGrabResult{
		IP:                   target,
		ResolvedIP:           target,
		ProbeHost:            probeHost,
		Port:                 port,
		Protocol:             "tcp",
		Banner:               strings.TrimSpace(selection.Banner),
		IsTLS:                selection.IsTLS,
		ResponseClass:        selection.ResponseClass,
		ProxyResponse:        selection.ProxyResponse,
		OriginRetryAttempted: selection.OriginRetryAttempted,
		OriginRetrySuccess:   selection.OriginRetrySuccess,
		Evidence:             observations,
	}
	if shouldExposeSNI(observations) {
		result.SNIServerName = chooseTLSServerName(resolvePreferredHost(originHost, probeHost), target)
	}

	if result.Banner == "" && lastError != "" {
		result.Error = lastError
	}

	return result
}

func (m *BannerGrabModule) collectObservation(observations *[]engine.ProbeObservation, obs engine.ProbeObservation, lastError *string) {
	if obs.ProbeID == "" {
		return
	}

	if obs.Response != "" {
		trimmed := strings.TrimSpace(obs.Response)
		obs.Response = trimmed
		if trimmed != "" {
			if obs.Error == "" {
				*lastError = ""
			}
		}
	}

	if obs.Error != "" {
		*lastError = obs.Error
	}

	*observations = append(*observations, obs)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (m *BannerGrabModule) runOriginRetry(ctx context.Context, dialHost string, originHost string, port int, spec fingerprint.ProbeSpec) engine.ProbeObservation {
	commands := prepareProbeCommands(spec, originHost, port)
	return m.runCommandProbe(ctx, dialHost, originHost, port, commandProbeSpec{
		ProbeID:         spec.ID + "-origin",
		Description:     strings.TrimSpace(spec.Description + " (origin retry)"),
		Protocol:        spec.Protocol,
		Commands:        commands,
		UseTLS:          spec.UseTLS,
		SkipInitialRead: spec.SkipInitialRead,
	})
}

func (m *BannerGrabModule) runConnectTunnelOriginRetry(ctx context.Context, dialHost string, originHost string, port int) engine.ProbeObservation {
	obs := engine.ProbeObservation{
		ProbeID:     "https-connect-origin",
		Description: "HTTP CONNECT tunnel origin retry",
		Protocol:    "https",
		IsTLS:       true,
	}

	address := net.JoinHostPort(dialHost, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: m.config.ConnectTimeout}
	start := time.Now()

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		obs.Duration = time.Since(start)
		obs.Error = classifyConnectTunnelError(err)
		return obs
	}
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	if err := conn.SetWriteDeadline(time.Now().Add(m.config.ConnectTimeout)); err != nil {
		obs.Duration = time.Since(start)
		obs.Error = classifyConnectTunnelError(err)
		return obs
	}

	if _, err := conn.Write([]byte(buildConnectRequest(originHost, port))); err != nil {
		obs.Duration = time.Since(start)
		obs.Error = classifyConnectTunnelError(err)
		return obs
	}

	connectResp, analysis, err := m.readHTTPHeaderBlock(ctx, conn, reader)
	if err != nil {
		if connectResp != "" {
			obs.Response = strings.TrimSpace(connectResp)
		}
		obs.Duration = time.Since(start)
		obs.Error = classifyConnectTunnelError(err)
		return obs
	}
	if !analysis.IsHTTP {
		if connectResp != "" {
			obs.Response = strings.TrimSpace(connectResp)
		}
		obs.Duration = time.Since(start)
		obs.Error = "connect_tunnel_failed"
		return obs
	}
	if analysis.StatusCode != http.StatusOK {
		if connectResp != "" {
			obs.Response = strings.TrimSpace(connectResp)
		}
		obs.Duration = time.Since(start)
		obs.Error = classifyConnectTunnelStatus(analysis.StatusCode)
		return obs
	}

	serverName := chooseTLSServerName(originHost, dialHost)
	tlsConn := tls.Client(&bufferedConn{Conn: conn, reader: reader}, &tls.Config{
		InsecureSkipVerify: m.config.TLSInsecureSkipVerify,
		ServerName:         serverName,
	})
	if err := tlsConn.SetDeadline(time.Now().Add(m.config.ReadTimeout)); err != nil {
		obs.Duration = time.Since(start)
		obs.Error = classifyConnectTunnelError(err)
		return obs
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		obs.Duration = time.Since(start)
		obs.Error = classifyConnectTunnelError(err)
		return obs
	}
	obs.TLS = extractTLSObservation(tlsConn.ConnectionState())

	if _, err := tlsConn.Write([]byte(buildCanonicalGETRequest(originHost))); err != nil {
		obs.Duration = time.Since(start)
		obs.Error = classifyConnectTunnelError(err)
		return obs
	}
	resp, err := m.readProbeResponse(ctx, tlsConn)
	obs.Duration = time.Since(start)
	if resp != "" {
		obs.Response = strings.TrimSpace(resp)
	}
	if err != nil && err != io.EOF {
		obs.Error = classifyConnectTunnelError(err)
		return obs
	}
	if obs.Response == "" {
		obs.Error = "connect_tunnel_failed"
	}
	return obs
}

func shouldAttemptOriginRetry(spec fingerprint.ProbeSpec, obs engine.ProbeObservation, originHost string, port int) bool {
	if strings.TrimSpace(originHost) == "" || net.ParseIP(strings.TrimSpace(originHost)) != nil {
		return false
	}
	if !obs.ProxyResponse {
		return false
	}
	if port != 80 && port != 443 && !strings.EqualFold(spec.Protocol, "http") && !strings.EqualFold(spec.Protocol, "https") {
		return false
	}
	switch spec.ID {
	case "http-get", "https-get":
		return true
	}
	return strings.EqualFold(spec.Protocol, "http") || strings.EqualFold(spec.Protocol, "https")
}

func shouldAttemptConnectTunnelRetry(spec fingerprint.ProbeSpec, initialObs engine.ProbeObservation, retryObs engine.ProbeObservation, originHost string, port int) bool {
	if strings.TrimSpace(originHost) == "" || net.ParseIP(strings.TrimSpace(originHost)) != nil {
		return false
	}
	if !isLikelyTLSPort(port) {
		return false
	}
	switch spec.ID {
	case "http-get", "https-get":
	default:
		if !strings.EqualFold(spec.Protocol, "http") && !strings.EqualFold(spec.Protocol, "https") {
			return false
		}
	}
	if retryObs.Response != "" && !retryObs.ProxyResponse {
		return false
	}
	return initialObs.ProxyResponse || retryObs.ProxyResponse
}

func classifyHTTPProbeObservation(obs *engine.ProbeObservation) {
	if obs == nil {
		return
	}
	analysis := analyzeHTTPResponse(obs.Response)
	if !analysis.IsHTTP {
		return
	}
	if isHTTPProxyResponse(analysis) {
		obs.ProxyResponse = true
		if obs.ResponseClass == "" {
			obs.ResponseClass = "proxy_only"
		}
		return
	}
	obs.ProxyResponse = false
	if obs.ResponseClass == "" {
		obs.ResponseClass = "origin"
	}
}

type bannerSelection struct {
	ProbeID              string
	Banner               string
	IsTLS                bool
	ResponseClass        string
	ProxyResponse        bool
	OriginRetryAttempted bool
	OriginRetrySuccess   bool
}

func selectPrimaryBannerObservation(observations []engine.ProbeObservation) bannerSelection {
	selection := bannerSelection{}
	bestScore := -1
	sawProxy := false

	for _, obs := range observations {
		if obs.OriginRetryAttempted {
			selection.OriginRetryAttempted = true
		}
		if obs.OriginRetrySuccess {
			selection.OriginRetrySuccess = true
		}

		response := strings.TrimSpace(obs.Response)
		if response == "" {
			continue
		}

		if obs.ProxyResponse || obs.ResponseClass == "proxy" || obs.ResponseClass == "proxy_only" {
			sawProxy = true
			continue
		}

		score := bannerObservationScore(obs)
		if score < bestScore {
			continue
		}

		bestScore = score
		selection.ProbeID = obs.ProbeID
		selection.Banner = response
		selection.IsTLS = obs.IsTLS
		selection.ResponseClass = obs.ResponseClass
		selection.ProxyResponse = false
	}

	if selection.Banner == "" && sawProxy {
		selection.ResponseClass = "proxy_only"
		selection.ProxyResponse = true
	}

	return selection
}

func shouldKeepTLSFallbackProbing(port int, selection bannerSelection) bool {
	if selection.Banner == "" {
		return false
	}
	if !isLikelyTLSPort(port) {
		return false
	}
	return strings.HasPrefix(selection.ProbeID, "http-get")
}

func bannerObservationScore(obs engine.ProbeObservation) int {
	score := 0
	if obs.ResponseClass == "origin" {
		score += 100
	}
	switch {
	case strings.HasPrefix(obs.ProbeID, "https"):
		score += 40
	case strings.HasPrefix(obs.ProbeID, "http"):
		score += 30
	case obs.ProbeID != "tcp-passive":
		score += 10
	}
	if obs.IsTLS {
		score += 5
	}
	return score
}

func isLikelyTLSPort(port int) bool {
	switch port {
	case 443, 8443, 9443, 10443:
		return true
	default:
		return false
	}
}

type httpResponseAnalysis struct {
	IsHTTP     bool
	StatusCode int
	Headers    map[string]string
	Body       string
}

func analyzeHTTPResponse(response string) httpResponseAnalysis {
	response = strings.TrimSpace(response)
	if response == "" {
		return httpResponseAnalysis{}
	}

	headerBlock := response
	body := ""
	switch {
	case strings.Contains(response, "\r\n\r\n"):
		parts := strings.SplitN(response, "\r\n\r\n", 2)
		headerBlock, body = parts[0], parts[1]
	case strings.Contains(response, "\n\n"):
		parts := strings.SplitN(response, "\n\n", 2)
		headerBlock, body = parts[0], parts[1]
	}

	lines := strings.Split(headerBlock, "\n")
	if len(lines) == 0 {
		return httpResponseAnalysis{}
	}

	statusLine := strings.TrimSpace(lines[0])
	if !strings.HasPrefix(strings.ToUpper(statusLine), "HTTP/") {
		return httpResponseAnalysis{}
	}

	analysis := httpResponseAnalysis{
		IsHTTP:  true,
		Headers: make(map[string]string, len(lines)),
		Body:    strings.ToLower(body),
	}

	fields := strings.Fields(statusLine)
	if len(fields) >= 2 {
		if code, err := strconv.Atoi(fields[1]); err == nil {
			analysis.StatusCode = code
		}
	}

	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		value := strings.ToLower(strings.TrimSpace(line[idx+1:]))
		if key == "" || value == "" {
			continue
		}
		analysis.Headers[key] = value
	}

	return analysis
}

func isHTTPProxyResponse(analysis httpResponseAnalysis) bool {
	if !analysis.IsHTTP {
		return false
	}

	if via := analysis.Headers["via"]; via != "" && (strings.Contains(via, "proxy") || strings.Contains(via, "forward")) {
		return true
	}

	for _, key := range []string{"proxy-agent", "proxy-connection", "proxy-authenticate", "x-squid-error"} {
		if analysis.Headers[key] != "" {
			return true
		}
	}

	combined := strings.Join([]string{
		analysis.Headers["server"],
		analysis.Headers["via"],
		analysis.Headers["warning"],
		analysis.Body,
	}, "\n")

	for _, needle := range []string{
		"forward.http.proxy",
		"forward proxy",
		"proxy-generated",
		"this is a proxy server",
		"generated by proxy",
	} {
		if strings.Contains(combined, needle) {
			return true
		}
	}

	if analysis.StatusCode == 407 {
		return true
	}

	return analysis.StatusCode >= 500 && strings.Contains(combined, "proxy")
}

func (m *BannerGrabModule) readHTTPHeaderBlock(ctx context.Context, conn net.Conn, reader *bufio.Reader) (string, httpResponseAnalysis, error) {
	var builder strings.Builder

	for builder.Len() < m.config.BufferSize {
		if ctx.Err() != nil {
			return builder.String(), httpResponseAnalysis{}, ctx.Err()
		}
		if err := conn.SetReadDeadline(time.Now().Add(m.config.ReadTimeout)); err != nil {
			return builder.String(), httpResponseAnalysis{}, err
		}

		b, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return builder.String(), httpResponseAnalysis{}, err
		}
		builder.WriteByte(b)

		data := builder.String()
		if strings.Contains(data, "\r\n\r\n") || strings.Contains(data, "\n\n") {
			break
		}
	}

	header := builder.String()
	return header, analyzeHTTPResponse(header), nil
}

func buildConnectRequest(host string, port int) string {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	return strings.Join([]string{
		fmt.Sprintf("CONNECT %s HTTP/1.1", target),
		fmt.Sprintf("Host: %s", target),
		"User-Agent: vulntor-probe/1.0",
		"Proxy-Connection: keep-alive",
		"",
		"",
	}, "\r\n")
}

func classifyConnectTunnelError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		return "connect_timeout"
	case strings.Contains(msg, "connection refused"):
		return "connect_refused"
	default:
		return "connect_tunnel_failed"
	}
}

func classifyConnectTunnelStatus(statusCode int) string {
	switch statusCode {
	case http.StatusForbidden, http.StatusMethodNotAllowed, http.StatusProxyAuthRequired:
		return "connect_refused"
	default:
		return "connect_tunnel_failed"
	}
}

func (m *BannerGrabModule) runPassiveProbe(ctx context.Context, target string, port int) engine.ProbeObservation {
	obs := engine.ProbeObservation{
		ProbeID:     "tcp-passive",
		Description: "Initial TCP banner read",
		Protocol:    "tcp",
	}

	banner, duration, err := m.grabGenericBanner(ctx, target, port)
	obs.Duration = duration
	obs.Response = banner
	if err != nil {
		obs.Error = err.Error()
	}

	return obs
}

func (m *BannerGrabModule) executeProbeSpec(ctx context.Context, dialHost string, probeHost string, port int, spec fingerprint.ProbeSpec) engine.ProbeObservation {
	commands := prepareProbeCommands(spec, probeHost, port)
	cmdSpec := commandProbeSpec{
		ProbeID:         spec.ID,
		Description:     spec.Description,
		Protocol:        spec.Protocol,
		Commands:        commands,
		UseTLS:          spec.UseTLS,
		SkipInitialRead: spec.SkipInitialRead,
	}
	return m.runCommandProbe(ctx, dialHost, probeHost, port, cmdSpec)
}

func (m *BannerGrabModule) runCommandProbe(ctx context.Context, dialHost string, probeHost string, port int, spec commandProbeSpec) engine.ProbeObservation {
	obs := engine.ProbeObservation{
		ProbeID:     spec.ProbeID,
		Description: spec.Description,
		Protocol:    spec.Protocol,
		IsTLS:       spec.UseTLS,
	}

	address := net.JoinHostPort(dialHost, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: m.config.ConnectTimeout}
	start := time.Now()

	var (
		conn    net.Conn
		err     error
		tlsInfo *engine.TLSObservation
	)

	if spec.UseTLS {
		serverName := chooseTLSServerName(probeHost, dialHost)
		var tlsConn *tls.Conn
		tlsConn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			InsecureSkipVerify: m.config.TLSInsecureSkipVerify,
			ServerName:         serverName,
		})
		if err == nil {
			tlsInfo = extractTLSObservation(tlsConn.ConnectionState())
			conn = tlsConn
		}
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}

	if err != nil {
		obs.Duration = time.Since(start)
		obs.Error = err.Error()
		return obs
	}
	defer func() { _ = conn.Close() }()

	if tlsInfo != nil {
		obs.TLS = tlsInfo
	}

	responses := make([]string, 0, len(spec.Commands)+1)
	if !spec.SkipInitialRead {
		initial, readErr := m.readProbeResponse(ctx, conn)
		if initial != "" {
			responses = append(responses, initial)
		}
		if readErr != nil && readErr != io.EOF && ctx.Err() == nil {
			obs.Error = readErr.Error()
		}
	}

	for _, cmd := range spec.Commands {
		if ctx.Err() != nil {
			obs.Error = ctx.Err().Error()
			break
		}
		if _, writeErr := conn.Write([]byte(cmd)); writeErr != nil {
			obs.Error = writeErr.Error()
			break
		}
		resp, rErr := m.readProbeResponse(ctx, conn)
		if resp != "" {
			responses = append(responses, resp)
		}
		if rErr != nil && rErr != io.EOF && ctx.Err() == nil {
			obs.Error = rErr.Error()
			break
		}
	}

	obs.Duration = time.Since(start)

	if len(responses) > 0 {
		obs.Response = strings.TrimSpace(strings.Join(responses, "\n"))
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		obs.Error = ctxErr.Error()
	}

	return obs
}

func (m *BannerGrabModule) grabGenericBanner(ctx context.Context, host string, port int) (string, time.Duration, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: m.config.ConnectTimeout}
	start := time.Now()

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", time.Since(start), err
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetReadDeadline(time.Now().Add(m.config.ReadTimeout)); err != nil {
		return "", time.Since(start), err
	}

	reader := bufio.NewReader(conn)
	buffer := make([]byte, m.config.BufferSize)
	n, readErr := reader.Read(buffer)
	duration := time.Since(start)

	if ctx.Err() != nil {
		return "", duration, ctx.Err()
	}
	if readErr != nil && readErr != io.EOF {
		return "", duration, readErr
	}
	if n == 0 {
		return "", duration, nil
	}

	return string(buffer[:n]), duration, nil
}

func (m *BannerGrabModule) readProbeResponse(ctx context.Context, conn net.Conn) (string, error) {
	buffer := make([]byte, m.config.BufferSize)
	var builder strings.Builder

	for {
		if ctx.Err() != nil {
			return builder.String(), ctx.Err()
		}

		if err := conn.SetReadDeadline(time.Now().Add(m.config.ReadTimeout)); err != nil {
			return builder.String(), err
		}

		n, err := conn.Read(buffer)
		if n > 0 {
			builder.Write(buffer[:n])
			if n < len(buffer) || builder.Len() >= m.config.BufferSize {
				return builder.String(), nil
			}
			continue
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				return builder.String(), nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if builder.Len() == 0 {
					return "", nil
				}
				return builder.String(), nil
			}
			return builder.String(), err
		}

		if builder.Len() > 0 {
			return builder.String(), nil
		}

		return "", nil
	}
}

func prepareProbeCommands(spec fingerprint.ProbeSpec, host string, port int) []string {
	if spec.ID == "https-get" {
		return []string{buildCanonicalGETRequest(host)}
	}

	if spec.Payload == "" {
		return nil
	}

	payload := decodeProbePayload(spec.Payload)
	payload = strings.ReplaceAll(payload, "{HOST}", host)
	if port > 0 {
		payload = strings.ReplaceAll(payload, "{PORT}", strconv.Itoa(port))
	}

	return []string{payload}
}

func decodeProbePayload(payload string) string {
	replacer := strings.NewReplacer(
		`\\r\\n`, "\r\n",
		`\r\n`, "\r\n",
		`\\n`, "\n",
		`\n`, "\n",
		`\\r`, "\r",
		`\r`, "\r",
		`\\t`, "\t",
		`\t`, "\t",
	)
	return replacer.Replace(payload)
}

func buildCanonicalGETRequest(host string) string {
	return strings.Join([]string{
		"GET / HTTP/1.1",
		fmt.Sprintf("Host: %s", host),
		"User-Agent: vulntor-probe/1.0",
		"Accept: */*",
		"Connection: close",
		"",
		"",
	}, "\r\n")
}

func readOriginalTargets(inputs map[string]any) []string {
	raw, ok := inputs["config.original_cli_targets"]
	if !ok {
		return nil
	}
	switch targets := raw.(type) {
	case []string:
		return targets
	case []any:
		out := make([]string, 0, len(targets))
		for _, target := range targets {
			text, ok := target.(string)
			if !ok {
				return nil
			}
			out = append(out, text)
		}
		return out
	default:
		return nil
	}
}

func resolveProbeHostOverride(originalTargets []string) string {
	return resolveSingleNonIPHostnameTarget(originalTargets)
}

func resolveSingleNonIPHostnameTarget(targets []string) string {
	if len(targets) != 1 {
		return ""
	}
	return normalizeNonIPHostname(strings.TrimSpace(targets[0]))
}

func normalizeNonIPHostname(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if net.ParseIP(target) != nil {
		return ""
	}
	return target
}

func resolvePreferredHost(originHost, probeHost string) string {
	if host := normalizeNonIPHostname(originHost); host != "" {
		return host
	}
	return strings.TrimSpace(probeHost)
}

func chooseTLSServerName(probeHost, dialHost string) string {
	host := strings.TrimSpace(probeHost)
	if host != "" && net.ParseIP(host) == nil {
		return host
	}
	return dialHost
}

func shouldExposeSNI(observations []engine.ProbeObservation) bool {
	for _, obs := range observations {
		if obs.IsTLS {
			return true
		}
	}
	return false
}

func portHintsFromCatalog(catalog *fingerprint.ProbeCatalog, port int) []string {
	if catalog == nil {
		return nil
	}

	hints := make(map[string]struct{})
	for _, group := range catalog.Groups {
		if len(group.PortHints) > 0 && !portInList(group.PortHints, port) {
			continue
		}
		if group.ID != "" {
			hints[strings.ToLower(group.ID)] = struct{}{}
		}
		for _, hint := range group.ProtocolHints {
			if hint == "" {
				continue
			}
			hints[strings.ToLower(hint)] = struct{}{}
		}
	}

	if len(hints) == 0 {
		return nil
	}

	out := make([]string, 0, len(hints))
	for hint := range hints {
		out = append(out, hint)
	}
	return out
}

func portInList(list []int, port int) bool {
	return slices.Contains(list, port)
}

func protocolHintFromBanner(banner string) string {
	banner = strings.ToLower(banner)
	switch {
	case strings.HasPrefix(banner, "ssh-"):
		return "ssh"
	case strings.Contains(banner, "http/") || strings.Contains(banner, "server:"):
		return "http"
	case strings.Contains(banner, "smtp"):
		return "smtp"
	case strings.Contains(banner, "ftp"):
		return "ftp"
	case strings.Contains(banner, "imap"):
		return "imap"
	case strings.Contains(banner, "pop3"):
		return "pop3"
	case strings.Contains(banner, "redis"):
		return "redis"
	}
	return ""
}

type hintAccumulator struct {
	set map[string]struct{}
}

func newHintAccumulator() hintAccumulator {
	return hintAccumulator{set: make(map[string]struct{})}
}

func (h *hintAccumulator) add(hint string) {
	if hint == "" {
		return
	}
	if h.set == nil {
		h.set = make(map[string]struct{})
	}
	h.set[strings.ToLower(hint)] = struct{}{}
}

func (h *hintAccumulator) addAll(hints []string) {
	for _, hint := range hints {
		h.add(hint)
	}
}

func (h hintAccumulator) slice() []string {
	if len(h.set) == 0 {
		return nil
	}
	out := make([]string, 0, len(h.set))
	for hint := range h.set {
		out = append(out, hint)
	}
	return out
}

func extractTLSObservation(state tls.ConnectionState) *engine.TLSObservation {
	if !state.HandshakeComplete {
		return nil
	}

	obs := &engine.TLSObservation{
		Version:     tlsVersionString(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ServerName:  state.ServerName,
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		obs.PeerCommonName = cert.Subject.CommonName
		if len(cert.DNSNames) > 0 {
			obs.PeerDNSNames = append([]string(nil), cert.DNSNames...)
		}

		// Phase 1.7: Extract certificate validity and security indicators
		obs.Issuer = cert.Issuer.String()
		obs.NotBefore = cert.NotBefore
		obs.NotAfter = cert.NotAfter
		obs.IsExpired = time.Now().After(cert.NotAfter)
		obs.IsSelfSigned = cert.Subject.String() == cert.Issuer.String()
	}

	return obs
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%x", version)
	}
}

// BannerGrabModuleFactory creates a new BannerGrabModule instance.
func BannerGrabModuleFactory() engine.Module {
	return newBannerGrabModule()
}

func init() {
	engine.RegisterModuleFactory("banner-grabber", BannerGrabModuleFactory)
}
