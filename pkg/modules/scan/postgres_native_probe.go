package scan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

const (
	postgresNativeProbeModuleID          = "postgres-native-probe-instance"
	postgresNativeProbeModuleName        = "postgres-native-probe"
	postgresNativeProbeModuleDescription = "Runs a bounded native PostgreSQL startup probe and emits structured PostgreSQL metadata."

	postgresNativePort        = 5432
	postgresProtocolVersion3  = 196608 // 3.0
	postgresMaxMessageBytes   = 32 * 1024
	postgresMaxMessagesPerRun = 64
)

// PostgresProbeOptions bounds the native PostgreSQL probe.
type PostgresProbeOptions struct {
	TotalTimeout   time.Duration `json:"total_timeout"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	IOTimeout      time.Duration `json:"io_timeout"`
	Retries        int           `json:"retries"`
	CandidatePorts []int         `json:"candidate_ports,omitempty"`
}

// PostgresProbeAttempt records one probe attempt for audit/debug.
type PostgresProbeAttempt struct {
	Strategy   string `json:"strategy"`
	Transport  string `json:"transport"`
	Success    bool   `json:"success"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

// PostgresServiceInfo is the structured native PostgreSQL probe output.
type PostgresServiceInfo struct {
	Target        string                 `json:"target"`
	Port          int                    `json:"port"`
	PostgresProbe bool                   `json:"postgres_probe"`
	GreetingKind  string                 `json:"greeting_kind,omitempty"` // auth_ok | auth_required | error
	ServerVersion string                 `json:"server_version,omitempty"`
	AuthRequired  bool                   `json:"auth_required"`
	AuthMethod    string                 `json:"auth_method,omitempty"`
	ProductHint   string                 `json:"product_hint,omitempty"`
	VendorHint    string                 `json:"vendor_hint,omitempty"`
	VersionHint   string                 `json:"version_hint,omitempty"`
	ProbeError    string                 `json:"probe_error,omitempty"`
	Attempts      []PostgresProbeAttempt `json:"attempts,omitempty"`
}

type postgresNativeProbeModule struct {
	meta    engine.ModuleMetadata
	options PostgresProbeOptions
}

type postgresProbeCandidate struct {
	target   string
	hostname string
	port     int
}

var (
	probePostgresDetailsFunc = probePostgresDetails

	postgresVersionCorePattern = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)*)`)
)

func newPostgresNativeProbeModuleWithSpec(moduleID, moduleName, description, outputKey string, tags []string) *postgresNativeProbeModule {
	return &postgresNativeProbeModule{
		meta: buildTCPNativeProbeMetadata(tcpNativeProbeMetadataSpec{
			moduleID:          moduleID,
			moduleName:        moduleName,
			description:       description,
			outputKey:         outputKey,
			outputType:        "scan.PostgresServiceInfo",
			outputDescription: "Structured PostgreSQL native probe output per target and port.",
			tags:              tags,
			consumes: []engine.DataContractEntry{
				nativeOpenTCPPortsConsume(false, "Open TCP ports used to identify PostgreSQL candidate services."),
				nativeBannerConsume("Banner results used as PostgreSQL candidate hints."),
			},
			timeoutDefault:        "2500ms",
			connectTimeoutDefault: "800ms",
			ioTimeoutDefault:      "800ms",
			extraConfigParameters: map[string]engine.ParameterDefinition{
				"candidate_ports": {
					Description: "Optional explicit ports to treat as PostgreSQL candidates when already known open.",
					Type:        "[]int",
					Required:    false,
				},
			},
		}),
		options: defaultPostgresProbeOptions(),
	}
}

func newPostgresNativeProbeModule() *postgresNativeProbeModule {
	return newPostgresNativeProbeModuleWithSpec(
		postgresNativeProbeModuleID,
		postgresNativeProbeModuleName,
		postgresNativeProbeModuleDescription,
		"service.postgres.details",
		[]string{"scan", "postgresql", "database", "enrichment", "native_probe"},
	)
}

func (m *postgresNativeProbeModule) Metadata() engine.ModuleMetadata { return m.meta }

func (m *postgresNativeProbeModule) Init(instanceID string, configMap map[string]any) error {
	opts := defaultPostgresProbeOptions()
	initCommonTCPProbeOptions(&m.meta, instanceID, configMap, &opts.TotalTimeout, &opts.ConnectTimeout, &opts.IOTimeout, &opts.Retries)
	opts.CandidatePorts = parseOptionalPortList(configMap, "candidate_ports")
	m.options = opts
	return nil
}

func (m *postgresNativeProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	rawOpenPorts, ok := inputs["discovery.open_tcp_ports"]
	if !ok {
		return nil
	}

	explicitCandidatePorts := make(map[int]struct{}, len(m.options.CandidatePorts))
	for _, port := range m.options.CandidatePorts {
		if port > 0 && port <= 65535 {
			explicitCandidatePorts[port] = struct{}{}
		}
	}

	candidates := make(map[string]postgresProbeCandidate)
	for _, item := range toAnySlice(rawOpenPorts) {
		for _, candidate := range postgresCandidatesFromOpenPorts(item, explicitCandidatePorts) {
			mergePostgresCandidate(candidates, candidate)
		}
	}
	if rawBanner, ok := inputs["service.banner.tcp"]; ok {
		for _, item := range toAnySlice(rawBanner) {
			if candidate, ok := postgresCandidateFromBanner(item, explicitCandidatePorts); ok {
				mergePostgresCandidate(candidates, candidate)
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	keys := make([]string, 0, len(candidates))
	for key := range candidates {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := candidates[keys[i]], candidates[keys[j]]
		if left.target == right.target {
			return left.port < right.port
		}
		return left.target < right.target
	})

	for _, key := range keys {
		candidate := candidates[key]
		targetCtx := ctx
		var cancel context.CancelFunc
		if m.options.TotalTimeout > 0 {
			targetCtx, cancel = context.WithTimeout(ctx, m.options.TotalTimeout)
		}
		result := probePostgresDetailsFunc(targetCtx, candidate.target, candidate.port, m.options)
		if cancel != nil {
			cancel()
		}
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        m.meta.Produces[0].Key,
			Data:           result,
			Timestamp:      time.Now(),
			Target:         candidate.target,
		}
	}
	return nil
}

func defaultPostgresProbeOptions() PostgresProbeOptions {
	return PostgresProbeOptions{
		TotalTimeout:   2500 * time.Millisecond,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
		Retries:        0,
	}
}

func isPostgresNativePort(port int) bool { return port == postgresNativePort }

func postgresCandidatesFromOpenPorts(item any, explicitCandidatePorts map[int]struct{}) []postgresProbeCandidate {
	candidates := make([]postgresProbeCandidate, 0, 1)
	appendCandidate := func(target, hostname string, port int) {
		target = strings.TrimSpace(target)
		if target == "" || port <= 0 || port > 65535 {
			return
		}
		if !isPostgresNativePort(port) {
			if _, ok := explicitCandidatePorts[port]; !ok {
				return
			}
		}
		candidates = append(candidates, postgresProbeCandidate{target: target, hostname: normalizeNonIPHostname(hostname), port: port})
	}
	switch v := item.(type) {
	case discovery.TCPPortDiscoveryResult:
		for _, port := range v.OpenPorts {
			appendCandidate(v.Target, v.Hostname, port)
		}
	case map[string]any:
		target := getMapString(v, "target", "Target")
		hostname := getMapString(v, "hostname", "Hostname")
		switch ports := v["open_ports"].(type) {
		case []int:
			for _, port := range ports {
				appendCandidate(target, hostname, port)
			}
		case []any:
			for _, p := range ports {
				switch port := p.(type) {
				case int:
					appendCandidate(target, hostname, port)
				case float64:
					appendCandidate(target, hostname, int(port))
				}
			}
		}
	}
	return candidates
}

func postgresCandidateFromBanner(item any, explicitCandidatePorts map[int]struct{}) (postgresProbeCandidate, bool) {
	switch v := item.(type) {
	case BannerGrabResult:
		if !isPostgresNativePort(v.Port) {
			if _, ok := explicitCandidatePorts[v.Port]; !ok {
				return postgresProbeCandidate{}, false
			}
		}
		ip := strings.TrimSpace(v.IP)
		return postgresProbeCandidate{target: ip, hostname: firstNonEmptyHostname(v.ProbeHost, v.SNIServerName), port: v.Port}, ip != "" && v.Port > 0
	case map[string]any:
		target := getMapString(v, "ip", "IP")
		port := mapPortValue(v["port"])
		if target == "" || port <= 0 {
			return postgresProbeCandidate{}, false
		}
		if !isPostgresNativePort(port) {
			if _, ok := explicitCandidatePorts[port]; !ok {
				return postgresProbeCandidate{}, false
			}
		}
		return postgresProbeCandidate{target: target, hostname: firstNonEmptyHostname(getMapString(v, "probe_host", "ProbeHost"), getMapString(v, "sni_server_name", "SNIServerName")), port: port}, true
	}
	return postgresProbeCandidate{}, false
}

func mergePostgresCandidate(dst map[string]postgresProbeCandidate, candidate postgresProbeCandidate) {
	key := fmt.Sprintf("%s:%d", candidate.target, candidate.port)
	if current, ok := dst[key]; ok {
		if current.hostname == "" && candidate.hostname != "" {
			current.hostname = candidate.hostname
			dst[key] = current
		}
		return
	}
	dst[key] = candidate
}

func probePostgresDetails(ctx context.Context, target string, port int, opts PostgresProbeOptions) PostgresServiceInfo {
	if port <= 0 {
		port = postgresNativePort
	}
	if opts.TotalTimeout <= 0 {
		opts.TotalTimeout = 2500 * time.Millisecond
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

	result := PostgresServiceInfo{Target: target, Port: port, Attempts: make([]PostgresProbeAttempt, 0, opts.Retries+1)}
	errorCodes := make([]string, 0, opts.Retries+1)

	for retry := 0; retry <= opts.Retries; retry++ {
		start := time.Now()
		if err := runPostgresStartup(probeCtx, target, port, opts, &result); err != nil {
			code := classifyPostgresError(err)
			errorCodes = append(errorCodes, code)
			result.Attempts = append(result.Attempts, PostgresProbeAttempt{Strategy: "postgres-startup", Transport: "tcp", Success: false, DurationMS: time.Since(start).Milliseconds(), Error: code})
			continue
		}
		result.Attempts = append(result.Attempts, PostgresProbeAttempt{Strategy: "postgres-startup", Transport: "tcp", Success: true, DurationMS: time.Since(start).Milliseconds()})
		if result.ServerVersion != "" || result.PostgresProbe {
			applyPostgresHints(&result)
			return result
		}
	}
	if !result.PostgresProbe {
		result.ProbeError = pickTopPostgresError(errorCodes)
	}
	applyPostgresHints(&result)
	return result
}

// runPostgresStartup sends a v3 StartupMessage and reads server messages,
// extracting server_version from ParameterStatus when the server leaks it
// (trust auth / pre-auth burst). Auth-required servers are identified but
// yield no version without credentials.
func runPostgresStartup(ctx context.Context, target string, port int, opts PostgresProbeOptions, result *PostgresServiceInfo) error {
	address := net.JoinHostPort(strings.TrimSpace(target), fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: effectiveProbeTimeout(ctx, opts.ConnectTimeout)}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(opts.IOTimeout))
	}

	if _, err := conn.Write(buildPostgresStartupMessage("postgres")); err != nil {
		return err
	}

	header := make([]byte, 5)
	for i := 0; i < postgresMaxMessagesPerRun; i++ {
		if _, err := io.ReadFull(conn, header); err != nil {
			if result.PostgresProbe {
				return nil // spoke the protocol; connection ended after what we got
			}
			return err
		}
		msgType := header[0]
		length := int(binary.BigEndian.Uint32(header[1:5]))
		if length < 4 || length-4 > postgresMaxMessageBytes {
			if result.PostgresProbe {
				return nil
			}
			return errors.New("protocol_mismatch")
		}
		payload := make([]byte, length-4)
		if _, err := io.ReadFull(conn, payload); err != nil {
			if result.PostgresProbe {
				return nil
			}
			return err
		}

		switch msgType {
		case 'R': // Authentication
			result.PostgresProbe = true
			if len(payload) >= 4 {
				authType := binary.BigEndian.Uint32(payload[0:4])
				if authType == 0 {
					result.GreetingKind = "auth_ok"
				} else {
					result.GreetingKind = "auth_required"
					result.AuthRequired = true
					result.AuthMethod = postgresAuthMethodName(authType)
					return nil // no version without credentials
				}
			}
		case 'S': // ParameterStatus: name\0value\0
			result.PostgresProbe = true
			name, value := parsePostgresParameterStatus(payload)
			if strings.EqualFold(name, "server_version") && result.ServerVersion == "" {
				result.ServerVersion = strings.TrimSpace(value)
			}
		case 'E': // ErrorResponse — server spoke the protocol but rejected us
			result.PostgresProbe = true
			if result.GreetingKind == "" {
				result.GreetingKind = "error"
			}
			return nil
		case 'Z': // ReadyForQuery — end of startup
			return nil
		default:
			// Keep reading a few more framed messages; already-set PostgresProbe stands.
		}

		if result.ServerVersion != "" {
			return nil
		}
	}
	return nil
}

func buildPostgresStartupMessage(user string) []byte {
	params := []byte{}
	params = append(params, []byte("user")...)
	params = append(params, 0)
	params = append(params, []byte(user)...)
	params = append(params, 0)
	params = append(params, 0) // terminator

	body := make([]byte, 4+len(params))
	binary.BigEndian.PutUint32(body[0:4], uint32(postgresProtocolVersion3))
	copy(body[4:], params)

	msg := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(msg[0:4], uint32(4+len(body)))
	copy(msg[4:], body)
	return msg
}

func parsePostgresParameterStatus(payload []byte) (string, string) {
	parts := strings.SplitN(strings.TrimRight(string(payload), "\x00"), "\x00", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return "", ""
}

func postgresAuthMethodName(authType uint32) string {
	switch authType {
	case 3:
		return "cleartext_password"
	case 5:
		return "md5_password"
	case 7:
		return "gss"
	case 10:
		return "sasl"
	default:
		return fmt.Sprintf("auth_%d", authType)
	}
}

func applyPostgresHints(result *PostgresServiceInfo) {
	if !result.PostgresProbe {
		return
	}
	result.ProductHint = "PostgreSQL"
	result.VendorHint = "PostgreSQL Global Development Group"
	if result.ServerVersion != "" {
		result.VersionHint = extractPostgresCoreVersion(result.ServerVersion)
	}
}

func extractPostgresCoreVersion(value string) string {
	if v := postgresVersionCorePattern.FindString(strings.TrimSpace(value)); v != "" {
		return v
	}
	return ""
}

func classifyPostgresError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case strings.Contains(msg, "protocol_mismatch"):
		return "protocol_mismatch"
	case errors.Is(err, io.EOF) || strings.Contains(msg, "eof"):
		return "probe_failed"
	case strings.Contains(msg, "refused"):
		return "connect_failed"
	default:
		return "probe_failed"
	}
}

func pickTopPostgresError(codes []string) string {
	priority := map[string]int{"timeout": 5, "connect_failed": 4, "protocol_mismatch": 2, "probe_failed": 1}
	best, bestP := "", -1
	for _, code := range codes {
		if p := priority[code]; p > bestP {
			bestP, best = p, code
		}
	}
	return best
}

func postgresNativeProbeModuleFactory() engine.Module { return newPostgresNativeProbeModule() }

func init() {
	engine.RegisterModuleFactory(postgresNativeProbeModuleName, postgresNativeProbeModuleFactory)
}
