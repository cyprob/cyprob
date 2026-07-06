package scan

import (
	"bufio"
	"context"
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
	redisNativeProbeModuleID          = "redis-native-probe-instance"
	redisNativeProbeModuleName        = "redis-native-probe"
	redisNativeProbeModuleDescription = "Runs a bounded native Redis INFO probe and emits structured Redis metadata."

	redisNativePort         = 6379
	redisMaxResponseBytes   = 16 * 1024
	redisNoAuthErrorMessage = "noauth"
)

// RedisProbeOptions bounds the native Redis probe.
type RedisProbeOptions struct {
	TotalTimeout   time.Duration `json:"total_timeout"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	IOTimeout      time.Duration `json:"io_timeout"`
	Retries        int           `json:"retries"`
	CandidatePorts []int         `json:"candidate_ports,omitempty"`
}

// RedisProbeAttempt records one probe attempt for audit/debug.
type RedisProbeAttempt struct {
	Strategy   string `json:"strategy"`
	Transport  string `json:"transport"`
	Success    bool   `json:"success"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

// RedisServiceInfo is the structured native Redis probe output.
type RedisServiceInfo struct {
	Target        string              `json:"target"`
	Port          int                 `json:"port"`
	RedisProbe    bool                `json:"redis_probe"`
	GreetingKind  string              `json:"greeting_kind,omitempty"`
	ServerVersion string              `json:"server_version,omitempty"`
	Mode          string              `json:"mode,omitempty"`
	OS            string              `json:"os,omitempty"`
	ArchBits      string              `json:"arch_bits,omitempty"`
	AuthRequired  bool                `json:"auth_required"`
	ProductHint   string              `json:"product_hint,omitempty"`
	VendorHint    string              `json:"vendor_hint,omitempty"`
	VersionHint   string              `json:"version_hint,omitempty"`
	ProbeError    string              `json:"probe_error,omitempty"`
	Attempts      []RedisProbeAttempt `json:"attempts,omitempty"`
}

type redisNativeProbeModule struct {
	meta    engine.ModuleMetadata
	options RedisProbeOptions
}

type redisProbeCandidate struct {
	target   string
	hostname string
	port     int
}

var (
	probeRedisDetailsFunc = probeRedisDetails

	redisVersionLinePattern = regexp.MustCompile(`(?im)^redis_version:\s*([0-9][0-9a-z._-]*)`)
	redisModeLinePattern    = regexp.MustCompile(`(?im)^redis_mode:\s*([a-z]+)`)
	redisOSLinePattern      = regexp.MustCompile(`(?im)^os:\s*(.+)$`)
	redisArchLinePattern    = regexp.MustCompile(`(?im)^arch_bits:\s*([0-9]+)`)
)

func newRedisNativeProbeModuleWithSpec(moduleID, moduleName, description, outputKey string, tags []string) *redisNativeProbeModule {
	return &redisNativeProbeModule{
		meta: buildTCPNativeProbeMetadata(tcpNativeProbeMetadataSpec{
			moduleID:          moduleID,
			moduleName:        moduleName,
			description:       description,
			outputKey:         outputKey,
			outputType:        "scan.RedisServiceInfo",
			outputDescription: "Structured Redis native probe output per target and port.",
			tags:              tags,
			consumes: []engine.DataContractEntry{
				nativeOpenTCPPortsConsume(false, "Open TCP ports used to identify Redis candidate services."),
				nativeBannerConsume("Banner results used as Redis candidate hints."),
			},
			timeoutDefault:        "2500ms",
			connectTimeoutDefault: "800ms",
			ioTimeoutDefault:      "800ms",
			extraConfigParameters: map[string]engine.ParameterDefinition{
				"candidate_ports": {
					Description: "Optional explicit ports to treat as Redis candidates when already known open.",
					Type:        "[]int",
					Required:    false,
				},
			},
		}),
		options: defaultRedisProbeOptions(),
	}
}

func newRedisNativeProbeModule() *redisNativeProbeModule {
	return newRedisNativeProbeModuleWithSpec(
		redisNativeProbeModuleID,
		redisNativeProbeModuleName,
		redisNativeProbeModuleDescription,
		"service.redis.details",
		[]string{"scan", "redis", "database", "enrichment", "native_probe"},
	)
}

func (m *redisNativeProbeModule) Metadata() engine.ModuleMetadata { return m.meta }

func (m *redisNativeProbeModule) Init(instanceID string, configMap map[string]any) error {
	opts := defaultRedisProbeOptions()
	initCommonTCPProbeOptions(&m.meta, instanceID, configMap, &opts.TotalTimeout, &opts.ConnectTimeout, &opts.IOTimeout, &opts.Retries)
	opts.CandidatePorts = parseOptionalPortList(configMap, "candidate_ports")
	m.options = opts
	return nil
}

func (m *redisNativeProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
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

	candidates := make(map[string]redisProbeCandidate)
	for _, item := range toAnySlice(rawOpenPorts) {
		for _, candidate := range redisCandidatesFromOpenPorts(item, explicitCandidatePorts) {
			mergeRedisCandidate(candidates, candidate)
		}
	}
	if rawBanner, ok := inputs["service.banner.tcp"]; ok {
		for _, item := range toAnySlice(rawBanner) {
			if candidate, ok := redisCandidateFromBanner(item, explicitCandidatePorts); ok {
				mergeRedisCandidate(candidates, candidate)
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
		result := probeRedisDetailsFunc(targetCtx, candidate.target, candidate.port, m.options)
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

func defaultRedisProbeOptions() RedisProbeOptions {
	return RedisProbeOptions{
		TotalTimeout:   2500 * time.Millisecond,
		ConnectTimeout: 800 * time.Millisecond,
		IOTimeout:      800 * time.Millisecond,
		Retries:        0,
	}
}

func isRedisNativePort(port int) bool { return port == redisNativePort }

func redisCandidatesFromOpenPorts(item any, explicitCandidatePorts map[int]struct{}) []redisProbeCandidate {
	candidates := make([]redisProbeCandidate, 0, 1)
	appendCandidate := func(target, hostname string, port int) {
		target = strings.TrimSpace(target)
		if target == "" || port <= 0 || port > 65535 {
			return
		}
		if !isRedisNativePort(port) {
			if _, ok := explicitCandidatePorts[port]; !ok {
				return
			}
		}
		candidates = append(candidates, redisProbeCandidate{target: target, hostname: normalizeNonIPHostname(hostname), port: port})
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

func redisCandidateFromBanner(item any, explicitCandidatePorts map[int]struct{}) (redisProbeCandidate, bool) {
	switch v := item.(type) {
	case BannerGrabResult:
		if !isRedisNativePort(v.Port) {
			if _, ok := explicitCandidatePorts[v.Port]; !ok {
				return redisProbeCandidate{}, false
			}
		}
		ip := strings.TrimSpace(v.IP)
		return redisProbeCandidate{target: ip, hostname: firstNonEmptyHostname(v.ProbeHost, v.SNIServerName), port: v.Port}, ip != "" && v.Port > 0
	case map[string]any:
		target := getMapString(v, "ip", "IP")
		port := mapPortValue(v["port"])
		if target == "" || port <= 0 {
			return redisProbeCandidate{}, false
		}
		if !isRedisNativePort(port) {
			if _, ok := explicitCandidatePorts[port]; !ok {
				return redisProbeCandidate{}, false
			}
		}
		return redisProbeCandidate{target: target, hostname: firstNonEmptyHostname(getMapString(v, "probe_host", "ProbeHost"), getMapString(v, "sni_server_name", "SNIServerName")), port: port}, true
	}
	return redisProbeCandidate{}, false
}

func mergeRedisCandidate(dst map[string]redisProbeCandidate, candidate redisProbeCandidate) {
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

func probeRedisDetails(ctx context.Context, target string, port int, opts RedisProbeOptions) RedisServiceInfo {
	if port <= 0 {
		port = redisNativePort
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

	result := RedisServiceInfo{Target: target, Port: port, Attempts: make([]RedisProbeAttempt, 0, opts.Retries+1)}
	errorCodes := make([]string, 0, opts.Retries+1)

	for retry := 0; retry <= opts.Retries; retry++ {
		start := time.Now()
		payload, err := runRedisInfo(probeCtx, target, port, opts)
		if err != nil {
			code := classifyRedisError(err)
			errorCodes = append(errorCodes, code)
			result.Attempts = append(result.Attempts, RedisProbeAttempt{Strategy: "redis-info", Transport: "tcp", Success: false, DurationMS: time.Since(start).Milliseconds(), Error: code})
			continue
		}
		result.Attempts = append(result.Attempts, RedisProbeAttempt{Strategy: "redis-info", Transport: "tcp", Success: true, DurationMS: time.Since(start).Milliseconds()})
		result.RedisProbe = true
		applyRedisInfo(&result, payload)
		return result
	}
	result.ProbeError = pickTopRedisError(errorCodes)
	return result
}

// runRedisInfo sends an inline INFO command and returns the raw reply text.
func runRedisInfo(ctx context.Context, target string, port int, opts RedisProbeOptions) (string, error) {
	address := net.JoinHostPort(strings.TrimSpace(target), fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: effectiveProbeTimeout(ctx, opts.ConnectTimeout)}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(opts.IOTimeout))
	}

	// Inline command form; Redis accepts "INFO server\r\n" without RESP framing.
	if _, err := conn.Write([]byte("INFO server\r\n")); err != nil {
		return "", err
	}

	reader := bufio.NewReader(io.LimitReader(conn, redisMaxResponseBytes))
	prefix, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	switch prefix {
	case '$':
		// Bulk string: $<len>\r\n<payload>\r\n
		header, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		_ = header
		body := make([]byte, 0, 2048)
		buf := make([]byte, 1024)
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				body = append(body, buf[:n]...)
			}
			if err != nil {
				break
			}
			if len(body) >= redisMaxResponseBytes {
				break
			}
		}
		return string(body), nil
	case '-':
		// Error reply, e.g. "-NOAUTH Authentication required."
		line, _ := reader.ReadString('\n')
		return string(prefix) + line, nil
	default:
		// Not a Redis-shaped reply.
		line, _ := reader.ReadString('\n')
		return "", fmt.Errorf("protocol_mismatch: %c%s", prefix, strings.TrimSpace(line))
	}
}

func applyRedisInfo(result *RedisServiceInfo, payload string) {
	lower := strings.ToLower(payload)
	if strings.HasPrefix(strings.TrimSpace(payload), "-") && strings.Contains(lower, redisNoAuthErrorMessage) {
		result.GreetingKind = "auth_required"
		result.AuthRequired = true
		result.ProductHint = "Redis"
		result.VendorHint = "Redis"
		return
	}
	result.GreetingKind = "info"
	if m := redisVersionLinePattern.FindStringSubmatch(payload); len(m) > 1 {
		result.ServerVersion = strings.TrimSpace(m[1])
	}
	if m := redisModeLinePattern.FindStringSubmatch(payload); len(m) > 1 {
		result.Mode = strings.TrimSpace(m[1])
	}
	if m := redisOSLinePattern.FindStringSubmatch(payload); len(m) > 1 {
		result.OS = strings.TrimSpace(m[1])
	}
	if m := redisArchLinePattern.FindStringSubmatch(payload); len(m) > 1 {
		result.ArchBits = strings.TrimSpace(m[1])
	}
	if result.ServerVersion != "" || result.Mode != "" {
		result.ProductHint = "Redis"
		result.VendorHint = "Redis"
		result.VersionHint = result.ServerVersion
	}
}

func classifyRedisError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case strings.Contains(msg, "protocol_mismatch"):
		return "protocol_mismatch"
	case errors.Is(err, io.EOF):
		return "probe_failed"
	case strings.Contains(msg, "refused"):
		return "connect_failed"
	default:
		return "probe_failed"
	}
}

func pickTopRedisError(codes []string) string {
	priority := map[string]int{"timeout": 5, "connect_failed": 4, "protocol_mismatch": 2, "probe_failed": 1}
	best, bestP := "", -1
	for _, code := range codes {
		if p := priority[code]; p > bestP {
			bestP, best = p, code
		}
	}
	return best
}

func redisNativeProbeModuleFactory() engine.Module { return newRedisNativeProbeModule() }

func init() {
	engine.RegisterModuleFactory(redisNativeProbeModuleName, redisNativeProbeModuleFactory)
}
