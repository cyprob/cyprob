package scan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

const (
	faviconProbeModuleID          = "favicon-probe-instance"
	faviconProbeModuleName        = "favicon-probe"
	faviconProbeModuleDescription = "Fetches /favicon.ico from HTTP services and emits a Shodan-convention favicon hash for device identification."

	faviconPath = "/favicon.ico"
	// faviconMaxBytes bounds the read: real icons are a few KB, and anything
	// larger is not a favicon worth hashing.
	faviconMaxBytes = 256 * 1024
	// faviconRetryDelay gives a device a moment to recover before the one retry.
	faviconRetryDelay = 250 * time.Millisecond
)

// FaviconProbeOptions controls the probe's time budget.
type FaviconProbeOptions struct {
	TotalTimeout   time.Duration `json:"total_timeout"`
	RequestTimeout time.Duration `json:"request_timeout"`
}

// FaviconServiceInfo is the canonical favicon probe output.
//
// The hash is emitted whether or not the corpus recognizes it: an unrecognized
// hash is still a stable device fingerprint, so identical hardware groups
// together across a fleet and an operator can identify it once for everyone.
type FaviconServiceInfo struct {
	Target      string `json:"target"`
	Port        int    `json:"port"`
	Scheme      string `json:"scheme,omitempty"`
	FaviconHash int32  `json:"favicon_hash,omitempty"`
	SizeBytes   int    `json:"size_bytes,omitempty"`
	VendorHint  string `json:"vendor_hint,omitempty"`
	ProductHint string `json:"product_hint,omitempty"`
	ProbeError  string `json:"probe_error,omitempty"`
	// Attempts records how many requests were made, so a report can tell a
	// device that answered immediately from one that needed a retry.
	Attempts int `json:"attempts,omitempty"`
}

type faviconProbeModule struct {
	meta    engine.ModuleMetadata
	options FaviconProbeOptions
}

type faviconCandidate struct {
	target string
	port   int
	scheme string
}

var probeFaviconFunc = probeFavicon

// faviconHTTPPorts are the ports probed over plain HTTP; faviconHTTPSPorts over
// TLS. Management interfaces are commonly on the alternate ports.
var (
	faviconHTTPPorts  = map[int]struct{}{80: {}, 8000: {}, 8080: {}, 8081: {}, 8888: {}}
	faviconHTTPSPorts = map[int]struct{}{443: {}, 4443: {}, 8443: {}, 9443: {}, 10443: {}}
)

func newFaviconProbeModule() *faviconProbeModule {
	return &faviconProbeModule{
		meta: engine.ModuleMetadata{
			ID:          faviconProbeModuleID,
			Name:        faviconProbeModuleName,
			Description: faviconProbeModuleDescription,
			Version:     "0.1.0",
			Type:        engine.ScanModuleType,
			Author:      "Vulntor Team",
			Tags:        []string{"scan", "http", "favicon", "enrichment", "native_probe"},
			Consumes: []engine.DataContractEntry{
				{
					Key:          "discovery.open_tcp_ports",
					DataTypeName: "discovery.TCPPortDiscoveryResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   false,
					Description:  "Open TCP ports used to identify HTTP favicon candidates.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key:          "service.favicon.details",
					DataTypeName: "scan.FaviconServiceInfo",
					Cardinality:  engine.CardinalityList,
					Description:  "Favicon hash and derived device identity per target and port.",
				},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				"timeout": {
					Description: "Total timeout budget per target (e.g. 4s).",
					Type:        "duration",
					Required:    false,
					Default:     "4s",
				},
				"request_timeout": {
					Description: "Timeout for the favicon request.",
					Type:        "duration",
					Required:    false,
					Default:     "2s",
				},
			},
			EstimatedCost: 1,
		},
		options: defaultFaviconProbeOptions(),
	}
}

func (m *faviconProbeModule) Metadata() engine.ModuleMetadata { return m.meta }

func (m *faviconProbeModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	opts := defaultFaviconProbeOptions()
	if configMap != nil {
		if d, ok := parseDurationConfig(configMap["timeout"]); ok && d > 0 {
			opts.TotalTimeout = d
		}
		if d, ok := parseDurationConfig(configMap["request_timeout"]); ok && d > 0 {
			opts.RequestTimeout = d
		}
	}
	m.options = opts
	return nil
}

func (m *faviconProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	rawOpenPorts, ok := inputs["discovery.open_tcp_ports"]
	if !ok {
		return nil
	}

	candidates := map[string]faviconCandidate{}
	for _, item := range toAnySlice(rawOpenPorts) {
		for _, candidate := range faviconCandidatesFromOpenPorts(item) {
			candidates[fmt.Sprintf("%s:%d", candidate.target, candidate.port)] = candidate
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

	for _, key := range keys {
		candidate := candidates[key]
		result := probeFaviconFunc(ctx, candidate, m.options)
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "service.favicon.details",
			Data:           result,
			Timestamp:      time.Now(),
			Target:         candidate.target,
		}
	}
	return nil
}

func defaultFaviconProbeOptions() FaviconProbeOptions {
	return FaviconProbeOptions{TotalTimeout: 4 * time.Second, RequestTimeout: 2 * time.Second}
}

// classifyFaviconError turns a transport failure into a stable, diagnosable
// reason.
//
// A single "no_response" for every failure mode is untraceable: a refused port,
// an unresponsive device and a TLS mismatch need different answers, and the
// difference is exactly what an operator needs to know when a device that
// should be identified is not.
func classifyFaviconError(err error) string {
	if err == nil {
		return ""
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "connection refused"):
		return "connection_refused"
	case strings.Contains(message, "connection reset"):
		return "connection_reset"
	case strings.Contains(message, "no route to host"):
		return "no_route"
	case strings.Contains(message, "tls"), strings.Contains(message, "certificate"):
		return "tls_error"
	}
	return "no_response"
}

func faviconCandidatesFromOpenPorts(item any) []faviconCandidate {
	candidates := make([]faviconCandidate, 0, 2)
	appendCandidate := func(target string, port int) {
		target = strings.TrimSpace(target)
		if target == "" {
			return
		}
		switch {
		case isFaviconHTTPSPort(port):
			candidates = append(candidates, faviconCandidate{target: target, port: port, scheme: "https"})
		case isFaviconHTTPPort(port):
			candidates = append(candidates, faviconCandidate{target: target, port: port, scheme: "http"})
		}
	}

	switch v := item.(type) {
	case discovery.TCPPortDiscoveryResult:
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

func isFaviconHTTPPort(port int) bool  { _, ok := faviconHTTPPorts[port]; return ok }
func isFaviconHTTPSPort(port int) bool { _, ok := faviconHTTPSPorts[port]; return ok }

func probeFavicon(ctx context.Context, candidate faviconCandidate, opts FaviconProbeOptions) FaviconServiceInfo {
	result := FaviconServiceInfo{Target: candidate.target, Port: candidate.port, Scheme: candidate.scheme}
	if opts.TotalTimeout <= 0 {
		opts.TotalTimeout = 4 * time.Second
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 2 * time.Second
	}

	result.Attempts = 1
	probeCtx, cancel := context.WithTimeout(ctx, opts.TotalTimeout)
	defer cancel()

	url := fmt.Sprintf("%s://%s%s", candidate.scheme, net.JoinHostPort(candidate.target, strconv.Itoa(candidate.port)), faviconPath)
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, url, nil)
	if err != nil {
		result.ProbeError = "request_error"
		return result
	}

	client := &http.Client{
		Timeout: opts.RequestTimeout,
		Transport: &http.Transport{
			// Management interfaces almost always use self-signed certificates;
			// certificate validity is assessed by the TLS probe, not here.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // identification probe, not a trust decision
		},
		// A favicon that redirects elsewhere is not this host's identity.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	response, err := client.Do(request)
	if err != nil {
		// One retry. A device can drop a single request while being perfectly
		// responsive a moment later: observed on a live router that served this
		// icon in 15ms outside a scan and not at all inside one. Without a
		// retry the identity is lost silently, which is the worst outcome —
		// the corpus entry exists and matches, but never fires.
		result.Attempts = 2
		retryCtx, retryCancel := context.WithTimeout(ctx, opts.TotalTimeout)
		defer retryCancel()
		retryRequest, retryErr := http.NewRequestWithContext(retryCtx, http.MethodGet, url, nil)
		if retryErr != nil {
			result.ProbeError = classifyFaviconError(err)
			return result
		}
		time.Sleep(faviconRetryDelay)
		response, err = client.Do(retryRequest)
		if err != nil {
			result.ProbeError = classifyFaviconError(err)
			return result
		}
	}
	defer response.Body.Close() //nolint:errcheck // best-effort cleanup

	if response.StatusCode != http.StatusOK {
		result.ProbeError = fmt.Sprintf("status_%d", response.StatusCode)
		return result
	}

	content, err := io.ReadAll(io.LimitReader(response.Body, faviconMaxBytes))
	if err != nil || len(content) == 0 {
		result.ProbeError = "empty_body"
		return result
	}

	result.SizeBytes = len(content)
	result.FaviconHash = FaviconHash(content)
	result.VendorHint, result.ProductHint = LookupFaviconIdentity(result.FaviconHash)
	return result
}

func init() {
	engine.RegisterModuleFactory(faviconProbeModuleName, func() engine.Module {
		return newFaviconProbeModule()
	})
}
