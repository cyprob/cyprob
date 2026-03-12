package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"github.com/gosnmp/gosnmp"
)

const (
	snmpNativeProbeModuleID          = "snmp-native-probe-instance"
	snmpNativeProbeModuleName        = "snmp-native-probe"
	snmpNativeProbeModuleDescription = "Runs bounded native SNMP probes against UDP/161 and emits structured SNMP metadata."

	snmpOIDSysDescr   = ".1.3.6.1.2.1.1.1.0"
	snmpOIDSysObject  = ".1.3.6.1.2.1.1.2.0"
	snmpOIDSysName    = ".1.3.6.1.2.1.1.5.0"
	snmpCommunityPub  = "public"
	snmpCommunityPriv = "private"
)

type SNMPProbeOptions struct {
	TotalTimeout      time.Duration `json:"total_timeout"`
	PerAttemptTimeout time.Duration `json:"per_attempt_timeout"`
	Retries           int           `json:"retries"`
}

type SNMPProbeAttempt struct {
	Community  string `json:"community,omitempty"`
	VersionTry string `json:"version_try,omitempty"`
	Success    bool   `json:"success"`
	DurationMS int64  `json:"duration_ms"`
	ErrorClass string `json:"error_class,omitempty"`
}

type SNMPServiceInfo struct {
	Target        string             `json:"target"`
	Port          int                `json:"port"`
	SNMPProbe     bool               `json:"snmp_probe"`
	SNMPVersion   string             `json:"snmp_version,omitempty"`
	Community     string             `json:"community,omitempty"`
	SysDescr      string             `json:"sys_descr,omitempty"`
	SysName       string             `json:"sys_name,omitempty"`
	SysObjectID   string             `json:"sys_object_id,omitempty"`
	VendorHint    string             `json:"vendor_hint,omitempty"`
	ProductHint   string             `json:"product_hint,omitempty"`
	VersionHint   string             `json:"version_hint,omitempty"`
	WeakProtocol  bool               `json:"weak_protocol"`
	WeakCommunity bool               `json:"weak_community"`
	ProbeError    string             `json:"probe_error,omitempty"`
	Attempts      []SNMPProbeAttempt `json:"attempts,omitempty"`
}

type snmpNativeProbeModule struct {
	meta    engine.ModuleMetadata
	options SNMPProbeOptions
}

type snmpProbeCandidate struct {
	target string
	port   int
}

type snmpAttemptPlan struct {
	community string
	version   gosnmp.SnmpVersion
}

type snmpProbeOutcome struct {
	snmpVersion string
	community   string
	sysDescr    string
	sysName     string
	sysObjectID string
	vendorHint  string
	productHint string
	versionHint string
	duration    time.Duration
}

var (
	probeSNMPDetailsFunc   = probeSNMPDetails
	executeSNMPAttemptFunc = executeSNMPAttempt

	errSNMPNoResponse = errors.New("snmp no response")
	errSNMPDecode     = errors.New("snmp decode error")

	snmpNetSNMPPattern  = regexp.MustCompile(`(?i)\bnet-snmp(?:\s+v?([0-9][0-9a-z._-]*))?`)
	snmpCiscoIOSPattern = regexp.MustCompile(`(?i)\bcisco ios(?: software)?[, ]+version\s+([0-9][0-9a-z()._-]*)`)
	snmpWindowsPattern  = regexp.MustCompile(`(?i)\bversion\s+([0-9][0-9a-z._-]*)`)
	//nolint:misspell // RouterOS is the upstream product name.
	snmpMikroTikPattern = regexp.MustCompile(`(?i)\bmikrotik(?:\s+routeros)?(?:\s+v?([0-9][0-9a-z._-]*))?`)
)

func newSNMPNativeProbeModule() *snmpNativeProbeModule {
	return &snmpNativeProbeModule{
		meta: engine.ModuleMetadata{
			ID:          snmpNativeProbeModuleID,
			Name:        snmpNativeProbeModuleName,
			Description: snmpNativeProbeModuleDescription,
			Version:     "0.1.0",
			Type:        engine.ScanModuleType,
			Author:      "Vulntor Team",
			Tags:        []string{"scan", "snmp", "udp", "native_probe", "enrichment"},
			Consumes: []engine.DataContractEntry{
				{
					Key:          "discovery.open_udp_ports",
					DataTypeName: "discovery.UDPPortDiscoveryResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   false,
					Description:  "Open UDP ports used to identify SNMP candidates.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key:          "service.snmp.details",
					DataTypeName: "scan.SNMPServiceInfo",
					Cardinality:  engine.CardinalityList,
					Description:  "Structured SNMP native probe output per target and port.",
				},
				{
					Key:          "snmp.version",
					DataTypeName: "string",
					Cardinality:  engine.CardinalityList,
					Description:  "SNMP version for evaluation compatibility.",
				},
				{
					Key:          "snmp.community",
					DataTypeName: "string",
					Cardinality:  engine.CardinalityList,
					Description:  "SNMP community string for evaluation compatibility.",
				},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				"timeout": {
					Description: "Total timeout budget per target (e.g. 2s).",
					Type:        "duration",
					Required:    false,
					Default:     "2s",
				},
				"per_attempt_timeout": {
					Description: "Timeout per SNMP request attempt.",
					Type:        "duration",
					Required:    false,
					Default:     "700ms",
				},
				"retries": {
					Description: "Retry count per attempt plan.",
					Type:        "int",
					Required:    false,
					Default:     0,
				},
			},
		},
		options: defaultSNMPProbeOptions(),
	}
}

func (m *snmpNativeProbeModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *snmpNativeProbeModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	opts := defaultSNMPProbeOptions()
	if configMap != nil {
		if d, ok := parseDurationConfig(configMap["timeout"]); ok && d > 0 {
			opts.TotalTimeout = d
		}
		if d, ok := parseDurationConfig(configMap["per_attempt_timeout"]); ok && d > 0 {
			opts.PerAttemptTimeout = d
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

func (m *snmpNativeProbeModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	rawOpenPorts, ok := inputs["discovery.open_udp_ports"]
	if !ok {
		return nil
	}

	candidateMap := map[string]snmpProbeCandidate{}
	for _, item := range toAnySlice(rawOpenPorts) {
		for _, candidate := range snmpCandidatesFromOpenPorts(item) {
			candidateMap[snmpCandidateKey(candidate)] = candidate
		}
	}
	if len(candidateMap) == 0 {
		return nil
	}

	keys := make([]string, 0, len(candidateMap))
	for key := range candidateMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		candidate := candidateMap[key]
		result := probeSNMPDetailsFunc(ctx, candidate.target, candidate.port, m.options)
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "service.snmp.details",
			Data:           result,
			Timestamp:      time.Now(),
			Target:         candidate.target,
		}
		if strings.TrimSpace(result.SNMPVersion) != "" {
			outputChan <- engine.ModuleOutput{
				FromModuleName: m.meta.ID,
				DataKey:        "snmp.version",
				Data:           result.SNMPVersion,
				Timestamp:      time.Now(),
				Target:         candidate.target,
			}
		}
		if strings.TrimSpace(result.Community) != "" {
			outputChan <- engine.ModuleOutput{
				FromModuleName: m.meta.ID,
				DataKey:        "snmp.community",
				Data:           result.Community,
				Timestamp:      time.Now(),
				Target:         candidate.target,
			}
		}
	}

	return nil
}

func defaultSNMPProbeOptions() SNMPProbeOptions {
	return SNMPProbeOptions{
		TotalTimeout:      2 * time.Second,
		PerAttemptTimeout: 700 * time.Millisecond,
		Retries:           0,
	}
}

func snmpCandidatesFromOpenPorts(item any) []snmpProbeCandidate {
	candidates := make([]snmpProbeCandidate, 0, 1)
	appendCandidate := func(target string, port int) {
		target = strings.TrimSpace(target)
		if target == "" || port != 161 {
			return
		}
		candidates = append(candidates, snmpProbeCandidate{target: target, port: port})
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
			for _, item := range ports {
				switch port := item.(type) {
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

func snmpCandidateKey(candidate snmpProbeCandidate) string {
	return fmt.Sprintf("%s:%d", candidate.target, candidate.port)
}

func probeSNMPDetails(ctx context.Context, target string, port int, opts SNMPProbeOptions) SNMPServiceInfo {
	if port <= 0 {
		port = 161
	}
	if opts.TotalTimeout <= 0 {
		opts.TotalTimeout = 2 * time.Second
	}
	if opts.PerAttemptTimeout <= 0 {
		opts.PerAttemptTimeout = 700 * time.Millisecond
	}
	if opts.Retries < 0 {
		opts.Retries = 0
	}

	probeCtx, cancel := context.WithTimeout(ctx, opts.TotalTimeout)
	defer cancel()

	result := SNMPServiceInfo{
		Target:   target,
		Port:     port,
		Attempts: make([]SNMPProbeAttempt, 0, 4*(opts.Retries+1)),
	}

	attemptErrors := make([]string, 0, 4*(opts.Retries+1))
	for _, plan := range buildSNMPAttemptPlan() {
		for retry := 0; retry <= opts.Retries; retry++ {
			outcome, err := executeSNMPAttemptFunc(probeCtx, target, port, plan, opts.PerAttemptTimeout)
			if err != nil {
				errorClass := classifySNMPProbeError(err)
				attemptErrors = append(attemptErrors, errorClass)
				result.Attempts = append(result.Attempts, SNMPProbeAttempt{
					Community:  plan.community,
					VersionTry: snmpVersionString(plan.version),
					Success:    false,
					DurationMS: outcome.duration.Milliseconds(),
					ErrorClass: errorClass,
				})
				if probeCtx.Err() != nil {
					result.ProbeError = "timeout"
					return result
				}
				continue
			}

			result.Attempts = append(result.Attempts, SNMPProbeAttempt{
				Community:  plan.community,
				VersionTry: outcome.snmpVersion,
				Success:    true,
				DurationMS: outcome.duration.Milliseconds(),
			})
			result.SNMPProbe = true
			result.SNMPVersion = outcome.snmpVersion
			result.Community = outcome.community
			result.SysDescr = outcome.sysDescr
			result.SysName = outcome.sysName
			result.SysObjectID = outcome.sysObjectID
			result.VendorHint = outcome.vendorHint
			result.ProductHint = outcome.productHint
			result.VersionHint = outcome.versionHint
			result.WeakProtocol = outcome.snmpVersion == "SNMPv1"
			result.WeakCommunity = isWeakSNMPCommunity(outcome.community)
			return result
		}
	}

	result.ProbeError = pickTopSNMPProbeError(attemptErrors)
	if result.ProbeError == "" {
		result.ProbeError = "probe_failed"
	}
	return result
}

func buildSNMPAttemptPlan() []snmpAttemptPlan {
	return []snmpAttemptPlan{
		{community: snmpCommunityPub, version: gosnmp.Version2c},
		{community: snmpCommunityPub, version: gosnmp.Version1},
		{community: snmpCommunityPriv, version: gosnmp.Version2c},
		{community: snmpCommunityPriv, version: gosnmp.Version1},
	}
}

func executeSNMPAttempt(
	ctx context.Context,
	target string,
	port int,
	plan snmpAttemptPlan,
	perAttemptTimeout time.Duration,
) (snmpProbeOutcome, error) {
	outcome := snmpProbeOutcome{}
	if ctx.Err() != nil {
		return outcome, ctx.Err()
	}

	timeout := perAttemptTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return outcome, context.DeadlineExceeded
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return outcome, context.DeadlineExceeded
	}

	start := time.Now()
	client := &gosnmp.GoSNMP{
		Target:    target,
		Port:      uint16(port), //nolint:gosec
		Transport: "udp",
		Community: plan.community,
		Version:   plan.version,
		Timeout:   timeout,
		Retries:   0,
		Context:   ctx,
	}
	if err := client.Connect(); err != nil {
		outcome.duration = time.Since(start)
		return outcome, err
	}
	defer client.Conn.Close()

	packet, err := client.Get([]string{snmpOIDSysDescr, snmpOIDSysObject, snmpOIDSysName})
	outcome.duration = time.Since(start)
	if err != nil {
		return outcome, err
	}
	if packet == nil || len(packet.Variables) == 0 {
		return outcome, errSNMPNoResponse
	}

	sysDescr, sysObjectID, sysName, err := extractSNMPResponse(packet.Variables)
	if err != nil {
		return outcome, err
	}

	vendorHint, productHint, versionHint := inferSNMPHints(sysDescr, sysObjectID)
	outcome.snmpVersion = snmpVersionString(plan.version)
	outcome.community = plan.community
	outcome.sysDescr = sysDescr
	outcome.sysObjectID = sysObjectID
	outcome.sysName = sysName
	outcome.vendorHint = vendorHint
	outcome.productHint = productHint
	outcome.versionHint = versionHint
	return outcome, nil
}

func extractSNMPResponse(variables []gosnmp.SnmpPDU) (string, string, string, error) {
	var sysDescr string
	var sysObjectID string
	var sysName string

	for _, variable := range variables {
		switch strings.TrimSpace(variable.Name) {
		case snmpOIDSysDescr, strings.TrimPrefix(snmpOIDSysDescr, "."):
			sysDescr = strings.TrimSpace(snmpPDUStringValue(variable))
		case snmpOIDSysObject, strings.TrimPrefix(snmpOIDSysObject, "."):
			sysObjectID = strings.TrimSpace(snmpPDUStringValue(variable))
		case snmpOIDSysName, strings.TrimPrefix(snmpOIDSysName, "."):
			sysName = strings.TrimSpace(snmpPDUStringValue(variable))
		}
	}

	if sysDescr == "" && sysObjectID == "" && sysName == "" {
		return "", "", "", errSNMPDecode
	}
	return sysDescr, sysObjectID, sysName, nil
}

func snmpPDUStringValue(variable gosnmp.SnmpPDU) string {
	switch value := variable.Value.(type) {
	case string:
		return value
	case []byte:
		return string(value)
	case fmt.Stringer:
		return value.String()
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func inferSNMPHints(sysDescr string, sysObjectID string) (string, string, string) {
	lowerDescr := strings.ToLower(strings.TrimSpace(sysDescr))
	objectID := strings.TrimSpace(sysObjectID)

	if match := snmpNetSNMPPattern.FindStringSubmatch(sysDescr); match != nil {
		return "Net-SNMP Project", "Net-SNMP", firstRegexGroup(match)
	}

	if strings.Contains(lowerDescr, "cisco ios") || strings.HasPrefix(objectID, ".1.3.6.1.4.1.9.") || strings.HasPrefix(objectID, "1.3.6.1.4.1.9.") {
		return "Cisco", "Cisco IOS", firstRegexGroup(snmpCiscoIOSPattern.FindStringSubmatch(sysDescr))
	}

	if (strings.Contains(lowerDescr, "windows") && strings.Contains(lowerDescr, "snmp")) ||
		strings.HasPrefix(objectID, ".1.3.6.1.4.1.311.") ||
		strings.HasPrefix(objectID, "1.3.6.1.4.1.311.") {
		return "Microsoft", "Windows SNMP", firstRegexGroup(snmpWindowsPattern.FindStringSubmatch(sysDescr))
	}

	if strings.Contains(lowerDescr, "mikrotik") ||
		strings.HasPrefix(objectID, ".1.3.6.1.4.1.14988.") ||
		strings.HasPrefix(objectID, "1.3.6.1.4.1.14988.") {
		return "MikroTik", "MikroTik SNMP", firstRegexGroup(snmpMikroTikPattern.FindStringSubmatch(sysDescr))
	}

	return "", "", ""
}

func firstRegexGroup(groups []string) string {
	if len(groups) < 2 {
		return ""
	}
	return strings.TrimSpace(groups[1])
}

func snmpVersionString(version gosnmp.SnmpVersion) string {
	switch version {
	case gosnmp.Version1:
		return "SNMPv1"
	case gosnmp.Version2c:
		return "SNMPv2c"
	default:
		return ""
	}
}

func isWeakSNMPCommunity(community string) bool {
	switch strings.ToLower(strings.TrimSpace(community)) {
	case snmpCommunityPub, snmpCommunityPriv:
		return true
	default:
		return false
	}
}

func classifySNMPProbeError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, errSNMPNoResponse) {
		return "no_response"
	}
	if errors.Is(err, errSNMPDecode) {
		return "decode_error"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "no_response"
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(message, "no response"), strings.Contains(message, "request timeout"), strings.Contains(message, "timeout"):
		return "no_response"
	case strings.Contains(message, "unmarshal"), strings.Contains(message, "malformed"), strings.Contains(message, "asn1"), strings.Contains(message, "decode"):
		return "decode_error"
	default:
		return "probe_failed"
	}
}

func pickTopSNMPProbeError(errorsSeen []string) string {
	if len(errorsSeen) == 0 {
		return ""
	}
	for _, candidate := range []string{"decode_error", "timeout", "no_response", "probe_failed"} {
		if slices.Contains(errorsSeen, candidate) {
			return candidate
		}
	}
	return errorsSeen[0]
}

func init() {
	engine.RegisterModuleFactory(snmpNativeProbeModuleName, func() engine.Module {
		return newSNMPNativeProbeModule()
	})
}
