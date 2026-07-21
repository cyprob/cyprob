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

	// SNMPv3 (USM) credentials. When V3Username is set, a v3 attempt is tried
	// first, before the v1/v2c community fallbacks. The security level is
	// derived from which passphrases are supplied: authPriv (auth+priv),
	// authNoPriv (auth only), or noAuthNoPriv (neither).
	V3Username       string `json:"v3_username,omitempty"`
	V3AuthProtocol   string `json:"v3_auth_protocol,omitempty"`
	V3AuthPassphrase string `json:"v3_auth_passphrase,omitempty"`
	V3PrivProtocol   string `json:"v3_priv_protocol,omitempty"`
	V3PrivPassphrase string `json:"v3_priv_passphrase,omitempty"`
}

type SNMPProbeAttempt struct {
	Community  string `json:"community,omitempty"`
	User       string `json:"user,omitempty"`
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
	User          string             `json:"user,omitempty"`
	SecurityLevel string             `json:"security_level,omitempty"`
	SysDescr      string             `json:"sys_descr,omitempty"`
	SysName       string             `json:"sys_name,omitempty"`
	SysObjectID   string             `json:"sys_object_id,omitempty"`
	VendorHint    string             `json:"vendor_hint,omitempty"`
	ProductHint   string             `json:"product_hint,omitempty"`
	VersionHint   string             `json:"version_hint,omitempty"`
	DeviceType    string             `json:"device_type,omitempty"`
	Model         string             `json:"model,omitempty"`
	Serial        string             `json:"serial,omitempty"`
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
	v3        *snmpV3Credential
}

// snmpV3Credential holds a resolved SNMPv3 (USM) credential set plus the
// derived message flags / human-readable security level.
type snmpV3Credential struct {
	username       string
	authProtocol   gosnmp.SnmpV3AuthProtocol
	authPassphrase string
	privProtocol   gosnmp.SnmpV3PrivProtocol
	privPassphrase string
	msgFlags       gosnmp.SnmpV3MsgFlags
	securityLevel  string
}

type snmpProbeOutcome struct {
	snmpVersion   string
	community     string
	username      string
	securityLevel string
	sysDescr      string
	sysName       string
	sysObjectID   string
	vendorHint    string
	productHint   string
	versionHint   string
	model         string
	serial        string
	duration      time.Duration
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
				"snmpv3_username": {
					Description: "SNMPv3 (USM) security name. When set, a v3 attempt is tried before v1/v2c.",
					Type:        "string",
					Required:    false,
					Default:     "",
				},
				"snmpv3_auth_protocol": {
					Description: "SNMPv3 authentication protocol: MD5, SHA, SHA224, SHA256, SHA384, SHA512 (default SHA256).",
					Type:        "string",
					Required:    false,
					Default:     "SHA256",
				},
				"snmpv3_auth_pass": {
					Description: "SNMPv3 authentication passphrase. Omit for noAuthNoPriv.",
					Type:        "string",
					Required:    false,
					Default:     "",
				},
				"snmpv3_priv_protocol": {
					Description: "SNMPv3 privacy protocol: DES, AES, AES192, AES256 (default AES256).",
					Type:        "string",
					Required:    false,
					Default:     "AES256",
				},
				"snmpv3_priv_pass": {
					Description: "SNMPv3 privacy passphrase. Omit for authNoPriv.",
					Type:        "string",
					Required:    false,
					Default:     "",
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
		opts.V3Username = snmpConfigString(configMap, "snmpv3_username", opts.V3Username)
		opts.V3AuthProtocol = snmpConfigString(configMap, "snmpv3_auth_protocol", opts.V3AuthProtocol)
		opts.V3AuthPassphrase = snmpConfigString(configMap, "snmpv3_auth_pass", opts.V3AuthPassphrase)
		opts.V3PrivProtocol = snmpConfigString(configMap, "snmpv3_priv_protocol", opts.V3PrivProtocol)
		opts.V3PrivPassphrase = snmpConfigString(configMap, "snmpv3_priv_pass", opts.V3PrivPassphrase)
	}
	m.options = opts
	return nil
}

func snmpConfigString(configMap map[string]any, key, fallback string) string {
	if value, ok := configMap[key].(string); ok {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return fallback
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

	plans := buildSNMPAttemptPlan(opts)
	attemptErrors := make([]string, 0, len(plans)*(opts.Retries+1))
	for _, plan := range plans {
		for retry := 0; retry <= opts.Retries; retry++ {
			outcome, err := executeSNMPAttemptFunc(probeCtx, target, port, plan, opts.PerAttemptTimeout)
			if err != nil {
				errorClass := classifySNMPProbeError(err)
				attemptErrors = append(attemptErrors, errorClass)
				result.Attempts = append(result.Attempts, SNMPProbeAttempt{
					Community:  plan.community,
					User:       snmpPlanUser(plan),
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
				User:       snmpPlanUser(plan),
				VersionTry: outcome.snmpVersion,
				Success:    true,
				DurationMS: outcome.duration.Milliseconds(),
			})
			result.SNMPProbe = true
			result.SNMPVersion = outcome.snmpVersion
			result.Community = outcome.community
			result.User = outcome.username
			result.SecurityLevel = outcome.securityLevel
			result.SysDescr = outcome.sysDescr
			result.SysName = outcome.sysName
			result.SysObjectID = outcome.sysObjectID
			result.VendorHint = outcome.vendorHint
			result.ProductHint = outcome.productHint
			result.VersionHint = outcome.versionHint
			result.DeviceType = classifySNMPDevice(outcome.sysDescr, outcome.vendorHint, outcome.productHint)
			result.Model = outcome.model
			result.Serial = outcome.serial
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

func buildSNMPAttemptPlan(opts SNMPProbeOptions) []snmpAttemptPlan {
	plans := make([]snmpAttemptPlan, 0, 5)
	// SNMPv3 is tried first when configured: hardened targets (e.g. banks)
	// disable v1/v2c, and v3 credentials cannot be guessed.
	if cred := opts.resolveV3Credential(); cred != nil {
		plans = append(plans, snmpAttemptPlan{version: gosnmp.Version3, v3: cred})
	}
	plans = append(plans,
		snmpAttemptPlan{community: snmpCommunityPub, version: gosnmp.Version2c},
		snmpAttemptPlan{community: snmpCommunityPub, version: gosnmp.Version1},
		snmpAttemptPlan{community: snmpCommunityPriv, version: gosnmp.Version2c},
		snmpAttemptPlan{community: snmpCommunityPriv, version: gosnmp.Version1},
	)
	return plans
}

// resolveV3Credential builds a USM credential from the options, deriving the
// security level from which passphrases were supplied. Returns nil when no
// SNMPv3 username is configured.
func (o SNMPProbeOptions) resolveV3Credential() *snmpV3Credential {
	username := strings.TrimSpace(o.V3Username)
	if username == "" {
		return nil
	}
	cred := &snmpV3Credential{
		username:       username,
		authProtocol:   mapSNMPAuthProtocol(o.V3AuthProtocol),
		authPassphrase: o.V3AuthPassphrase,
		privProtocol:   mapSNMPPrivProtocol(o.V3PrivProtocol),
		privPassphrase: o.V3PrivPassphrase,
	}

	hasAuth := cred.authProtocol != gosnmp.NoAuth && strings.TrimSpace(cred.authPassphrase) != ""
	hasPriv := cred.privProtocol != gosnmp.NoPriv && strings.TrimSpace(cred.privPassphrase) != ""
	switch {
	case hasAuth && hasPriv:
		cred.msgFlags = gosnmp.AuthPriv
		cred.securityLevel = "authPriv"
	case hasAuth:
		cred.msgFlags = gosnmp.AuthNoPriv
		cred.securityLevel = "authNoPriv"
		cred.privProtocol = gosnmp.NoPriv
		cred.privPassphrase = ""
	default:
		cred.msgFlags = gosnmp.NoAuthNoPriv
		cred.securityLevel = "noAuthNoPriv"
		cred.authProtocol = gosnmp.NoAuth
		cred.authPassphrase = ""
		cred.privProtocol = gosnmp.NoPriv
		cred.privPassphrase = ""
	}
	return cred
}

func mapSNMPAuthProtocol(name string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "MD5":
		return gosnmp.MD5
	case "SHA", "SHA1":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	default:
		// SHA256 is the bank-friendly default (also for empty/unknown).
		return gosnmp.SHA256
	}
}

func mapSNMPPrivProtocol(name string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "DES":
		return gosnmp.DES
	case "AES", "AES128":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	default:
		// AES256 is the bank-friendly default (also for empty/unknown).
		return gosnmp.AES256
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
		Version:   plan.version,
		Timeout:   timeout,
		Retries:   0,
		Context:   ctx,
	}
	if plan.v3 != nil {
		client.SecurityModel = gosnmp.UserSecurityModel
		client.MsgFlags = plan.v3.msgFlags
		client.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 plan.v3.username,
			AuthenticationProtocol:   plan.v3.authProtocol,
			AuthenticationPassphrase: plan.v3.authPassphrase,
			PrivacyProtocol:          plan.v3.privProtocol,
			PrivacyPassphrase:        plan.v3.privPassphrase,
		}
	} else {
		client.Community = plan.community
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
	if plan.v3 != nil {
		outcome.username = plan.v3.username
		outcome.securityLevel = plan.v3.securityLevel
	} else {
		outcome.community = plan.community
	}
	// Best-effort model/serial via ENTITY-MIB, only for identified devices (a
	// vendor hint means it is infra gear more likely to expose ENTITY-MIB, and
	// avoids a wasted walk on unidentified hosts).
	if vendorHint != "" {
		outcome.model, outcome.serial = fetchSNMPEntityFunc(client)
	}
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

	// Fallback: map the sysObjectID's enterprise number to a manufacturer via
	// the IANA PEN table. This recognizes the long tail of vendors (Fortinet,
	// Palo Alto, F5, Juniper, HP, printers, ...) that the specific patterns
	// above do not, without a version.
	if vendor, product, ok := lookupSNMPEnterprise(objectID); ok {
		return vendor, product, ""
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
	case gosnmp.Version3:
		return "SNMPv3"
	default:
		return ""
	}
}

func snmpPlanUser(plan snmpAttemptPlan) string {
	if plan.v3 != nil {
		return plan.v3.username
	}
	return ""
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
