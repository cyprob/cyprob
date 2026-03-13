package parse

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
	"github.com/rs/zerolog/log"
)

const (
	serviceIdentityNormalizerModuleID          = "service-identity-normalizer-instance"
	serviceIdentityNormalizerModuleName        = "service-identity-normalizer"
	serviceIdentityNormalizerModuleDescription = "Merges fingerprint, SMB native probe, and heuristics into canonical service identity."
)

const (
	sourceSMBNative        = "smb_native_enum"
	sourceSMBCorrelation   = "smb_correlation"
	sourceRDPNative        = "rdp_native_probe"
	sourceRPCNative        = "rpc_native_probe"
	sourceTLSNative        = "tls_native_probe"
	sourceSSHNative        = "ssh_native_probe"
	sourceSMTPNative       = "smtp_native_probe"
	sourceSNMPNative       = "snmp_native_probe"
	sourceFTPNative        = "ftp_native_probe"
	sourceMySQLNative      = "mysql_native_probe"
	sourceHTTPIdentityHint = "http_identity_hint"
	sourceFingerprint      = "fingerprint"
	sourceHeuristic        = "heuristic"
	sourceBanner           = "banner"
)

// ServiceOSHints contains canonical OS hint fields.
type ServiceOSHints struct {
	Family  string `json:"family,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// ServiceIdentityInfo is canonical per-service identity output.
type ServiceIdentityInfo struct {
	Target          string             `json:"target"`
	Port            int                `json:"port"`
	Protocol        string             `json:"protocol,omitempty"`
	ServiceName     string             `json:"service_name,omitempty"`
	Product         string             `json:"product,omitempty"`
	Vendor          string             `json:"vendor,omitempty"`
	Version         string             `json:"version,omitempty"`
	CPE             string             `json:"cpe,omitempty"`
	Banner          string             `json:"banner,omitempty"`
	TechTags        []string           `json:"tech_tags,omitempty"`
	HostnameHint    string             `json:"hostname_hint,omitempty"`
	OSHints         ServiceOSHints     `json:"os_hints,omitzero"`
	FieldSources    map[string]string  `json:"field_sources,omitempty"`
	FieldConfidence map[string]float64 `json:"field_confidence,omitempty"`
}

type serviceIdentityNormalizerModule struct {
	meta engine.ModuleMetadata
}

type smbHostEvidence struct {
	Vendor  string
	Version string
}

type httpIdentityDecision struct {
	Rule       string
	Signals    []string
	Product    string
	Vendor     string
	Confidence float64
}

var httpIdentityDecisionTable = []httpIdentityDecision{
	{
		Rule: httpIdentitySignalGitHubHost,
		Signals: []string{
			httpIdentitySignalGitHubHost,
			httpIdentitySignalGitHubTitle,
			httpIdentitySignalGitHubBody,
			httpIdentitySignalGitHubCookie,
		},
		Product:    "GitHub Web",
		Vendor:     "GitHub",
		Confidence: httpIdentityConfidenceGitHub,
	},
	{
		Rule: httpIdentitySignalSmarterMailRoute,
		Signals: []string{
			httpIdentitySignalSmarterMailRoute,
			httpIdentitySignalSmarterMailTitle,
			httpIdentitySignalSmarterMailBody,
		},
		Product:    "SmarterMail",
		Vendor:     "SmarterTools",
		Confidence: httpIdentityConfidenceSmarterMail,
	},
	{
		Rule: httpIdentitySignalWordPressContent,
		Signals: []string{
			httpIdentitySignalWordPressContent,
			httpIdentitySignalWordPressBody,
			httpIdentitySignalWordPressTitle,
		},
		Product:    "WordPress",
		Confidence: httpIdentityConfidenceCMS,
	},
	{
		Rule: httpIdentitySignalDrupalBody,
		Signals: []string{
			httpIdentitySignalDrupalBody,
			httpIdentitySignalDrupalSitesDefault,
			httpIdentitySignalDrupalSitesAll,
		},
		Product:    "Drupal",
		Confidence: httpIdentityConfidenceCMS,
	},
	{
		Rule: httpIdentitySignalJoomlaBody,
		Signals: []string{
			httpIdentitySignalJoomlaBody,
			httpIdentitySignalJoomlaContent,
		},
		Product:    "Joomla",
		Confidence: httpIdentityConfidenceCMS,
	},
}

func newServiceIdentityNormalizerModule() *serviceIdentityNormalizerModule {
	return &serviceIdentityNormalizerModule{
		meta: engine.ModuleMetadata{
			ID:          serviceIdentityNormalizerModuleID,
			Name:        serviceIdentityNormalizerModuleName,
			Description: serviceIdentityNormalizerModuleDescription,
			Version:     "0.1.0",
			Type:        engine.ParseModuleType,
			Author:      "Vulntor Team",
			Tags:        []string{"parse", "normalizer", "identity", "canonical"},
			Consumes: []engine.DataContractEntry{
				{Key: "service.banner.tcp", DataTypeName: "scan.BannerGrabResult", Cardinality: engine.CardinalityList, IsOptional: true},
				{Key: "service.fingerprint.details", DataTypeName: "parse.FingerprintParsedInfo", Cardinality: engine.CardinalityList, IsOptional: true},
				{Key: "service.tech.tags", DataTypeName: "parse.TechTagResult", Cardinality: engine.CardinalityList, IsOptional: true},
				{Key: "service.ftp.details", DataTypeName: "scan.FTPServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
				{Key: "service.mysql.details", DataTypeName: "scan.MySQLServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
				{Key: "service.smtp.details", DataTypeName: "scan.SMTPServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
				{Key: "service.ssh.details", DataTypeName: "scan.SSHServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
					{Key: "service.snmp.details", DataTypeName: "scan.SNMPServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
				{Key: "service.smb.details", DataTypeName: "scan.SMBServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
				{Key: "service.rdp.details", DataTypeName: "scan.RDPServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
					{Key: "service.rpc.details", DataTypeName: "scan.RPCServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
					{Key: "service.tls.details", DataTypeName: "scan.TLSServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
			},
			Produces: []engine.DataContractEntry{
				{Key: "service.identity.details", DataTypeName: "parse.ServiceIdentityInfo", Cardinality: engine.CardinalityList},
			},
		},
	}
}

func (m *serviceIdentityNormalizerModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

func (m *serviceIdentityNormalizerModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	_ = configMap
	return nil
}

func (m *serviceIdentityNormalizerModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	entries := make(map[string]*ServiceIdentityInfo)

	getEntry := func(target string, port int) *ServiceIdentityInfo {
		key := identityKey(target, port)
		if existing, ok := entries[key]; ok {
			return existing
		}
		entry := &ServiceIdentityInfo{
			Target:          target,
			Port:            port,
			FieldSources:    map[string]string{},
			FieldConfidence: map[string]float64{},
		}
		entries[key] = entry
		return entry
	}

	m.ingestBanners(inputs, getEntry)
	m.ingestFingerprints(inputs, getEntry)
	m.ingestTechTags(inputs, getEntry)
	m.ingestFTPDetails(inputs, getEntry)
	m.ingestMySQLDetails(inputs, getEntry)
	m.ingestSMTPDetails(inputs, getEntry)
	m.ingestSNMPDetails(inputs, getEntry)
	m.ingestSMBDetails(inputs, getEntry)
	smbEvidence := collectSMBHostEvidence(inputs)
	m.ingestRDPDetails(inputs, smbEvidence, getEntry)
	m.ingestRPCDetails(inputs, getEntry)
	m.ingestTLSDetails(inputs, getEntry)
	m.ingestSSHDetails(inputs, getEntry)
	m.ingestHTTPIdentityHints(inputs, getEntry)
	m.applyHeuristics(entries)
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		entry := entries[key]
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "service.identity.details",
			Data:           *entry,
			Timestamp:      time.Now(),
			Target:         entry.Target,
		}
	}
	return nil
}

func (m *serviceIdentityNormalizerModule) ingestBanners(inputs map[string]any, getEntry func(target string, port int) *ServiceIdentityInfo) {
	raw, ok := inputs["service.banner.tcp"]
	if !ok {
		return
	}
	items := toAnyList(raw)
	for _, item := range items {
		banner, ok := item.(scanpkg.BannerGrabResult)
		if !ok {
			continue
		}
		if banner.IP == "" || banner.Port <= 0 {
			continue
		}
		entry := getEntry(banner.IP, banner.Port)
		if entry.Protocol == "" {
			entry.Protocol = strings.ToLower(strings.TrimSpace(banner.Protocol))
			if entry.Protocol == "" {
				entry.Protocol = "tcp"
			}
		}
		if isServiceNameEmptyOrUnknown(entry.ServiceName) {
			setIdentityField(entry, "service_name", serviceNameFromPort(banner.Port), sourceHeuristic, 0.40)
		}
		if strings.TrimSpace(banner.Banner) != "" {
			setIdentityField(entry, "banner", strings.TrimSpace(banner.Banner), sourceBanner, 0.55)
		}
	}
}

func (m *serviceIdentityNormalizerModule) ingestFingerprints(inputs map[string]any, getEntry func(target string, port int) *ServiceIdentityInfo) {
	raw, ok := inputs["service.fingerprint.details"]
	if !ok {
		return
	}
	items := toAnyList(raw)
	for _, item := range items {
		fp, ok := item.(FingerprintParsedInfo)
		if !ok {
			continue
		}
		if fp.Target == "" || fp.Port <= 0 {
			continue
		}
		entry := getEntry(fp.Target, fp.Port)
		baseConf := fp.Confidence
		if baseConf <= 0 {
			baseConf = 0.70
		}
		if baseConf > 0.95 {
			baseConf = 0.95
		}
		if fp.Protocol != "" {
			setIdentityField(entry, "service_name", strings.ToLower(strings.TrimSpace(fp.Protocol)), sourceFingerprint, baseConf)
		}
		if fp.Product != "" {
			setIdentityField(entry, "product", strings.TrimSpace(fp.Product), sourceFingerprint, baseConf)
		}
		if fp.Vendor != "" {
			setIdentityField(entry, "vendor", strings.TrimSpace(fp.Vendor), sourceFingerprint, baseConf)
		}
		if fp.Version != "" {
			setIdentityField(entry, "version", strings.TrimSpace(fp.Version), sourceFingerprint, baseConf)
		}
		if fp.CPE != "" && !strings.HasPrefix(strings.ToLower(fp.CPE), "unknown:") {
			setIdentityField(entry, "cpe", strings.TrimSpace(fp.CPE), sourceFingerprint, baseConf)
		}
	}
}

func (m *serviceIdentityNormalizerModule) ingestTechTags(inputs map[string]any, getEntry func(target string, port int) *ServiceIdentityInfo) {
	raw, ok := inputs["service.tech.tags"]
	if !ok {
		return
	}
	items := toAnyList(raw)
	for _, item := range items {
		tagResult, ok := item.(TechTagResult)
		if !ok {
			continue
		}
		if tagResult.Target == "" || tagResult.Port <= 0 {
			continue
		}
		entry := getEntry(tagResult.Target, tagResult.Port)
		entry.TechTags = NormalizeTechTags(append(entry.TechTags, tagResult.Tags...))
	}
}

//nolint:gocyclo // Native SMTP mapping is intentionally field-by-field to keep precedence explicit.
func (m *serviceIdentityNormalizerModule) ingestSMTPDetails(inputs map[string]any, getEntry func(target string, port int) *ServiceIdentityInfo) {
	raw, ok := inputs["service.smtp.details"]
	if !ok {
		return
	}
	items := toAnyList(raw)
	for _, item := range items {
		smtpInfo, ok := item.(scanpkg.SMTPServiceInfo)
		if !ok {
			continue
		}
		if smtpInfo.Target == "" || smtpInfo.Port <= 0 {
			continue
		}
		if !smtpInfo.SMTPProbe && strings.TrimSpace(smtpInfo.Banner) == "" && strings.TrimSpace(smtpInfo.EHLOResponse) == "" {
			continue
		}

		entry := getEntry(smtpInfo.Target, smtpInfo.Port)
		setIdentityField(entry, "service_name", smtpServiceNameFromNative(smtpInfo), sourceSMTPNative, 0.62)
		if strings.TrimSpace(entry.Product) == "" && strings.TrimSpace(smtpInfo.SoftwareHint) != "" {
			setIdentityField(entry, "product", strings.TrimSpace(smtpInfo.SoftwareHint), sourceSMTPNative, 0.70)
		}
		if strings.TrimSpace(entry.Vendor) == "" && strings.TrimSpace(smtpInfo.VendorHint) != "" {
			setIdentityField(entry, "vendor", strings.TrimSpace(smtpInfo.VendorHint), sourceSMTPNative, 0.68)
		}
		if strings.TrimSpace(entry.Version) == "" && strings.TrimSpace(smtpInfo.VersionHint) != "" {
			setIdentityField(entry, "version", strings.TrimSpace(smtpInfo.VersionHint), sourceSMTPNative, 0.66)
		}
		if strings.TrimSpace(entry.Banner) == "" && strings.TrimSpace(smtpInfo.Banner) != "" {
			setIdentityField(entry, "banner", strings.TrimSpace(smtpInfo.Banner), sourceSMTPNative, 0.56)
		}

		tags := []string{TagSMTP}
		if smtpInfo.TLSEnabled || strings.EqualFold(strings.TrimSpace(smtpInfo.SMTPProtocol), "smtps") {
			tags = append(tags, TagTLS)
		}
		entry.TechTags = NormalizeTechTags(append(entry.TechTags, tags...))
	}
}

func (m *serviceIdentityNormalizerModule) ingestFTPDetails(inputs map[string]any, getEntry func(target string, port int) *ServiceIdentityInfo) {
	raw, ok := inputs["service.ftp.details"]
	if !ok {
		return
	}
	items := toAnyList(raw)
	for _, item := range items {
		ftpInfo, ok := item.(scanpkg.FTPServiceInfo)
		if !ok {
			continue
		}
		if ftpInfo.Target == "" || ftpInfo.Port <= 0 {
			continue
		}
		if !ftpInfo.FTPProbe && strings.TrimSpace(ftpInfo.Banner) == "" && len(ftpInfo.Features) == 0 && strings.TrimSpace(ftpInfo.SystemHint) == "" {
			continue
		}

		entry := getEntry(ftpInfo.Target, ftpInfo.Port)
		setIdentityField(entry, "service_name", ftpServiceNameFromNative(ftpInfo), sourceFTPNative, 0.62)
		if strings.TrimSpace(entry.Product) == "" && strings.TrimSpace(ftpInfo.SoftwareHint) != "" {
			setIdentityField(entry, "product", strings.TrimSpace(ftpInfo.SoftwareHint), sourceFTPNative, 0.72)
		}
		if strings.TrimSpace(entry.Vendor) == "" && strings.TrimSpace(ftpInfo.VendorHint) != "" {
			setIdentityField(entry, "vendor", strings.TrimSpace(ftpInfo.VendorHint), sourceFTPNative, 0.70)
		}
		if strings.TrimSpace(entry.Version) == "" && strings.TrimSpace(ftpInfo.VersionHint) != "" {
			setIdentityField(entry, "version", strings.TrimSpace(ftpInfo.VersionHint), sourceFTPNative, 0.66)
		}
		if strings.TrimSpace(entry.Banner) == "" && strings.TrimSpace(ftpInfo.Banner) != "" {
			setIdentityField(entry, "banner", strings.TrimSpace(ftpInfo.Banner), sourceFTPNative, 0.56)
		}

		tags := []string{TagFTP}
		if ftpInfo.TLSEnabled || strings.EqualFold(strings.TrimSpace(ftpInfo.FTPProtocol), "ftps") {
			tags = append(tags, TagTLS)
		}
		entry.TechTags = NormalizeTechTags(append(entry.TechTags, tags...))
	}
}

func (m *serviceIdentityNormalizerModule) ingestMySQLDetails(inputs map[string]any, getEntry func(target string, port int) *ServiceIdentityInfo) {
	raw, ok := inputs["service.mysql.details"]
	if !ok {
		return
	}
	items := toAnyList(raw)
	for _, item := range items {
		mysqlInfo, ok := item.(scanpkg.MySQLServiceInfo)
		if !ok {
			continue
		}
		if mysqlInfo.Target == "" || mysqlInfo.Port <= 0 || !mysqlInfo.MySQLProbe {
			continue
		}

		entry := getEntry(mysqlInfo.Target, mysqlInfo.Port)
		setIdentityField(entry, "service_name", "mysql", sourceMySQLNative, 0.68)
		if strings.TrimSpace(entry.Product) == "" && strings.TrimSpace(mysqlInfo.ProductHint) != "" {
			setIdentityField(entry, "product", strings.TrimSpace(mysqlInfo.ProductHint), sourceMySQLNative, 0.74)
		}
		if strings.TrimSpace(entry.Vendor) == "" && strings.TrimSpace(mysqlInfo.VendorHint) != "" {
			setIdentityField(entry, "vendor", strings.TrimSpace(mysqlInfo.VendorHint), sourceMySQLNative, 0.72)
		}
		if strings.TrimSpace(entry.Version) == "" && strings.TrimSpace(mysqlInfo.VersionHint) != "" {
			setIdentityField(entry, "version", strings.TrimSpace(mysqlInfo.VersionHint), sourceMySQLNative, 0.66)
		}
		entry.TechTags = NormalizeTechTags(append(entry.TechTags, "mysql"))
	}
}

func (m *serviceIdentityNormalizerModule) ingestSNMPDetails(inputs map[string]any, getEntry func(target string, port int) *ServiceIdentityInfo) {
	raw, ok := inputs["service.snmp.details"]
	if !ok {
		return
	}
	items := toAnyList(raw)
	for _, item := range items {
		snmpInfo, ok := item.(scanpkg.SNMPServiceInfo)
		if !ok {
			continue
		}
		if snmpInfo.Target == "" || snmpInfo.Port <= 0 {
			continue
		}
		if !snmpInfo.SNMPProbe && strings.TrimSpace(snmpInfo.SysDescr) == "" && strings.TrimSpace(snmpInfo.SysObjectID) == "" {
			continue
		}

		entry := getEntry(snmpInfo.Target, snmpInfo.Port)
		setIdentityField(entry, "service_name", "snmp", sourceSNMPNative, 0.64)
		if strings.TrimSpace(entry.Product) == "" && strings.TrimSpace(snmpInfo.ProductHint) != "" {
			setIdentityField(entry, "product", strings.TrimSpace(snmpInfo.ProductHint), sourceSNMPNative, snmpProductConfidence(snmpInfo))
		}
		if strings.TrimSpace(entry.Vendor) == "" && strings.TrimSpace(snmpInfo.VendorHint) != "" {
			setIdentityField(entry, "vendor", strings.TrimSpace(snmpInfo.VendorHint), sourceSNMPNative, snmpVendorConfidence(snmpInfo))
		}
		if strings.TrimSpace(entry.Version) == "" && strings.TrimSpace(snmpInfo.VersionHint) != "" {
			setIdentityField(entry, "version", strings.TrimSpace(snmpInfo.VersionHint), sourceSNMPNative, 0.65)
		}
		entry.TechTags = NormalizeTechTags(append(entry.TechTags, TagSNMP))
	}
}

func (m *serviceIdentityNormalizerModule) ingestSMBDetails(inputs map[string]any, getEntry func(target string, port int) *ServiceIdentityInfo) {
	raw, ok := inputs["service.smb.details"]
	if !ok {
		return
	}
	items := toAnyList(raw)
	for _, item := range items {
		smb, ok := item.(scanpkg.SMBServiceInfo)
		if !ok {
			continue
		}
		if smb.Target == "" || smb.Port <= 0 {
			continue
		}
		entry := getEntry(smb.Target, smb.Port)
		setIdentityField(entry, "service_name", "smb", sourceSMBNative, 0.95)
		if smb.Product != "" {
			setIdentityField(entry, "product", smb.Product, sourceSMBNative, 0.95)
		}
		if smb.Vendor != "" {
			setIdentityField(entry, "vendor", smb.Vendor, sourceSMBNative, 0.95)
		}
		if smb.ProductVersion != "" {
			setIdentityField(entry, "version", smb.ProductVersion, sourceSMBNative, 0.95)
		}

		hostnameHint := chooseHostnameHint(smb.HostHints)
		if hostnameHint != "" {
			setIdentityField(entry, "hostname_hint", hostnameHint, sourceSMBNative, 0.92)
		}
		if smb.OSHints.Family != "" {
			setIdentityOS(entry, smb.OSHints, sourceSMBNative, 0.90)
		}
	}
}

//nolint:gocyclo // RDP normalization keeps correlation rules inline to preserve precedence clarity.
func (m *serviceIdentityNormalizerModule) ingestRDPDetails(
	inputs map[string]any,
	smbEvidence map[string]smbHostEvidence,
	getEntry func(target string, port int) *ServiceIdentityInfo,
) {
	raw, ok := inputs["service.rdp.details"]
	if !ok {
		return
	}
	items := toAnyList(raw)
	for _, item := range items {
		rdp, ok := item.(scanpkg.RDPServiceInfo)
		if !ok {
			continue
		}
		if rdp.Target == "" || rdp.Port <= 0 {
			continue
		}
		if !rdp.RDPProbe && strings.TrimSpace(rdp.RDPDetected) == "" && strings.TrimSpace(rdp.SelectedProtocol) == "" && strings.TrimSpace(rdp.NegFailureCode) == "" {
			continue
		}

		entry := getEntry(rdp.Target, rdp.Port)
		setIdentityField(entry, "service_name", "rdp", sourceRDPNative, 0.96)

		evidence, hasSMBEvidence := smbEvidence[rdp.Target]
		if hasSMBEvidence {
			if strings.TrimSpace(entry.Vendor) == "" && evidence.Vendor != "" {
				setIdentityField(entry, "vendor", evidence.Vendor, sourceSMBCorrelation, 0.60)
			}
			if strings.TrimSpace(entry.Version) == "" && evidence.Version != "" {
				setIdentityField(entry, "version", evidence.Version, sourceSMBCorrelation, 0.60)
			}
		}

		if strings.TrimSpace(entry.Product) == "" && hasSMBEvidence && strings.EqualFold(strings.TrimSpace(entry.Vendor), "microsoft") {
			setIdentityField(entry, "product", "Microsoft Remote Desktop Services (RDP)", sourceSMBCorrelation, 0.60)
		}
		if strings.TrimSpace(entry.Product) == "" {
			setIdentityField(entry, "product", "RDP", sourceRDPNative, 0.70)
		}
		entry.TechTags = NormalizeTechTags(append(entry.TechTags, "rdp"))
	}
}

//nolint:gocyclo // RPC normalization keeps service naming and Windows hinting in one place.
func (m *serviceIdentityNormalizerModule) ingestRPCDetails(inputs map[string]any, getEntry func(target string, port int) *ServiceIdentityInfo) {
	raw, ok := inputs["service.rpc.details"]
	if !ok {
		return
	}
	items := toAnyList(raw)
	for _, item := range items {
		rpcInfo, ok := item.(scanpkg.RPCServiceInfo)
		if !ok {
			continue
		}
		if rpcInfo.Target == "" || rpcInfo.Port <= 0 {
			continue
		}
		if !rpcInfo.RPCProbe && strings.TrimSpace(rpcInfo.PrincipalName) == "" && len(rpcInfo.InterfaceUUIDs) == 0 {
			continue
		}

		entry := getEntry(rpcInfo.Target, rpcInfo.Port)

		strongRPCSignal := rpcInfo.RPCProbe || len(rpcInfo.InterfaceUUIDs) > 0 || strings.TrimSpace(rpcInfo.PrincipalName) != ""

		currentSource := entry.FieldSources["service_name"]
		if isServiceNameEmptyOrUnknown(entry.ServiceName) || currentSource == sourceHeuristic || currentSource == sourceTLSNative {
			serviceName := "rpc"
			if rpcInfo.Port == 135 {
				serviceName = "msrpc"
			}
			setIdentityField(entry, "service_name", serviceName, sourceRPCNative, 0.68)
		}

		if strings.TrimSpace(entry.Product) == "" {
			if rpcInfo.Port == 135 {
				setIdentityField(entry, "product", "Microsoft RPC Endpoint Mapper", sourceRPCNative, 0.66)
			} else {
				setIdentityField(entry, "product", "Microsoft RPC Service", sourceRPCNative, 0.66)
			}
		}

		if strongRPCSignal && strings.TrimSpace(entry.Vendor) == "" {
			setIdentityField(entry, "vendor", "microsoft", sourceRPCNative, 0.60)
		}

		if strongRPCSignal && strings.TrimSpace(entry.Version) == "" {
			if version := inferRPCVersionHint(rpcInfo); version != "" {
				setIdentityField(entry, "version", version, sourceRPCNative, 0.60)
			}
		}

		tags := []string{TagRPC}
		if rpcInfo.Port == 135 {
			tags = append(tags, TagMSRPC)
		}
		if hasStrongWindowsRPCHint(rpcInfo) {
			tags = append(tags, TagWindowsHint)
		}
		entry.TechTags = NormalizeTechTags(append(entry.TechTags, tags...))
	}
}

func (m *serviceIdentityNormalizerModule) ingestTLSDetails(inputs map[string]any, getEntry func(target string, port int) *ServiceIdentityInfo) {
	raw, ok := inputs["service.tls.details"]
	if !ok {
		return
	}
	items := toAnyList(raw)
	for _, item := range items {
		tlsInfo, ok := item.(scanpkg.TLSServiceInfo)
		if !ok {
			continue
		}
		if tlsInfo.Target == "" || tlsInfo.Port <= 0 {
			continue
		}
		if !tlsInfo.TLSProbe && strings.TrimSpace(tlsInfo.TLSVersion) == "" && strings.TrimSpace(tlsInfo.CipherSuite) == "" {
			continue
		}

		entry := getEntry(tlsInfo.Target, tlsInfo.Port)
		currentSource := entry.FieldSources["service_name"]
		if (isServiceNameEmptyOrUnknown(entry.ServiceName) || currentSource == sourceHeuristic) && isHTTPSLikePort(tlsInfo.Port) {
			setIdentityField(entry, "service_name", "https", sourceTLSNative, 0.65)
		}
		entry.TechTags = NormalizeTechTags(append(entry.TechTags, TagTLS, TagHTTPS))
	}
}

func (m *serviceIdentityNormalizerModule) ingestSSHDetails(inputs map[string]any, getEntry func(target string, port int) *ServiceIdentityInfo) {
	raw, ok := inputs["service.ssh.details"]
	if !ok {
		return
	}
	items := toAnyList(raw)
	for _, item := range items {
		sshInfo, ok := item.(scanpkg.SSHServiceInfo)
		if !ok {
			continue
		}
		if sshInfo.Target == "" || sshInfo.Port <= 0 {
			continue
		}
		if !sshInfo.SSHProbe && strings.TrimSpace(sshInfo.SSHBanner) == "" {
			continue
		}

		entry := getEntry(sshInfo.Target, sshInfo.Port)
		setIdentityField(entry, "service_name", "ssh", sourceSSHNative, 0.64)
		if strings.TrimSpace(entry.Product) == "" {
			if strings.TrimSpace(sshInfo.SSHSoftware) != "" {
				setIdentityField(entry, "product", strings.TrimSpace(sshInfo.SSHSoftware), sourceSSHNative, 0.64)
			} else {
				setIdentityField(entry, "product", "SSH", sourceSSHNative, 0.58)
			}
		}
		if strings.TrimSpace(sshInfo.SSHVersion) != "" {
			setIdentityField(entry, "version", strings.TrimSpace(sshInfo.SSHVersion), sourceSSHNative, 0.64)
		}
		if strings.TrimSpace(sshInfo.SSHBanner) != "" && strings.TrimSpace(entry.Banner) == "" {
			setIdentityField(entry, "banner", strings.TrimSpace(sshInfo.SSHBanner), sourceSSHNative, 0.56)
		}
		entry.TechTags = NormalizeTechTags(append(entry.TechTags, "ssh"))
	}
}

func (m *serviceIdentityNormalizerModule) ingestHTTPIdentityHints(inputs map[string]any, getEntry func(target string, port int) *ServiceIdentityInfo) {
	raw, ok := inputs["service.banner.tcp"]
	if !ok {
		return
	}
	items := toAnyList(raw)
	for _, item := range items {
		banner, ok := item.(scanpkg.BannerGrabResult)
		if !ok {
			continue
		}
		if banner.IP == "" || banner.Port <= 0 {
			continue
		}
		entry := getEntry(banner.IP, banner.Port)
		applyHTTPIdentitySignals(entry, banner)
	}
}

func applyHTTPIdentitySignals(entry *ServiceIdentityInfo, banner scanpkg.BannerGrabResult) {
	if entry == nil || !shouldEvaluateHTTPIdentity(entry, banner) {
		return
	}

	signals, skipReason := detectHTTPIdentitySignals(banner)
	if skipReason != "" {
		log.Debug().
			Str("target", entry.Target).
			Int("port", entry.Port).
			Str("http_identity_hint_skipped_reason", skipReason).
			Msg("http_identity_hint_skipped")
		return
	}

	decision, ok := resolveHTTPIdentityDecision(signals)
	if !ok {
		log.Debug().
			Str("target", entry.Target).
			Int("port", entry.Port).
			Str("http_identity_hint_skipped_reason", httpIdentitySkipNoSignature).
			Msg("http_identity_hint_skipped")
		return
	}

	applied := false
	if strings.TrimSpace(entry.Product) == "" && decision.Product != "" {
		setIdentityField(entry, "product", decision.Product, sourceHTTPIdentityHint, decision.Confidence)
		applied = true
	}
	if strings.TrimSpace(entry.Vendor) == "" && decision.Vendor != "" {
		setIdentityField(entry, "vendor", decision.Vendor, sourceHTTPIdentityHint, decision.Confidence)
		applied = true
	}

	if !applied {
		log.Debug().
			Str("target", entry.Target).
			Int("port", entry.Port).
			Str("http_identity_hint_rule", decision.Rule).
			Float64("http_identity_hint_confidence", decision.Confidence).
			Str("http_identity_hint_skipped_reason", httpIdentitySkipStrongerSource).
			Msg("http_identity_hint_skipped")
		return
	}

	log.Debug().
		Str("target", entry.Target).
		Int("port", entry.Port).
		Str("http_identity_hint_rule", decision.Rule).
		Float64("http_identity_hint_confidence", decision.Confidence).
		Msg("http_identity_hint_applied")
}

func resolveHTTPIdentityDecision(signals []httpIdentitySignal) (httpIdentityDecision, bool) {
	if len(signals) == 0 {
		return httpIdentityDecision{}, false
	}
	tokenSet := make(map[string]struct{}, len(signals))
	for _, signal := range signals {
		tokenSet[strings.TrimSpace(signal.Token)] = struct{}{}
	}
	for _, decision := range httpIdentityDecisionTable {
		for _, signal := range decision.Signals {
			if _, ok := tokenSet[signal]; ok {
				return decision, true
			}
		}
	}
	return httpIdentityDecision{}, false
}

func collectSMBHostEvidence(inputs map[string]any) map[string]smbHostEvidence {
	raw, ok := inputs["service.smb.details"]
	if !ok {
		return nil
	}

	items := toAnyList(raw)
	if len(items) == 0 {
		return nil
	}

	candidates := make(map[string][]scanpkg.SMBServiceInfo)
	for _, item := range items {
		smb, ok := item.(scanpkg.SMBServiceInfo)
		if !ok {
			continue
		}
		target := strings.TrimSpace(smb.Target)
		if target == "" || smb.Port <= 0 {
			continue
		}
		candidates[target] = append(candidates[target], smb)
	}
	if len(candidates) == 0 {
		return nil
	}

	evidenceByTarget := make(map[string]smbHostEvidence, len(candidates))
	for target, perTarget := range candidates {
		best, ok := pickBestSMBForCorrelation(perTarget)
		if !ok {
			continue
		}
		evidenceByTarget[target] = smbHostEvidence{
			Vendor:  strings.TrimSpace(best.Vendor),
			Version: strings.TrimSpace(best.ProductVersion),
		}
	}

	if len(evidenceByTarget) == 0 {
		return nil
	}
	return evidenceByTarget
}

func pickBestSMBForCorrelation(items []scanpkg.SMBServiceInfo) (scanpkg.SMBServiceInfo, bool) {
	if len(items) == 0 {
		return scanpkg.SMBServiceInfo{}, false
	}

	best := items[0]
	for i := 1; i < len(items); i++ {
		if isBetterSMBCandidate(items[i], best) {
			best = items[i]
		}
	}
	return best, true
}

func isBetterSMBCandidate(candidate, current scanpkg.SMBServiceInfo) bool {
	cPort := smbPortPriority(candidate.Port)
	oPort := smbPortPriority(current.Port)
	if cPort != oPort {
		return cPort > oPort
	}

	cVendorVersion := smbHasVendorVersion(candidate)
	oVendorVersion := smbHasVendorVersion(current)
	if cVendorVersion != oVendorVersion {
		return cVendorVersion
	}

	cCompleteness := smbCompletenessScore(candidate)
	oCompleteness := smbCompletenessScore(current)
	if cCompleteness != oCompleteness {
		return cCompleteness > oCompleteness
	}

	return smbDeterministicKey(candidate) < smbDeterministicKey(current)
}

func smbPortPriority(port int) int {
	switch port {
	case 445:
		return 2
	case 139:
		return 1
	default:
		return 0
	}
}

func smbHasVendorVersion(smb scanpkg.SMBServiceInfo) bool {
	return strings.TrimSpace(smb.Vendor) != "" && strings.TrimSpace(smb.ProductVersion) != ""
}

func smbCompletenessScore(smb scanpkg.SMBServiceInfo) int {
	score := 0
	for _, value := range []string{
		smb.ProtocolVersion,
		smb.Dialect,
		smb.Product,
		smb.Vendor,
		smb.ProductVersion,
		smb.OSHints.Family,
		smb.OSHints.Name,
		smb.OSHints.Version,
		smb.HostHints.DNSComputer,
		smb.HostHints.TargetName,
		smb.HostHints.NBComputer,
		smb.HostHints.NBDomain,
		smb.HostHints.DNSDomain,
	} {
		if strings.TrimSpace(value) != "" {
			score++
		}
	}
	if smb.SigningRequired != nil {
		score++
	}
	return score
}

func smbDeterministicKey(smb scanpkg.SMBServiceInfo) string {
	signing := "nil"
	if smb.SigningRequired != nil {
		if *smb.SigningRequired {
			signing = "true"
		} else {
			signing = "false"
		}
	}
	return fmt.Sprintf(
		"%03d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		smb.Port,
		strings.TrimSpace(smb.ProtocolVersion),
		strings.TrimSpace(smb.Dialect),
		strings.TrimSpace(smb.Product),
		strings.TrimSpace(smb.Vendor),
		strings.TrimSpace(smb.ProductVersion),
		signing,
		strings.TrimSpace(smb.OSHints.Family),
		strings.TrimSpace(smb.OSHints.Name),
		strings.TrimSpace(smb.OSHints.Version),
		strings.TrimSpace(smb.HostHints.DNSComputer),
		strings.TrimSpace(smb.HostHints.TargetName),
		strings.TrimSpace(smb.HostHints.NBComputer),
		strings.TrimSpace(smb.HostHints.DNSDomain),
	)
}

func inferRPCVersionHint(info scanpkg.RPCServiceInfo) string {
	_ = info
	return ""
}

func hasStrongWindowsRPCHint(info scanpkg.RPCServiceInfo) bool {
	normalizedPrincipal := strings.ToLower(strings.TrimSpace(info.PrincipalName))
	if strings.Contains(normalizedPrincipal, "nt authority\\") || strings.HasPrefix(normalizedPrincipal, "host/") {
		return true
	}
	for _, pipe := range info.NamedPipes {
		normalizedPipe := strings.ToLower(strings.TrimSpace(pipe))
		if strings.Contains(normalizedPipe, "eventlog") || strings.Contains(normalizedPipe, "lsm_") || strings.Contains(normalizedPipe, "initshutdown") {
			return true
		}
	}
	return false
}

func (m *serviceIdentityNormalizerModule) applyHeuristics(entries map[string]*ServiceIdentityInfo) {
	for _, entry := range entries {
		if entry.ServiceName == "" {
			setIdentityField(entry, "service_name", serviceNameFromPort(entry.Port), sourceHeuristic, 0.40)
		}
		if entry.Product == "" && (entry.Port == 445 || entry.Port == 139 || hasTag(entry.TechTags, "smb")) {
			setIdentityField(entry, "product", "smb", sourceHeuristic, 0.35)
		}
	}
}

func setIdentityField(entry *ServiceIdentityInfo, field, value, source string, confidence float64) {
	if entry == nil || strings.TrimSpace(value) == "" {
		return
	}
	currentConfidence := entry.FieldConfidence[field]
	if confidence < currentConfidence {
		return
	}

	cleanValue := strings.TrimSpace(value)
	switch field {
	case "service_name":
		entry.ServiceName = cleanValue
	case "product":
		entry.Product = cleanValue
	case "vendor":
		entry.Vendor = cleanValue
	case "version":
		entry.Version = cleanValue
	case "cpe":
		entry.CPE = cleanValue
	case "banner":
		entry.Banner = cleanValue
	case "hostname_hint":
		entry.HostnameHint = cleanValue
	}

	entry.FieldSources[field] = source
	entry.FieldConfidence[field] = confidence
}

func setIdentityOS(entry *ServiceIdentityInfo, hints scanpkg.SMBOSHints, source string, confidence float64) {
	if entry == nil {
		return
	}
	currentConfidence := entry.FieldConfidence["os_hints"]
	if confidence < currentConfidence {
		return
	}
	entry.OSHints = ServiceOSHints{
		Family:  strings.TrimSpace(hints.Family),
		Name:    strings.TrimSpace(hints.Name),
		Version: strings.TrimSpace(hints.Version),
	}
	entry.FieldSources["os_hints"] = source
	entry.FieldConfidence["os_hints"] = confidence
}

func chooseHostnameHint(h scanpkg.SMBHostHints) string {
	if strings.TrimSpace(h.DNSComputer) != "" {
		return strings.TrimSpace(h.DNSComputer)
	}
	if strings.TrimSpace(h.TargetName) != "" {
		return strings.TrimSpace(h.TargetName)
	}
	if strings.TrimSpace(h.NBComputer) != "" {
		return strings.TrimSpace(h.NBComputer)
	}
	return ""
}

func identityKey(target string, port int) string {
	return fmt.Sprintf("%s:%d", strings.TrimSpace(target), port)
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if strings.EqualFold(strings.TrimSpace(tag), want) {
			return true
		}
	}
	return false
}

func isServiceNameEmptyOrUnknown(name string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(name))
	return trimmed == "" || trimmed == "unknown"
}

func isHTTPSLikePort(port int) bool {
	return port == 443 || port == 8443 || port == 9443
}

func smtpServiceNameFromNative(info scanpkg.SMTPServiceInfo) string {
	if info.Port == 465 || strings.EqualFold(strings.TrimSpace(info.SMTPProtocol), "smtps") {
		return "smtps"
	}
	return "smtp"
}

func ftpServiceNameFromNative(info scanpkg.FTPServiceInfo) string {
	if info.Port == 990 || strings.EqualFold(strings.TrimSpace(info.FTPProtocol), "ftps") || info.TLSEnabled {
		return "ftps"
	}
	return "ftp"
}

func snmpProductConfidence(info scanpkg.SNMPServiceInfo) float64 {
	if snmpHasExplicitIdentityToken(info) {
		return 0.75
	}
	if strings.TrimSpace(info.SysObjectID) != "" {
		return 0.70
	}
	return 0.75
}

func snmpVendorConfidence(info scanpkg.SNMPServiceInfo) float64 {
	if snmpHasExplicitIdentityToken(info) {
		return 0.75
	}
	if strings.TrimSpace(info.SysObjectID) != "" {
		return 0.70
	}
	return 0.75
}

func snmpHasExplicitIdentityToken(info scanpkg.SNMPServiceInfo) bool {
	descr := strings.ToLower(strings.TrimSpace(info.SysDescr))
	return strings.Contains(descr, "net-snmp") ||
		strings.Contains(descr, "cisco ios") ||
		strings.Contains(descr, "mikrotik") ||
		(strings.Contains(descr, "windows") && strings.Contains(descr, "snmp"))
}

func serviceNameFromPort(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 990:
		return "ftps"
	case 22:
		return "ssh"
	case 25, 587, 2525:
		return "smtp"
	case 465:
		return "smtps"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	case 161:
		return "snmp"
	case 443:
		return "https"
	case 445, 139:
		return "smb"
	case 3389:
		return "rdp"
	default:
		return "unknown"
	}
}

//nolint:gocyclo // This helper intentionally accepts multiple orchestrator/runtime shapes.
func toAnyList(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	case []scanpkg.BannerGrabResult:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	case []FingerprintParsedInfo:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	case []TechTagResult:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	case []scanpkg.SMTPServiceInfo:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	case []scanpkg.FTPServiceInfo:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	case []scanpkg.SSHServiceInfo:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	case []scanpkg.SNMPServiceInfo:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	case []scanpkg.SMBServiceInfo:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	case []scanpkg.RDPServiceInfo:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	case []scanpkg.RPCServiceInfo:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	case []scanpkg.TLSServiceInfo:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	default:
		return nil
	}
}

func serviceIdentityNormalizerModuleFactory() engine.Module {
	return newServiceIdentityNormalizerModule()
}

func init() {
	engine.RegisterModuleFactory(serviceIdentityNormalizerModuleName, serviceIdentityNormalizerModuleFactory)
}
