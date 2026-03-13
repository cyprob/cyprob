// pkg/modules/reporting/asset_profile_builder.go
package reporting

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"github.com/cyprob/cyprob/pkg/modules/evaluation" // For VulnerabilityResult
	"github.com/cyprob/cyprob/pkg/modules/parse"
	"github.com/cyprob/cyprob/pkg/modules/scan"
	"github.com/cyprob/cyprob/pkg/netutil"
)

const (
	assetProfileBuilderModuleTypeName = "asset-profile-builder"
)

// AssetProfileBuilderConfig (şu an için boş, ileride eklenebilir)
type AssetProfileBuilderConfig struct{}

// AssetProfileBuilderModule implements the engine.Module interface.
type AssetProfileBuilderModule struct {
	meta   engine.ModuleMetadata
	config AssetProfileBuilderConfig
}

func newAssetProfileBuilderModule() *AssetProfileBuilderModule {
	return &AssetProfileBuilderModule{
		meta: engine.ModuleMetadata{
			Name:         assetProfileBuilderModuleTypeName,
			Version:      "0.1.0",
			Description:  "Aggregates all scan data into comprehensive asset profiles.",
			Type:         engine.ReportingModuleType, // veya OrchestrationModuleType
			Author:       "Vulntor Team",
			Tags:         []string{"reporting", "aggregation", "asset-profile"},
			Consumes:     buildAssetProfileBuilderConsumes(),
			Produces:     buildAssetProfileBuilderProduces(),
			ConfigSchema: map[string]engine.ParameterDefinition{},
		},
		config: AssetProfileBuilderConfig{},
	}
}

func buildAssetProfileBuilderConsumes() []engine.DataContractEntry {
	keys := []engine.DataContractEntry{
		{Key: "config.targets", DataTypeName: "[]string", Cardinality: engine.CardinalitySingle, IsOptional: true},
		{Key: "discovery.live_hosts", DataTypeName: "discovery.ICMPPingDiscoveryResult", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "discovery.open_tcp_ports", DataTypeName: "discovery.TCPPortDiscoveryResult", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "discovery.open_udp_ports", DataTypeName: "discovery.UDPPortDiscoveryResult", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "service.banner.tcp", DataTypeName: "scan.BannerGrabResult", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "service.http.details", DataTypeName: "parse.HTTPParsedInfo", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "service.ftp.details", DataTypeName: "scan.FTPServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "service.mysql.details", DataTypeName: "scan.MySQLServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "service.ssh.details", DataTypeName: "scan.SSHServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "service.smtp.details", DataTypeName: "scan.SMTPServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "service.snmp.details", DataTypeName: "scan.SNMPServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "service.dns.details", DataTypeName: "scan.DNSServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "service.fingerprint.details", DataTypeName: "parse.FingerprintParsedInfo", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "service.tech.tags", DataTypeName: "parse.TechTagResult", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "service.rdp.details", DataTypeName: "scan.RDPServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "service.rpc.details", DataTypeName: "scan.RPCServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "service.tls.details", DataTypeName: "scan.TLSServiceInfo", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "service.identity.details", DataTypeName: "parse.ServiceIdentityInfo", Cardinality: engine.CardinalityList, IsOptional: true},
		{Key: "evaluation.vulnerabilities", DataTypeName: "evaluation.VulnerabilityResult", Cardinality: engine.CardinalityList, IsOptional: true},
	}
	return keys
}

func buildAssetProfileBuilderProduces() []engine.DataContractEntry {
	return []engine.DataContractEntry{
		{Key: "asset.profiles", DataTypeName: "[]engine.AssetProfile", Cardinality: engine.CardinalitySingle},
	}
}

func (m *AssetProfileBuilderModule) Metadata() engine.ModuleMetadata { return m.meta }

func (m *AssetProfileBuilderModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	logger := log.With().Str("module", m.meta.Name).Str("instance_id", m.meta.ID).Logger()
	logger.Debug().Msg("Initializing AssetProfileBuilderModule")
	// No specific config to parse for now
	return nil
}

//nolint:gocyclo // Asset aggregation intentionally centralizes fan-in from many module outputs.
func (m *AssetProfileBuilderModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	logger := log.With().Str("module", m.meta.Name).Str("instance_id", m.meta.ID).Logger()
	logger.Info().Msg("Starting asset profile aggregation")
	logger.Debug().Interface("received_inputs_for_aggregation", inputs).Msg("Full inputs")

	// Helper to safely get and cast data from inputs
	// Tüketilen her anahtarın []interface{} listesi olarak geldiğini varsayıyoruz (modül çıktıları için)
	// veya doğrudan tip (initialInputs için). DataContext ve Orchestrator'daki Get/Set mantığına bağlı.
	// Bir önceki konuşmamızdaki DataContext.SetInitial ve AddModuleOutput ayrımına göre:

	var initialTargets []string
	if rawInitialTargets, ok := inputs["config.targets"]; ok {
		if casted, castOk := rawInitialTargets.([]string); castOk { // SetInitial doğrudan saklar
			initialTargets = casted
		} else if rawInitialTargets != nil {
			logger.Warn().Type("type", rawInitialTargets).Msg("config.targets input has unexpected type")
		}
	}

	liveHostResults := []discovery.ICMPPingDiscoveryResult{}
	if rawLiveHosts, ok := inputs["discovery.live_hosts"]; ok {
		if list, listOk := rawLiveHosts.([]any); listOk {
			for _, item := range list {
				if casted, castOk := item.(discovery.ICMPPingDiscoveryResult); castOk {
					liveHostResults = append(liveHostResults, casted)
				} // else log cast error
			}
		} // else log not a list error
	}

	openTCPPortResults := []discovery.TCPPortDiscoveryResult{}
	if rawOpenTCPPorts, ok := inputs["discovery.open_tcp_ports"]; ok {
		if list, listOk := rawOpenTCPPorts.([]any); listOk {
			for _, item := range list {
				if casted, castOk := item.(discovery.TCPPortDiscoveryResult); castOk {
					openTCPPortResults = append(openTCPPortResults, casted)
				}
			}
		}
	}

	openUDPPortResults := []discovery.UDPPortDiscoveryResult{}
	if rawOpenUDPPorts, ok := inputs["discovery.open_udp_ports"]; ok {
		if list, listOk := rawOpenUDPPorts.([]any); listOk {
			for _, item := range list {
				if casted, castOk := item.(discovery.UDPPortDiscoveryResult); castOk {
					openUDPPortResults = append(openUDPPortResults, casted)
				}
			}
		} else if typed, ok := rawOpenUDPPorts.([]discovery.UDPPortDiscoveryResult); ok {
			openUDPPortResults = append(openUDPPortResults, typed...)
		}
	}

	bannerResults := []scan.BannerGrabResult{}
	if rawBanners, ok := inputs["service.banner.tcp"]; ok { // veya service.banner.raw
		if list, listOk := rawBanners.([]any); listOk {
			for _, item := range list {
				if casted, castOk := item.(scan.BannerGrabResult); castOk {
					bannerResults = append(bannerResults, casted)
				}
			}
		} else if typed, ok := rawBanners.([]scan.BannerGrabResult); ok {
			bannerResults = append(bannerResults, typed...)
		}
	}

	httpDetailsResults := []parse.HTTPParsedInfo{}
	if rawHTTP, ok := inputs["service.http.details"]; ok {
		if list, listOk := rawHTTP.([]any); listOk {
			for _, item := range list {
				if casted, castOk := item.(parse.HTTPParsedInfo); castOk {
					httpDetailsResults = append(httpDetailsResults, casted)
				}
			}
		}
	}

	ftpDetails := []scan.FTPServiceInfo{}
	if rawFTP, ok := inputs["service.ftp.details"]; ok {
		if list, listOk := rawFTP.([]any); listOk {
			for _, item := range list {
				if casted, castOk := item.(scan.FTPServiceInfo); castOk {
					ftpDetails = append(ftpDetails, casted)
				}
			}
		} else if typed, typedOk := rawFTP.([]scan.FTPServiceInfo); typedOk {
			ftpDetails = append(ftpDetails, typed...)
		}
	}

	mysqlDetails := []scan.MySQLServiceInfo{}
	if rawMySQL, ok := inputs["service.mysql.details"]; ok {
		if list, listOk := rawMySQL.([]any); listOk {
			for _, item := range list {
				if casted, castOk := item.(scan.MySQLServiceInfo); castOk {
					mysqlDetails = append(mysqlDetails, casted)
				}
			}
		} else if typed, typedOk := rawMySQL.([]scan.MySQLServiceInfo); typedOk {
			mysqlDetails = append(mysqlDetails, typed...)
		}
	}

	sshNativeDetailsResults := []scan.SSHServiceInfo{}
	if rawSSH, ok := inputs["service.ssh.details"]; ok {
		if list, listOk := rawSSH.([]any); listOk {
			for _, item := range list {
				if casted, castOk := item.(scan.SSHServiceInfo); castOk {
					sshNativeDetailsResults = append(sshNativeDetailsResults, casted)
				}
			}
		} else if typed, typedOk := rawSSH.([]scan.SSHServiceInfo); typedOk {
			sshNativeDetailsResults = append(sshNativeDetailsResults, typed...)
		}
	}

	smtpDetails := []scan.SMTPServiceInfo{}
	if rawSMTP, ok := inputs["service.smtp.details"]; ok {
		if list, listOk := rawSMTP.([]any); listOk {
			for _, item := range list {
				if casted, castOk := item.(scan.SMTPServiceInfo); castOk {
					smtpDetails = append(smtpDetails, casted)
				}
			}
		} else if typed, typedOk := rawSMTP.([]scan.SMTPServiceInfo); typedOk {
			smtpDetails = append(smtpDetails, typed...)
		}
	}

	snmpDetails := []scan.SNMPServiceInfo{}
	if rawSNMP, ok := inputs["service.snmp.details"]; ok {
		if list, listOk := rawSNMP.([]any); listOk {
			for _, item := range list {
				if casted, castOk := item.(scan.SNMPServiceInfo); castOk {
					snmpDetails = append(snmpDetails, casted)
				}
			}
		} else if typed, typedOk := rawSNMP.([]scan.SNMPServiceInfo); typedOk {
			snmpDetails = append(snmpDetails, typed...)
		}
	}

	dnsDetails := []scan.DNSServiceInfo{}
	if rawDNS, ok := inputs["service.dns.details"]; ok {
		if list, listOk := rawDNS.([]any); listOk {
			for _, item := range list {
				if casted, castOk := item.(scan.DNSServiceInfo); castOk {
					dnsDetails = append(dnsDetails, casted)
				}
			}
		} else if typed, typedOk := rawDNS.([]scan.DNSServiceInfo); typedOk {
			dnsDetails = append(dnsDetails, typed...)
		}
	}

	fingerprintDetails := []parse.FingerprintParsedInfo{}
	if rawFP, ok := inputs["service.fingerprint.details"]; ok {
		if list, listOk := rawFP.([]any); listOk {
			for _, item := range list {
				if casted, castOk := item.(parse.FingerprintParsedInfo); castOk {
					fingerprintDetails = append(fingerprintDetails, casted)
				}
			}
		}
	}

	techTagResults := []parse.TechTagResult{}
	if rawTags, ok := inputs["service.tech.tags"]; ok {
		if list, listOk := rawTags.([]any); listOk {
			for _, item := range list {
				if casted, castOk := item.(parse.TechTagResult); castOk {
					techTagResults = append(techTagResults, casted)
				}
			}
		}
	}

	identityDetails := []parse.ServiceIdentityInfo{}
	if rawIdentity, ok := inputs["service.identity.details"]; ok {
		if list, listOK := rawIdentity.([]any); listOK {
			for _, item := range list {
				if casted, castOK := item.(parse.ServiceIdentityInfo); castOK {
					identityDetails = append(identityDetails, casted)
				}
			}
		} else if typed, typedOK := rawIdentity.([]parse.ServiceIdentityInfo); typedOK {
			identityDetails = append(identityDetails, typed...)
		}
	}

	rdpDetails := []scan.RDPServiceInfo{}
	if rawRDP, ok := inputs["service.rdp.details"]; ok {
		if list, listOK := rawRDP.([]any); listOK {
			for _, item := range list {
				if casted, castOK := item.(scan.RDPServiceInfo); castOK {
					rdpDetails = append(rdpDetails, casted)
				}
			}
		} else if typed, typedOK := rawRDP.([]scan.RDPServiceInfo); typedOK {
			rdpDetails = append(rdpDetails, typed...)
		}
	}

	rpcDetails := []scan.RPCServiceInfo{}
	if rawRPC, ok := inputs["service.rpc.details"]; ok {
		if list, listOK := rawRPC.([]any); listOK {
			for _, item := range list {
				if casted, castOK := item.(scan.RPCServiceInfo); castOK {
					rpcDetails = append(rpcDetails, casted)
				}
			}
		} else if typed, typedOK := rawRPC.([]scan.RPCServiceInfo); typedOK {
			rpcDetails = append(rpcDetails, typed...)
		}
	}

	tlsDetails := []scan.TLSServiceInfo{}
	if rawTLS, ok := inputs["service.tls.details"]; ok {
		if list, listOK := rawTLS.([]any); listOK {
			for _, item := range list {
				if casted, castOK := item.(scan.TLSServiceInfo); castOK {
					tlsDetails = append(tlsDetails, casted)
				}
			}
		} else if typed, typedOK := rawTLS.([]scan.TLSServiceInfo); typedOK {
			tlsDetails = append(tlsDetails, typed...)
		}
	}

	// TODO: Zafiyetleri de benzer şekilde topla.
	// Zafiyet modüllerinin çıktılarının types.VulnerabilityFinding veya benzeri bir struct olması beklenir.
	// Ve DataContext'te "instance_id.vulnerability.<type>.<vuln_id>" gibi anahtarlarla saklanabilirler.
	// Bu modül, tüm bu anahtarları tarayarak veya belirli bir pattern'e uyanları alarak zafiyetleri toplar.
	allVulnerabilities := make(map[string][]engine.VulnerabilityFinding) // Key: targetIP:port

	// inputs map'i üzerinde dönerek vulnerability anahtarlarını bul
	for key, data := range inputs {
		// Check for both legacy "vulnerability.*" pattern and new "evaluation.vulnerabilities"
		if strings.Contains(key, "vulnerability") || strings.Contains(key, "evaluation.vulnerabilities") {
			if vulnList, listOk := data.([]any); listOk {
				for _, item := range vulnList {
					// Try evaluation.VulnerabilityResult (new format from plugin evaluation)
					if vulnResult, ok := item.(evaluation.VulnerabilityResult); ok {
						// Convert to engine.VulnerabilityFinding
						finding := engine.VulnerabilityFinding{
							ID:           strings.Join(vulnResult.CVE, ", "), // Use CVE as ID if available
							SourceModule: vulnResult.Plugin,
							Summary:      vulnResult.Message,
							Severity:     engine.FindingSeverity(vulnResult.Severity),
							Remediation:  vulnResult.Remediation,
							References:   []string{vulnResult.Reference},
						}
						targetPortKey := fmt.Sprintf("%s:%d", vulnResult.Target, vulnResult.Port)
						allVulnerabilities[targetPortKey] = append(allVulnerabilities[targetPortKey], finding)
					} else if vuln, castOk := item.(engine.VulnerabilityFinding); castOk {
						// Legacy format support
						targetPortKey := "nil" // Legacy format doesn't have target/port
						allVulnerabilities[targetPortKey] = append(allVulnerabilities[targetPortKey], vuln)
					}
				}
			}
		}
	}

	// Ana veri işleme ve birleştirme mantığı
	finalAssetProfiles := []engine.AssetProfile{}
	processedTargets := make(map[string]int) // Target'a göre AssetProfile slice index'i

	seedProfile := func(target string, isAlive bool, hostnameHint string) {
		target = strings.TrimSpace(target)
		if target == "" {
			return
		}

		now := time.Now()
		if idx, exists := processedTargets[target]; exists {
			profile := &finalAssetProfiles[idx]
			if profile.ResolvedIPs == nil {
				profile.ResolvedIPs = make(map[string]time.Time)
			}
			if _, known := profile.ResolvedIPs[target]; !known {
				profile.ResolvedIPs[target] = now
			}
			if isAlive {
				profile.IsAlive = true
				if profile.FirstSeenAlive.IsZero() {
					profile.FirstSeenAlive = now
				}
			}
			profile.Hostnames = appendUniqueString(profile.Hostnames, hostnameHint)
			profile.LastObservationTime = now
			return
		}

		profile := engine.AssetProfile{
			Target:              target,
			ResolvedIPs:         map[string]time.Time{target: now},
			IsAlive:             isAlive,
			LastObservationTime: now,
			OpenPorts:           make(map[string][]engine.PortProfile),
		}
		if isAlive {
			profile.FirstSeenAlive = now
		}
		profile.Hostnames = appendUniqueString(profile.Hostnames, hostnameHint)

		finalAssetProfiles = append(finalAssetProfiles, profile)
		processedTargets[target] = len(finalAssetProfiles) - 1
	}

	totalLiveHosts := 0
	for _, icmpResult := range liveHostResults {
		for _, liveIP := range icmpResult.LiveHosts {
			if strings.TrimSpace(liveIP) != "" {
				totalLiveHosts++
			}
		}
	}
	usableOpenPortTargets := 0
	for _, tcpResult := range openTCPPortResults {
		if strings.TrimSpace(tcpResult.Target) != "" {
			usableOpenPortTargets++
		}
	}
	usableOpenUDPPortTargets := 0
	for _, udpResult := range openUDPPortResults {
		if strings.TrimSpace(udpResult.Target) != "" {
			usableOpenUDPPortTargets++
		}
	}

	switch {
	case totalLiveHosts > 0:
		for _, icmpResult := range liveHostResults {
			for _, liveIP := range icmpResult.LiveHosts {
				seedProfile(liveIP, true, "")
			}
		}
	case usableOpenPortTargets > 0 || usableOpenUDPPortTargets > 0:
		for _, tcpResult := range openTCPPortResults {
			seedProfile(tcpResult.Target, false, tcpResult.Hostname)
		}
		for _, udpResult := range openUDPPortResults {
			seedProfile(udpResult.Target, false, "")
		}
	default:
		expandedInitialTargets := netutil.ParseAndExpandTargets(initialTargets)
		for _, target := range expandedInitialTargets {
			seedProfile(target, false, "")
		}
	}

	// 2. Her bir AssetProfile'ı güncelle (referans üzerinden)
	for i := range finalAssetProfiles {
		asset := &finalAssetProfiles[i] // Referans alarak güncelleme yapabilmek için
		targetIP := asset.Target        // Veya ResolvedIPs'ten biri (şimdilik Target'ı IP kabul edelim)

		assetOpenPorts := []engine.PortProfile{}

		// Açık TCP Portlarını işle
		for _, tcpResult := range openTCPPortResults {
			if tcpResult.Target == targetIP {
				for _, portNum := range tcpResult.OpenPorts {
					portProfile := engine.PortProfile{
						PortNumber: portNum,
						Protocol:   "tcp",
						Status:     "open",
						Service:    engine.ServiceDetails{},
					}

					// Bu porta ait banner'ı bul
					for _, banner := range bannerResults {
						if banner.IP == targetIP && banner.Port == portNum {
							portProfile.Service.RawBanner = banner.Banner
							portProfile.Service.IsTLS = banner.IsTLS
							portProfile.Service.Evidence = banner.Evidence // Issue #199: Include probe evidence in JSON output
							break
						}
					}

					// Bu porta ait parse edilmiş HTTP detaylarını bul
					for _, httpDetail := range httpDetailsResults {
						if httpDetail.Target == targetIP && httpDetail.Port == portNum {
							portProfile.Service.Name = "http" // Veya httpDetail.ServerProduct
							if httpDetail.ServerProduct != "" {
								portProfile.Service.Product = httpDetail.ServerProduct
							} else {
								portProfile.Service.Product = "HTTP" // Genel
							}
							portProfile.Service.Version = httpDetail.ServerVersion
							if portProfile.Service.ParsedAttributes == nil {
								portProfile.Service.ParsedAttributes = make(map[string]any)
							}
							portProfile.Service.ParsedAttributes["http_status_code"] = httpDetail.StatusCode
							portProfile.Service.ParsedAttributes["http_version"] = httpDetail.HTTPVersion
							portProfile.Service.ParsedAttributes["html_title"] = httpDetail.HTMLTitle
							portProfile.Service.ParsedAttributes["content_type"] = httpDetail.ContentType
							portProfile.Service.ParsedAttributes["headers"] = httpDetail.Headers
							// portProfile.Service.Scheme = httpDetail.Scheme
							break
						}
					}
					if sshNative := findSSHNativeDetails(sshNativeDetailsResults, targetIP, portNum); sshNative != nil {
						applySSHNativeDetails(&portProfile, *sshNative)
					}
					if ftpNative := findFTPDetails(ftpDetails, targetIP, portNum); ftpNative != nil {
						applyFTPDetails(&portProfile, *ftpNative)
					}

					// Bu porta ait tech tagleri bul
					for _, tags := range techTagResults {
						if tags.Target == targetIP && tags.Port == portNum {
							portProfile.Service.TechTags = parse.NormalizeTechTags(tags.Tags)
							break
						}
					}

					var fpMatches []parse.FingerprintParsedInfo
					var primaryFP *parse.FingerprintParsedInfo
					for _, fpDetail := range fingerprintDetails {
						if fpDetail.Target != targetIP || fpDetail.Port != portNum {
							continue
						}
						matchCopy := fpDetail
						fpMatches = append(fpMatches, matchCopy)
						if primaryFP == nil {
							primaryFP = &matchCopy
						}
					}
					if len(fpMatches) > 0 {
						if portProfile.Service.ParsedAttributes == nil {
							portProfile.Service.ParsedAttributes = make(map[string]any)
						}
						if primaryFP != nil {
							if portProfile.Service.Name == "" {
								portProfile.Service.Name = primaryFP.Protocol
							}
							if portProfile.Service.Product == "" {
								portProfile.Service.Product = primaryFP.Product
							}
							if portProfile.Service.Version == "" {
								portProfile.Service.Version = primaryFP.Version
							}
							portProfile.Service.ParsedAttributes["fingerprint_confidence"] = primaryFP.Confidence
							if primaryFP.CPE != "" {
								portProfile.Service.ParsedAttributes["cpe"] = primaryFP.CPE
							}
							if primaryFP.Vendor != "" {
								portProfile.Service.ParsedAttributes["vendor"] = primaryFP.Vendor
							}
							if primaryFP.Description != "" {
								portProfile.Service.ParsedAttributes["fingerprint_primary_description"] = primaryFP.Description
							}
							if primaryFP.SourceProbe != "" {
								portProfile.Service.ParsedAttributes["fingerprint_primary_probe"] = primaryFP.SourceProbe
							}
						}
						portProfile.Service.ParsedAttributes["fingerprints"] = fpMatches
					}
					if smtpNative := findSMTPDetails(smtpDetails, targetIP, portNum); smtpNative != nil {
						applySMTPDetails(&portProfile, *smtpNative)
					}
					if mysqlNative := findMySQLDetails(mysqlDetails, targetIP, portNum); mysqlNative != nil {
						applyMySQLDetails(&portProfile, *mysqlNative)
					}
					if dnsNative := findDNSDetails(dnsDetails, targetIP, portNum, "tcp"); dnsNative != nil {
						applyDNSDetails(&portProfile, *dnsNative)
					}

					identity := findServiceIdentity(identityDetails, targetIP, portNum)
					if identity != nil {
						applyServiceIdentity(asset, &portProfile, *identity)
					}
					rdp := findRDPDetails(rdpDetails, targetIP, portNum)
					if rdp != nil {
						applyRDPDetails(&portProfile, *rdp)
					}
					rpc := findRPCDetails(rpcDetails, targetIP, portNum)
					if rpc != nil {
						applyRPCDetails(&portProfile, *rpc)
					}
					tls := findTLSDetails(tlsDetails, targetIP, portNum)
					if tls != nil {
						applyTLSDetails(&portProfile, *tls)
					}
					// Bu porta ait zafiyetleri bul
					targetPortKey := fmt.Sprintf("%s:%d", targetIP, portNum)
					if vulns, found := allVulnerabilities[targetPortKey]; found {
						portProfile.Vulnerabilities = vulns
						asset.TotalVulnerabilities += len(vulns)
					}

					assetOpenPorts = append(assetOpenPorts, portProfile)
				}
			}
		}

		for _, udpResult := range openUDPPortResults {
			if udpResult.Target != targetIP {
				continue
			}
			for _, portNum := range udpResult.OpenPorts {
				portProfile := engine.PortProfile{
					PortNumber: portNum,
					Protocol:   "udp",
					Status:     "open",
					Service:    engine.ServiceDetails{},
				}

				if snmpNative := findSNMPDetails(snmpDetails, targetIP, portNum); snmpNative != nil {
					applySNMPDetails(&portProfile, *snmpNative)
				}
				if dnsNative := findDNSDetails(dnsDetails, targetIP, portNum, "udp"); dnsNative != nil {
					applyDNSDetails(&portProfile, *dnsNative)
				}

				identity := findServiceIdentity(identityDetails, targetIP, portNum)
				if identity != nil {
					applyServiceIdentity(asset, &portProfile, *identity)
				}

				targetPortKey := fmt.Sprintf("%s:%d", targetIP, portNum)
				if vulns, found := allVulnerabilities[targetPortKey]; found {
					portProfile.Vulnerabilities = vulns
					asset.TotalVulnerabilities += len(vulns)
				}

				assetOpenPorts = append(assetOpenPorts, portProfile)
			}
		}
		asset.OpenPorts[targetIP] = assetOpenPorts // Haritaya ekle
		asset.LastObservationTime = time.Now()
	}

	// asset.profiles'ı ModuleOutput olarak gönder
	logger.Info().Int("profile_count", len(finalAssetProfiles)).Msg("Asset profile aggregation completed")
	outputChan <- engine.ModuleOutput{
		FromModuleName: m.meta.ID,
		DataKey:        m.meta.Produces[0].Key,
		Data:           finalAssetProfiles,
		Timestamp:      time.Now(),
	}
	return nil
}

func AssetProfileBuilderModuleFactory() engine.Module {
	return newAssetProfileBuilderModule()
}

func init() {
	engine.RegisterModuleFactory(assetProfileBuilderModuleTypeName, AssetProfileBuilderModuleFactory)
}

func findServiceIdentity(items []parse.ServiceIdentityInfo, target string, port int) *parse.ServiceIdentityInfo {
	for i := range items {
		if items[i].Target == target && items[i].Port == port {
			return &items[i]
		}
	}
	return nil
}

func applyServiceIdentity(asset *engine.AssetProfile, portProfile *engine.PortProfile, identity parse.ServiceIdentityInfo) {
	if portProfile.Service.ParsedAttributes == nil {
		portProfile.Service.ParsedAttributes = make(map[string]any)
	}

	if strings.TrimSpace(identity.ServiceName) != "" {
		portProfile.Service.Name = strings.TrimSpace(identity.ServiceName)
	}
	if strings.TrimSpace(identity.Product) != "" {
		portProfile.Service.Product = strings.TrimSpace(identity.Product)
	}
	if strings.TrimSpace(identity.Version) != "" {
		portProfile.Service.Version = strings.TrimSpace(identity.Version)
	}
	if strings.TrimSpace(identity.Banner) != "" && strings.TrimSpace(portProfile.Service.RawBanner) == "" {
		portProfile.Service.RawBanner = strings.TrimSpace(identity.Banner)
	}

	if strings.TrimSpace(identity.Vendor) != "" {
		portProfile.Service.ParsedAttributes["vendor"] = strings.TrimSpace(identity.Vendor)
	}
	if strings.TrimSpace(identity.CPE) != "" {
		portProfile.Service.ParsedAttributes["cpe"] = strings.TrimSpace(identity.CPE)
	}
	if strings.TrimSpace(identity.HostnameHint) != "" {
		host := strings.TrimSpace(identity.HostnameHint)
		portProfile.Service.ParsedAttributes["hostname_hint"] = host
		asset.Hostnames = appendUniqueString(asset.Hostnames, host)
	}
	if (identity.OSHints != parse.ServiceOSHints{}) {
		portProfile.Service.ParsedAttributes["os_hints"] = identity.OSHints
	}
	if len(identity.FieldSources) > 0 {
		portProfile.Service.ParsedAttributes["field_sources"] = identity.FieldSources
	}
	if len(identity.FieldConfidence) > 0 {
		portProfile.Service.ParsedAttributes["field_confidence"] = identity.FieldConfidence
	}

	if len(identity.TechTags) > 0 {
		portProfile.Service.TechTags = parse.NormalizeTechTags(append(portProfile.Service.TechTags, identity.TechTags...))
	}
}

func findSSHNativeDetails(items []scan.SSHServiceInfo, target string, port int) *scan.SSHServiceInfo {
	for i := range items {
		if items[i].Target == target && items[i].Port == port {
			return &items[i]
		}
	}
	return nil
}

//nolint:gocyclo // SSH attribute emission is intentionally explicit to preserve JSON contract names.
func applySSHNativeDetails(portProfile *engine.PortProfile, details scan.SSHServiceInfo) {
	if portProfile.Service.ParsedAttributes == nil {
		portProfile.Service.ParsedAttributes = make(map[string]any)
	}

	if details.SSHProbe {
		portProfile.Service.Name = "ssh"
	}
	if strings.TrimSpace(details.SSHSoftware) != "" {
		portProfile.Service.Product = strings.TrimSpace(details.SSHSoftware)
	} else if details.SSHProbe && strings.TrimSpace(portProfile.Service.Product) == "" {
		portProfile.Service.Product = "SSH"
	}
	if strings.TrimSpace(details.SSHVersion) != "" {
		portProfile.Service.Version = strings.TrimSpace(details.SSHVersion)
	}
	if strings.TrimSpace(details.SSHBanner) != "" && strings.TrimSpace(portProfile.Service.RawBanner) == "" {
		portProfile.Service.RawBanner = strings.TrimSpace(details.SSHBanner)
	}

	if strings.TrimSpace(details.SSHBanner) != "" {
		portProfile.Service.ParsedAttributes["ssh_banner"] = strings.TrimSpace(details.SSHBanner)
	}
	if strings.TrimSpace(details.SSHProtocol) != "" {
		portProfile.Service.ParsedAttributes["ssh_protocol"] = strings.TrimSpace(details.SSHProtocol)
		portProfile.Service.ParsedAttributes["ssh_protocol_version"] = strings.TrimSpace(details.SSHProtocol)
	}
	if strings.TrimSpace(details.SSHSoftware) != "" {
		portProfile.Service.ParsedAttributes["ssh_software"] = strings.TrimSpace(details.SSHSoftware)
	}
	if strings.TrimSpace(details.SSHVersion) != "" {
		portProfile.Service.ParsedAttributes["ssh_version"] = strings.TrimSpace(details.SSHVersion)
	}
	if len(details.KEXAlgorithms) > 0 {
		portProfile.Service.ParsedAttributes["ssh_kex_algorithms"] = append([]string(nil), details.KEXAlgorithms...)
	}
	if len(details.HostKeyAlgorithms) > 0 {
		portProfile.Service.ParsedAttributes["ssh_host_key_algorithms"] = append([]string(nil), details.HostKeyAlgorithms...)
	}
	if len(details.Ciphers) > 0 {
		portProfile.Service.ParsedAttributes["ssh_ciphers"] = append([]string(nil), details.Ciphers...)
	}
	if len(details.MACs) > 0 {
		portProfile.Service.ParsedAttributes["ssh_macs"] = append([]string(nil), details.MACs...)
	}
	if len(details.AuthMethods) > 0 {
		portProfile.Service.ParsedAttributes["ssh_auth_methods"] = append([]string(nil), details.AuthMethods...)
	}

	portProfile.Service.ParsedAttributes["ssh_weak_protocol"] = details.WeakProtocol
	portProfile.Service.ParsedAttributes["ssh_weak_kex"] = details.WeakKEX
	portProfile.Service.ParsedAttributes["ssh_weak_cipher"] = details.WeakCipher
	portProfile.Service.ParsedAttributes["ssh_weak_mac"] = details.WeakMAC

	if strings.TrimSpace(details.ProbeError) != "" {
		portProfile.Service.ParsedAttributes["ssh_probe_error"] = strings.TrimSpace(details.ProbeError)
	}
}

func findSMTPDetails(items []scan.SMTPServiceInfo, target string, port int) *scan.SMTPServiceInfo {
	for i := range items {
		if items[i].Target == target && items[i].Port == port {
			return &items[i]
		}
	}
	return nil
}

func findFTPDetails(items []scan.FTPServiceInfo, target string, port int) *scan.FTPServiceInfo {
	for i := range items {
		if items[i].Target == target && items[i].Port == port {
			return &items[i]
		}
	}
	return nil
}

func findMySQLDetails(items []scan.MySQLServiceInfo, target string, port int) *scan.MySQLServiceInfo {
	for i := range items {
		if items[i].Target == target && items[i].Port == port {
			return &items[i]
		}
	}
	return nil
}

//nolint:gocyclo // FTP attribute emission is intentionally explicit to preserve JSON contract names.
func applyFTPDetails(portProfile *engine.PortProfile, details scan.FTPServiceInfo) {
	if portProfile.Service.ParsedAttributes == nil {
		portProfile.Service.ParsedAttributes = make(map[string]any)
	}

	if details.FTPProbe && strings.TrimSpace(portProfile.Service.Name) == "" {
		if strings.EqualFold(strings.TrimSpace(details.FTPProtocol), "ftps") {
			portProfile.Service.Name = "ftps"
		} else {
			portProfile.Service.Name = "ftp"
		}
	}
	if strings.TrimSpace(details.SoftwareHint) != "" && strings.TrimSpace(portProfile.Service.Product) == "" {
		portProfile.Service.Product = strings.TrimSpace(details.SoftwareHint)
	}
	if strings.TrimSpace(details.VersionHint) != "" && strings.TrimSpace(portProfile.Service.Version) == "" {
		portProfile.Service.Version = strings.TrimSpace(details.VersionHint)
	}
	if strings.TrimSpace(details.Banner) != "" && strings.TrimSpace(portProfile.Service.RawBanner) == "" {
		portProfile.Service.RawBanner = strings.TrimSpace(details.Banner)
	}
	if details.TLSEnabled || strings.EqualFold(strings.TrimSpace(details.FTPProtocol), "ftps") {
		portProfile.Service.IsTLS = true
	}

	if strings.TrimSpace(details.Banner) != "" {
		portProfile.Service.ParsedAttributes["ftp_banner"] = strings.TrimSpace(details.Banner)
	}
	if strings.TrimSpace(details.FTPProtocol) != "" {
		portProfile.Service.ParsedAttributes["ftp_protocol"] = strings.TrimSpace(details.FTPProtocol)
	}
	if details.GreetingCode > 0 {
		portProfile.Service.ParsedAttributes["ftp_greeting_code"] = details.GreetingCode
	}
	if len(details.Features) > 0 {
		portProfile.Service.ParsedAttributes["ftp_features"] = append([]string(nil), details.Features...)
	}
	portProfile.Service.ParsedAttributes["ftp_auth_tls_supported"] = details.AuthTLSSupported
	portProfile.Service.ParsedAttributes["ftp_tls_enabled"] = details.TLSEnabled
	portProfile.Service.ParsedAttributes["ftp_weak_tls_protocol"] = details.WeakTLSProtocol
	portProfile.Service.ParsedAttributes["ftp_weak_tls_cipher"] = details.WeakTLSCipher

	if strings.TrimSpace(details.TLSVersion) != "" {
		portProfile.Service.ParsedAttributes["ftp_tls_version"] = strings.TrimSpace(details.TLSVersion)
	}
	if strings.TrimSpace(details.TLSCipherSuite) != "" {
		portProfile.Service.ParsedAttributes["ftp_tls_cipher_suite"] = strings.TrimSpace(details.TLSCipherSuite)
	}
	if strings.TrimSpace(details.CertSubjectCN) != "" {
		portProfile.Service.ParsedAttributes["ftp_cert_subject_cn"] = strings.TrimSpace(details.CertSubjectCN)
	}
	if strings.TrimSpace(details.CertIssuer) != "" {
		portProfile.Service.ParsedAttributes["ftp_cert_issuer"] = strings.TrimSpace(details.CertIssuer)
	}
	if !details.CertNotAfter.IsZero() {
		portProfile.Service.ParsedAttributes["ftp_cert_not_after"] = details.CertNotAfter
	}
	portProfile.Service.ParsedAttributes["ftp_cert_is_self_signed"] = details.CertIsSelfSigned

	if strings.TrimSpace(details.SystemHint) != "" {
		portProfile.Service.ParsedAttributes["ftp_system_hint"] = strings.TrimSpace(details.SystemHint)
	}
	if strings.TrimSpace(details.SoftwareHint) != "" {
		portProfile.Service.ParsedAttributes["ftp_software_hint"] = strings.TrimSpace(details.SoftwareHint)
	}
	if strings.TrimSpace(details.VendorHint) != "" {
		portProfile.Service.ParsedAttributes["ftp_vendor_hint"] = strings.TrimSpace(details.VendorHint)
	}
	if strings.TrimSpace(details.VersionHint) != "" {
		portProfile.Service.ParsedAttributes["ftp_version_hint"] = strings.TrimSpace(details.VersionHint)
	}
	if strings.TrimSpace(details.ProbeError) != "" {
		portProfile.Service.ParsedAttributes["ftp_probe_error"] = strings.TrimSpace(details.ProbeError)
	}
}

func applyMySQLDetails(portProfile *engine.PortProfile, details scan.MySQLServiceInfo) {
	if portProfile.Service.ParsedAttributes == nil {
		portProfile.Service.ParsedAttributes = make(map[string]any)
	}

	if details.MySQLProbe && strings.TrimSpace(portProfile.Service.Name) == "" {
		portProfile.Service.Name = "mysql"
	}
	if strings.TrimSpace(details.ProductHint) != "" && strings.TrimSpace(portProfile.Service.Product) == "" {
		portProfile.Service.Product = strings.TrimSpace(details.ProductHint)
	}
	if strings.TrimSpace(details.VersionHint) != "" && strings.TrimSpace(portProfile.Service.Version) == "" {
		portProfile.Service.Version = strings.TrimSpace(details.VersionHint)
	}
	if details.TLSEnabled {
		portProfile.Service.IsTLS = true
	}

	if strings.TrimSpace(details.GreetingKind) != "" {
		portProfile.Service.ParsedAttributes["mysql_greeting_kind"] = strings.TrimSpace(details.GreetingKind)
	}
	if details.ProtocolVersion > 0 {
		portProfile.Service.ParsedAttributes["mysql_protocol_version"] = details.ProtocolVersion
	}
	if strings.TrimSpace(details.ServerVersion) != "" {
		portProfile.Service.ParsedAttributes["mysql_server_version"] = strings.TrimSpace(details.ServerVersion)
	}
	if details.ConnectionID > 0 {
		portProfile.Service.ParsedAttributes["mysql_connection_id"] = details.ConnectionID
	}
	if details.CapabilityFlags > 0 {
		portProfile.Service.ParsedAttributes["mysql_capability_flags"] = details.CapabilityFlags
	}
	if details.StatusFlags > 0 {
		portProfile.Service.ParsedAttributes["mysql_status_flags"] = details.StatusFlags
	}
	if details.CharacterSet > 0 {
		portProfile.Service.ParsedAttributes["mysql_character_set"] = details.CharacterSet
	}
	if strings.TrimSpace(details.AuthPluginName) != "" {
		portProfile.Service.ParsedAttributes["mysql_auth_plugin_name"] = strings.TrimSpace(details.AuthPluginName)
	}
	portProfile.Service.ParsedAttributes["mysql_tls_supported"] = details.TLSSupported
	portProfile.Service.ParsedAttributes["mysql_tls_enabled"] = details.TLSEnabled

	if strings.TrimSpace(details.TLSVersion) != "" {
		portProfile.Service.ParsedAttributes["mysql_tls_version"] = strings.TrimSpace(details.TLSVersion)
	}
	if strings.TrimSpace(details.TLSCipherSuite) != "" {
		portProfile.Service.ParsedAttributes["mysql_tls_cipher_suite"] = strings.TrimSpace(details.TLSCipherSuite)
	}
	if strings.TrimSpace(details.CertSubjectCN) != "" {
		portProfile.Service.ParsedAttributes["mysql_cert_subject_cn"] = strings.TrimSpace(details.CertSubjectCN)
	}
	if strings.TrimSpace(details.CertIssuer) != "" {
		portProfile.Service.ParsedAttributes["mysql_cert_issuer"] = strings.TrimSpace(details.CertIssuer)
	}
	if !details.CertNotAfter.IsZero() {
		portProfile.Service.ParsedAttributes["mysql_cert_not_after"] = details.CertNotAfter
	}
	portProfile.Service.ParsedAttributes["mysql_cert_is_self_signed"] = details.CertIsSelfSigned

	if strings.TrimSpace(details.ProductHint) != "" {
		portProfile.Service.ParsedAttributes["mysql_product_hint"] = strings.TrimSpace(details.ProductHint)
	}
	if strings.TrimSpace(details.VendorHint) != "" {
		portProfile.Service.ParsedAttributes["mysql_vendor_hint"] = strings.TrimSpace(details.VendorHint)
		portProfile.Service.ParsedAttributes["vendor"] = strings.TrimSpace(details.VendorHint)
	}
	if strings.TrimSpace(details.VersionHint) != "" {
		portProfile.Service.ParsedAttributes["mysql_version_hint"] = strings.TrimSpace(details.VersionHint)
	}
	if strings.TrimSpace(details.ProbeError) != "" {
		portProfile.Service.ParsedAttributes["mysql_probe_error"] = strings.TrimSpace(details.ProbeError)
	}
}

//nolint:gocyclo // SMTP attribute emission is intentionally explicit to preserve JSON contract names.
func applySMTPDetails(portProfile *engine.PortProfile, details scan.SMTPServiceInfo) {
	if portProfile.Service.ParsedAttributes == nil {
		portProfile.Service.ParsedAttributes = make(map[string]any)
	}

	if details.SMTPProbe && strings.TrimSpace(portProfile.Service.Name) == "" {
		if strings.TrimSpace(details.SMTPProtocol) == "smtps" {
			portProfile.Service.Name = "smtps"
		} else {
			portProfile.Service.Name = "smtp"
		}
	}
	if strings.TrimSpace(details.SoftwareHint) != "" && strings.TrimSpace(portProfile.Service.Product) == "" {
		portProfile.Service.Product = strings.TrimSpace(details.SoftwareHint)
	}
	if strings.TrimSpace(details.VersionHint) != "" && strings.TrimSpace(portProfile.Service.Version) == "" {
		portProfile.Service.Version = strings.TrimSpace(details.VersionHint)
	}
	if strings.TrimSpace(details.Banner) != "" && strings.TrimSpace(portProfile.Service.RawBanner) == "" {
		portProfile.Service.RawBanner = strings.TrimSpace(details.Banner)
	}
	if details.TLSEnabled {
		portProfile.Service.IsTLS = true
	}

	if strings.TrimSpace(details.Banner) != "" {
		portProfile.Service.ParsedAttributes["smtp_banner"] = strings.TrimSpace(details.Banner)
	}
	if strings.TrimSpace(details.SMTPProtocol) != "" {
		portProfile.Service.ParsedAttributes["smtp_protocol"] = strings.TrimSpace(details.SMTPProtocol)
	}
	if strings.TrimSpace(details.GreetingDomain) != "" {
		portProfile.Service.ParsedAttributes["smtp_greeting_domain"] = strings.TrimSpace(details.GreetingDomain)
	}
	if strings.TrimSpace(details.EHLOResponse) != "" {
		portProfile.Service.ParsedAttributes["smtp_ehlo_response"] = strings.TrimSpace(details.EHLOResponse)
	}

	portProfile.Service.ParsedAttributes["smtp_starttls_supported"] = details.StartTLSSupported
	portProfile.Service.ParsedAttributes["smtp_auth_supported"] = details.AuthSupported
	portProfile.Service.ParsedAttributes["smtp_pipelining_supported"] = details.PipeliningSupported
	portProfile.Service.ParsedAttributes["smtp_chunking_supported"] = details.ChunkingSupported
	portProfile.Service.ParsedAttributes["smtp_size_advertised"] = details.SizeAdvertised
	portProfile.Service.ParsedAttributes["smtp_tls_enabled"] = details.TLSEnabled
	portProfile.Service.ParsedAttributes["smtp_open_relay_suspected"] = details.OpenRelaySuspected
	portProfile.Service.ParsedAttributes["smtp_weak_tls_protocol"] = details.WeakTLSProtocol
	portProfile.Service.ParsedAttributes["smtp_weak_tls_cipher"] = details.WeakTLSCipher

	if strings.TrimSpace(details.TLSVersion) != "" {
		portProfile.Service.ParsedAttributes["smtp_tls_version"] = strings.TrimSpace(details.TLSVersion)
	}
	if strings.TrimSpace(details.TLSCipherSuite) != "" {
		portProfile.Service.ParsedAttributes["smtp_tls_cipher_suite"] = strings.TrimSpace(details.TLSCipherSuite)
	}
	if strings.TrimSpace(details.CertSubjectCN) != "" {
		portProfile.Service.ParsedAttributes["smtp_cert_subject_cn"] = strings.TrimSpace(details.CertSubjectCN)
	}
	if strings.TrimSpace(details.CertIssuer) != "" {
		portProfile.Service.ParsedAttributes["smtp_cert_issuer"] = strings.TrimSpace(details.CertIssuer)
	}
	if !details.CertNotAfter.IsZero() {
		portProfile.Service.ParsedAttributes["smtp_cert_not_after"] = details.CertNotAfter
	}
	portProfile.Service.ParsedAttributes["smtp_cert_is_self_signed"] = details.CertIsSelfSigned

	if strings.TrimSpace(details.SoftwareHint) != "" {
		portProfile.Service.ParsedAttributes["smtp_software_hint"] = strings.TrimSpace(details.SoftwareHint)
	}
	if strings.TrimSpace(details.VendorHint) != "" {
		portProfile.Service.ParsedAttributes["smtp_vendor_hint"] = strings.TrimSpace(details.VendorHint)
	}
	if strings.TrimSpace(details.VersionHint) != "" {
		portProfile.Service.ParsedAttributes["smtp_version_hint"] = strings.TrimSpace(details.VersionHint)
	}
	if strings.TrimSpace(details.ProbeError) != "" {
		portProfile.Service.ParsedAttributes["smtp_probe_error"] = strings.TrimSpace(details.ProbeError)
	}
}

func findSNMPDetails(items []scan.SNMPServiceInfo, target string, port int) *scan.SNMPServiceInfo {
	for i := range items {
		if items[i].Target == target && items[i].Port == port {
			return &items[i]
		}
	}
	return nil
}

func findDNSDetails(items []scan.DNSServiceInfo, target string, port int, transport string) *scan.DNSServiceInfo {
	for i := range items {
		if items[i].Target == target && items[i].Port == port && strings.EqualFold(strings.TrimSpace(items[i].Transport), transport) {
			return &items[i]
		}
	}
	return nil
}

//nolint:gocyclo // SNMP attribute emission is intentionally explicit to preserve JSON contract names.
func applySNMPDetails(portProfile *engine.PortProfile, details scan.SNMPServiceInfo) {
	if portProfile.Service.ParsedAttributes == nil {
		portProfile.Service.ParsedAttributes = make(map[string]any)
	}

	if details.SNMPProbe && strings.TrimSpace(portProfile.Service.Name) == "" {
		portProfile.Service.Name = "snmp"
	}
	if strings.TrimSpace(details.ProductHint) != "" && strings.TrimSpace(portProfile.Service.Product) == "" {
		portProfile.Service.Product = strings.TrimSpace(details.ProductHint)
	}
	if strings.TrimSpace(details.VersionHint) != "" && strings.TrimSpace(portProfile.Service.Version) == "" {
		portProfile.Service.Version = strings.TrimSpace(details.VersionHint)
	}

	if strings.TrimSpace(details.SNMPVersion) != "" {
		portProfile.Service.ParsedAttributes["snmp_version"] = strings.TrimSpace(details.SNMPVersion)
	}
	if strings.TrimSpace(details.SysDescr) != "" {
		portProfile.Service.ParsedAttributes["snmp_sysdescr"] = strings.TrimSpace(details.SysDescr)
	}
	if strings.TrimSpace(details.SysName) != "" {
		portProfile.Service.ParsedAttributes["snmp_sysname"] = strings.TrimSpace(details.SysName)
	}
	if strings.TrimSpace(details.SysObjectID) != "" {
		portProfile.Service.ParsedAttributes["snmp_sysobjectid"] = strings.TrimSpace(details.SysObjectID)
	}
	if strings.TrimSpace(details.ProductHint) != "" {
		portProfile.Service.ParsedAttributes["snmp_product_hint"] = strings.TrimSpace(details.ProductHint)
	}
	if strings.TrimSpace(details.VendorHint) != "" {
		portProfile.Service.ParsedAttributes["snmp_vendor_hint"] = strings.TrimSpace(details.VendorHint)
	}
	if strings.TrimSpace(details.VersionHint) != "" {
		portProfile.Service.ParsedAttributes["snmp_version_hint"] = strings.TrimSpace(details.VersionHint)
	}
	portProfile.Service.ParsedAttributes["snmp_weak_protocol"] = details.WeakProtocol
	portProfile.Service.ParsedAttributes["snmp_weak_community"] = details.WeakCommunity
	if strings.TrimSpace(details.ProbeError) != "" {
		portProfile.Service.ParsedAttributes["snmp_probe_error"] = strings.TrimSpace(details.ProbeError)
	}
}

func applyDNSDetails(portProfile *engine.PortProfile, details scan.DNSServiceInfo) {
	if portProfile.Service.ParsedAttributes == nil {
		portProfile.Service.ParsedAttributes = make(map[string]any)
	}

	if details.DNSProbe && strings.TrimSpace(portProfile.Service.Name) == "" {
		portProfile.Service.Name = "dns"
	}
	if strings.TrimSpace(details.ProductHint) != "" && strings.TrimSpace(portProfile.Service.Product) == "" {
		portProfile.Service.Product = strings.TrimSpace(details.ProductHint)
	}
	if strings.TrimSpace(details.VersionHint) != "" && strings.TrimSpace(portProfile.Service.Version) == "" {
		portProfile.Service.Version = strings.TrimSpace(details.VersionHint)
	}

	if strings.TrimSpace(details.Transport) != "" {
		portProfile.Service.ParsedAttributes["dns_transport"] = strings.TrimSpace(details.Transport)
	}
	if strings.TrimSpace(details.ResponseCode) != "" {
		portProfile.Service.ParsedAttributes["dns_response_code"] = strings.TrimSpace(details.ResponseCode)
	}
	portProfile.Service.ParsedAttributes["dns_recursion_available"] = details.RecursionAvailable
	portProfile.Service.ParsedAttributes["dns_authoritative_answer"] = details.AuthoritativeAnswer
	portProfile.Service.ParsedAttributes["dns_truncated_response"] = details.TruncatedResponse
	portProfile.Service.ParsedAttributes["dns_ns_query_responded"] = details.NSQueryResponded
	portProfile.Service.ParsedAttributes["dns_version_bind_responded"] = details.VersionBindResponded
	portProfile.Service.ParsedAttributes["dns_version_bind_supported"] = details.VersionBindSupported
	if strings.TrimSpace(details.VersionBind) != "" {
		portProfile.Service.ParsedAttributes["dns_version_bind"] = strings.TrimSpace(details.VersionBind)
	}
	if len(details.NSRecords) > 0 {
		portProfile.Service.ParsedAttributes["dns_ns_records"] = append([]string(nil), details.NSRecords...)
	}
	if strings.TrimSpace(details.ProbeError) != "" {
		portProfile.Service.ParsedAttributes["dns_probe_error"] = strings.TrimSpace(details.ProbeError)
	}
}

func appendUniqueString(values []string, candidate string) []string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return values
	}
	for _, existing := range values {
		if strings.EqualFold(existing, candidate) {
			return values
		}
	}
	return append(values, candidate)
}

func findRDPDetails(items []scan.RDPServiceInfo, target string, port int) *scan.RDPServiceInfo {
	for i := range items {
		if items[i].Target == target && items[i].Port == port {
			return &items[i]
		}
	}
	return nil
}

func applyRDPDetails(portProfile *engine.PortProfile, details scan.RDPServiceInfo) {
	if portProfile.Service.ParsedAttributes == nil {
		portProfile.Service.ParsedAttributes = make(map[string]any)
	}

	if strings.TrimSpace(details.RDPDetected) != "" {
		portProfile.Service.ParsedAttributes["rdp_detected"] = strings.TrimSpace(details.RDPDetected)
	}
	if strings.TrimSpace(details.SelectedProtocol) != "" {
		portProfile.Service.ParsedAttributes["rdp_selected_protocol"] = strings.TrimSpace(details.SelectedProtocol)
	}
	if details.NLACapable != nil {
		portProfile.Service.ParsedAttributes["rdp_nla_capable"] = *details.NLACapable
	}
	if details.TLSCapable != nil {
		portProfile.Service.ParsedAttributes["rdp_tls_capable"] = *details.TLSCapable
	}
	if strings.TrimSpace(details.NegFailureCode) != "" {
		portProfile.Service.ParsedAttributes["rdp_neg_failure_code"] = strings.TrimSpace(details.NegFailureCode)
	}
	if strings.TrimSpace(details.Error) != "" {
		portProfile.Service.ParsedAttributes["rdp_probe_error"] = strings.TrimSpace(details.Error)
	}
}

func findTLSDetails(items []scan.TLSServiceInfo, target string, port int) *scan.TLSServiceInfo {
	for i := range items {
		if items[i].Target == target && items[i].Port == port {
			return &items[i]
		}
	}
	return nil
}

func findRPCDetails(items []scan.RPCServiceInfo, target string, port int) *scan.RPCServiceInfo {
	for i := range items {
		if items[i].Target == target && items[i].Port == port {
			return &items[i]
		}
	}
	return nil
}

func applyRPCDetails(portProfile *engine.PortProfile, details scan.RPCServiceInfo) {
	if portProfile.Service.ParsedAttributes == nil {
		portProfile.Service.ParsedAttributes = make(map[string]any)
	}

	portProfile.Service.ParsedAttributes["rpc_probe"] = details.RPCProbe
	if details.DerivedFromPort > 0 {
		portProfile.Service.ParsedAttributes["rpc_derived_from_port"] = details.DerivedFromPort
	}
	portProfile.Service.ParsedAttributes["rpc_anonymous_bind"] = details.AnonymousBind
	portProfile.Service.ParsedAttributes["rpc_is_server_listening"] = details.IsServerListening

	if strings.TrimSpace(details.PrincipalName) != "" {
		portProfile.Service.ParsedAttributes["rpc_principal_name"] = strings.TrimSpace(details.PrincipalName)
	}
	if details.InterfaceCount > 0 {
		portProfile.Service.ParsedAttributes["rpc_interface_count"] = details.InterfaceCount
	}
	if len(details.InterfaceUUIDs) > 0 {
		portProfile.Service.ParsedAttributes["rpc_interface_uuids"] = append([]string(nil), details.InterfaceUUIDs...)
	}
	if len(details.NamedPipes) > 0 {
		portProfile.Service.ParsedAttributes["rpc_named_pipes"] = append([]string(nil), details.NamedPipes...)
	}
	if len(details.InternalIPs) > 0 {
		portProfile.Service.ParsedAttributes["rpc_internal_ips"] = append([]string(nil), details.InternalIPs...)
	}
	if len(details.RPCStats) > 0 {
		portProfile.Service.ParsedAttributes["rpc_stats"] = append([]int(nil), details.RPCStats...)
	}
	if strings.TrimSpace(details.ProbeError) != "" {
		portProfile.Service.ParsedAttributes["rpc_probe_error"] = strings.TrimSpace(details.ProbeError)
	}
}

func applyTLSDetails(portProfile *engine.PortProfile, details scan.TLSServiceInfo) {
	if portProfile.Service.ParsedAttributes == nil {
		portProfile.Service.ParsedAttributes = make(map[string]any)
	}

	if details.TLSProbe {
		portProfile.Service.IsTLS = true
	}
	if strings.TrimSpace(details.TLSVersion) != "" {
		portProfile.Service.ParsedAttributes["tls_version"] = strings.TrimSpace(details.TLSVersion)
	}
	if strings.TrimSpace(details.CipherSuite) != "" {
		portProfile.Service.ParsedAttributes["tls_cipher_suite"] = strings.TrimSpace(details.CipherSuite)
	}
	if strings.TrimSpace(details.ALPN) != "" {
		portProfile.Service.ParsedAttributes["tls_alpn"] = strings.TrimSpace(details.ALPN)
	}
	if strings.TrimSpace(details.SNIServerName) != "" {
		portProfile.Service.ParsedAttributes["tls_sni_server_name"] = strings.TrimSpace(details.SNIServerName)
	}
	if strings.TrimSpace(details.CertSubjectCN) != "" {
		portProfile.Service.ParsedAttributes["tls_cert_subject_cn"] = strings.TrimSpace(details.CertSubjectCN)
	}
	if strings.TrimSpace(details.CertIssuer) != "" {
		portProfile.Service.ParsedAttributes["tls_cert_issuer"] = strings.TrimSpace(details.CertIssuer)
	}
	if len(details.CertDNSNames) > 0 {
		portProfile.Service.ParsedAttributes["tls_cert_dns_names"] = append([]string(nil), details.CertDNSNames...)
	}
	if !details.CertNotBefore.IsZero() {
		portProfile.Service.ParsedAttributes["tls_cert_not_before"] = details.CertNotBefore
	}
	if !details.CertNotAfter.IsZero() {
		portProfile.Service.ParsedAttributes["tls_cert_not_after"] = details.CertNotAfter
	}
	if strings.TrimSpace(details.CertSHA256) != "" {
		portProfile.Service.ParsedAttributes["tls_cert_sha256"] = strings.TrimSpace(details.CertSHA256)
	}

	portProfile.Service.ParsedAttributes["tls_cert_is_expired"] = details.CertIsExpired
	portProfile.Service.ParsedAttributes["tls_cert_is_self_signed"] = details.CertIsSelfSigned
	portProfile.Service.ParsedAttributes["tls_weak_protocol"] = details.WeakProtocol
	portProfile.Service.ParsedAttributes["tls_weak_cipher"] = details.WeakCipher
	portProfile.Service.ParsedAttributes["tls_hostname_mismatch"] = details.HostnameMismatch
	portProfile.Service.ParsedAttributes["tls_cert_expiring_soon"] = details.CertExpiringSoon

	if strings.TrimSpace(details.ProbeError) != "" {
		portProfile.Service.ParsedAttributes["tls_probe_error"] = strings.TrimSpace(details.ProbeError)
	}
}
