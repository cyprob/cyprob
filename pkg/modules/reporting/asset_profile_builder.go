// pkg/modules/reporting/asset_profile_builder.go
package reporting

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"  // For ICMPPingDiscoveryResult, TCPPortDiscoveryResult
	"github.com/cyprob/cyprob/pkg/modules/evaluation" // For VulnerabilityResult
	"github.com/cyprob/cyprob/pkg/modules/parse"      // For HTTPParsedInfo, SSHParsedInfo
	"github.com/cyprob/cyprob/pkg/modules/scan"       // For BannerGrabResult
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
			Name:        assetProfileBuilderModuleTypeName,
			Version:     "0.1.0",
			Description: "Aggregates all scan data into comprehensive asset profiles.",
			Type:        engine.ReportingModuleType, // veya OrchestrationModuleType
			Author:      "Vulntor Team",
			Tags:        []string{"reporting", "aggregation", "asset-profile"},
			Consumes: []engine.DataContractEntry{ // Bu modül birçok şeyi tüketir
				// Planner bu anahtarları DataContext'ten alıp bu modülün input'una verir.
				// Veya bu modül doğrudan DataContext'in tamamını alıp kendi içinde filtreleyebilir.
				// Şimdilik spesifik anahtarlar varsayalım:
				{Key: "config.targets", DataTypeName: "[]string", Cardinality: engine.CardinalitySingle, IsOptional: true},
				{Key: "discovery.live_hosts", DataTypeName: "discovery.ICMPPingDiscoveryResult", Cardinality: engine.CardinalityList, IsOptional: true},    // DataContext'te []interface{}{ICMPPingDiscoveryResult}
				{Key: "discovery.open_tcp_ports", DataTypeName: "discovery.TCPPortDiscoveryResult", Cardinality: engine.CardinalityList, IsOptional: true}, // []interface{}{TCPPortDiscoveryResult1, TCPResult2}
				{Key: "service.banner.tcp", DataTypeName: "scan.BannerGrabResult", Cardinality: engine.CardinalityList, IsOptional: true},                  // []interface{}{BannerResult1, BannerResult2}
				{Key: "service.http.details", DataTypeName: "parse.HTTPParsedInfo", Cardinality: engine.CardinalityList, IsOptional: true},                 // []interface{}{HTTPParsedInfo1, ...}
				{Key: "service.ssh.details", DataTypeName: "parse.SSHParsedInfo", Cardinality: engine.CardinalityList, IsOptional: true},                   // []interface{}{SSHParsedInfo1, ...}
				{Key: "service.fingerprint.details", DataTypeName: "parse.FingerprintParsedInfo", Cardinality: engine.CardinalityList, IsOptional: true},   // []interface{}{FingerprintParsedInfo1, ...}
				{Key: "service.tech.tags", DataTypeName: "parse.TechTagResult", Cardinality: engine.CardinalityList, IsOptional: true},                     // []interface{}{TechTagResult1, ...}
				{Key: "evaluation.vulnerabilities", DataTypeName: "evaluation.VulnerabilityResult", Cardinality: engine.CardinalityList, IsOptional: true}, // []interface{}{VulnerabilityResult1, ...}
			},
			Produces: []engine.DataContractEntry{
				{Key: "asset.profiles", DataTypeName: "[]engine.AssetProfile", Cardinality: engine.CardinalitySingle}, // Tek bir liste üretir
			},
			ConfigSchema: map[string]engine.ParameterDefinition{},
		},
		config: AssetProfileBuilderConfig{},
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

//nolint:gocyclo // Complexity is inherent to aggregation logic
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

	sshDetailsResults := []parse.SSHParsedInfo{}
	if rawSSH, ok := inputs["service.ssh.details"]; ok {
		if list, listOk := rawSSH.([]any); listOk {
			for _, item := range list {
				if casted, castOk := item.(parse.SSHParsedInfo); castOk {
					sshDetailsResults = append(sshDetailsResults, casted)
				}
			}
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
	processedTargets := make(map[string]*engine.AssetProfile) // IP adresine göre AssetProfile tutar

	// 1. Canlı hostlardan AssetProfile'ları başlat
	for _, icmpResult := range liveHostResults {
		for _, liveIP := range icmpResult.LiveHosts {
			if _, exists := processedTargets[liveIP]; !exists {
				now := time.Now()
				profile := &engine.AssetProfile{
					Target:              liveIP,
					ResolvedIPs:         map[string]time.Time{liveIP: now},
					IsAlive:             true,
					LastObservationTime: now,
					OpenPorts:           make(map[string][]engine.PortProfile),
				}
				processedTargets[liveIP] = profile
				finalAssetProfiles = append(finalAssetProfiles, *profile) // Slice'a eklerken değerini kopyala
			} else {
				processedTargets[liveIP].IsAlive = true
				processedTargets[liveIP].LastObservationTime = time.Now()
			}
		}
	}

	// Eğer canlı host bilgisi yoksa, initialTargets'ı kullan (ping kapalıysa veya yanıt yoksa)
	if len(liveHostResults) == 0 {
		expandedInitialTargets := netutil.ParseAndExpandTargets(initialTargets) // utils'dan
		for _, target := range expandedInitialTargets {
			if _, exists := processedTargets[target]; !exists {
				now := time.Now()
				profile := &engine.AssetProfile{
					Target:      target,
					ResolvedIPs: map[string]time.Time{target: now},
					IsAlive:     false, // Ping ile doğrulanmadı
					// ScanStartTime:       now,
					LastObservationTime: now,
					OpenPorts:           make(map[string][]engine.PortProfile),
				}
				processedTargets[target] = profile
				finalAssetProfiles = append(finalAssetProfiles, *profile)
			}
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
					// Bu porta ait parse edilmiş SSH detaylarını bul
					for _, sshDetail := range sshDetailsResults {
						if sshDetail.Target == targetIP && sshDetail.Port == portNum {
							portProfile.Service.Name = sshDetail.ProtocolName
							portProfile.Service.Product = sshDetail.Software
							portProfile.Service.Version = sshDetail.SoftwareVersion
							if portProfile.Service.ParsedAttributes == nil {
								portProfile.Service.ParsedAttributes = make(map[string]any)
							}
							portProfile.Service.ParsedAttributes["ssh_protocol_version"] = sshDetail.SSHVersion
							portProfile.Service.ParsedAttributes["ssh_full_version_info"] = sshDetail.VersionInfo
							break
						}
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
		asset.OpenPorts[targetIP] = assetOpenPorts // Haritaya ekle
		asset.LastObservationTime = time.Now()
	}

	// asset.profiles'ı ModuleOutput olarak gönder
	outputChan <- engine.ModuleOutput{
		FromModuleName: m.meta.ID,
		DataKey:        m.meta.Produces[0].Key, // "asset.profiles"
		Data:           finalAssetProfiles,     // Bu []engine.AssetProfile tipinde olmalı
		Timestamp:      time.Now(),
	}

	logger.Info().Int("profile_count", len(finalAssetProfiles)).Msg("Asset profile aggregation completed")
	return nil
}

func AssetProfileBuilderModuleFactory() engine.Module {
	return newAssetProfileBuilderModule()
}

func init() {
	engine.RegisterModuleFactory(assetProfileBuilderModuleTypeName, AssetProfileBuilderModuleFactory)
}
