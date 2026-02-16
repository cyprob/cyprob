// pkg/modules/parse/ssh_parser.go
package parse

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/scan"
	"github.com/cyprob/cyprob/pkg/output"
)

const (
	// Module metadata constants
	sshParserModuleID          = "ssh-parser-instance"
	sshParserModuleName        = "ssh-parser"
	sshParserModuleDescription = "Parses raw SSH response banners into structured data (service, product, etc.)."
	sshParserModuleVersion     = "0.1.0"
	sshParserModuleAuthor      = "Vulntor Team"
)

// Package parse provides a module for parsing SSH messages.
type SSHParserConfig struct {
	// Add any specific configuration options for the SSH parser here.
	// For example, you might want to add options for parsing specific SSH message types.
	// For now, we keep it empty as a placeholder.
	// ExampleOption string `json:"example_option,omitempty"`
}

// HTTPParserModule implements the engine.Module interface.
type SSHParserModule struct {
	meta   engine.ModuleMetadata
	config SSHParserConfig
	logger zerolog.Logger
}

// SSHParsedInfo holds structured information extracted from an SSH banner.
type SSHParsedInfo struct {
	Target          string `json:"target"`
	Port            int    `json:"port"`
	ProtocolName    string `json:"protocol_name"`                  // Should be "SSH"
	VersionInfo     string `json:"version_info,omitempty"`         // e.g., "OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
	SSHVersion      string `json:"ssh_protocol_version,omitempty"` // e.g., "2.0"
	Software        string `json:"software,omitempty"`             // e.g., "OpenSSH" (if parsable)
	SoftwareVersion string `json:"software_version,omitempty"`     // e.g., "8.9p1" (if parsable)
	RawBanner       string `json:"-"`                              // Store raw banner for reference
	ParseError      string `json:"parse_error,omitempty"`
}

// newSSHParserModule creates a new instance of SSHParserModule.
func newSSHParserModule() *SSHParserModule {
	defaultConfig := SSHParserConfig{}
	return &SSHParserModule{
		meta: engine.ModuleMetadata{
			ID:          sshParserModuleID,
			Name:        sshParserModuleName,
			Description: sshParserModuleDescription,
			Version:     sshParserModuleVersion,
			Type:        engine.ParseModuleType,
			Author:      sshParserModuleAuthor,
			Tags:        []string{"parser", "http", "banner"},
			Consumes: []engine.DataContractEntry{
				{
					Key: "service.banner.tcp", // Expects output from service-banner-scanner
					// DataTypeName is the type of *each item* within the []interface{} list
					// that DataContext stores for "instance_id_of_banner_scanner.service.banner.tcp".
					DataTypeName: "scan.BannerGrabResult", // Defined in pkg/modules/scan
					// CardinalityList means this module expects the value for "service.banner.tcp"
					// in its 'inputs' map to be an []interface{} list, where each element
					// can be cast to scan.BannerGrabResult.
					Cardinality: engine.CardinalityList,
					IsOptional:  false, // Requires banner input to do any work
					Description: "List of raw TCP banners, where each item is a scan.BannerGrabResult.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key: "service.ssh.details",
					// This module will send multiple ModuleOutput messages if it parses multiple SSH banners.
					// Each ModuleOutput.Data will be a single parse.SSHParsedInfo struct.
					// DataContext will aggregate these into a list: []interface{}{SSHParsedInfo1, SSHParsedInfo2, ...}
					DataTypeName: "parse.SSHParsedInfo",  // The type of the Data field in each ModuleOutput
					Cardinality:  engine.CardinalityList, // Indicates DataContext will store a list for this DataKey.
					Description:  "List of parsed SSH details, one result per successfully parsed SSH banner.",
				},
				{
					Key:          "ssh.banner",
					DataTypeName: "string",
					Cardinality:  engine.CardinalityList,
					Description:  "Raw SSH banner strings for plugin evaluation (e.g., 'SSH-2.0-OpenSSH_6.6.1p1').",
				},
				{
					Key:          "ssh.version",
					DataTypeName: "string",
					Cardinality:  engine.CardinalityList,
					Description:  "SSH version info for plugin evaluation (e.g., 'OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13').",
				},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				// No specific config parameters for now for this simple parser.
			},
			// ActivationTriggers: This parser could be dynamically activated if a banner
			// is identified as potentially SSH by a very lightweight pre-parser, or it can
			// simply try to parse all banners it receives.
			// Example (if a pre-filter existed):
			// ActivationTriggers: []engine.ActivationTrigger{
			//  { DataKey: "service.banner.tcp.content_hint", ValueCondition: "SSH-", ConditionType: "starts_with"},
			// },
			// IsDynamic: true, // If using ActivationTriggers
			EstimatedCost: 1, // Parsing is generally fast.
		},
		config: defaultConfig,
		logger: log.With().Str("module", sshParserModuleName).Str("instance_id", sshParserModuleID).Logger(),
	}
}

// Metadata returns the module's metadata.
func (m *SSHParserModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

// Init initializes the module with its instance ID and configuration.
func (m *SSHParserModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	m.logger.Debug().Interface("received_config_map", configMap).Msg("Initializing module (no specific config for ssh-parser)")
	// No config parameters to parse from configMap for now for this simple parser
	m.logger.Debug().Msg("Module initialized")
	return nil
}

// Execute parses SSH banners.
//
//nolint:gocyclo // Complexity is inherent to banner parsing logic
func (m *SSHParserModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	// Extract Output interface for real-time SSH service detection
	out, _ := ctx.Value(output.OutputKey).(output.Output)

	rawBannerInput, ok := inputs["service.banner.tcp"] // This comes from service-banner-scanner
	if !ok {
		m.logger.Info().Msg("'service.banner.tcp' not found in inputs. Nothing to parse for SSH.")
		return nil // Not an error for this module, just no relevant input
	}

	bannerList, listOk := rawBannerInput.([]any)
	if !listOk {
		if typed, ok := rawBannerInput.([]scan.BannerGrabResult); ok {
			for _, item := range typed {
				bannerList = append(bannerList, item)
			}
		} else {
			m.logger.Error().Type("input_type", rawBannerInput).Msg("'service.banner.tcp' input is not a list as expected by ssh-parser.")
			return fmt.Errorf("input 'service.banner.tcp' is not a list, type: %T", rawBannerInput)
		}
	}

	m.logger.Info().Int("banner_count_to_process", len(bannerList)).Msg("Processing banners for SSH identification")
	processedCount := 0

	for i, item := range bannerList {
		select {
		case <-ctx.Done():
			m.logger.Info().Int("processed_ssh_banners", processedCount).Msg("Context canceled. Aborting further SSH parsing.")
			return ctx.Err()
		default:
		}

		bannerResult, castOk := item.(scan.BannerGrabResult) // This is the output from service-banner-scanner
		if !castOk {
			m.logger.Warn().Int("item_index", i).Type("item_type", item).Msg("Item in 'service.banner.tcp' list is not scan.BannerGrabResult, skipping.")
			continue
		}

		if bannerResult.Error != "" || bannerResult.Banner == "" {
			// m.logger.Debug().Str("target",bannerResult.Target).Int("port",bannerResult.Port).Msg("Skipping banner with error or empty content.")
			continue
		}

		// Check if the banner starts with "SSH-" (standard SSH identification string)
		if !strings.HasPrefix(bannerResult.Banner, "SSH-") {
			// m.logger.Debug().Str("target",bannerResult.Target).Int("port",bannerResult.Port).Msg("Banner does not start with SSH-, not an SSH banner.")
			continue // Not an SSH banner
		}
		processedCount++

		parsedInfo := SSHParsedInfo{
			Target:       bannerResult.IP,
			Port:         bannerResult.Port,
			ProtocolName: "SSH",
			RawBanner:    bannerResult.Banner,
		}

		// Example banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-3ubuntu0.7"
		parts := strings.SplitN(bannerResult.Banner, "-", 3)
		if len(parts) >= 2 { // SSH-ProtoBehavior
			parsedInfo.SSHVersion = parts[1] // e.g., "2.0"
		}
		if len(parts) >= 3 {
			fullVersionInfo := strings.TrimSpace(parts[2]) // e.g., "OpenSSH_8.2p1 Ubuntu-3ubuntu0.7"
			parsedInfo.VersionInfo = fullVersionInfo

			// Extract software and its version from the full version info
			// This might be just the first part for some servers e.g. "OpenSSH_8.2p1"
			softwareAndComment := strings.Fields(fullVersionInfo)
			if len(softwareAndComment) > 0 {
				parsedInfo.Software, parsedInfo.SoftwareVersion = extractSSHSoftwareAndVersion(softwareAndComment[0])
			}
		}

		if parsedInfo.SSHVersion == "" && parsedInfo.VersionInfo == "" {
			parsedInfo.ParseError = "Could not parse SSH version or software information from banner"
			m.logger.Warn().Str("ip", bannerResult.IP).Int("port", bannerResult.Port).Str("banner", bannerResult.Banner).Msg(parsedInfo.ParseError)
		}

		m.logger.Debug().Str("ip", bannerResult.IP).Int("port", bannerResult.Port).Str("ssh_version", parsedInfo.SSHVersion).Str("software", parsedInfo.Software).Msg("SSH banner parsed")

		// Real-time output: Emit SSH service detection to user
		if out != nil {
			message := fmt.Sprintf("SSH service detected: %s:%d - %s", bannerResult.IP, bannerResult.Port, parsedInfo.Software)
			if parsedInfo.SoftwareVersion != "" {
				message = fmt.Sprintf("SSH service detected: %s:%d - %s %s", bannerResult.IP, bannerResult.Port, parsedInfo.Software, parsedInfo.SoftwareVersion)
			}
			out.Diag(output.LevelNormal, message, nil)
		}

		// Output structured SSH details
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "service.ssh.details",
			Data:           parsedInfo,
			Timestamp:      time.Now(),
			Target:         bannerResult.IP,
		}

		// Output raw banner for plugin evaluation
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "ssh.banner",
			Data:           parsedInfo.RawBanner,
			Timestamp:      time.Now(),
			Target:         bannerResult.IP,
		}

		// Output version info for plugin evaluation
		if parsedInfo.VersionInfo != "" {
			outputChan <- engine.ModuleOutput{
				FromModuleName: m.meta.ID,
				DataKey:        "ssh.version",
				Data:           parsedInfo.VersionInfo,
				Timestamp:      time.Now(),
				Target:         bannerResult.IP,
			}
		}
	}

	m.logger.Info().Int("ssh_banners_parsed", processedCount).Msg("SSH parsing completed for all relevant banners.")
	return nil
}

// SSHParserModuleFactory creates a new SSHParserModule instance.
func SSHParserModuleFactory() engine.Module {
	return newSSHParserModule()
}

func init() {
	engine.RegisterModuleFactory(sshParserModuleName, SSHParserModuleFactory)
}

// extractSSHSoftwareAndVersion attempts to get a more granular software and version.
// Example: "OpenSSH_8.9p1" -> "OpenSSH", "8.9p1"
// Example: "dropbear_2020.78" -> "dropbear", "2020.78"
func extractSSHSoftwareAndVersion(versionInfo string) (software, swVersion string) {
	if versionInfo == "" {
		return "", ""
	}
	parts := strings.SplitN(versionInfo, "_", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	// Fallback for some other formats or if no underscore
	spaceParts := strings.Fields(versionInfo)
	if len(spaceParts) > 0 {
		// Attempt to identify common SSH software names
		lcFirstPart := strings.ToLower(spaceParts[0])
		if strings.HasPrefix(lcFirstPart, "openssh") || strings.HasPrefix(lcFirstPart, "dropbear") {
			software = spaceParts[0]
			if len(spaceParts) > 1 {
				swVersion = spaceParts[1]
			}
			return software, swVersion
		}
	}
	return versionInfo, "" // Default to full string as software, no specific version
}
