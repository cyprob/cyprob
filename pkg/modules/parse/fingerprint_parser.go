// pkg/modules/parse/fingerprint_parser.go
package parse

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/vulntor/vulntor/pkg/engine"
	"github.com/vulntor/vulntor/pkg/fingerprint"
	"github.com/vulntor/vulntor/pkg/modules/scan"
)

const (
	fingerprintParserModuleID          = "fingerprint-parser-instance"
	fingerprintParserModuleName        = "fingerprint-parser"
	fingerprintParserModuleDescription = "Matches service banners with fingerprint catalog entries."
	fingerprintParserModuleVersion     = "0.1.0"
	fingerprintParserModuleAuthor      = "Vulntor Team"
)

var getResolver = fingerprint.GetFingerprintResolver

// FingerprintParsedInfo represents structured fingerprint output.
type FingerprintParsedInfo struct {
	Target      string  `json:"target"`
	Port        int     `json:"port"`
	Protocol    string  `json:"protocol,omitempty"`
	Product     string  `json:"product,omitempty"`
	Vendor      string  `json:"vendor,omitempty"`
	Version     string  `json:"version,omitempty"`
	CPE         string  `json:"cpe,omitempty"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description,omitempty"`
	SourceProbe string  `json:"source_probe,omitempty"`

	// Phase 1.7: TLS metadata (certificate validity and security indicators)
	TLS *engine.TLSObservation `json:"tls,omitempty"`
}

// FingerprintParserModule consumes banner results and produces fingerprint matches.
type FingerprintParserModule struct {
	meta engine.ModuleMetadata
}

func newFingerprintParserModule() *FingerprintParserModule {
	return &FingerprintParserModule{
		meta: engine.ModuleMetadata{
			ID:          fingerprintParserModuleID,
			Name:        fingerprintParserModuleName,
			Description: fingerprintParserModuleDescription,
			Version:     fingerprintParserModuleVersion,
			Type:        engine.ParseModuleType,
			Author:      fingerprintParserModuleAuthor,
			Tags:        []string{"parser", "fingerprint"},
			Consumes: []engine.DataContractEntry{
				{
					Key:          "service.banner.tcp",
					DataTypeName: "scan.BannerGrabResult",
					Cardinality:  engine.CardinalityList,
					IsOptional:   true,
					Description:  "List of raw TCP banners captured from the service-banner module.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key:          "service.fingerprint.details",
					DataTypeName: "parse.FingerprintParsedInfo",
					Cardinality:  engine.CardinalityList,
					Description:  "Fingerprint matches derived from service banners.",
				},
				// Phase 1.8: TLS metadata keys (protocol-level)
				{
					Key:          "tls.version",
					DataTypeName: "string",
					Cardinality:  engine.CardinalitySingle,
					IsOptional:   true,
					Description:  "TLS protocol version (e.g., TLS1.3, TLS1.2)",
				},
				{
					Key:          "tls.cipher_suite",
					DataTypeName: "string",
					Cardinality:  engine.CardinalitySingle,
					IsOptional:   true,
					Description:  "TLS cipher suite name",
				},
				{
					Key:          "tls.server_name",
					DataTypeName: "string",
					Cardinality:  engine.CardinalitySingle,
					IsOptional:   true,
					Description:  "TLS SNI server name",
				},
				// Phase 1.8: TLS certificate metadata keys
				{
					Key:          "tls.certificate.issuer",
					DataTypeName: "string",
					Cardinality:  engine.CardinalitySingle,
					IsOptional:   true,
					Description:  "TLS certificate issuer DN",
				},
				{
					Key:          "tls.certificate.common_name",
					DataTypeName: "string",
					Cardinality:  engine.CardinalitySingle,
					IsOptional:   true,
					Description:  "TLS certificate common name (CN)",
				},
				{
					Key:          "tls.certificate.dns_names",
					DataTypeName: "[]string",
					Cardinality:  engine.CardinalityList,
					IsOptional:   true,
					Description:  "TLS certificate Subject Alternative Names (DNS names)",
				},
				{
					Key:          "tls.certificate.not_before",
					DataTypeName: "time.Time",
					Cardinality:  engine.CardinalitySingle,
					IsOptional:   true,
					Description:  "TLS certificate validity start time",
				},
				{
					Key:          "tls.certificate.not_after",
					DataTypeName: "time.Time",
					Cardinality:  engine.CardinalitySingle,
					IsOptional:   true,
					Description:  "TLS certificate validity end time (expiration)",
				},
				{
					Key:          "tls.certificate.is_expired",
					DataTypeName: "bool",
					Cardinality:  engine.CardinalitySingle,
					IsOptional:   true,
					Description:  "Whether the TLS certificate is expired",
				},
				{
					Key:          "tls.certificate.is_self_signed",
					DataTypeName: "bool",
					Cardinality:  engine.CardinalitySingle,
					IsOptional:   true,
					Description:  "Whether the TLS certificate is self-signed",
				},
			},
		},
	}
}

// Metadata returns the metadata information for the FingerprintParserModule.
// It implements the engine.Module interface.
func (m *FingerprintParserModule) Metadata() engine.ModuleMetadata { return m.meta }

func (m *FingerprintParserModule) Init(instanceID string, _ map[string]any) error {
	m.meta.ID = instanceID
	initLogger := log.With().Str("module", m.meta.Name).Str("instance_id", m.meta.ID).Logger()
	initLogger.Debug().Msg("Fingerprint parser initialized")
	return nil
}

func (m *FingerprintParserModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	logger := log.With().Str("module", m.meta.Name).Str("instance_id", m.meta.ID).Logger()

	raw, ok := inputs["service.banner.tcp"]
	if !ok {
		return nil
	}

	bannerList, listOk := raw.([]any)
	if !listOk {
		return nil
	}

	resolver := getResolver()
	matches := 0

	for _, item := range bannerList {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		banner, castOk := item.(scan.BannerGrabResult)
		if !castOk {
			continue
		}

		matches += m.processBannerCandidates(ctx, banner, resolver, outputChan)
	}

	logger.Info().Int("matches", matches).Msg("Fingerprint parsing completed")
	return nil
}

func (m *FingerprintParserModule) processBannerCandidates(ctx context.Context, banner scan.BannerGrabResult, resolver fingerprint.Resolver, outputChan chan<- engine.ModuleOutput) int {
	logger := log.With().Str("module", m.meta.Name).Str("instance_id", m.meta.ID).Logger()
	seenCandidates := make(map[string]struct{}) // Changed: track (response, probeID) to allow TLS and non-TLS versions
	seenMatches := make(map[string]struct{})
	matches := 0

	for _, candidate := range gatherBannerCandidates(banner) {
		response := strings.TrimSpace(candidate.Response)
		if response == "" {
			continue
		}
		// Phase 1.8 Fix: Deduplicate by (response, probeID) instead of just response
		// This allows both tcp-passive and imap-capability-tls (with TLS metadata) to be processed
		candidateKey := fmt.Sprintf("%s|%s", response, candidate.ProbeID)
		if _, exists := seenCandidates[candidateKey]; exists {
			continue
		}
		seenCandidates[candidateKey] = struct{}{}

		logger.Debug().
			Str("probe_id", candidate.ProbeID).
			Bool("has_tls", candidate.TLS != nil).
			Str("response_preview", response[:min(len(response), 50)]).
			Msg("Processing banner candidate")

		protocolHint := strings.ToLower(candidate.Protocol)
		if protocolHint == "" || protocolHint == "tcp" || protocolHint == "udp" {
			protocolHint = strings.ToLower(banner.Protocol)
		}
		if protocolHint == "" || protocolHint == "tcp" || protocolHint == "udp" {
			detectedHint := fingerprintProtocolHint(banner.Port, response)
			if detectedHint != "" {
				protocolHint = detectedHint
			} else {
				// Phase 1: If no hint found, leave as generic to trigger fallback in resolver
				// This enables detection on non-standard ports (e.g., MySQL on 3210, HTTP on 2096)
				protocolHint = "" // Empty triggers fallback mode
			}
		}

		result, err := resolver.Resolve(ctx, fingerprint.Input{
			Protocol:    protocolHint,
			Banner:      response,
			Port:        banner.Port,
			ServiceHint: "",
		})
		if err != nil || result.Product == "" {
			continue
		}

		// Phase 1.8: Emit TLS metadata BEFORE deduplication
		// This ensures TLS metadata is emitted even if the fingerprint match is duplicate
		if candidate.TLS != nil {
			logger.Debug().
				Str("target", banner.IP).
				Int("port", banner.Port).
				Str("probe_id", candidate.ProbeID).
				Msg("Emitting TLS metadata to DataContext")
			m.emitTLSMetadata(candidate.TLS, banner.IP, outputChan)
		}

		matchKey := fmt.Sprintf("%s|%s|%s", result.Product, result.Version, protocolHint)
		if _, exists := seenMatches[matchKey]; exists {
			continue
		}
		seenMatches[matchKey] = struct{}{}

		parsed := FingerprintParsedInfo{
			Target:      banner.IP,
			Port:        banner.Port,
			Protocol:    protocolHint,
			Product:     result.Product,
			Vendor:      result.Vendor,
			Version:     result.Version,
			CPE:         result.CPE,
			Confidence:  result.Confidence,
			Description: result.Description,
			SourceProbe: candidate.ProbeID,
			TLS:         candidate.TLS, // Phase 1.7: Include TLS metadata in output
		}

		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        m.meta.Produces[0].Key,
			Data:           parsed,
			Timestamp:      time.Now(),
			Target:         banner.IP,
		}
		matches++
	}

	return matches
}

// emitTLSMetadata emits TLS observation data as individual data keys to DataContext.
// Phase 1.8: This enables TLS plugins to trigger and match on TLS metadata.
//
// Emitted keys follow hierarchical structure:
// - Protocol-level: tls.version, tls.cipher_suite, tls.server_name
// - Certificate-level: tls.certificate.* (issuer, common_name, not_after, is_expired, is_self_signed, etc.)
func (m *FingerprintParserModule) emitTLSMetadata(tls *engine.TLSObservation, target string, outputChan chan<- engine.ModuleOutput) {
	timestamp := time.Now()

	// Protocol-level keys
	if tls.Version != "" {
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "tls.version",
			Data:           tls.Version,
			Timestamp:      timestamp,
			Target:         target,
		}
	}
	if tls.CipherSuite != "" {
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "tls.cipher_suite",
			Data:           tls.CipherSuite,
			Timestamp:      timestamp,
			Target:         target,
		}
	}
	if tls.ServerName != "" {
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "tls.server_name",
			Data:           tls.ServerName,
			Timestamp:      timestamp,
			Target:         target,
		}
	}

	// Certificate-level keys
	if tls.Issuer != "" {
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "tls.certificate.issuer",
			Data:           tls.Issuer,
			Timestamp:      timestamp,
			Target:         target,
		}
	}
	if tls.PeerCommonName != "" {
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "tls.certificate.common_name",
			Data:           tls.PeerCommonName,
			Timestamp:      timestamp,
			Target:         target,
		}
	}
	if len(tls.PeerDNSNames) > 0 {
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "tls.certificate.dns_names",
			Data:           tls.PeerDNSNames,
			Timestamp:      timestamp,
			Target:         target,
		}
	}
	if !tls.NotBefore.IsZero() {
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "tls.certificate.not_before",
			Data:           tls.NotBefore,
			Timestamp:      timestamp,
			Target:         target,
		}
	}
	if !tls.NotAfter.IsZero() {
		outputChan <- engine.ModuleOutput{
			FromModuleName: m.meta.ID,
			DataKey:        "tls.certificate.not_after",
			Data:           tls.NotAfter,
			Timestamp:      timestamp,
			Target:         target,
		}
	}

	// Boolean flags (always emit, even if false, for plugin matching)
	outputChan <- engine.ModuleOutput{
		FromModuleName: m.meta.ID,
		DataKey:        "tls.certificate.is_expired",
		Data:           tls.IsExpired,
		Timestamp:      timestamp,
		Target:         target,
	}
	outputChan <- engine.ModuleOutput{
		FromModuleName: m.meta.ID,
		DataKey:        "tls.certificate.is_self_signed",
		Data:           tls.IsSelfSigned,
		Timestamp:      timestamp,
		Target:         target,
	}
}

type bannerCandidate struct {
	Response string
	Protocol string
	ProbeID  string
	TLS      *engine.TLSObservation // Phase 1.7: TLS metadata from probe
}

func gatherBannerCandidates(banner scan.BannerGrabResult) []bannerCandidate {
	candidates := make([]bannerCandidate, 0, len(banner.Evidence)+1)

	// Prioritize active probe evidence over synthetic tcp-passive fallback
	// so source_probe attribution reflects the real producing probe.
	appendEvidence := func(passiveOnly bool) {
		for _, obs := range banner.Evidence {
			if passiveOnly && obs.ProbeID != "tcp-passive" {
				continue
			}
			if !passiveOnly && obs.ProbeID == "tcp-passive" {
				continue
			}
			resp := strings.TrimSpace(obs.Response)
			if resp == "" {
				continue
			}
			protocol := obs.Protocol
			if protocol == "" {
				protocol = banner.Protocol
			}
			candidates = append(candidates, bannerCandidate{
				Response: resp,
				Protocol: protocol,
				ProbeID:  obs.ProbeID,
				TLS:      obs.TLS, // Phase 1.7: Include TLS metadata from probe
			})
		}
	}

	appendEvidence(false)
	appendEvidence(true)

	if len(candidates) == 0 {
		if trimmed := strings.TrimSpace(banner.Banner); trimmed != "" {
			candidates = append(candidates, bannerCandidate{
				Response: trimmed,
				Protocol: banner.Protocol,
				ProbeID:  "tcp-passive",
				TLS:      nil, // Passive banner doesn't have TLS metadata
			})
		}
	}

	return candidates
}

func fingerprintProtocolHint(port int, banner string) string {
	banner = strings.ToLower(banner)

	// First, try banner content matching
	if hint := detectProtocolFromBanner(banner); hint != "" {
		return hint
	}

	// Fallback to port number detection
	return detectProtocolFromPort(port)
}

func detectProtocolFromBanner(banner string) string {
	switch {
	case strings.HasPrefix(banner, "ssh-"):
		return "ssh"
	case strings.Contains(banner, "http/") || strings.Contains(banner, "server:"):
		return "http"
	case strings.Contains(banner, "smtp"):
		return "smtp"
	case strings.Contains(banner, "ftp"):
		return "ftp"
	case strings.Contains(banner, "mysql"), strings.Contains(banner, "mariadb"):
		return "mysql"
	}
	return ""
}

//nolint:gocyclo // Port mapping switch is intentionally comprehensive for protocol detection
func detectProtocolFromPort(port int) string {
	switch port {
	// Databases
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 27017:
		return "mongodb"
	// Network Services
	case 22:
		return "ssh"
	case 21:
		return "ftp"
	case 25, 587:
		return "smtp"
	// Mail Protocols (Phase 1.6)
	case 110, 995:
		return "pop3"
	case 143, 993:
		return "imap"
	// Enterprise/Messaging (Phase 1.6)
	case 53:
		return "dns"
	case 389, 636, 3268, 3269:
		return "ldap"
	case 5672, 5671:
		return "rabbitmq"
	case 9092, 9093:
		return "kafka"
	case 9200, 9300:
		return "elasticsearch"
	case 161, 162:
		return "snmp"
	// File Sharing / Windows Services
	case 135:
		return "msrpc"
	case 139:
		return "netbios"
	case 445:
		return "smb"
	// Infrastructure Services
	case 111:
		return "rpc"
	}
	return ""
}

func fingerprintParserModuleFactory() engine.Module {
	return newFingerprintParserModule()
}

func init() {
	engine.RegisterModuleFactory(fingerprintParserModuleName, fingerprintParserModuleFactory)
}
