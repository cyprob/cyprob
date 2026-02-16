package parse

import (
	"context"
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"github.com/vulntor/vulntor/pkg/engine"
	"github.com/vulntor/vulntor/pkg/modules/scan"
)

const (
	techTaggerModuleID          = "tech-tagger-instance"
	techTaggerModuleName        = "tech-tagger"
	techTaggerModuleDescription = "Enriches service profiles with technology tags using regex matches (from YAML) and fingerprint mapping."
	techTaggerModuleVersion     = "0.1.0"
	techTaggerModuleAuthor      = "Vulntor Team"
)

//go:embed tech_queries.yaml
var techQueriesYAML []byte

// TechTagResult represents the output of the tech-tagger module.
type TechTagResult struct {
	Target string   `json:"target"`
	Port   int      `json:"port"`
	Tags   []string `json:"tags"`
}

// TechRule defines the internal compiled rule structure.
type TechRule struct {
	Name  string
	Regex *regexp.Regexp
	Part  string // "header", "body", "all"
}

// TechRuleConfig defines the YAML structure for rules.
type TechRuleConfig struct {
	Name  string `yaml:"name"`
	Part  string `yaml:"part"`
	Regex string `yaml:"regex"`
}

type TechRulesConfig struct {
	Rules []TechRuleConfig `yaml:"rules"`
}

// Global variable to hold loaded rules (compiled once)
var (
	techRules     []TechRule
	techRulesOnce sync.Once
)

// Hardcoded mapping for Product -> Tags (Code-level mapping for high-confidence fingerprint results)
var productToTags = map[string][]string{
	"OpenSSH":                   {"ssh", "secure_shell", "protocol"},
	"Apache":                    {"http_server", "web_server", "apache"},
	"nginx":                     {"http_server", "web_server", "nginx", "reverse_proxy"},
	"MySQL":                     {"database", "sql", "mysql", "rdbms"},
	"PostgreSQL":                {"database", "sql", "postgresql", "rdbms"},
	"Redis":                     {"database", "nosql", "redis", "cache"},
	"MongoDB":                   {"database", "nosql", "mongodb", "document_store"},
	"Elasticsearch":             {"database", "nosql", "elasticsearch", "search_engine"},
	"RabbitMQ":                  {"message_broker", "rabbitmq", "amqp"},
	"Kafka":                     {"message_broker", "kafka", "streaming"},
	"Microsoft Exchange":        {TagExchange, TagMailService},
	"Microsoft Exchange Server": {TagExchange, TagMailService},
	"OWA":                       {TagOWA, TagWebmail, TagExchange, TagMailService},
	"SmarterMail":               {TagSmarterMail, TagWebmail, TagMailService},
	"Roundcube":                 {TagRoundcube, TagWebmail, TagMailService},
	"Zimbra":                    {TagZimbra, TagWebmail, TagMailService},
	"SOGo":                      {TagSOGo, TagWebmail, TagMailService},
	"RainLoop":                  {TagRainLoop, TagWebmail, TagMailService},
	"Postfix":                   {TagPostfix, TagSMTP, TagMailService},
	"Exim":                      {TagExim, TagSMTP, TagMailService},
	"Dovecot":                   {TagDovecot, TagIMAP, TagPOP3, TagMailService},
}

// TechTaggerModule implements the engine.Module interface.
type TechTaggerModule struct {
	meta engine.ModuleMetadata
}

func newTechTaggerModule() *TechTaggerModule {
	// Ensure rules are loaded once
	techRulesOnce.Do(func() {
		loadEmbeddedRules()
	})

	return &TechTaggerModule{
		meta: engine.ModuleMetadata{
			ID:          techTaggerModuleID,
			Name:        techTaggerModuleName,
			Description: techTaggerModuleDescription,
			Version:     techTaggerModuleVersion,
			Type:        engine.ParseModuleType,
			Author:      techTaggerModuleAuthor,
			Tags:        []string{"parser", "tagger", "enrichment"},
			Consumes: []engine.DataContractEntry{
				{Key: "service.fingerprint.details", DataTypeName: "parse.FingerprintParsedInfo", Cardinality: engine.CardinalityList, IsOptional: true},
				{Key: "service.http.details", DataTypeName: "parse.HTTPParsedInfo", Cardinality: engine.CardinalityList, IsOptional: true},
				{Key: "service.banner.tcp", DataTypeName: "scan.BannerGrabResult", Cardinality: engine.CardinalityList, IsOptional: true},
			},
			Produces: []engine.DataContractEntry{
				{Key: "service.tech.tags", DataTypeName: "parse.TechTagResult", Cardinality: engine.CardinalityList},
			},
		},
	}
}

func loadEmbeddedRules() {
	var config TechRulesConfig
	if err := yaml.Unmarshal(techQueriesYAML, &config); err != nil {
		log.Error().Err(err).Msg("Failed to parse embedded tech queries YAML")
		// Fallback to empty rules or panic? Logging error is safer.
		return
	}

	for _, r := range config.Rules {
		compiled, err := regexp.Compile(r.Regex)
		if err != nil {
			log.Warn().Str("rule", r.Name).Str("regex", r.Regex).Err(err).Msg("Invalid regex in tech rule, skipping")
			continue
		}
		techRules = append(techRules, TechRule{
			Name:  r.Name,
			Part:  r.Part,
			Regex: compiled,
		})
	}
	log.Info().Int("rule_count", len(techRules)).Msg("Loaded embedded tech detection rules")
}

func (m *TechTaggerModule) Metadata() engine.ModuleMetadata { return m.meta }

func (m *TechTaggerModule) Init(instanceID string, configMap map[string]any) error {
	m.meta.ID = instanceID
	return nil
}

func (m *TechTaggerModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- engine.ModuleOutput) error {
	logger := log.With().Str("module", m.meta.Name).Logger()
	// logger.Debug().Msg("Starting tech tagging execution")

	targets := make(map[string]map[int]*targetData)

	getData := func(target string, port int) *targetData {
		if targets[target] == nil {
			targets[target] = make(map[int]*targetData)
		}
		if targets[target][port] == nil {
			targets[target][port] = &targetData{Target: target, Port: port}
		}
		return targets[target][port]
	}

	m.ingestFingerprints(inputs, getData)
	m.ingestHTTP(inputs, getData)
	m.ingestBanners(inputs, getData)

	// Process all gathered data
	count := 0
	for _, ports := range targets {
		for _, data := range ports {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			tags := m.generateTags(data)
			if len(tags) > 0 {
				outputChan <- engine.ModuleOutput{
					FromModuleName: m.meta.ID,
					DataKey:        "service.tech.tags",
					Data:           TechTagResult{Target: data.Target, Port: data.Port, Tags: tags},
					Timestamp:      time.Now(),
					Target:         data.Target,
				}
				count++
			}
		}
	}

	if count > 0 {
		logger.Info().Int("tagged_services", count).Msg("Tech tagging completed successfully")
	} else {
		logger.Debug().Msg("Tech tagging completed (no tags generated)")
	}
	return nil
}

// ingestFingerprints processes FingerprintParsedInfo from inputs
func (m *TechTaggerModule) ingestFingerprints(inputs map[string]any, getData func(string, int) *targetData) {
	if raw, ok := inputs["service.fingerprint.details"]; ok {
		if list, ok := raw.([]any); ok {
			for _, item := range list {
				if fp, ok := item.(FingerprintParsedInfo); ok {
					d := getData(fp.Target, fp.Port)
					d.Product = fp.Product
					d.Version = fp.Version
				}
			}
		}
	}
}

// ingestHTTP processes HTTPParsedInfo from inputs
func (m *TechTaggerModule) ingestHTTP(inputs map[string]any, getData func(string, int) *targetData) {
	if raw, ok := inputs["service.http.details"]; ok {
		if list, ok := raw.([]any); ok {
			for _, item := range list {
				if httpInfo, ok := item.(HTTPParsedInfo); ok {
					d := getData(httpInfo.Target, httpInfo.Port)
					d.HTTPHeaders = httpInfo.Headers
					// If banner is empty from fingerprint/scan, usage this raw banner
					if d.Banner == "" {
						d.Banner = httpInfo.RawBanner
					}
				}
			}
		}
	}
}

// ingestBanners processes BannerGrabResult from inputs
func (m *TechTaggerModule) ingestBanners(inputs map[string]any, getData func(string, int) *targetData) {
	if raw, ok := inputs["service.banner.tcp"]; ok {
		if list, ok := raw.([]any); ok {
			for _, item := range list {
				if b, ok := item.(scan.BannerGrabResult); ok {
					d := getData(b.IP, b.Port)
					if d.Banner == "" {
						d.Banner = b.Banner
					}
				}
			}
		}
	}
}

type targetData struct {
	Target      string
	Port        int
	Product     string
	Version     string
	Banner      string
	HTTPHeaders map[string]string
}

func (m *TechTaggerModule) generateTags(data *targetData) []string {
	tagSet := make(map[string]struct{})
	addTag := func(raw string) {
		normalized, ok := NormalizeTechTag(raw)
		if !ok {
			return
		}
		tagSet[normalized] = struct{}{}
	}

	// 1. Map Product -> Tags (from high-confidence fingerprint)
	if tags, ok := findProductTags(data.Product); ok {
		for _, t := range tags {
			addTag(t)
		}
	}

	// Prepare content for regex rules
	headerDump := dumpHeaders(data.HTTPHeaders)

	// 2. Apply Rules (from loaded YAML)
	for _, rule := range techRules {
		match := false
		if rule.Part == "header" && headerDump != "" {
			if rule.Regex.MatchString(headerDump) {
				match = true
			}
		} else if (rule.Part == "body" || rule.Part == "all") && data.Banner != "" {
			if rule.Regex.MatchString(data.Banner) {
				match = true
			}
		}

		if match {
			addTag(rule.Name)
		}
	}

	var result []string
	for t := range tagSet {
		result = append(result, t)
	}
	result = NormalizeTechTags(result)
	sort.Strings(result)
	return result
}

func findProductTags(product string) ([]string, bool) {
	for key, tags := range productToTags {
		if strings.EqualFold(strings.TrimSpace(product), key) {
			return tags, true
		}
	}
	return nil, false
}

func dumpHeaders(h map[string]string) string {
	if len(h) == 0 {
		return ""
	}
	var sb strings.Builder
	for k, v := range h {
		sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
	}
	return sb.String()
}

func init() {
	engine.RegisterModuleFactory(techTaggerModuleName, func() engine.Module { return newTechTaggerModule() })
}
