// Package fingerprint provides a static, rule-based fingerprint resolver implementation.
package fingerprint

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// StaticRule defines a fingerprint rule loaded from fingerprint_db.yaml.
type StaticRule struct {
	ID                string `yaml:"id"`
	Protocol          string `yaml:"protocol"`
	Description       string `yaml:"description"`
	Product           string `yaml:"product"`
	Vendor            string `yaml:"vendor"`
	CPE               string `yaml:"cpe"`
	Match             string `yaml:"match"`              // regex or plain string
	VersionExtraction string `yaml:"version_extraction"` // regex with capturing group

	// Anti-patterns and exclusions
	ExcludePatterns     []string `yaml:"exclude_patterns"`
	SoftExcludePatterns []string `yaml:"soft_exclude_patterns"`

	// Confidence and scoring metadata
	PatternStrength float64 `yaml:"pattern_strength"`
	PortBonuses     []int   `yaml:"port_bonuses"`

	// Binary verification fields
	BinaryMinLength int      `yaml:"binary_min_length"`
	BinaryMagic     []string `yaml:"binary_magic"`

	// Compiled expressions (not serialized)
	matchRegex   *regexp.Regexp
	versionRegex *regexp.Regexp
	excludeRegex []*regexp.Regexp
	softExRegex  []*regexp.Regexp
}

// RuleBasedResolver uses a preloaded list of static rules to resolve banners into metadata.
type RuleBasedResolver struct {
	rules     []StaticRule
	telemetry *TelemetryWriter
}

// NewRuleBasedResolver initializes a resolver using fingerprint rules loaded from a YAML file.
func NewRuleBasedResolver(rules []StaticRule) *RuleBasedResolver {
	return &RuleBasedResolver{rules: prepareRules(rules), telemetry: nil}
}

// SetTelemetry configures telemetry writer for the resolver.
func (r *RuleBasedResolver) SetTelemetry(telemetry *TelemetryWriter) {
	r.telemetry = telemetry
}

// Resolve attempts to identify a fingerprint based on the provided FingerprintInput.
// It normalizes the input banner, iterates through the resolver's rules, and checks for a matching protocol and banner pattern.
// If a rule matches, it extracts the version (if available) using the rule's versionRegex, and returns a FingerprintResult
// populated with the rule's metadata and a high confidence score. If no rule matches, it returns an error.
//
// Phase 1: If in.Protocol is empty, "tcp", or "udp" (generic transport), this method will try ALL rules
// as a fallback mechanism. This enables detection on non-standard ports (e.g., MySQL on 3210, HTTP on 2096).
//
// Parameters:
//
//	ctx - The context for cancellation and deadlines.
//	in  - The FingerprintInput containing protocol and banner information.
//
// Returns:
//
//	Result - The result of the fingerprinting process, populated if a rule matches.
//	error             - An error if no matching rule is found.
//
// ruleCandidate is a rule that matched, with the score used to rank it and the
// confidence reported for it.
//
// The two are not the same number. Confidence is clamped to 1.0 because that is
// what the field means to a reader, but clamping before the comparison threw
// away the ordering: 8 of the shipped rules reach the ceiling once a port bonus
// applies, so within that band pattern_strength distinguished nothing and the
// winner was decided by the order the rules appear in the file.
//
//nolint:gocyclo // Telemetry logging adds complexity, refactor planned for later
type ruleCandidate struct {
	rule       StaticRule
	version    string
	score      float64
	confidence float64
}

// rankedCandidates returns every rule that matched, strongest first.
//
// Exposed to the package so a test can assert on the ranking itself rather than
// only on the winner. A test that checks the winner alone cannot tell a rule
// that won on merit from one that won because it is listed first.
func (r *RuleBasedResolver) rankedCandidates(in Input) []ruleCandidate {
	normalizedBanner := strings.ToLower(in.Banner)
	cands := make([]ruleCandidate, 0, 8)

	// Phase 1: Determine if we should try all rules (fallback mode)
	// Fallback activates when protocol hint is generic (tcp/udp) or unknown
	useFallback := in.Protocol == "" || in.Protocol == "tcp" || in.Protocol == "udp"

	for _, rule := range r.rules {
		// Phase 1: Skip protocol check if fallback mode is active
		if !useFallback && rule.Protocol != in.Protocol {
			continue // skip unrelated protocol (fast path)
		}
		if !rule.matchRegex.MatchString(normalizedBanner) {
			continue
		}
		// Hard exclude
		if isHardRejected(normalizedBanner, rule.excludeRegex) {
			// Log rejection if telemetry is enabled
			if r.telemetry != nil && r.telemetry.IsEnabled() {
				_ = r.telemetry.WriteRejected("", in.Port, in.Protocol, "hard_exclude_pattern", "static", rule.ID)
			}
			continue
		}
		// Version extraction (optional)
		version := ""
		if rule.versionRegex != nil {
			if m := rule.versionRegex.FindStringSubmatch(normalizedBanner); len(m) >= 2 {
				version = m[1]
			}
		}
		version = normalizeVersion(version)

		// Soft exclude penalties
		softPenalty := softExcludePenalty(normalizedBanner, rule.softExRegex, 0.20)
		// Port bonus
		portBonus := 0.0
		if in.Port > 0 && containsPort(rule.PortBonuses, in.Port) {
			portBonus = 0.05
		}
		// Base strength defaulted in prepareRules()
		base := rule.PatternStrength
		// Ranked on the unclamped score, reported on the clamped one.
		score := base - softPenalty + portBonus
		conf := calculateConfidence(base, softPenalty, portBonus)

		// Threshold filter
		if conf < 0.50 {
			// Log low confidence rejection if telemetry is enabled
			if r.telemetry != nil && r.telemetry.IsEnabled() {
				_ = r.telemetry.WriteRejected("", in.Port, in.Protocol, "confidence_below_threshold", "static", rule.ID)
			}
			continue
		}
		cands = append(cands, ruleCandidate{rule: rule, version: version, score: score, confidence: conf})
	}

	sort.SliceStable(cands, func(i, j int) bool { return cands[i].score > cands[j].score })
	return cands
}

func (r *RuleBasedResolver) Resolve(_ context.Context, in Input) (Result, error) {
	cands := r.rankedCandidates(in)

	if len(cands) == 0 {
		// Log no match if telemetry is enabled
		if r.telemetry != nil && r.telemetry.IsEnabled() {
			_ = r.telemetry.WriteNoMatch("", in.Port, in.Protocol, "static")
		}
		return Result{}, fmt.Errorf("no matching rule found")
	}
	best := cands[0]

	result := Result{
		Product:     best.rule.Product,
		Vendor:      best.rule.Vendor,
		Version:     best.version,
		CPE:         best.rule.CPE,
		Confidence:  best.confidence,
		Technique:   "static",
		Description: best.rule.Description,
	}

	// Log successful match if telemetry is enabled
	if r.telemetry != nil && r.telemetry.IsEnabled() {
		_ = r.telemetry.WriteSuccess("", in.Port, in.Protocol, result, "static", best.rule.ID)
	}

	return result, nil
}

func prepareRules(rules []StaticRule) []StaticRule {
	compiled := make([]StaticRule, 0, len(rules))
	for _, rule := range rules {
		copy := rule
		if copy.matchRegex == nil {
			copy.matchRegex = regexp.MustCompile(copy.Match)
		}
		if copy.versionRegex == nil && copy.VersionExtraction != "" {
			copy.versionRegex = regexp.MustCompile(copy.VersionExtraction)
		}
		// Defaults
		if copy.PatternStrength == 0 {
			copy.PatternStrength = 0.80
		}
		// Compile exclude patterns
		if len(copy.ExcludePatterns) > 0 && copy.excludeRegex == nil {
			for _, p := range copy.ExcludePatterns {
				copy.excludeRegex = append(copy.excludeRegex, regexp.MustCompile(p))
			}
		}
		if len(copy.SoftExcludePatterns) > 0 && copy.softExRegex == nil {
			for _, p := range copy.SoftExcludePatterns {
				copy.softExRegex = append(copy.softExRegex, regexp.MustCompile(p))
			}
		}
		compiled = append(compiled, copy)
	}
	return compiled
}
