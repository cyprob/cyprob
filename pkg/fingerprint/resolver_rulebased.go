// Package fingerprint provides a static, rule-based fingerprint resolver implementation.
package fingerprint

import (
	"context"
	"errors"
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
	portBonus float64
	telemetry *TelemetryWriter
}

// NewRuleBasedResolver initializes a resolver using fingerprint rules loaded from a YAML file.
func NewRuleBasedResolver(rules []StaticRule) *RuleBasedResolver {
	prepared := prepareRules(rules)
	return &RuleBasedResolver{
		rules:     prepared,
		portBonus: derivePortBonus(prepared),
		telemetry: nil,
	}
}

// fallbackPortBonus applies when the database holds fewer than two distinct
// strengths, so there is no gap to measure. It is small for the same reason the
// derived value is: with one strength in play there is nothing but ties to break.
const fallbackPortBonus = 0.005

// derivePortBonus sizes the port bonus from the vocabulary it is added to,
// rather than from a constant somebody chose once.
//
// The bonus exists to break a tie, not to cast a vote: two rules whose authors
// wrote different strengths must keep that order at every port. A constant
// cannot promise that, because it has no idea what the smallest deliberate step
// is -- and the constant this replaces was 0.05, one whole step of the scale the
// issue describes, which is why http.apache at 0.85 reached http.winrm at 0.90
// on port 80 (cyprob#237).
//
// Half the smallest gap is the largest value that cannot cross any boundary,
// even when only one of two rules is eligible.
//
// Measured on the shipped database while writing this: the vocabulary is not the
// four values the issue lists. It is nine -- 0.75, 0.82, 0.85, 0.88, 0.90, 0.92,
// 0.93, 0.94, 0.95 -- with a smallest gap of 0.01, so the derived bonus is
// 0.005. A fixed 0.02, which is what was first proposed here against the issue's
// four-value description, would already have been too large. That is the reason
// this is derived: the vocabulary had moved and the constant had not.
func derivePortBonus(rules []StaticRule) float64 {
	seen := make(map[float64]struct{}, len(rules))
	for _, rule := range rules {
		seen[rule.PatternStrength] = struct{}{}
	}
	if len(seen) < 2 {
		return fallbackPortBonus
	}

	strengths := make([]float64, 0, len(seen))
	for strength := range seen {
		strengths = append(strengths, strength)
	}
	sort.Float64s(strengths)

	smallestGap := strengths[len(strengths)-1] - strengths[0]
	for i := 1; i < len(strengths); i++ {
		if gap := strengths[i] - strengths[i-1]; gap < smallestGap {
			smallestGap = gap
		}
	}
	if smallestGap <= 0 {
		return fallbackPortBonus
	}
	return smallestGap / 2
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
// ErrNoRuleMatched is returned when nothing in the database recognized the
// banner. A new rule is what would fix that.
//
// ErrAllCandidatesBelowThreshold is returned when something did recognize it and
// was then removed by the confidence floor. That is a different problem with a
// different remedy -- the rule exists and its score was pushed under 0.50 -- and
// until cyprob#239 the two were the same error, so an operator seeing nothing
// could not tell which had happened, and neither could anyone counting how often
// it happens (cyprob#239).
var (
	ErrNoRuleMatched               = errors.New("no matching rule found")
	ErrAllCandidatesBelowThreshold = errors.New("every matching rule fell below the confidence threshold")
)

func (r *RuleBasedResolver) rankedCandidates(in Input) []ruleCandidate {
	candidates, _ := r.rankedCandidatesWithDropped(in)
	return candidates
}

// rankedCandidatesWithDropped also reports how many rules matched the banner and
// were then removed by the floor. The count is the difference between "no rule
// covers this" and "a rule covers it and we threw the answer away".
func (r *RuleBasedResolver) rankedCandidatesWithDropped(in Input) ([]ruleCandidate, int) {
	normalizedBanner := strings.ToLower(in.Banner)
	cands := make([]ruleCandidate, 0, 8)
	droppedByThreshold := 0

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
			portBonus = r.portBonus
		}
		// Base strength defaulted in prepareRules()
		base := rule.PatternStrength
		// Ranked on the unclamped score, reported on the clamped one.
		score := base - softPenalty + portBonus
		conf := calculateConfidence(base, softPenalty, portBonus)

		// Threshold filter
		if conf < 0.50 {
			droppedByThreshold++
			// Log low confidence rejection if telemetry is enabled
			if r.telemetry != nil && r.telemetry.IsEnabled() {
				_ = r.telemetry.WriteRejected("", in.Port, in.Protocol, "confidence_below_threshold", "static", rule.ID)
			}
			continue
		}
		cands = append(cands, ruleCandidate{rule: rule, version: version, score: score, confidence: conf})
	}

	sort.SliceStable(cands, func(i, j int) bool { return cands[i].score > cands[j].score })
	return cands, droppedByThreshold
}

func (r *RuleBasedResolver) Resolve(_ context.Context, in Input) (Result, error) {
	cands, droppedByThreshold := r.rankedCandidatesWithDropped(in)

	if len(cands) == 0 {
		// Log no match if telemetry is enabled
		if r.telemetry != nil && r.telemetry.IsEnabled() {
			_ = r.telemetry.WriteNoMatch("", in.Port, in.Protocol, "static")
		}
		if droppedByThreshold > 0 {
			return Result{}, fmt.Errorf("%w: %d rule(s) matched", ErrAllCandidatesBelowThreshold, droppedByThreshold)
		}
		return Result{}, ErrNoRuleMatched
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
