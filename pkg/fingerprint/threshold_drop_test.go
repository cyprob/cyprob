package fingerprint

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// cyprob#239: a rule could match a banner, be penalized below the 0.50 floor and
// vanish from the ranking with no record that it was ever a candidate. Downstream
// that is indistinguishable from a banner no rule covers — and the two need
// opposite remedies. One wants a rule written; the other has a rule already and
// its score was pushed under the floor.
//
// The issue is explicit that the numbers are not the defect: not the 0.20 charge,
// not the three patterns a drop needs, not the 0.50 floor. Only that their effect
// is invisible when it fires. Nothing below changes any of them.

func thresholdDropRules() []StaticRule {
	return []StaticRule{{
		ID: "http.dropme", Protocol: "http", Product: "DropMe", Vendor: "V",
		CPE: "cpe:2.3:a:v:dropme:*:*:*:*:*:*:*:*", Match: `acme-server`,
		PatternStrength: 0.85,
		// Three patterns at 0.20 each takes 0.85 to 0.25, under the floor.
		SoftExcludePatterns: []string{`forbidden`, `not found`, `bad gateway`},
	}}
}

func TestResolve_ADroppedCandidateIsNotAMissingRule(t *testing.T) {
	t.Parallel()

	resolver := NewRuleBasedResolver(thresholdDropRules())

	t.Run("a banner no rule covers", func(t *testing.T) {
		t.Parallel()
		_, err := resolver.Resolve(context.Background(), Input{
			Protocol: "http", Banner: "something else entirely", Port: 80,
		})
		require.ErrorIs(t, err, ErrNoRuleMatched)
		require.NotErrorIs(t, err, ErrAllCandidatesBelowThreshold,
			"nothing matched, so nothing was dropped")
	})

	t.Run("a banner a rule covers and the floor removed", func(t *testing.T) {
		t.Parallel()
		_, err := resolver.Resolve(context.Background(), Input{
			Protocol: "http",
			Banner:   "acme-server: forbidden, not found, bad gateway",
			Port:     80,
		})
		require.ErrorIs(t, err, ErrAllCandidatesBelowThreshold)
		require.NotErrorIs(t, err, ErrNoRuleMatched,
			"a rule matched; calling that a missing rule is the defect")
		require.Contains(t, err.Error(), "1 rule(s) matched",
			"the count is what says how much was thrown away")
	})

	// The hazard is real before the distinction is relied on: the same rule must
	// still identify the service when the penalties do not fire. Without this a
	// rule that never matched anything would satisfy both cases above.
	t.Run("and the same rule still answers when nothing penalizes it", func(t *testing.T) {
		t.Parallel()
		result, err := resolver.Resolve(context.Background(), Input{
			Protocol: "http", Banner: "acme-server ready", Port: 80,
		})
		require.NoError(t, err)
		require.Equal(t, "DropMe", result.Product)
	})
}

// The gap report is where an operator meets this, and it is the reason the
// distinction is worth carrying rather than only logging: the two causes are
// already counted together there, under a heading that says "no rule recognized".
func TestAnalyzeGaps_SeparatesADroppedCandidateFromAMissingRule(t *testing.T) {
	t.Parallel()

	report := analyzeGapsWithRules([]Observation{
		{Target: "192.0.2.1", Protocol: "http", Port: 80, Banner: "something else entirely"},
		{Target: "192.0.2.2", Protocol: "http", Port: 80, Banner: "acme-server: forbidden, not found, bad gateway"},
		{Target: "192.0.2.3", Protocol: "http", Port: 80, Banner: "acme-server ready"},
	}, thresholdDropRules())

	require.Equal(t, 3, report.Observations)
	require.Equal(t, 2, report.Unmatched, "the identified one is not a gap")
	require.Equal(t, 1, report.DroppedByThreshold,
		"one of the two has a rule already, and saying so is the whole point")
}

// The sentinel the issue asked for, in the shape it asked for: resolve every
// banner twice, penalties on and off, and report the ones that differ.
//
// It asserts nothing about the corpus today — measured at 0 differing — and that
// is the intended result rather than a weakness. What it does is fire loudly the
// first time an error page enters the dataset, which is exactly when the silent
// removal path would start costing identifications.
//
// The count of probes is asserted, because a sweep that ran zero comparisons
// would report zero differences and read as a pass.
func TestResolve_PenaltiesChangeNoAnswerInTheShippedCorpus(t *testing.T) {
	t.Parallel()

	withPenalties, withoutPenalties := softExcludeSentinelResolvers()

	compared, differing := 0, 0
	for _, sample := range loadValidationCorpus(t) {
		for _, protocol := range []string{sample.Protocol, ""} {
			in := Input{Protocol: protocol, Banner: sample.Banner, Port: sample.Port}
			compared++

			penalized, penalizedErr := withPenalties.Resolve(context.Background(), in)
			plain, plainErr := withoutPenalties.Resolve(context.Background(), in)

			if (penalizedErr == nil) != (plainErr == nil) || penalized.Product != plain.Product {
				differing++
				t.Errorf("%q on port %d (hint %q): penalties change the answer — "+
					"with %q (err %v), without %q (err %v)",
					truncateForMessage(sample.Banner), sample.Port, protocol,
					penalized.Product, penalizedErr, plain.Product, plainErr)
			}
		}
	}

	require.Positive(t, compared, "the sweep compared nothing, so zero differences means nothing")
	t.Logf("soft-exclude sentinel: %d probes compared, %d differing", compared, differing)
}

// The sentinel above compares two resolvers, and it reports zero differences if
// they are the same resolver — which is how a sweep says "penalties change
// nothing" while never having removed one. Two controls, both positive.
func TestResolve_TheSoftExcludeSentinelCanActuallyFire(t *testing.T) {
	t.Parallel()

	// Built through the same helper the sweep uses, so gutting that line is
	// caught here rather than leaving the sweep comparing a resolver with
	// itself and reporting no differences.
	withPenalties, withoutPenalties := softExcludeSentinelResolvers()

	shippedPatterns, strippedPatterns := 0, 0
	for _, rule := range withPenalties.rules {
		shippedPatterns += len(rule.SoftExcludePatterns)
	}
	for _, rule := range withoutPenalties.rules {
		strippedPatterns += len(rule.SoftExcludePatterns)
	}
	require.Positive(t, shippedPatterns,
		"the sweep's penalized side carries no soft-exclude patterns, so it varies nothing")
	require.Zero(t, strippedPatterns, "the sweep's unpenalized side still carries penalties")

	// And the two resolvers really do disagree where a penalty bites, so the
	// sweep's zero is a measurement rather than a property of its setup.
	penalized := NewRuleBasedResolver(thresholdDropRules())
	plain := NewRuleBasedResolver(rulesWithoutSoftExcludes(thresholdDropRules()))
	in := Input{Protocol: "http", Banner: "acme-server: forbidden, not found, bad gateway", Port: 80}

	_, penalizedErr := penalized.Resolve(context.Background(), in)
	plainResult, plainErr := plain.Resolve(context.Background(), in)

	require.ErrorIs(t, penalizedErr, ErrAllCandidatesBelowThreshold)
	require.NoError(t, plainErr, "without the penalties the same banner resolves")
	require.Equal(t, "DropMe", plainResult.Product)
}

// softExcludeSentinelResolvers builds the pair the sweep compares. It is a
// helper rather than two lines inside the sweep so that the control test can
// assert the pair really differs -- a sweep that resolves the same rules twice
// reports no differences and reads as a pass.
func softExcludeSentinelResolvers() (*RuleBasedResolver, *RuleBasedResolver) {
	shipped := loadBuiltinRules()
	return NewRuleBasedResolver(shipped), NewRuleBasedResolver(rulesWithoutSoftExcludes(shipped))
}

// rulesWithoutSoftExcludes is the same database with the penalties removed, so
// the sweep compares one variable rather than two.
func rulesWithoutSoftExcludes(rules []StaticRule) []StaticRule {
	out := make([]StaticRule, 0, len(rules))
	for _, rule := range rules {
		copied := rule
		copied.SoftExcludePatterns = nil
		copied.softExRegex = nil
		out = append(out, copied)
	}
	return out
}
