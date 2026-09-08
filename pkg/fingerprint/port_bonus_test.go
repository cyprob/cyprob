package fingerprint

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// cyprob#237: the port bonus was a constant 0.05, and the strengths it was added
// to are one step apart, so the bonus was a whole step of the scale. A rule
// written weaker than another outranked it wherever only the weaker one was
// eligible — the strength its author wrote had stopped expressing what they
// meant. The bonus is meant to break a tie, not to cast a vote.

// The property the issue asked to pin, and it holds for any bonus small enough
// rather than for one particular number. Checked over the shipped database
// without needing a banner: for every pair of rules whose authors wrote
// different strengths, the weaker one must not reach the stronger one at any
// port.
func TestPortBonus_ARuleNeverOutranksOneWrittenStronger(t *testing.T) {
	t.Parallel()

	resolver := NewRuleBasedResolver(loadBuiltinRules())
	bonus := resolver.portBonus

	compared := 0
	for i := range resolver.rules {
		for j := range resolver.rules {
			weak, strong := resolver.rules[i], resolver.rules[j]
			if weak.PatternStrength >= strong.PatternStrength {
				continue
			}
			compared++

			// The most generous case for the weaker rule: it is eligible for
			// the bonus at some port and the stronger one is not.
			require.Lessf(t, weak.PatternStrength+bonus, strong.PatternStrength,
				"%s (%.2f) reaches or passes %s (%.2f) once the port bonus of %.4f applies, "+
					"so the gap their authors wrote stops meaning anything",
				weak.ID, weak.PatternStrength, strong.ID, strong.PatternStrength, bonus)
		}
	}

	require.Positive(t, compared,
		"no pair of rules had different strengths, so this compared nothing")
	t.Logf("port bonus %.4f checked against %d ordered pairs", bonus, compared)
}

// The property above reads resolver.portBonus, which is the number the resolver
// holds rather than the number it scores with. Those are the same thing only
// while the call site uses the field -- and restoring the old constant at that
// one line left every assertion here green.
//
// So this one goes through the scoring path instead, on a vocabulary whose
// smallest step is a hundredth, like the shipped one. Only the weaker rule is
// eligible for the port bonus, which is the case cyprob#237 is about: the bonus
// applying to one side of a deliberate gap.
func TestPortBonus_TheScoringPathHonoursTheDerivedSize(t *testing.T) {
	t.Parallel()

	rules := []StaticRule{
		{ID: "weak-on-port", Protocol: "http", Product: "Weak", Vendor: "V",
			CPE: "cpe:2.3:a:v:weak:*:*:*:*:*:*:*:*", Match: `acme`,
			PatternStrength: 0.90, PortBonuses: []int{8080}},
		{ID: "strong-off-port", Protocol: "http", Product: "Strong", Vendor: "V",
			CPE: "cpe:2.3:a:v:strong:*:*:*:*:*:*:*:*", Match: `acme`,
			PatternStrength: 0.91},
		// A third strength so the derivation has a gap to measure and lands on
		// a hundredth, as it does against the shipped database.
		{ID: "unrelated", Protocol: "http", Product: "Other", Vendor: "V",
			CPE: "cpe:2.3:a:v:other:*:*:*:*:*:*:*:*", Match: `nothing-matches-this`,
			PatternStrength: 0.95},
	}

	resolver := NewRuleBasedResolver(rules)
	require.InDelta(t, 0.005, resolver.portBonus, 1e-9, "the fixture must reproduce the shipped step")

	candidates := resolver.rankedCandidates(Input{Protocol: "http", Banner: "acme", Port: 8080})
	require.Len(t, candidates, 2)
	require.Equal(t, "strong-off-port", candidates[0].rule.ID,
		"0.91 must still beat 0.90 when only the weaker one gets the port bonus; "+
			"a bonus of one whole step of the scale is what inverted this")
}

// The derivation itself, against the vocabulary it reads. Without this the
// property above is satisfied by a bonus of zero, which would also stop the
// bonus doing its job.
func TestDerivePortBonus_IsHalfTheSmallestDeliberateStep(t *testing.T) {
	t.Parallel()

	rules := prepareRules(loadBuiltinRules())
	seen := map[float64]struct{}{}
	for _, rule := range rules {
		seen[rule.PatternStrength] = struct{}{}
	}
	strengths := make([]float64, 0, len(seen))
	for strength := range seen {
		strengths = append(strengths, strength)
	}
	sort.Float64s(strengths)
	require.Greater(t, len(strengths), 1, "one strength means no gap to measure")

	smallest := strengths[len(strengths)-1] - strengths[0]
	for i := 1; i < len(strengths); i++ {
		if gap := strengths[i] - strengths[i-1]; gap < smallest {
			smallest = gap
		}
	}

	require.InDelta(t, smallest/2, derivePortBonus(rules), 1e-9)
	require.Positive(t, derivePortBonus(rules),
		"a bonus of zero satisfies every ordering property and breaks no ties")
	t.Logf("%d distinct strengths, smallest gap %.4f, bonus %.4f",
		len(strengths), smallest, derivePortBonus(rules))
}

// A vocabulary that grows a finer step must shrink the bonus by itself. This is
// the case a fixed number cannot survive, and the reason the value is derived:
// the shipped database already moved from the four strengths cyprob#237
// describes to nine, and a constant chosen against the old description would
// have been too large the day it was written.
func TestDerivePortBonus_FollowsTheVocabulary(t *testing.T) {
	t.Parallel()

	coarse := []StaticRule{
		{ID: "a", Match: `a`, PatternStrength: 0.80},
		{ID: "b", Match: `b`, PatternStrength: 0.90},
	}
	fine := append(append([]StaticRule(nil), coarse...),
		StaticRule{ID: "c", Match: `c`, PatternStrength: 0.81})

	require.InDelta(t, 0.05, derivePortBonus(prepareRules(coarse)), 1e-9)
	require.InDelta(t, 0.005, derivePortBonus(prepareRules(fine)), 1e-9,
		"adding one rule a hundredth above another must halve the step it can cross")
}

// One strength has no gap to measure, and the bonus must still be something a
// tie can be broken with rather than zero or a division by nothing.
func TestDerivePortBonus_HandlesAVocabularyWithNoGap(t *testing.T) {
	t.Parallel()

	single := prepareRules([]StaticRule{
		{ID: "a", Match: `a`, PatternStrength: 0.90},
		{ID: "b", Match: `b`, PatternStrength: 0.90},
	})
	require.InDelta(t, fallbackPortBonus, derivePortBonus(single), 1e-9)
	require.Positive(t, derivePortBonus(single))
}

// And the bonus still does its job: an eligible rule outranks an identical rule
// that is not eligible. A change that shrank the bonus to nothing would satisfy
// every ordering assertion above.
func TestPortBonus_StillBreaksATieBetweenEqualStrengths(t *testing.T) {
	t.Parallel()

	rules := []StaticRule{
		{ID: "no-port", Protocol: "http", Product: "NoPort", Vendor: "V",
			CPE: "cpe:2.3:a:v:noport:*:*:*:*:*:*:*:*", Match: `acme`, PatternStrength: 0.90},
		{ID: "on-port", Protocol: "http", Product: "OnPort", Vendor: "V",
			CPE: "cpe:2.3:a:v:onport:*:*:*:*:*:*:*:*", Match: `acme`, PatternStrength: 0.90,
			PortBonuses: []int{8080}},
	}

	candidates := NewRuleBasedResolver(rules).
		rankedCandidates(Input{Protocol: "http", Banner: "acme", Port: 8080})

	require.Len(t, candidates, 2)
	require.Equal(t, "on-port", candidates[0].rule.ID,
		"the port is the only thing separating them, so it must separate them")
	require.Greater(t, candidates[0].score, candidates[1].score)
}
