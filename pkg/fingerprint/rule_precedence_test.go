package fingerprint

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// A tie between the winner and the runner-up is resolved by sort.SliceStable,
// which means by the order the rules appear in the YAML. That is not a decision
// anybody made, and it is invisible: the right answer still comes out, until
// somebody reorders the file or adds a rule above another one.
//
// This test turns "file order is saving us" into a build failure.
//
// It finds nothing today, and it is worth recording how hard that was looked
// for: 322 probes here (161 banners x 2 hints), and 11,130 in the review
// sweep (161 banners x 7 hints x 10 ports), producing 250 probes with more
// than one candidate and zero ties in either. The emptiness is structural
// rather than a sampling accident -- no shipped rule can exceed the ceiling,
// so a tie needs equal pattern_strength, equal bonus eligibility, and a banner
// matching both, and the corpus holds no such banner. One exists in reality:
// a page serving `Server: Jetty(9.4.z)` with an IBM Storwize title puts two
// rules at exactly 1.0000.
func TestRulePrecedence_NoTieDecidesAMatchInTheShippedCorpus(t *testing.T) {
	resolver := NewRuleBasedResolver(loadBuiltinRules())

	for _, sample := range loadValidationCorpus(t) {
		for _, protocol := range []string{sample.Protocol, ""} {
			candidates := resolver.rankedCandidates(Input{
				Protocol: protocol, Banner: sample.Banner, Port: sample.Port,
			})
			if len(candidates) < 2 {
				continue
			}

			winner, runnerUp := candidates[0], candidates[1]
			require.NotEqual(t, runnerUp.score, winner.score,
				"%q on port %d (hint %q) is decided by a tie between %s and %s at "+
					"score %.2f, which sort.SliceStable resolves by their order in "+
					"the YAML rather than by anything anybody decided",
				truncateForMessage(sample.Banner), sample.Port, protocol,
				winner.rule.ID, runnerUp.rule.ID, winner.score)
		}
	}
}

// The clamp belongs on the number reported to a reader, not on the comparison.
// Two rules whose strengths differ must keep differing after a port bonus that
// would push both past 1.0.
func TestRulePrecedence_TheCeilingDoesNotFlattenTheRanking(t *testing.T) {
	rules := []StaticRule{
		{ID: "specific", Protocol: "http", Product: "Specific", Vendor: "V",
			CPE: "cpe:2.3:a:v:specific:*:*:*:*:*:*:*:*", Match: `acme`,
			PatternStrength: 0.95, PortBonuses: []int{8080}},
		{ID: "generic", Protocol: "http", Product: "Generic", Vendor: "V",
			CPE: "cpe:2.3:a:v:generic:*:*:*:*:*:*:*:*", Match: `acme`,
			PatternStrength: 0.99, PortBonuses: []int{8080}},
	}
	// Listed with the weaker rule first, so file order cannot supply the answer.
	candidates := NewRuleBasedResolver(rules).
		rankedCandidates(Input{Protocol: "http", Banner: "acme", Port: 8080})

	require.Len(t, candidates, 2)
	require.Equal(t, "generic", candidates[0].rule.ID,
		"0.99 must outrank 0.95 even though both clamp to 1.0 when reported")
	require.Equal(t, 1.0, candidates[0].confidence, "the reported value is still clamped")
	require.Greater(t, candidates[0].score, candidates[1].score,
		"the ranking runs on the unclamped score")
}

// loadValidationCorpus reads the banners the repository already ships as its
// validation set, through the loader production uses rather than a second
// parser of the same file. The corpus grows without this test being edited.
func loadValidationCorpus(t *testing.T) []ValidationTestCase {
	t.Helper()

	dataset, err := LoadValidationDataset("testdata/validation_dataset.yaml")
	require.NoError(t, err)

	cases := make([]ValidationTestCase, 0,
		len(dataset.TruePositives)+len(dataset.TrueNegatives)+len(dataset.EdgeCases))
	cases = append(cases, dataset.TruePositives...)
	cases = append(cases, dataset.TrueNegatives...)
	cases = append(cases, dataset.EdgeCases...)
	require.NotEmpty(t, cases, "the validation corpus must not be empty")
	return cases
}

func truncateForMessage(banner string) string {
	const limit = 48
	if len(banner) <= limit {
		return banner
	}
	return fmt.Sprintf("%s...", banner[:limit])
}

// Resolve must answer with what the ranking says, or extracting the ranking
// bought nothing: a helper production has stopped calling is worse than never
// having extracted it, because the tests around it keep passing while the
// behavior they describe has moved elsewhere.
func TestRulePrecedence_ResolveAnswersWithTheTopRankedCandidate(t *testing.T) {
	resolver := NewRuleBasedResolver(loadBuiltinRules())
	checked := 0

	for _, sample := range loadValidationCorpus(t) {
		for _, protocol := range []string{sample.Protocol, ""} {
			input := Input{Protocol: protocol, Banner: sample.Banner, Port: sample.Port}

			ranked := resolver.rankedCandidates(input)
			result, err := resolver.Resolve(context.Background(), input)

			if len(ranked) == 0 {
				require.Error(t, err, "no candidate ranked, so nothing may be resolved")
				continue
			}
			require.NoError(t, err)
			require.Equal(t, ranked[0].rule.Product, result.Product,
				"Resolve disagreed with the ranking on %q", truncateForMessage(sample.Banner))
			require.Equal(t, ranked[0].rule.Vendor, result.Vendor)
			require.Equal(t, ranked[0].confidence, result.Confidence)
			checked++
		}
	}
	require.NotZero(t, checked, "the corpus must exercise at least one match")
}
