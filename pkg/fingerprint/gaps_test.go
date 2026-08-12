package fingerprint

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// storwizeBanner is the response an IBM Storwize V3700 actually sent, captured
// from a live array. The array names itself twice: in the Server header and in
// the page title.
const storwizeBanner = "HTTP/1.1 200 OK\r\n" +
	"Content-Type: text/html;charset=UTF-8\r\n" +
	"Server: SVC GUI\r\n\r\n" +
	"<html><head><title>\n        LS_V3700 - Log in - \n        IBM Storwize V3700\n    </title></head>"

func gapRules() []StaticRule {
	return []StaticRule{
		{ID: "http.nginx", Protocol: "http", Product: "nginx", Vendor: "F5 Networks",
			Match: `server:\s*nginx`, PatternStrength: 0.9},
	}
}

func TestAnalyzeGaps_ReportsOnlyWhatNoRuleRecognizes(t *testing.T) {
	report := analyzeGapsWithRules([]Observation{
		{Target: "10.0.0.1", Port: 80, Protocol: "http", Banner: storwizeBanner},
		{Target: "10.0.0.2", Port: 80, Protocol: "http",
			Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"},
	}, gapRules())

	require.Equal(t, 2, report.Observations)
	require.Equal(t, 1, report.Unmatched, "the nginx banner is already recognized")

	for _, gap := range report.Gaps {
		require.NotContains(t, strings.ToLower(gap.Signature), "nginx",
			"a recognized banner must not be reported as a gap")
	}
}

// A device that names itself in two places is worth reporting under both, since
// which one a rule should anchor on is a judgement the tool cannot make.
func TestAnalyzeGaps_ReportsEveryAnchorABannerOffers(t *testing.T) {
	report := analyzeGapsWithRules([]Observation{
		{Target: "10.0.0.1", Port: 80, Protocol: "http", Banner: storwizeBanner},
	}, gapRules())

	kinds := map[string]string{}
	for _, gap := range report.Gaps {
		kinds[gap.Kind] = gap.Signature
	}
	require.Equal(t, "SVC GUI", kinds["server"])
	require.Contains(t, kinds["title"], "IBM Storwize V3700")
	require.Equal(t, 1, report.Unmatched, "one service, however many anchors it offers")
}

func TestAnalyzeGaps_GroupsAndRanksByFrequency(t *testing.T) {
	observations := []Observation{
		{Target: "10.0.0.1", Port: 80, Protocol: "http", Banner: storwizeBanner},
		{Target: "10.0.0.2", Port: 80, Protocol: "http", Banner: storwizeBanner},
		{Target: "10.0.0.3", Port: 80, Protocol: "http",
			Banner: "HTTP/1.1 401\r\nServer: cisco-IOS\r\n\r\n"},
	}
	report := analyzeGapsWithRules(observations, gapRules())

	require.Equal(t, 3, report.Unmatched)
	require.NotEmpty(t, report.Gaps)

	// Frequency decides the order; ties fall back to the signature so two runs
	// over the same corpus produce the same report and a diff means something.
	counts := make([]int, 0, len(report.Gaps))
	for _, gap := range report.Gaps {
		counts = append(counts, gap.Count)
	}
	require.IsNonIncreasing(t, counts, "the most frequent gap is reported first")
	require.Equal(t, 1, report.Gaps[len(report.Gaps)-1].Count, "the rarest comes last")

	byKind := map[string]Gap{}
	for _, gap := range report.Gaps {
		byKind[gap.Kind+"|"+gap.Signature] = gap
	}
	server := byKind["server|SVC GUI"]
	require.Equal(t, 2, server.Count, "the same array seen twice is one gap counted twice")
	require.Equal(t, []string{"10.0.0.1:80", "10.0.0.2:80"}, server.Samples,
		"a gap names where to go and confirm it")
}

// The banner is text a scanned host chose to send. It reaches an operator's
// terminal, so it must not be able to carry escape sequences there.
func TestAnalyzeGaps_SanitizesHostSuppliedText(t *testing.T) {
	report := analyzeGapsWithRules([]Observation{
		{Target: "10.0.0.1", Port: 80, Protocol: "http",
			Banner: "HTTP/1.1 200 OK\r\nServer: evil\x1b[31mred\x07\r\n\r\n"},
	}, gapRules())

	require.Len(t, report.Gaps, 1)
	require.NotContains(t, report.Gaps[0].Signature, "\x1b")
	require.NotContains(t, report.Gaps[0].Signature, "\x07")
}

func TestAnalyzeGaps_BoundsWhatAHostCanClaim(t *testing.T) {
	report := analyzeGapsWithRules([]Observation{
		{Target: "10.0.0.1", Port: 80, Protocol: "http",
			Banner: "HTTP/1.1 200 OK\r\nServer: " + strings.Repeat("A", 5000) + "\r\n\r\n"},
	}, gapRules())

	require.Len(t, report.Gaps, 1)
	require.LessOrEqual(t, len([]rune(report.Gaps[0].Signature)), gapMaxSignature+1,
		"a long banner is truncated rather than filling the report")
}

// Non-HTTP services carry their identity on the first line.
func TestAnalyzeGaps_FallsBackToTheFirstLine(t *testing.T) {
	report := analyzeGapsWithRules([]Observation{
		{Target: "10.0.0.1", Port: 21, Protocol: "ftp", Banner: "220 SomeAppliance FTP ready\r\n"},
	}, gapRules())

	require.Len(t, report.Gaps, 1)
	require.Equal(t, "banner", report.Gaps[0].Kind)
	require.Equal(t, "220 SomeAppliance FTP ready", report.Gaps[0].Signature)
}

func TestAnalyzeGaps_IgnoresServicesWithoutABanner(t *testing.T) {
	report := analyzeGapsWithRules([]Observation{
		{Target: "10.0.0.1", Port: 445, Protocol: "smb", Banner: ""},
		{Target: "10.0.0.2", Port: 139, Protocol: "smb", Banner: "   "},
	}, gapRules())

	require.Zero(t, report.Observations)
	require.Empty(t, report.Gaps)
}

func TestRuleStub_AnchorsOnTheRightPartAndEscapes(t *testing.T) {
	server := Gap{Kind: "server", Signature: "ntopng 5.7.230405 (x86_64)", Protocol: "http"}
	stub := server.RuleStub()
	require.Contains(t, stub, "protocol: 'http'")
	require.Contains(t, stub, `match: 'server:\s*ntopng\s+5\.7\.230405\s+\(x86_64\)'`,
		"metacharacters are escaped, and whitespace becomes a pattern so the "+
			"rule still matches a banner whose spacing the signature collapsed")

	title := Gap{Kind: "title", Signature: "LS_V3700 - Log in - IBM Storwize V3700", Protocol: "http"}
	require.Contains(t, title.RuleStub(), "<title>[^<]*")
	require.Contains(t, title.RuleStub(), "hostname",
		"a title stub must warn that it carries the site's own naming")
}

func TestRuleStub_DefaultsProtocolWhenUnknown(t *testing.T) {
	require.Contains(t, Gap{Kind: "banner", Signature: "x"}.RuleStub(), "protocol: 'tcp'")
}

// A stub that does not match the banner it was generated from is a dead rule,
// and nothing about the file it lands in would say so. The signature has had
// its whitespace collapsed, while the banner it came from wraps its title
// across lines and indents it, so anchoring the collapsed text literally was
// enough to break this.
func TestRuleStub_MatchesTheBannerItWasGeneratedFrom(t *testing.T) {
	report := analyzeGapsWithRules([]Observation{
		{Target: "10.0.0.1", Port: 443, Protocol: "http", Banner: storwizeBanner},
	}, gapRules())
	require.NotEmpty(t, report.Gaps)

	for _, gap := range report.Gaps {
		t.Run(gap.Kind, func(t *testing.T) {
			pattern := gap.matchExpression()
			compiled, err := regexp.Compile(pattern)
			require.NoError(t, err, "the generated pattern must compile")

			require.True(t, compiled.MatchString(strings.ToLower(storwizeBanner)),
				"generated %q does not match the banner it came from", pattern)
		})
	}
}

// The loader requires a CPE and rejects the whole file without one, so a stub
// that omits it silently disables every rule in the file it is pasted into.
func TestRuleStub_CarriesEveryFieldTheLoaderRequires(t *testing.T) {
	stub := Gap{Kind: "server", Signature: "SVC GUI", Protocol: "http"}.RuleStub()

	for _, required := range []string{"protocol:", "product:", "vendor:", "cpe:", "match:"} {
		require.Contains(t, stub, required)
	}
}

// A banner containing an apostrophe would end a single-quoted YAML scalar early
// and produce a file that does not parse.
func TestRuleStub_QuotesApostrophesForYAML(t *testing.T) {
	stub := Gap{Kind: "server", Signature: "Bob's Router", Protocol: "http"}.RuleStub()

	require.Contains(t, stub, "bob''s", "an apostrophe is doubled, not left to end the scalar")
	require.NotContains(t, stub, "match: 'server:\\s*bob's")
}

// The protocol is embedded in generated YAML and a corpus need not be one this
// machine produced, so an unrecognized value is dropped rather than passed on.
func TestRuleStub_RefusesAnUnknownProtocol(t *testing.T) {
	stub := Gap{Kind: "banner", Signature: "x", Protocol: "'; rm -rf /"}.RuleStub()
	require.Contains(t, stub, "protocol: 'tcp'")
}

// Frequency ranking is the whole value of the report, so a signature carrying
// the site's own naming splits one device model into as many clusters as there
// are copies of it and buries the thing worth writing a rule for.
func TestAnalyzeGaps_OneModelIsOneClusterAcrossManyHosts(t *testing.T) {
	const template = "HTTP/1.1 200 OK\r\nServer: SVC GUI\r\n\r\n" +
		"<html><head><title>\n    %s - Log in - \n    %s\n  </title></head>"

	observations := make([]Observation, 0, 8)
	for i, model := range []string{"IBM Storwize V3700", "IBM FlashSystem 5300"} {
		for copy := 0; copy < 4; copy++ {
			observations = append(observations, Observation{
				Target:   fmt.Sprintf("10.0.%d.%d", i, copy),
				Port:     443,
				Protocol: "http",
				// Each copy carries a different hostname, as a real estate does.
				Banner: fmt.Sprintf(template, fmt.Sprintf("SITE-%s-%02d", model[4:8], copy), model),
			})
		}
	}

	report := analyzeGapsWithRules(observations, gapRules())

	titles := map[string]int{}
	for _, gap := range report.Gaps {
		if gap.Kind == "title" {
			titles[gap.Signature] = gap.Count
		}
	}
	require.Len(t, titles, 2, "two models, two clusters — not one per host")

	for signature, count := range titles {
		require.Equal(t, 4, count, "every copy of a model lands in its cluster")
		require.NotContains(t, signature, "SITE-",
			"the site's own naming must not survive into the signature")
	}
}

// A banner with nothing in common with any other keeps its whole signature:
// dropping every token would leave nothing to write a rule from.
func TestAnalyzeGaps_AUniqueBannerKeepsItsSignature(t *testing.T) {
	report := analyzeGapsWithRules([]Observation{
		{Target: "10.0.0.1", Port: 80, Protocol: "http",
			Banner: "HTTP/1.1 200 OK\r\nServer: OneOfAKind/9.9\r\n\r\n"},
	}, gapRules())

	require.Len(t, report.Gaps, 1)
	require.Equal(t, "OneOfAKind/9.9", report.Gaps[0].Signature)
}

// Dropping tokens that appear on one host groups a model correctly, but a model
// number present on a single host is indistinguishable from a hostname by that
// measure. Measured on a real corpus, "IBM FlashSystem 5000" and "5300" lost
// exactly the number worth writing a rule for, so what is dropped is reported.
func TestAnalyzeGaps_ReportsWhatItDroppedFromTheSignature(t *testing.T) {
	const template = "HTTP/1.1 200 OK\r\nServer: SVC GUI\r\n\r\n<title>%s - Log in - IBM FlashSystem %s</title>"

	report := analyzeGapsWithRules([]Observation{
		{Target: "10.0.0.1", Port: 443, Protocol: "http", Banner: fmt.Sprintf(template, "SITE-A", "5000")},
		{Target: "10.0.0.2", Port: 443, Protocol: "http", Banner: fmt.Sprintf(template, "SITE-B", "5300")},
	}, gapRules())

	var title Gap
	for _, gap := range report.Gaps {
		if gap.Kind == "title" {
			title = gap
		}
	}
	require.Equal(t, 2, title.Count, "the two arrays group together")
	require.NotContains(t, title.Signature, "5000", "the differing token left the signature")
	require.Subset(t, title.Varying, []string{"5000", "5300"},
		"but it is reported, because it may be the model rather than a hostname")
}
