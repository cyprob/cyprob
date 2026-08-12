package fingerprint

import (
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
	require.Contains(t, stub, `match: 'server:\s*ntopng 5\.7\.230405 \(x86_64\)'`,
		"regex metacharacters in a banner must be escaped, not interpreted")

	title := Gap{Kind: "title", Signature: "LS_V3700 - Log in - IBM Storwize V3700", Protocol: "http"}
	require.Contains(t, title.RuleStub(), "<title>[^<]*")
	require.Contains(t, title.RuleStub(), "hostname",
		"a title stub must warn that it carries the site's own naming")
}

func TestRuleStub_DefaultsProtocolWhenUnknown(t *testing.T) {
	require.Contains(t, Gap{Kind: "banner", Signature: "x"}.RuleStub(), "protocol: 'tcp'")
}
