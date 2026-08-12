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
	require.Contains(t, stub, `ntopng`+gapSeparatorClass+`+5\.7\.230405`,
		"metacharacters are escaped, and the separator is a class rather than "+
			"a literal space: the sanitizer replaces every unprintable character "+
			"with one, so the class has to be the complement of what it keeps")

	title := Gap{Kind: "title", Signature: "LS_V3700 - Log in - IBM Storwize V3700", Protocol: "http"}
	require.Contains(t, title.RuleStub(), "<title[^>]*>[^<]*",
		"a title element carries attributes often enough that a literal "+
			"<title> misses them")
	require.Contains(t, title.RuleStub(), "hostname",
		"a title stub must warn that it carries the site's own naming")
}

func TestRuleStub_DefaultsProtocolWhenUnknown(t *testing.T) {
	require.Contains(t, Gap{Kind: "banner", Signature: "x"}.RuleStub(), "protocol: 'tcp'")
}

// A stub that does not match the banner it was generated from is a dead rule,
// and nothing about the file it lands in would say so.
//
// The first version of this test fed ONE observation, which meant no position
// ever qualified as site naming and the merged shape -- the one where a token
// has been dropped from the signature -- was never exercised at all. It passed
// while the server-kind stub matched none of the banners in its own cluster.
// Every case here therefore supplies at least two hosts, and the generated
// pattern is required to match EVERY banner in the cluster it came from.
func TestRuleStub_MatchesEveryBannerInItsCluster(t *testing.T) {
	for _, tc := range []struct {
		name    string
		banners []string
	}{
		{"single observation, nothing dropped", []string{
			storwizeBanner,
		}},
		{"server kind, leading token differs", []string{
			"HTTP/1.1 200 OK\r\nServer: node01 Acme Array 9000\r\n\r\n",
			"HTTP/1.1 200 OK\r\nServer: node02 Acme Array 9000\r\n\r\n",
		}},
		{"title kind, leading token differs", []string{
			"HTTP/1.1 200 OK\r\nServer: X\r\n\r\n<title>node01 - Acme Array 9000</title>",
			"HTTP/1.1 200 OK\r\nServer: X\r\n\r\n<title>node02 - Acme Array 9000</title>",
		}},
		{"banner kind, leading token differs", []string{
			"node01 Acme FTP ready\r\n",
			"node02 Acme FTP ready\r\n",
		}},
		{"title wrapped across lines, as a real one is", []string{
			"HTTP/1.1 200 OK\r\nServer: SVC GUI\r\n\r\n<title>\n  ls_v3700 - Log in - \n  IBM Storwize V3700\n</title>",
			"HTTP/1.1 200 OK\r\nServer: SVC GUI\r\n\r\n<title>\n  ls_v3701 - Log in - \n  IBM Storwize V3700\n</title>",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observations := make([]Observation, 0, len(tc.banners))
			for i, banner := range tc.banners {
				observations = append(observations, Observation{
					Target: fmt.Sprintf("10.9.0.%d", i), Port: 80,
					Protocol: "http", Banner: banner,
				})
			}
			report := analyzeGapsWithRules(observations, gapRules())
			require.NotEmpty(t, report.Gaps)

			for _, gap := range report.Gaps {
				pattern := gap.matchExpression()
				compiled, err := regexp.Compile(pattern)
				require.NoError(t, err, "%s: the generated pattern must compile", gap.Kind)

				matched := 0
				for _, banner := range tc.banners {
					if compiled.MatchString(strings.ToLower(banner)) {
						matched++
					}
				}
				require.Equal(t, gap.Count, matched,
					"%s: generated %q matched %d of the %d banners in its cluster",
					gap.Kind, pattern, matched, gap.Count)
			}
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

// A token is dropped only when doing so merges signatures that agree
// everywhere else. Two arrays differing in BOTH the hostname and the model
// number differ in two positions, so they stay apart and keep their models --
// which is the case an earlier corpus-wide rule got wrong, collapsing
// "IBM FlashSystem 5000" and "5300" into one cluster with the numbers gone.
func TestAnalyzeGaps_TwoDifferencesMeanTwoDevices(t *testing.T) {
	const template = "HTTP/1.1 200 OK\r\nServer: SVC GUI\r\n\r\n<title>%s - Log in - IBM FlashSystem %s</title>"

	report := analyzeGapsWithRules([]Observation{
		{Target: "10.0.0.1", Port: 443, Protocol: "http", Banner: fmt.Sprintf(template, "SITE-A", "5000")},
		{Target: "10.0.0.2", Port: 443, Protocol: "http", Banner: fmt.Sprintf(template, "SITE-B", "5300")},
	}, gapRules())

	titles := map[string]Gap{}
	for _, gap := range report.Gaps {
		if gap.Kind == "title" {
			titles[gap.Signature] = gap
		}
	}
	require.Len(t, titles, 2, "different models are different devices")
	for signature := range titles {
		require.True(t,
			strings.Contains(signature, "5000") || strings.Contains(signature, "5300"),
			"the model number survives: %q", signature)
	}
}

// The same model across several hosts differs in one position, so it merges and
// the hostnames are reported rather than silently dropped.
func TestAnalyzeGaps_OneDifferenceMergesAndIsReported(t *testing.T) {
	const template = "HTTP/1.1 200 OK\r\nServer: SVC GUI\r\n\r\n<title>%s - Log in - IBM FlashSystem 5000</title>"

	observations := make([]Observation, 0, 3)
	for i, host := range []string{"SITE-A", "SITE-B", "SITE-C"} {
		observations = append(observations, Observation{
			Target: fmt.Sprintf("10.0.0.%d", i), Port: 443, Protocol: "http",
			Banner: fmt.Sprintf(template, host),
		})
	}

	report := analyzeGapsWithRules(observations, gapRules())

	var title Gap
	for _, gap := range report.Gaps {
		if gap.Kind == "title" {
			title = gap
		}
	}
	require.Equal(t, 3, title.Count, "one model, one cluster")
	require.Contains(t, title.Signature, "5000", "the model survives")
	require.NotContains(t, title.Signature, "SITE-", "the site naming does not")
	require.ElementsMatch(t, []string{"SITE-A", "SITE-B", "SITE-C"}, title.Varying,
		"every dropped token is reported, none silently cut")
}

// Unrelated devices must not merge through whatever noise they share. An
// earlier corpus-wide rule collapsed ten distinct appliances into clusters
// like "- Management" and produced a stub anchored on the word "ready".
func TestAnalyzeGaps_UnrelatedDevicesKeepTheirSignatures(t *testing.T) {
	titles := []string{
		"Vendor-A Box - Management",
		"Vendor-B Unit - Console",
		"Zeta 6000 Web Interface",
		"Omega 7000 Web Interface",
	}
	observations := make([]Observation, 0, len(titles))
	for i, title := range titles {
		observations = append(observations, Observation{
			Target: fmt.Sprintf("10.0.1.%d", i), Port: 443, Protocol: "http",
			Banner: fmt.Sprintf("HTTP/1.1 200 OK\r\nServer: Vendor%d/1.0\r\n\r\n<title>%s</title>", i, title),
		})
	}

	report := analyzeGapsWithRules(observations, gapRules())

	seen := map[string]bool{}
	for _, gap := range report.Gaps {
		if gap.Kind == "title" {
			seen[gap.Signature] = true
		}
	}
	for _, title := range titles {
		require.True(t, seen[title], "%q lost tokens to a merge that never happened", title)
	}
}

// A protocol is not free text, and RuleStub output is pasted into YAML.
func TestRuleStub_RefusesAProtocolThatIsNotAPlainToken(t *testing.T) {
	stub := Gap{Kind: "banner", Signature: "x", Protocol: "'; rm -rf /"}.RuleStub()
	require.Contains(t, stub, "protocol: 'tcp'")
	require.NotContains(t, stub, "rm -rf")
}

// The tool must ask the resolver the same question production asks, or its
// report is about a scanner nobody runs.
//
// An earlier version filtered the hint against the protocols the rules declare,
// which made the tool MORE generous than production: a service production
// cannot identify was resolved here in fallback mode and quietly left out of
// the report. That is the wrong direction for a gap report, and it also made
// the shared derivation dead code -- mutating it changed nothing. The filter is
// gone; the derivation is the only thing deciding the hint.
func TestAnalyzeGaps_UsesTheHintProductionWouldUse(t *testing.T) {
	// A service name no rule keys on is a real gap: production passes the same
	// name, matches nothing, and reports nothing about the host either.
	report := analyzeGapsWithRules([]Observation{
		{Target: "10.3.0.1", Port: 5672, Protocol: "rabbitmq",
			Banner: "AMQP\x00\x00\x09\x01"},
	}, gapRules())

	require.Equal(t, 1, report.Unmatched,
		"a service production cannot resolve must be reported, not resolved by a "+
			"more generous hint than production uses")
	require.NotEmpty(t, report.Gaps)
	require.Equal(t, "rabbitmq", report.Gaps[0].Protocol,
		"and the stub must declare the protocol production hands the resolver")
}

// A banner whose tokens are separated by something the sanitizer replaced must
// still be matched by the rule generated from it. The sanitizer turns every
// non-printable character into an ASCII space, and a plain \s cannot match what
// it replaced.
func TestRuleStub_MatchesBannersSeparatedByNonPrintableCharacters(t *testing.T) {
	for _, separator := range []string{
		"\u00a0", // no-break space (Z)
		"\u200b", // zero-width space (Cf)
		"\ufeff", // byte order mark (Cf)
		"\u00ad", // soft hyphen (Cf)
		"\u0085", // C1 NEL (Cc)
		"\u3000", // ideographic space (Z)
		"\x1b",   // escape (Cc)
		"\x00",   // NUL (Cc)
		// The sanitizer replaces everything unprintable, which is wider than
		// control and format characters. These are the classes a class built
		// from Cc+Cf+Z alone lets through, and they occur in binary banners and
		// in vendor strings carrying custom glyphs.
		"\ufffd",     // replacement character
		"\ue000",     // private use (Co)
		"\uf8ff",     // private use (Co)
		"\u0378",     // unassigned (Cn)
		"\u05ff",     // unassigned (Cn)
		"\xff",       // an invalid byte, which decodes to U+FFFD
	} {
		t.Run(fmt.Sprintf("%U", []rune(separator)[0]), func(t *testing.T) {
			banner := "HTTP/1.1 200 OK\r\nServer: Acme" + separator + "Array/1.0\r\n\r\n"
			report := analyzeGapsWithRules([]Observation{
				{Target: "10.0.0.1", Port: 80, Protocol: "http", Banner: banner},
			}, gapRules())
			require.NotEmpty(t, report.Gaps)

			pattern := report.Gaps[0].matchExpression()
			compiled, err := regexp.Compile(pattern)
			require.NoError(t, err)
			require.True(t, compiled.MatchString(strings.ToLower(banner)),
				"generated %q does not match the banner it came from", pattern)
		})
	}
}

// The ellipsis marks that this tool cut the signature; it is not something the
// host sent, and anchoring it produces a rule no banner can match.
func TestRuleStub_DoesNotAnchorOnTheTruncationMark(t *testing.T) {
	long := "HTTP/1.1 200 OK\r\nServer: " + strings.Repeat("Acme Array ", 30) + "\r\n\r\n"
	report := analyzeGapsWithRules([]Observation{
		{Target: "10.0.0.1", Port: 80, Protocol: "http", Banner: long},
	}, gapRules())
	require.NotEmpty(t, report.Gaps)

	pattern := report.Gaps[0].matchExpression()
	require.NotContains(t, pattern, "\u2026")
	compiled, err := regexp.Compile(pattern)
	require.NoError(t, err)
	require.True(t, compiled.MatchString(strings.ToLower(long)),
		"a truncated signature must still match the banner it came from")
}

// A single differing token cannot be classified from the text alone: "NODE-A"
// and "NODE-B" are hostnames, while "Router" and "Switch" in "Acme Router 1000"
// name two different products, and both are one token apart. The rule is
// therefore narrow, and narrow in the safe direction — refusing a merge splits
// one model across a few clusters, which is visible and recoverable, while
// accepting a wrong one hides two products behind a single line.
func TestAnalyzeGaps_DoesNotMergeTwoProductsThatDifferByOneWord(t *testing.T) {
	report := analyzeGapsWithRules([]Observation{
		{Target: "10.4.0.1", Port: 443, Protocol: "http",
			Banner: "HTTP/1.1 200 OK\r\nServer: AcmeOS\r\n\r\n<title>Acme Router 1000</title>"},
		{Target: "10.4.0.2", Port: 443, Protocol: "http",
			Banner: "HTTP/1.1 200 OK\r\nServer: AcmeOS\r\n\r\n<title>Acme Switch 1000</title>"},
	}, gapRules())

	titles := map[string]bool{}
	for _, gap := range report.Gaps {
		if gap.Kind == "title" {
			titles[gap.Signature] = true
		}
	}
	require.True(t, titles["Acme Router 1000"], "the router keeps its name")
	require.True(t, titles["Acme Switch 1000"], "and so does the switch")
	require.False(t, titles["Acme 1000"], "two products must not merge into one line")
}

func TestLooksLikeSiteNaming(t *testing.T) {
	hosts := func(values ...string) map[string]map[string]bool {
		out := map[string]map[string]bool{}
		for i, v := range values {
			out[v] = map[string]bool{fmt.Sprintf("10.0.0.%d", i): true}
		}
		return out
	}

	// Naming observed on real estates: digits, underscores, hyphens.
	require.True(t, looksLikeSiteNaming(0, hosts("ls_v3700", "lsv5030")))
	require.True(t, looksLikeSiteNaming(0, hosts("node-a", "node-b")))
	require.True(t, looksLikeSiteNaming(0, hosts("site-a", "site-b")))

	// Product vocabulary is plain words, and never dropped.
	require.False(t, looksLikeSiteNaming(0, hosts("router", "switch")))
	require.False(t, looksLikeSiteNaming(0, hosts("alpha", "beta")))

	// Only a leading token is treated as naming; every observed hostname is a
	// prefix, and a token inside a title is part of what the device calls itself.
	require.False(t, looksLikeSiteNaming(1, hosts("ls_v3700", "lsv5030")))
	require.False(t, looksLikeSiteNaming(2, hosts("5000", "5300")))
}
