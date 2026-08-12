package fingerprint

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Observation is one service banner as a scan recorded it.
type Observation struct {
	Target   string
	Port     int
	Protocol string
	Banner   string
}

// Gap is a group of banners that no rule in the database recognizes, keyed by
// the distinctive line a rule would most likely anchor on.
type Gap struct {
	// Kind is where the signature was taken from: "server", "title" or "banner".
	Kind string
	// Signature is the distinctive text itself, sanitized and bounded.
	Signature string
	// Count is how many observations carried this signature.
	Count int
	// Protocol is the service the signature was observed on, which is what a
	// rule closing this gap has to declare.
	Protocol string
	// Samples are up to a few "ip:port" locations, so the finding can be
	// confirmed against a real host rather than trusted.
	Samples []string
}

// GapReport summarizes what a scan corpus saw and what went unrecognized.
type GapReport struct {
	// Observations is how many services carried a banner at all.
	Observations int
	// Unmatched is how many of those no rule recognized.
	Unmatched int
	// Gaps are the clusters, most frequent first.
	Gaps []Gap
}

var (
	// gapServerHeader captures the value of an HTTP Server header.
	gapServerHeader = regexp.MustCompile(`(?im)^server:[ \t]*(.+?)[ \t]*\r?$`)
	// gapHTMLTitle captures the contents of a title element.
	gapHTMLTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	// gapWhitespace collapses the runs that titles are usually formatted with.
	gapWhitespace = regexp.MustCompile(`\s+`)
)

const (
	gapMaxSignature = 120
	gapMaxSamples   = 3
)

// AnalyzeGaps reports which observed banners no rule recognizes.
//
// It exists because writing fingerprint rules from intuition guesses at what an
// estate contains. The banners a scan already captured say it outright, and the
// only question worth answering first is which unrecognized ones are frequent.
//
// Nothing is sent anywhere: this reads a corpus already on disk and returns a
// summary for a person to read.
func AnalyzeGaps(observations []Observation) GapReport {
	return analyzeGapsWithRules(observations, loadBuiltinRules())
}

func analyzeGapsWithRules(observations []Observation, rules []StaticRule) GapReport {
	resolver := NewRuleBasedResolver(rules)
	ctx := context.Background()

	type cluster struct {
		kind      string
		signature string
		protocol  string
		count     int
		samples   []string
	}
	clusters := map[string]*cluster{}

	report := GapReport{}
	for _, obs := range observations {
		if strings.TrimSpace(obs.Banner) == "" {
			continue
		}
		report.Observations++

		if _, err := resolver.Resolve(ctx, Input{
			Protocol: obs.Protocol,
			Banner:   obs.Banner,
			Port:     obs.Port,
		}); err == nil {
			continue
		}
		report.Unmatched++

		location := fmt.Sprintf("%s:%d", obs.Target, obs.Port)
		// A banner can offer more than one anchor — the Storwize array names
		// itself in both its Server header and its page title — and which one a
		// rule should use is a judgement call, so both are reported.
		for _, sig := range gapSignatures(obs.Banner) {
			key := sig.kind + "\x00" + strings.ToLower(sig.text)
			existing, ok := clusters[key]
			if !ok {
				existing = &cluster{kind: sig.kind, signature: sig.text, protocol: obs.Protocol}
				clusters[key] = existing
			}
			existing.count++
			if len(existing.samples) < gapMaxSamples {
				existing.samples = append(existing.samples, location)
			}
		}
	}

	report.Gaps = make([]Gap, 0, len(clusters))
	for _, c := range clusters {
		report.Gaps = append(report.Gaps, Gap{
			Kind: c.kind, Signature: c.signature, Protocol: c.protocol,
			Count: c.count, Samples: c.samples,
		})
	}
	// Most frequent first; ties broken by signature so the report is stable
	// across runs and a diff between two corpora means something.
	sort.SliceStable(report.Gaps, func(i, j int) bool {
		if report.Gaps[i].Count != report.Gaps[j].Count {
			return report.Gaps[i].Count > report.Gaps[j].Count
		}
		return report.Gaps[i].Signature < report.Gaps[j].Signature
	})
	return report
}

type gapSignature struct {
	kind string
	text string
}

// gapSignatures picks the lines a rule would most likely anchor on.
func gapSignatures(banner string) []gapSignature {
	signatures := make([]gapSignature, 0, 2)

	if m := gapServerHeader.FindStringSubmatch(banner); len(m) == 2 {
		if value := sanitizeGapText(m[1]); value != "" {
			signatures = append(signatures, gapSignature{kind: "server", text: value})
		}
	}
	if m := gapHTMLTitle.FindStringSubmatch(banner); len(m) == 2 {
		if value := sanitizeGapText(m[1]); value != "" {
			signatures = append(signatures, gapSignature{kind: "title", text: value})
		}
	}
	if len(signatures) > 0 {
		return signatures
	}

	// Nothing structured: fall back to the first line that says anything, which
	// is what a non-HTTP banner usually is.
	for _, line := range strings.Split(banner, "\n") {
		if value := sanitizeGapText(line); value != "" {
			return []gapSignature{{kind: "banner", text: value}}
		}
	}
	return nil
}

// sanitizeGapText strips control characters and bounds the length.
//
// A banner is text a scanned host chose to send. Printing it to a terminal
// unfiltered would let a host inject escape sequences into the operator's
// screen, so the same treatment the probes apply is applied here.
func sanitizeGapText(value string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	cleaned = strings.TrimSpace(gapWhitespace.ReplaceAllString(cleaned, " "))
	if len(cleaned) > gapMaxSignature {
		cleaned = strings.TrimSpace(cleaned[:gapMaxSignature]) + "…"
	}
	return cleaned
}

// RuleStub renders a starting point for the rule that would close a gap.
//
// It is deliberately a starting point and not a finished rule. The vendor and
// product cannot be derived from a string nothing recognizes — guessing them is
// the failure this tool exists to avoid — and the captured signature routinely
// contains text belonging to the site rather than to the device.
func (g Gap) RuleStub() string {
	anchor := regexp.QuoteMeta(strings.ToLower(g.Signature))
	match := anchor
	switch g.Kind {
	case "server":
		match = `server:\s*` + anchor
	case "title":
		match = `<title>[^<]*` + anchor
	}

	protocol := strings.TrimSpace(g.Protocol)
	if protocol == "" {
		protocol = "tcp"
	}

	lines := []string{
		"- id: 'TODO.unique_id'",
		"  protocol: '" + protocol + "'",
		"  product: 'TODO'   # only what the device states about itself",
		"  vendor: 'TODO'    # the DEVICE vendor, not the software's vendor",
		"  match: '" + match + "'",
		"  pattern_strength: 0.90",
	}
	if g.Kind == "title" {
		// A page title is usually "<hostname> - <page> - <Product>", and the
		// hostname is the operator's own naming. Left in, the rule matches one
		// customer's device and nobody else's.
		lines = append(lines,
			"  # Narrow the match to the part naming the PRODUCT: a page title",
			"  # normally carries the site's own hostname, which is not the device.")
	}
	return strings.Join(lines, "\n")
}
