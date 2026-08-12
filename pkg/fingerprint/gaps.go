package fingerprint

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/cyprob/cyprob/pkg/stringutil"
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
	// Varying are the tokens dropped from the signature because they differed
	// between the hosts in this cluster. Usually that is the site's own naming,
	// but a model number present on a single host looks the same, so they are
	// reported rather than discarded.
	Varying []string
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
	gapMaxVarying   = 6
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

	report := GapReport{}

	// First pass: find what nothing recognizes, and record which hosts each
	// token of each signature appeared on.
	type unmatched struct {
		location   string
		host       string
		protocol   string
		signatures []gapSignature
	}
	found := make([]unmatched, 0, len(observations))
	tokenHosts := map[string]map[string]bool{}

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

		// The target comes from the corpus, and a corpus can arrive from a
		// customer, a partner or CI rather than from a local scan, so it is not
		// trusted any more than the banner is.
		host := stringutil.SanitizeUntrusted(obs.Target, 64)
		signatures := gapSignatures(obs.Banner)
		found = append(found, unmatched{
			location:   fmt.Sprintf("%s:%d", host, obs.Port),
			host:       host,
			protocol:   obs.Protocol,
			signatures: signatures,
		})
		for _, sig := range signatures {
			for _, token := range signatureTokens(sig.text) {
				key := sig.kind + "\x00" + token
				if tokenHosts[key] == nil {
					tokenHosts[key] = map[string]bool{}
				}
				tokenHosts[key][host] = true
			}
		}
	}

	// Second pass: group. A signature usually carries the site's own naming --
	// a hostname, a serial, a session id -- alongside the part that names the
	// product, and grouping on the whole string splits one device model into as
	// many clusters as there are copies of it. Tokens seen on a single host are
	// dropped, which is safe precisely because a token appearing once
	// distinguishes nothing.
	type cluster struct {
		kind      string
		signature string
		protocol  string
		count     int
		samples   []string
		varying   []string
	}
	clusters := map[string]*cluster{}

	for _, item := range found {
		// A banner can offer more than one anchor -- an IBM array names itself
		// in both its Server header and its page title -- and which one a rule
		// should use is a judgement the tool cannot make, so both are reported.
		for _, sig := range item.signatures {
			shared, dropped := sharedSignature(sig, tokenHosts)
			key := sig.kind + "\x00" + strings.ToLower(shared)
			existing, ok := clusters[key]
			if !ok {
				existing = &cluster{kind: sig.kind, signature: shared,
					protocol: knownProtocolOrEmpty(item.protocol)}
				clusters[key] = existing
			}
			existing.count++
			if len(existing.samples) < gapMaxSamples {
				existing.samples = append(existing.samples, item.location)
			}
			for _, token := range dropped {
				existing.varying = appendUniqueBounded(existing.varying, token, gapMaxVarying)
			}
		}
	}

	report.Gaps = make([]Gap, 0, len(clusters))
	for _, c := range clusters {
		sort.Strings(c.varying)
		report.Gaps = append(report.Gaps, Gap{
			Kind: c.kind, Signature: c.signature, Protocol: c.protocol,
			Count: c.count, Samples: c.samples, Varying: c.varying,
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

// signatureTokens splits a signature into the words a rule would anchor on.
func signatureTokens(signature string) []string {
	return strings.Fields(strings.ToLower(signature))
}

// sharedSignature drops the tokens that appeared on only one host, and returns
// what it dropped.
//
// Those are usually the site's own naming rather than the device's, and keeping
// them splits one model across as many clusters as there are copies of it. But
// a model number present on a single host is indistinguishable from a hostname
// by this measure -- measured on a real corpus, "IBM FlashSystem 5000" and
// "5300" lost exactly the number worth writing a rule for -- so what is dropped
// is reported rather than thrown away.
//
// The whole signature is kept when nothing in it is shared, since a genuinely
// unique banner has nothing to generalize.
func sharedSignature(sig gapSignature, tokenHosts map[string]map[string]bool) (shared string, dropped []string) {
	fields := strings.Fields(sig.text)
	kept := make([]string, 0, len(fields))
	for _, field := range fields {
		if len(tokenHosts[sig.kind+"\x00"+strings.ToLower(field)]) > 1 {
			kept = append(kept, field)
			continue
		}
		dropped = append(dropped, field)
	}
	if len(kept) == 0 {
		return sig.text, nil
	}
	return strings.Join(kept, " "), dropped
}

func appendUniqueBounded(values []string, value string, limit int) []string {
	if len(values) >= limit {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
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

// sanitizeGapText makes a captured banner safe to print and bounds it.
//
// A banner is text a scanned host chose to send, and it reaches the operator's
// terminal and any rule written from the report. The shared implementation
// removes the classes a hand-written control-character check misses -- the C1
// block, bidirectional overrides, zero-width characters -- and bounds by runes
// so a truncation cannot split a character.
func sanitizeGapText(value string) string {
	bounded := stringutil.SanitizeUntrusted(value, gapMaxSignature)
	if bounded != stringutil.SanitizeUntrusted(value, 0) {
		return bounded + "\u2026"
	}
	return bounded
}

// RuleStub renders a starting point for the rule that would close a gap.
//
// It is deliberately a starting point and not a finished rule. The vendor and
// product cannot be derived from a string nothing recognizes -- guessing them
// is the failure this tool exists to avoid -- and the captured signature
// routinely contains text belonging to the site rather than to the device.
func (g Gap) RuleStub() string {
	protocol := knownProtocolOrEmpty(g.Protocol)
	if protocol == "" {
		protocol = "tcp"
	}

	lines := []string{
		"- id: 'TODO.unique_id'",
		"  protocol: '" + protocol + "'",
		"  product: 'TODO'   # only what the device states about itself",
		"  vendor: 'TODO'    # the DEVICE vendor, not the vendor of the software",
		"                    # it runs: an nginx rule names F5, which is right for",
		"                    # nginx and wrong for every appliance serving it",
		"  cpe: 'TODO'       # required -- the loader rejects a rule without one,",
		"                    # and a rejected rule disables the whole file",
		"  match: " + yamlSingleQuoted(g.matchExpression()),
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

// matchExpression builds a pattern that matches the banner the signature came
// from.
//
// The signature has had its whitespace collapsed, so anchoring it literally
// would produce a rule that does not match its own banner: real banners wrap a
// title across lines and indent it. Whitespace in the signature therefore
// becomes a whitespace pattern rather than a literal space.
func (g Gap) matchExpression() string {
	parts := strings.Fields(strings.ToLower(g.Signature))
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}
	anchor := strings.Join(parts, `\s+`)

	switch g.Kind {
	case "server":
		return `server:\s*` + anchor
	case "title":
		return `<title>[^<]*` + anchor
	default:
		return anchor
	}
}

// yamlSingleQuoted quotes a value the way YAML requires, which means doubling
// any apostrophe. A banner containing one would otherwise end the scalar early
// and produce a file that does not parse.
func yamlSingleQuoted(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// gapKnownProtocols are the protocols a rule may declare. The value is embedded
// in generated YAML, and a corpus is not necessarily one this machine produced,
// so anything unrecognized is dropped rather than passed through.
var gapKnownProtocols = map[string]bool{
	"dns": true, "ftp": true, "http": true, "https": true, "imap": true,
	"kafka": true, "ldap": true, "mysql": true, "pop3": true, "rabbitmq": true,
	"rdp": true, "redis": true, "smb": true, "smtp": true, "snmp": true,
	"ssh": true, "tcp": true, "telnet": true, "udp": true, "vnc": true,
}

func knownProtocolOrEmpty(protocol string) string {
	normalized := strings.ToLower(strings.TrimSpace(protocol))
	if gapKnownProtocols[normalized] {
		return normalized
	}
	return ""
}
