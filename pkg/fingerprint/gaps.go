package fingerprint

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
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

// unmatchedObservation is one banner nothing recognized, with the anchors it
// offers.
type unmatchedObservation struct {
	location   string
	host       string
	protocol   string
	signatures []gapSignature
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
	// plainProtocolToken is what a rule's protocol may look like.
	plainProtocolToken = regexp.MustCompile(`^[a-z0-9_-]+$`)
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
	known := ruleProtocols(rules)
	ctx := context.Background()

	report := GapReport{}

	// First pass: find what nothing recognizes, and record which hosts each
	// token of each signature appeared on.
	found := make([]unmatchedObservation, 0, len(observations))
	tokenHosts := map[string]map[string]bool{}

	for _, obs := range observations {
		if strings.TrimSpace(obs.Banner) == "" {
			continue
		}
		report.Observations++

		protocol := resolvableProtocol(obs.Protocol, known)
		if _, err := resolver.Resolve(ctx, Input{
			Protocol: protocol,
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
		found = append(found, unmatchedObservation{
			location:   fmt.Sprintf("%s:%d", host, obs.Port),
			host:       host,
			protocol:   protocol,
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

	// Second pass: group.
	//
	// A signature usually carries the site's own naming beside the part that
	// names the product, and grouping on the whole string splits one model into
	// as many clusters as there are copies of it.
	//
	// Two signatures are treated as the same device when they agree everywhere
	// except ONE token position, and the values at that position each belong to
	// a single host. Requiring a single position is what keeps this honest:
	// dropping every token that happens to be unique merges unrelated devices
	// through whatever noise they share, and a corpus of one-off appliances is
	// mostly such tokens. Two differences mean two devices -- which is also why
	// "IBM FlashSystem 5000" and "5300" stay apart, since they differ in the
	// hostname AND the model.
	//
	// Comparison happens inside a bucket of the same kind, protocol and token
	// count, so a telnet banner and a postgres one are never candidates.
	type cluster struct {
		kind      string
		signature string
		protocol  string
		count     int
		samples   []string
		varying   []string
	}
	clusters := map[string]*cluster{}

	drops := chooseDroppedPositions(found)

	for index, item := range found {
		for sigIndex, sig := range item.signatures {
			// A missing entry means nothing qualified. Reading the zero value as
			// "drop position 0" silently truncated every signature that had no
			// merge to make.
			position, hasDrop := drops[dropKey{index, sigIndex}]
			if !hasDrop {
				position = -1
			}
			shared, dropped := applyDrop(sig, position)
			key := sig.kind + "\x00" + item.protocol +
				"\x00" + strings.ToLower(shared)
			existing, ok := clusters[key]
			if !ok {
				existing = &cluster{kind: sig.kind, signature: shared,
					protocol: item.protocol}
				clusters[key] = existing
			}
			existing.count++
			if len(existing.samples) < gapMaxSamples {
				existing.samples = append(existing.samples, item.location)
			}
			for _, token := range dropped {
				if !containsString(existing.varying, token) {
					existing.varying = append(existing.varying, token)
				}
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

// dropKey identifies one signature of one unmatched observation.
type dropKey struct{ observation, signature int }

// chooseDroppedPositions decides, for each signature, which token position (if
// any) is the site's own naming rather than the device's.
//
// A position qualifies when blanking it makes two or more signatures in the
// same bucket identical, and every value seen at that position belongs to a
// single host. When several positions qualify, the one merging the most
// signatures wins, and the earliest position breaks a tie so the result does
// not depend on map order.
func chooseDroppedPositions(found []unmatchedObservation) map[dropKey]int {
	type maskEntry struct {
		members []dropKey
		values  map[string]map[string]bool
	}
	masks := map[string]*maskEntry{}

	for index, item := range found {
		for sigIndex, sig := range item.signatures {
			tokens := strings.Fields(sig.text)
			bucket := sig.kind + "\x00" + item.protocol +
				"\x00" + strconv.Itoa(len(tokens))
			for position := range tokens {
				blanked := append([]string{}, tokens...)
				value := strings.ToLower(blanked[position])
				blanked[position] = "\x00"
				maskID := bucket + "\x00" + strconv.Itoa(position) + "\x00" +
					strings.ToLower(strings.Join(blanked, " "))

				entry, ok := masks[maskID]
				if !ok {
					entry = &maskEntry{values: map[string]map[string]bool{}}
					masks[maskID] = entry
				}
				entry.members = append(entry.members, dropKey{index, sigIndex})
				if entry.values[value] == nil {
					entry.values[value] = map[string]bool{}
				}
				entry.values[value][item.host] = true
			}
		}
	}

	best := map[dropKey]int{}
	bestSize := map[dropKey]int{}
	maskIDs := make([]string, 0, len(masks))
	for maskID := range masks {
		maskIDs = append(maskIDs, maskID)
	}
	sort.Strings(maskIDs)

	for _, maskID := range maskIDs {
		entry := masks[maskID]
		if len(entry.values) < 2 {
			continue // nothing varies here, so nothing is site-specific
		}
		siteSpecific := true
		for _, hosts := range entry.values {
			if len(hosts) > 1 {
				siteSpecific = false
				break
			}
		}
		if !siteSpecific {
			continue
		}
		position := maskPosition(maskID)
		for _, member := range entry.members {
			if size, seen := bestSize[member]; !seen || len(entry.members) > size ||
				(len(entry.members) == size && position < best[member]) {
				best[member] = position
				bestSize[member] = len(entry.members)
			}
		}
	}
	return best
}

func maskPosition(maskID string) int {
	parts := strings.Split(maskID, "\x00")
	if len(parts) < 4 {
		return 0
	}
	position, err := strconv.Atoi(parts[3])
	if err != nil {
		return 0
	}
	return position
}

// applyDrop removes the chosen position from a signature.
func applyDrop(sig gapSignature, position int) (shared string, dropped []string) {
	tokens := strings.Fields(sig.text)
	if position < 0 || position >= len(tokens) {
		return sig.text, nil
	}
	dropped = append(dropped, tokens[position])
	kept := append(append([]string{}, tokens[:position]...), tokens[position+1:]...)
	if len(kept) == 0 {
		return sig.text, nil
	}
	return strings.Join(kept, " "), dropped
}

func containsString(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}

// signatureTokens splits a signature into the words a rule would anchor on.
func signatureTokens(signature string) []string {
	return strings.Fields(strings.ToLower(signature))
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
	// Gap.Protocol is already the hint the resolver was given, so declaring it
	// puts the rule where production will look. When the hint was empty the
	// resolver was in fallback mode, and a rule is reachable there whatever it
	// declares -- but only there, which the stub says rather than hiding.
	// Gap.Protocol is produced by resolvableProtocol and so is already one of
	// the rule protocols, but RuleStub is exported and its output is pasted into
	// a YAML file: anything that is not a plain token is refused rather than
	// quoted, since a protocol is not free text and a corpus need not be one
	// this machine produced.
	protocol := g.Protocol
	if !plainProtocolToken.MatchString(protocol) {
		protocol = ""
	}
	fallbackOnly := protocol == ""
	if fallbackOnly {
		protocol = "tcp"
	}

	lines := []string{
		"- id: 'TODO.unique_id'",
		"  protocol: " + yamlSingleQuoted(protocol),
		"  product: 'TODO'   # only what the device states about itself",
		"  vendor: 'TODO'    # the DEVICE vendor, not the vendor of the software",
		"                    # it runs: an nginx rule names F5, which is right for",
		"                    # nginx and wrong for every appliance serving it",
		"  cpe: 'TODO'       # required -- the loader rejects a rule without one,",
		"                    # and a rejected rule disables the whole file",
		"  match: " + yamlSingleQuoted(g.matchExpression()),
		"  pattern_strength: 0.90",
	}
	if fallbackOnly {
		lines = append(lines,
			"  # This banner was resolved with no protocol hint, so the rule is",
			"  # reachable only in fallback mode. Name the protocol the service",
			"  # speaks if you know it, or the rule will be skipped wherever the",
			"  # scan does identify the service.")
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
	// The ellipsis is this tool's mark that the signature was cut, not something
	// the host sent. Anchoring it would produce a rule matching a character no
	// banner contains.
	signature := strings.TrimSuffix(g.Signature, "\u2026")

	parts := strings.Fields(strings.ToLower(signature))
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}
	// Whitespace in the signature stands for whatever separated the tokens in
	// the banner, and that is not necessarily a space: the sanitizer turns any
	// non-printable character into one, so a banner separated by a no-break
	// space, a zero-width space or a stray control byte would not match a plain
	// \\s. The class covers control, format and every Unicode space.
	anchor := strings.Join(parts, `[\s\p{Cc}\p{Cf}\p{Z}]+`)

	switch g.Kind {
	case "server":
		return `server:[\s\p{Cc}\p{Cf}\p{Z}]*` + anchor
	case "title":
		// The title element carries attributes often enough that a literal
		// <title> misses them.
		return `<title[^>]*>[^<]*` + anchor
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

// ruleProtocols is the set of protocols the rules actually key on, derived from
// the rules themselves rather than kept by hand: a list maintained separately
// drifts, and the drift is silent -- an unrecognized hint matches no rule at
// all instead of trying every one.
func ruleProtocols(rules []StaticRule) map[string]bool {
	known := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if protocol := strings.ToLower(strings.TrimSpace(rule.Protocol)); protocol != "" {
			known[protocol] = true
		}
	}
	return known
}

// resolvableProtocol keeps a hint only when some rule keys on it.
//
// The scan pipeline hands the resolver whatever the service was named, and a
// name no rule declares selects no rules at all -- the service then looks
// unrecognized when it was only mis-hinted. An empty hint puts the resolver in
// the mode that tries every rule, which is the honest answer when the name
// means nothing to the rules.
func resolvableProtocol(protocol string, known map[string]bool) string {
	normalized := strings.ToLower(strings.TrimSpace(protocol))
	if normalized == "" || normalized == "tcp" || normalized == "udp" {
		return ""
	}
	if known[normalized] {
		return normalized
	}
	return ""
}
