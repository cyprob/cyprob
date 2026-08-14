package fingerprint

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Greetings as the servers actually send them. An IMAP session opens with an
// untagged `*` line, and what follows it is the server's choice: RFC 3501
// suggests advertising CAPABILITY there, and some do, but Dovecot and Courier
// commonly answer with a plain OK and wait to be asked.
//
// That split is the whole point of imap.generic having two alternatives. The
// second one requires the word "capability"; the first exists to catch the
// servers that do not send it.
const (
	imapPlainGreetingBanner      = "* OK IMAP4rev1 Server ready\r\n"
	imapDovecotGreetingBanner    = "* OK Dovecot (Ubuntu) ready. IMAP4rev1\r\n"
	imapCapabilityGreetingBanner = "* OK [CAPABILITY IMAP4rev1 STARTTLS] Server ready\r\n"
)

// The regression this file exists for.
//
// The pattern was written in a single-quoted YAML scalar, which does not
// process escapes, but escaped as though it were double-quoted. The engine
// therefore compiled `\\*` — an escaped backslash followed by a quantifier —
// where `\*` was meant, and likewise `\\s` for `\s`. Both live in the FIRST
// alternative, so that entire branch could only match a banner containing a
// literal backslash, and no IMAP greeting does.
//
// The rule still matched through its second alternative, which is why nothing
// looked broken: servers that advertise CAPABILITY in the greeting were
// identified, and only the ones the first branch was written for were missed.
// A rule that half works is harder to notice than one that does not work.
func TestIMAPGeneric_PlainGreetingIsIdentified(t *testing.T) {
	result := requireResolved(t, imapPlainGreetingBanner, "imap", 143)

	require.Equal(t, "IMAP", result.Product,
		"the first alternative of imap.generic exists for greetings that do "+
			"not advertise CAPABILITY; if this fails it is matching nothing")
}

// A banner that names its server belongs to that server's rule, not to the
// generic one. Asserted because the fix widens what imap.generic can match, and
// a generic rule that starts winning against specific ones would trade a missed
// identification for a wrong one — the worse of the two.
//
// This is also the case that corrected the test rather than the code: it was
// first written expecting "IMAP" here, and the resolver was right.
func TestIMAPGeneric_DoesNotOutrankAServerThatNamesItself(t *testing.T) {
	result := requireResolved(t, imapDovecotGreetingBanner, "imap", 143)

	require.Equal(t, "Dovecot", result.Product,
		"the dovecot rule is more specific and must keep winning")
}

// The branch that was already working must keep working: the fix removes
// escaping from the first alternative and must not disturb the second.
func TestIMAPGeneric_CapabilityGreetingStillIdentified(t *testing.T) {
	result := requireResolved(t, imapCapabilityGreetingBanner, "imap", 993)

	require.Equal(t, "IMAP", result.Product)
}

// Asserted against the shipped pattern rather than through the resolver,
// because this is the defect itself: a pattern that cannot match what it
// describes. Going through Resolve would report the same failure, but not say
// which of the two alternatives died.
func TestIMAPGeneric_PatternIsNotDoubleEscaped(t *testing.T) {
	rule := ibmRule(t, "imap.generic")

	require.NotContains(t, rule.Match, `\\`,
		"a doubled backslash in a single-quoted YAML scalar reaches the regex "+
			"engine as a literal backslash, not as an escape")

	// The resolver lowercases the banner before matching, so the pattern is
	// written in lower case and compiled case-insensitively here to match that.
	re, err := regexp.Compile(`(?i)` + rule.Match)
	require.NoError(t, err)

	require.True(t, re.MatchString(strings.ToLower(imapPlainGreetingBanner)),
		"the first alternative must match an untagged OK greeting")
}

// The pattern is anchored on more than the untagged marker, so it must not
// claim every protocol that opens with `* OK`. This is what stops the fix from
// trading a dead branch for a greedy one.
func TestIMAPGeneric_DoesNotClaimUnrelatedGreetings(t *testing.T) {
	rule := ibmRule(t, "imap.generic")
	re, err := regexp.Compile(`(?i)` + rule.Match)
	require.NoError(t, err)

	for _, banner := range []string{
		"* OK server ready\r\n",                // untagged, but names no protocol
		"+OK POP3 server ready\r\n",            // POP3 greets with +OK
		"220 smtp.example.com ESMTP ready\r\n", // SMTP
	} {
		require.False(t, re.MatchString(strings.ToLower(banner)),
			"imap.generic must not match %q", banner)
	}
}

// Resolution has to survive the pipeline too, not just the pattern: a rule can
// match and still lose to the protocol hint gate.
func TestIMAPGeneric_ResolvesUnderBothHintAndFallback(t *testing.T) {
	for _, protocol := range []string{"", "imap"} {
		result, err := NewRuleBasedResolver(loadBuiltinRules()).
			Resolve(context.Background(), Input{
				Protocol: protocol,
				Banner:   imapPlainGreetingBanner,
				Port:     143,
			})
		require.NoError(t, err, "hint %q", protocol)
		require.Equal(t, "IMAP", result.Product, "hint %q", protocol)
	}
}
