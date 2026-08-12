package stringutil

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

// Each of these classes reaches a terminal or a report when only the obvious
// control characters are removed, which is what a hand-written denylist does.
// They are written as escapes on purpose: several are invisible in an editor,
// which is the whole reason they are worth removing.
func TestSanitizeUntrusted_RemovesEveryNonPrintableClass(t *testing.T) {
	for _, tc := range []struct {
		name   string
		unsafe rune
	}{
		{"C0 escape", '\x1b'},
		{"DEL", '\x7f'},
		{"C1 CSI, a single-byte escape introducer", '\u009b'},
		{"C1 OSC", '\u009d'},
		{"C1 NEL", '\u0085'},
		{"bidi override, reverses how a line reads", '\u202e'},
		{"zero-width space", '\u200b'},
		{"zero-width joiner", '\u200d'},
		{"byte order mark", '\ufeff'},
		{"soft hyphen", '\u00ad'},
		{"line separator", '\u2028'},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeUntrusted("AB"+string(tc.unsafe)+"C", 0)

			// What has to go is the character itself. Anything it introduced is
			// ordinary text once the introducer is gone -- an escape sequence
			// without its ESC is just the letters that followed it.
			require.NotContains(t, got, string(tc.unsafe),
				"%U reached the output", tc.unsafe)
			require.Equal(t, "AB C", got, "and it leaves a separator behind")
			require.True(t, utf8.ValidString(got))
		})
	}
}

// A removed character must not let its neighbors join into a token nobody
// sent: "ngi<zero-width>nx" is not the word nginx, and a rule written from it
// would never match.
func TestSanitizeUntrusted_DoesNotFuseTokensAcrossARemovedCharacter(t *testing.T) {
	require.Equal(t, "ngi nx", SanitizeUntrusted("ngi\u200bnx", 0))
}

// Cutting by bytes splits a multi-byte character and produces invalid UTF-8,
// which then travels wherever the report goes.
func TestSanitizeUntrusted_BoundsByRunesAndStaysValidUTF8(t *testing.T) {
	got := SanitizeUntrusted(strings.Repeat("配", 200), 120)

	require.True(t, utf8.ValidString(got), "truncation must not split a character")
	require.Equal(t, 120, utf8.RuneCountInString(got), "the limit counts runes, not bytes")
	require.Less(t, len(got), 200*3, "and it did truncate")
}

// Unsafe characters go before the cut, so a truncation cannot leave the front
// half of an escape sequence behind.
func TestSanitizeUntrusted_StripsBeforeTruncating(t *testing.T) {
	got := SanitizeUntrusted("\x1b[31m"+strings.Repeat("A", 200), 10)

	require.NotContains(t, got, "\x1b")
	require.LessOrEqual(t, utf8.RuneCountInString(got), 10)
}

func TestSanitizeUntrusted_CollapsesWhitespaceAndTrims(t *testing.T) {
	require.Equal(t, "a b c", SanitizeUntrusted("  a\t\tb\n\n c  ", 0))
	require.Empty(t, SanitizeUntrusted(strings.Repeat("\x00", 40), 0))
}

func TestSanitizeUntrusted_ZeroLimitDoesNotTruncate(t *testing.T) {
	long := strings.Repeat("A", 500)
	require.Equal(t, long, SanitizeUntrusted(long, 0))
}
