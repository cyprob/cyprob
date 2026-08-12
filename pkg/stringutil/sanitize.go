package stringutil

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// SanitizeUntrusted makes text a scanned host chose to send safe to put in a
// report or on an operator's terminal, and bounds how much of it a host can
// claim.
//
// Anything not printable becomes a space rather than disappearing, so two
// tokens separated only by a stripped character do not run together into a
// third thing that was never sent. Runs of whitespace then collapse to one.
//
// unicode.IsPrint is an allowlist, which is what makes this safe to reason
// about: it excludes C0, DEL, the C1 block (U+0080-U+009F, whose members are
// single-byte equivalents of escape sequences that several terminals still
// act on), and the whole Cf category -- which is where the bidirectional
// overrides live (U+202E and friends, able to reverse how a line reads) along
// with the zero-width characters (U+200B, U+FEFF, the soft hyphen). A denylist
// of the control characters someone thought of at the time misses all three of
// those groups.
//
// The limit counts runes, not bytes: cutting a multi-byte character in half
// produces invalid UTF-8, which then travels wherever the report goes.
//
// Order matters and is deliberate: unsafe characters are removed BEFORE the
// text is cut, so a truncation can never leave the front half of an escape
// sequence behind.
func SanitizeUntrusted(value string, maxRunes int) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return ' '
		}
		return r
	}, value)

	cleaned = strings.TrimSpace(strings.Join(strings.Fields(cleaned), " "))
	if maxRunes <= 0 {
		return cleaned
	}

	runes := []rune(cleaned)
	if len(runes) <= maxRunes {
		return cleaned
	}
	return strings.TrimSpace(string(runes[:maxRunes]))
}
