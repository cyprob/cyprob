package fingerprint

import (
	"context"
	"strings"
	"testing"
)

// Guards against YAML regex escaping regressions for \s (and similar)
// whitespace patterns — against the actual shipped rule catalog, not a
// hand-built stand-in.
//
// A rule constructed in Go rather than loaded from
// pkg/fingerprint/data/fingerprint_db.yaml proves nothing about that file:
// a YAML single-quoted string does not process backslash escapes, so
// 'server:\s*nginx' stays a literal backslash-s in the parsed Match field,
// while an accidental 'server:\\s*nginx' produces a literal double
// backslash that the compiled regex reads as "a literal backslash,
// followed by the letter s" - matching nothing a real banner ever sends.
// Reproduced directly: injecting that exact double-escape into the shipped
// http.nginx rule breaks resolution ("no matching rule found" against
// "Server: nginx") while a test built the way this file originally was
// stayed green, because it never read the YAML it was meant to guard.
func TestRegexWhitespaceGuard_HTTPServerHeader(t *testing.T) {
	rules := loadBuiltinRules()
	if len(rules) == 0 {
		t.Fatal("loadBuiltinRules returned no rules - embedded catalog failed to parse")
	}
	r := NewRuleBasedResolver(rules)

	banners := []string{
		"Server: nginx",
		"Server:    nginx",
		"server: nginx",
	}
	for _, b := range banners {
		res, err := r.Resolve(context.Background(), Input{Protocol: "http", Banner: b, Port: 80})
		if err != nil {
			t.Fatalf("shipped http.nginx rule did not resolve banner %q: %v", b, err)
		}
		if res.Product != "nginx" {
			t.Fatalf("expected nginx for banner %q, got %+v", b, res)
		}
	}
}

// Database-wide form of the same guard: no shipped rule's parsed Match
// pattern should contain a literal double backslash. A single backslash
// before a regex metacharacter (\s, \d, \w, ...) is the only form that
// occurs in this catalog today - verified against every rule currently
// shipped, not just http.nginx - so a double backslash appearing here is
// itself the regression, whatever rule it lands on next.
func TestNoShippedRuleHasDoubleEscapedMatch(t *testing.T) {
	rules := loadBuiltinRules()
	if len(rules) == 0 {
		t.Fatal("loadBuiltinRules returned no rules - embedded catalog failed to parse")
	}
	for _, rule := range rules {
		if strings.Contains(rule.Match, `\\`) {
			t.Errorf("rule %q has a double-escaped match pattern %q - this is a literal backslash in the compiled regex, not a whitespace/metacharacter class, and will not match a real banner", rule.ID, rule.Match)
		}
	}
}
