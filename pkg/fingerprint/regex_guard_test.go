package fingerprint

import (
	"context"
	"testing"
)

// Guard against YAML regex escaping regressions for \s whitespace.
func TestRegexWhitespaceGuard_HTTPServerHeader(t *testing.T) {
	rules := []StaticRule{{
		ID:              "test.http.nginx",
		Protocol:        "http",
		Product:         "nginx",
		Vendor:          "F5 Networks",
		Match:           "server:\\s*nginx",
		PatternStrength: 0.9,
	}}
	r := NewRuleBasedResolver(rules)

	banners := []string{
		"Server: nginx",
		"Server:    nginx",
		"server: nginx",
	}
	for _, b := range banners {
		res, err := r.Resolve(context.Background(), Input{Protocol: "http", Banner: b, Port: 80})
		if err != nil {
			t.Fatalf("unexpected error for banner %q: %v", b, err)
		}
		if res.Product != "nginx" {
			t.Fatalf("expected nginx for banner %q, got %+v", b, res)
		}
	}
}
