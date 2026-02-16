package fingerprint

import (
	"context"
	"testing"
)

func TestPrepareRules_DefaultsAndCompilation(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "r1",
		Protocol:            "http",
		Match:               `server: myhttp`,
		VersionExtraction:   `myhttp/(\d+\.\d+\.\d+)`,
		ExcludePatterns:     []string{`nothttp`},
		SoftExcludePatterns: []string{`test build`},
		// PatternStrength intentionally zero to trigger defaulting
	}}

	out := prepareRules(rules)
	if len(out) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(out))
	}
	r := out[0]

	if r.PatternStrength < 0.79 || r.PatternStrength > 0.81 {
		t.Fatalf("expected default PatternStrength ~0.80, got %v", r.PatternStrength)
	}
	if r.matchRegex == nil {
		t.Fatalf("expected matchRegex compiled")
	}
	if r.versionRegex == nil {
		t.Fatalf("expected versionRegex compiled")
	}
	if len(r.excludeRegex) != 1 || len(r.softExRegex) != 1 {
		t.Fatalf("expected compiled exclude and soft-exclude regexes, got %d/%d", len(r.excludeRegex), len(r.softExRegex))
	}
}

func TestResolve_BackwardCompatibility(t *testing.T) {
	// Ensure existing behavior still works with new fields present but unused
	rules := []StaticRule{{
		ID:                "r1",
		Protocol:          "http",
		Product:           "MyHTTP",
		Vendor:            "Acme",
		CPE:               "cpe:/a:acme:myhttp",
		Match:             `server: myhttp`,
		VersionExtraction: `myhttp/(\d+\.\d+\.\d+)`,
		// New fields left empty to avoid affecting current Resolve()
	}}
	rb := NewRuleBasedResolver(rules)

	res, err := rb.Resolve(context.TODO(), Input{Protocol: "http", Banner: "Server: MyHTTP myhttp/1.2.3"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Product != "MyHTTP" || res.Vendor != "Acme" || res.Version != "1.2.3" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.Confidence <= 0.5 || res.Confidence > 1.0 {
		t.Fatalf("expected confidence in (0.5,1], got %v", res.Confidence)
	}
}

func TestResolve_WinRMRequiresAdditionalEvidence(t *testing.T) {
	rules := []StaticRule{{
		ID:       "http.winrm",
		Protocol: "http",
		Product:  "WinRM",
		Vendor:   "Microsoft",
		CPE:      "cpe:2.3:a:microsoft:winrm:*:*:*:*:*:*:*:*",
		Match:    `(?s)(?:microsoft-httpapi/2\.0.*(?:wsman|application/soap\+xml|www-authenticate:\s*negotiate)|(?:wsman|application/soap\+xml|www-authenticate:\s*negotiate).*microsoft-httpapi/2\.0)`,
	}}
	rb := NewRuleBasedResolver(rules)

	_, err := rb.Resolve(context.TODO(), Input{
		Protocol: "http",
		Banner:   "HTTP/1.1 400 Bad Request\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n",
		Port:     80,
	})
	if err == nil {
		t.Fatalf("expected no match without wsman/soap/auth evidence")
	}

	res, err := rb.Resolve(context.TODO(), Input{
		Protocol: "http",
		Banner:   "HTTP/1.1 401 Unauthorized\r\nServer: Microsoft-HTTPAPI/2.0\r\nWWW-Authenticate: Negotiate\r\n\r\n",
		Port:     5985,
	})
	if err != nil {
		t.Fatalf("expected match with auth evidence, got %v", err)
	}
	if res.Product != "WinRM" {
		t.Fatalf("expected WinRM, got %s", res.Product)
	}
}

func TestResolve_MultiPhaseSelectionAndPenalties(t *testing.T) {
	rules := []StaticRule{
		{
			ID:                "a",
			Protocol:          "http",
			Product:           "SvcA",
			Vendor:            "V",
			CPE:               "cpe:/a:v:svca",
			Match:             `server: svc`,
			VersionExtraction: `svc/(\d+\.\d+)`,
			PatternStrength:   0.80,
			// soft exclude matches will penalize this candidate
			SoftExcludePatterns: []string{`beta`},
		},
		{
			ID:                "b",
			Protocol:          "http",
			Product:           "SvcB",
			Vendor:            "V",
			CPE:               "cpe:/a:v:svcb",
			Match:             `server: svc`,
			VersionExtraction: `svc/(\d+\.\d+)`,
			PatternStrength:   0.75,
			// no soft excludes
			PortBonuses: []int{8080},
		},
	}
	rb := NewRuleBasedResolver(rules)

	// Banner matches both; includes "beta" to penalize A. Port 8080 gives B a small bonus.
	res, err := rb.Resolve(context.TODO(), Input{Protocol: "http", Banner: "Server: SVC svc/1.0 beta", Port: 8080})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Product != "SvcB" {
		t.Fatalf("expected SvcB to win after penalties/bonuses, got %s", res.Product)
	}
	if res.Confidence < 0.5 || res.Confidence > 1.0 {
		t.Fatalf("confidence out of expected range: %v", res.Confidence)
	}
}

func TestResolve_ThresholdFiltersLowConfidence(t *testing.T) {
	rules := []StaticRule{{
		ID:              "low",
		Protocol:        "http",
		Product:         "Low",
		Vendor:          "V",
		CPE:             "cpe:/a:v:low",
		Match:           `server: low`,
		PatternStrength: 0.40, // below threshold after defaulting
	}}
	rb := NewRuleBasedResolver(rules)
	_, err := rb.Resolve(context.TODO(), Input{Protocol: "http", Banner: "server: low"})
	if err == nil {
		t.Fatalf("expected error due to threshold filtering")
	}
}

func TestResolve_SkipsDifferentProtocolAndNonMatchingAndHardExclude(t *testing.T) {
	rules := []StaticRule{
		{ // different protocol should be skipped
			ID:       "ftp",
			Protocol: "ftp",
			Product:  "FTPd",
			Vendor:   "V",
			CPE:      "cpe:/a:v:ftpd",
			Match:    `^220`,
		},
		{ // matches pattern but hard-exclude knocks it out
			ID:              "hx",
			Protocol:        "http",
			Product:         "BadSvc",
			Vendor:          "V",
			CPE:             "cpe:/a:v:bad",
			Match:           `server: bad`,
			ExcludePatterns: []string{`blockme`},
			PatternStrength: 0.90,
		},
		{ // proper candidate that should win
			ID:              "ok",
			Protocol:        "http",
			Product:         "GoodSvc",
			Vendor:          "V",
			CPE:             "cpe:/a:v:good",
			Match:           `server: good`,
			PatternStrength: 0.80,
		},
	}
	rb := NewRuleBasedResolver(rules)

	// Banner triggers: FTP rule is different protocol (skip),
	// second rule matches but contains hard-exclude token, third matches and should be selected.
	banner := "Server: GOOD\nserver: bad blockme" // includes both patterns; hard exclude applies only to bad
	res, err := rb.Resolve(context.TODO(), Input{Protocol: "http", Banner: banner})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Product != "GoodSvc" {
		t.Fatalf("expected GoodSvc to be selected, got %s", res.Product)
	}
}

func TestResolve_RegexNonMatchingBranchIsTaken(t *testing.T) {
	rules := []StaticRule{
		{
			ID:              "nonmatch",
			Protocol:        "http",
			Product:         "Never",
			Vendor:          "V",
			CPE:             "cpe:/a:v:never",
			Match:           `^zzz`, // won't match banner
			PatternStrength: 0.90,
		},
		{
			ID:              "winner",
			Protocol:        "http",
			Product:         "Winner",
			Vendor:          "V",
			CPE:             "cpe:/a:v:winner",
			Match:           `server: ok`,
			PatternStrength: 0.80,
		},
	}
	rb := NewRuleBasedResolver(rules)
	res, err := rb.Resolve(context.TODO(), Input{Protocol: "http", Banner: "server: ok"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Product != "Winner" {
		t.Fatalf("expected Winner, got %s", res.Product)
	}
}

func TestPrepareRules_EmptyAndNoVersionRegex(t *testing.T) {
	rules := []StaticRule{{
		ID:       "r2",
		Protocol: "ssh",
		Match:    `^ssh-2.0-`,
		// no VersionExtraction
	}}
	out := prepareRules(rules)
	if len(out) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(out))
	}
	if out[0].versionRegex != nil {
		t.Fatalf("expected nil versionRegex when VersionExtraction is empty")
	}
	if out[0].matchRegex == nil {
		t.Fatalf("expected matchRegex compiled")
	}
}

func TestResolve_HTTPFalsePositivePrevention(t *testing.T) {
	// Simulate two protocols with overlapping text; ensure protocol filter prevents FP
	rules := []StaticRule{
		{ID: "mysql", Protocol: "mysql", Product: "MySQL", Vendor: "Oracle", CPE: "cpe:/a:oracle:mysql", Match: `^handshake mysql`, PatternStrength: 0.9},
		{ID: "http", Protocol: "http", Product: "HTTPd", Vendor: "Generic", CPE: "cpe:/a:generic:httpd", Match: `server:`, PatternStrength: 0.8},
	}
	rb := NewRuleBasedResolver(rules)

	// Banner looks like HTTP; with Protocol=mysql resolver must not return HTTP
	if _, err := rb.Resolve(context.TODO(), Input{Protocol: "mysql", Banner: "Server: Apache"}); err == nil {
		t.Fatalf("expected no match for protocol=mysql with HTTP-like banner")
	}

	// With Protocol=http, match should succeed
	res, err := rb.Resolve(context.TODO(), Input{Protocol: "http", Banner: "server: nginx"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Product != "HTTPd" {
		t.Fatalf("expected HTTPd, got %s", res.Product)
	}
}

func TestResolve_BinaryVerificationHints(t *testing.T) {
	// Use BinaryMinLength and BinaryMagic as hints; current resolver doesn't hard-check
	// but ensure rules compile and still match text banners correctly.
	rules := []StaticRule{
		{ID: "redis", Protocol: "redis", Product: "Redis", Vendor: "Redis", CPE: "cpe:/a:redislabs:redis", Match: `^\+ok|^-err|^\$`, PatternStrength: 0.85, BinaryMinLength: 0, BinaryMagic: []string{"\x2a\x31"}},
	}
	rb := NewRuleBasedResolver(rules)
	// A simple Redis-like banner
	_, err := rb.Resolve(context.TODO(), Input{Protocol: "redis", Banner: "+ok"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolve_PrefersHigherConfidenceWithBonusesAndPenalties(t *testing.T) {
	rules := []StaticRule{
		{
			ID:                  "high-base-with-penalty",
			Protocol:            "http",
			Product:             "SvcHigh",
			Vendor:              "V",
			CPE:                 "cpe:/a:v:svchigh",
			Match:               `server: svcx`,
			VersionExtraction:   `svcx/(\d+\.\d+)`,
			PatternStrength:     0.90,
			SoftExcludePatterns: []string{`beta`}, // will penalize
		},
		{
			ID:                "lower-base-with-bonus",
			Protocol:          "http",
			Product:           "SvcLow",
			Vendor:            "V",
			CPE:               "cpe:/a:v:svclow",
			Match:             `server: svcx`,
			VersionExtraction: `svcx/(\d+\.\d+)`,
			PatternStrength:   0.80,
			PortBonuses:       []int{8080},
		},
	}
	rb := NewRuleBasedResolver(rules)
	// Banner matches both; contains "beta" penalizing SvcHigh; port bonus helps SvcLow.
	res, err := rb.Resolve(context.TODO(), Input{Protocol: "http", Banner: "Server: SVCX svcx/2.1 beta", Port: 8080})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Product != "SvcLow" {
		t.Fatalf("expected SvcLow to win after penalties/bonuses, got %s", res.Product)
	}
	if res.Version != "2.1" {
		t.Fatalf("expected version 2.1, got %s", res.Version)
	}
}

func TestResolve_HardExcludeBeatsPatternMatch(t *testing.T) {
	rules := []StaticRule{
		{
			ID:              "bad",
			Protocol:        "http",
			Product:         "Bad",
			Vendor:          "V",
			CPE:             "cpe:/a:v:bad",
			Match:           `server: bad`,
			ExcludePatterns: []string{`block`},
			PatternStrength: 0.95,
		},
		{
			ID:              "good",
			Protocol:        "http",
			Product:         "Good",
			Vendor:          "V",
			CPE:             "cpe:/a:v:good",
			Match:           `server: good`,
			PatternStrength: 0.60,
		},
	}
	rb := NewRuleBasedResolver(rules)
	// Contains both patterns; hard exclude should eliminate "bad" despite higher base strength.
	banner := "server: bad block\nserver: good"
	res, err := rb.Resolve(context.TODO(), Input{Protocol: "http", Banner: banner})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Product != "Good" {
		t.Fatalf("expected Good due to hard-exclude on Bad, got %s", res.Product)
	}
}

func TestResolve_ReturnsErrorWhenNoCandidatesPassThreshold(t *testing.T) {
	rules := []StaticRule{{
		ID:              "weak",
		Protocol:        "http",
		Product:         "Weak",
		Vendor:          "V",
		CPE:             "cpe:/a:v:weak",
		Match:           `server: weak`,
		PatternStrength: 0.45, // will remain below 0.5 after scoring
	}}
	rb := NewRuleBasedResolver(rules)
	if _, err := rb.Resolve(context.TODO(), Input{Protocol: "http", Banner: "server: weak"}); err == nil {
		t.Fatalf("expected error due to threshold filtering of all candidates")
	}
}

// MySQL Perfect Implementation Tests (Phase 3)

func TestResolve_MySQLHandshake_MySQL57(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "mysql.mysql",
		Protocol:            "mysql",
		Product:             "MySQL",
		Vendor:              "Oracle",
		CPE:                 "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
		Match:               `\x00\x00\x00\x0a`,
		VersionExtraction:   `\x0a([\d\.p]+[\w\-]*)`,
		ExcludePatterns:     []string{`http/`, `<html`, `<!doctype`, `<body`},
		SoftExcludePatterns: []string{`error`, `denied`, `refused`, `unavailable`},
		PatternStrength:     0.90,
		PortBonuses:         []int{3306, 33060},
		BinaryMinLength:     10,
		BinaryMagic:         []string{`\x00\x00\x00\x0a`},
	}}
	rb := NewRuleBasedResolver(rules)

	// Simulate MySQL 5.7 handshake banner
	banner := "\x00\x00\x00\x0a5.7.44-log\x00"
	res, err := rb.Resolve(context.TODO(), Input{Protocol: "mysql", Banner: banner, Port: 3306})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Product != "MySQL" {
		t.Fatalf("expected MySQL, got %s", res.Product)
	}
	if res.Version != "5.7.44-log" {
		t.Fatalf("expected version 5.7.44-log, got %s", res.Version)
	}
	if res.Confidence < 0.90 {
		t.Fatalf("expected high confidence (>0.90), got %v", res.Confidence)
	}
}

func TestResolve_MySQLHandshake_MySQL80(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "mysql.mysql",
		Protocol:            "mysql",
		Product:             "MySQL",
		Vendor:              "Oracle",
		CPE:                 "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
		Match:               `\x00\x00\x00\x0a`,
		VersionExtraction:   `\x0a([\d\.p]+[\w\-]*)`,
		ExcludePatterns:     []string{`http/`, `<html`, `<!doctype`, `<body`},
		SoftExcludePatterns: []string{`error`, `denied`, `refused`, `unavailable`},
		PatternStrength:     0.90,
		PortBonuses:         []int{3306, 33060},
		BinaryMinLength:     10,
		BinaryMagic:         []string{`\x00\x00\x00\x0a`},
	}}
	rb := NewRuleBasedResolver(rules)

	// Simulate MySQL 8.0 handshake banner
	banner := "\x00\x00\x00\x0a8.0.35\x00"
	res, err := rb.Resolve(context.TODO(), Input{Protocol: "mysql", Banner: banner, Port: 3306})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Product != "MySQL" {
		t.Fatalf("expected MySQL, got %s", res.Product)
	}
	if res.Version != "8.0.35" {
		t.Fatalf("expected version 8.0.35, got %s", res.Version)
	}
	if res.Confidence < 0.90 {
		t.Fatalf("expected high confidence (>0.90), got %v", res.Confidence)
	}
}

func TestResolve_MySQLHandshake_MariaDB(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "mysql.mysql",
		Protocol:            "mysql",
		Product:             "MySQL",
		Vendor:              "Oracle",
		CPE:                 "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
		Match:               `\x00\x00\x00\x0a`,
		VersionExtraction:   `\x0a([\d\.p]+[\w\-]*)`,
		ExcludePatterns:     []string{`http/`, `<html`, `<!doctype`, `<body`},
		SoftExcludePatterns: []string{`error`, `denied`, `refused`, `unavailable`},
		PatternStrength:     0.90,
		PortBonuses:         []int{3306, 33060},
		BinaryMinLength:     10,
		BinaryMagic:         []string{`\x00\x00\x00\x0a`},
	}}
	rb := NewRuleBasedResolver(rules)

	// Simulate MariaDB handshake banner
	banner := "\x00\x00\x00\x0a10.11.6-MariaDB\x00"
	res, err := rb.Resolve(context.TODO(), Input{Protocol: "mysql", Banner: banner, Port: 3306})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Product != "MySQL" {
		t.Fatalf("expected MySQL (MariaDB compatible), got %s", res.Product)
	}
	if res.Version != "10.11.6-mariadb" {
		t.Fatalf("expected version 10.11.6-mariadb, got %s", res.Version)
	}
	if res.Confidence < 0.90 {
		t.Fatalf("expected high confidence (>0.90), got %v", res.Confidence)
	}
}

func TestResolve_MySQLHandshake_PortBonus(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "mysql.mysql",
		Protocol:            "mysql",
		Product:             "MySQL",
		Vendor:              "Oracle",
		CPE:                 "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
		Match:               `\x00\x00\x00\x0a`,
		VersionExtraction:   `\x0a([\d\.p]+[\w\-]*)`,
		ExcludePatterns:     []string{`http/`, `<html`, `<!doctype`, `<body`},
		SoftExcludePatterns: []string{`error`, `denied`, `refused`, `unavailable`},
		PatternStrength:     0.90,
		PortBonuses:         []int{3306, 33060},
		BinaryMinLength:     10,
		BinaryMagic:         []string{`\x00\x00\x00\x0a`},
	}}
	rb := NewRuleBasedResolver(rules)

	banner := "\x00\x00\x00\x0a8.0.35\x00"

	// Test with standard MySQL port (should get bonus)
	resWithBonus, err := rb.Resolve(context.TODO(), Input{Protocol: "mysql", Banner: banner, Port: 3306})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test with non-standard port (no bonus)
	resNoBonus, err := rb.Resolve(context.TODO(), Input{Protocol: "mysql", Banner: banner, Port: 9999})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Confidence should be higher with port bonus
	if resWithBonus.Confidence <= resNoBonus.Confidence {
		t.Fatalf("expected port bonus to increase confidence: with=%v, without=%v", resWithBonus.Confidence, resNoBonus.Confidence)
	}
}

func TestResolve_MySQLHandshake_HTTPFalsePositiveRejection(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "mysql.mysql",
		Protocol:            "mysql",
		Product:             "MySQL",
		Vendor:              "Oracle",
		CPE:                 "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
		Match:               `\x00\x00\x00\x0a`,
		VersionExtraction:   `\x0a([\d\.p]+[\w\-]*)`,
		ExcludePatterns:     []string{`http/`, `<html`, `<!doctype`, `<body`},
		SoftExcludePatterns: []string{`error`, `denied`, `refused`, `unavailable`},
		PatternStrength:     0.90,
		PortBonuses:         []int{3306, 33060},
		BinaryMinLength:     10,
		BinaryMagic:         []string{`\x00\x00\x00\x0a`},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name   string
		banner string
	}{
		{"HTTP Response Header", "http/1.1 200 ok\r\ncontent-type: text/html\r\n\r\n\x00\x00\x00\x0amysql"},
		{"HTML Document", "<html><body>\x00\x00\x00\x0amysql</body></html>"},
		{"HTML Doctype", "<!doctype html>\x00\x00\x00\x0amysql"},
		{"HTML Body Tag", "<body>\x00\x00\x00\x0amysql</body>"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rb.Resolve(context.TODO(), Input{Protocol: "mysql", Banner: tc.banner})
			if err == nil {
				t.Fatalf("expected HTTP false positive to be rejected for: %s", tc.name)
			}
		})
	}
}

func TestResolve_MySQLHandshake_SoftExcludePenalty(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "mysql.mysql",
		Protocol:            "mysql",
		Product:             "MySQL",
		Vendor:              "Oracle",
		CPE:                 "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
		Match:               `\x00\x00\x00\x0a`,
		VersionExtraction:   `\x0a([\d\.p]+[\w\-]*)`,
		ExcludePatterns:     []string{`http/`, `<html`, `<!doctype`, `<body`},
		SoftExcludePatterns: []string{`error`, `denied`, `refused`, `unavailable`},
		PatternStrength:     0.90,
		PortBonuses:         []int{3306, 33060},
		BinaryMinLength:     10,
		BinaryMagic:         []string{`\x00\x00\x00\x0a`},
	}}
	rb := NewRuleBasedResolver(rules)

	// Normal MySQL handshake
	normalBanner := "\x00\x00\x00\x0a8.0.35\x00"
	normalRes, err := rb.Resolve(context.TODO(), Input{Protocol: "mysql", Banner: normalBanner, Port: 3306})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// MySQL handshake with error text (should get penalized)
	errorBanner := "\x00\x00\x00\x0a8.0.35\x00 access denied error"
	errorRes, err := rb.Resolve(context.TODO(), Input{Protocol: "mysql", Banner: errorBanner, Port: 3306})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Error banner should have lower confidence due to soft exclude penalty
	if errorRes.Confidence >= normalRes.Confidence {
		t.Fatalf("expected soft exclude to penalize confidence: normal=%v, error=%v", normalRes.Confidence, errorRes.Confidence)
	}
}

func TestResolve_MySQLHandshake_VersionExtractionEdgeCases(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "mysql.mysql",
		Protocol:            "mysql",
		Product:             "MySQL",
		Vendor:              "Oracle",
		CPE:                 "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
		Match:               `\x00\x00\x00\x0a`,
		VersionExtraction:   `\x0a([\d\.p]+[\w\-]*)`,
		ExcludePatterns:     []string{`http/`, `<html`, `<!doctype`, `<body`},
		SoftExcludePatterns: []string{`error`, `denied`, `refused`, `unavailable`},
		PatternStrength:     0.90,
		PortBonuses:         []int{3306, 33060},
		BinaryMinLength:     10,
		BinaryMagic:         []string{`\x00\x00\x00\x0a`},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		expectedVersion string
	}{
		{"Simple Version", "\x00\x00\x00\x0a8.0.35\x00", "8.0.35"},
		{"Version with Patch", "\x00\x00\x00\x0a5.7.44p1\x00", "5.7.44p1"},
		{"Version with Suffix", "\x00\x00\x00\x0a8.0.35-log\x00", "8.0.35-log"},
		{"MariaDB Version", "\x00\x00\x00\x0a10.11.6-MariaDB\x00", "10.11.6-mariadb"},
		{"Percona Version", "\x00\x00\x00\x0a8.0.35-27-percona\x00", "8.0.35-27-percona"},
		{"No Version", "\x00\x00\x00\x0a\x00", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := rb.Resolve(context.TODO(), Input{Protocol: "mysql", Banner: tc.banner, Port: 3306})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Version != tc.expectedVersion {
				t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
			}
		})
	}
}

// Web Services Tests (Phase 4)

func TestResolve_ApacheHTTPServer(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "http.apache",
		Protocol:            "http",
		Product:             "Apache HTTP Server",
		Vendor:              "Apache Software Foundation",
		CPE:                 "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
		Match:               `server:\s*apache`,
		VersionExtraction:   `apache/([\d\.]+)`,
		ExcludePatterns:     []string{`nginx`, `iis`, `litespeed`},
		SoftExcludePatterns: []string{`error`, `forbidden`, `unavailable`},
		PatternStrength:     0.85,
		PortBonuses:         []int{80, 443, 8080, 8443},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"Apache 2.4 standard", "Server: Apache/2.4.52 (Ubuntu)", 80, "2.4.52", true},
		{"Apache 2.2", "Server: Apache/2.2.34", 443, "2.2.34", true},
		{"Apache without version", "Server: Apache", 80, "", true},
		{"nginx banner (should reject)", "Server: nginx/1.18.0", 80, "", false},
		{"IIS banner (should reject)", "Server: Microsoft-IIS/10.0", 80, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := rb.Resolve(context.TODO(), Input{Protocol: "http", Banner: tc.banner, Port: tc.port})
			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "Apache HTTP Server" {
					t.Fatalf("expected Apache HTTP Server, got %s", res.Product)
				}
				if res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_Nginx(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "http.nginx",
		Protocol:            "http",
		Product:             "nginx",
		Vendor:              "F5 Networks",
		CPE:                 "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
		Match:               `server:\s*nginx`,
		VersionExtraction:   `nginx/([\d\.]+)`,
		ExcludePatterns:     []string{`apache`, `iis`, `litespeed`},
		SoftExcludePatterns: []string{`error`, `forbidden`, `unavailable`},
		PatternStrength:     0.85,
		PortBonuses:         []int{80, 443, 8080, 8443},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"nginx 1.21", "Server: nginx/1.21.6", 80, "1.21.6", true},
		{"nginx 1.18 on 443", "Server: nginx/1.18.0 (Ubuntu)", 443, "1.18.0", true},
		{"nginx without version", "Server: nginx", 80, "", true},
		{"Apache banner (should reject)", "Server: Apache/2.4.52", 80, "", false},
		{"LiteSpeed banner (should reject)", "Server: LiteSpeed", 80, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := rb.Resolve(context.TODO(), Input{Protocol: "http", Banner: tc.banner, Port: tc.port})
			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "nginx" {
					t.Fatalf("expected nginx, got %s", res.Product)
				}
				if res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_IIS(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "http.iis",
		Protocol:            "http",
		Product:             "IIS",
		Vendor:              "Microsoft",
		CPE:                 "cpe:2.3:a:microsoft:iis:*:*:*:*:*:*:*:*",
		Match:               `server:\s*microsoft-iis`,
		VersionExtraction:   `microsoft-iis/([\d\.]+)`,
		ExcludePatterns:     []string{`apache`, `nginx`, `litespeed`},
		SoftExcludePatterns: []string{`error`, `forbidden`, `unavailable`},
		PatternStrength:     0.85,
		PortBonuses:         []int{80, 443, 8080},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"IIS 10.0", "Server: Microsoft-IIS/10.0", 80, "10.0", true},
		{"IIS 8.5 on 443", "Server: Microsoft-IIS/8.5", 443, "8.5", true},
		{"IIS 7.5", "Server: Microsoft-IIS/7.5", 8080, "7.5", true},
		{"Apache banner (should reject)", "Server: Apache/2.4.52", 80, "", false},
		{"nginx banner (should reject)", "Server: nginx/1.21.6", 80, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := rb.Resolve(context.TODO(), Input{Protocol: "http", Banner: tc.banner, Port: tc.port})
			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "IIS" {
					t.Fatalf("expected IIS, got %s", res.Product)
				}
				if res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_LiteSpeed(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "http.litespeed",
		Protocol:            "http",
		Product:             "LiteSpeed Web Server",
		Vendor:              "LiteSpeed Technologies",
		CPE:                 "cpe:2.3:a:litespeedtech:litespeed_web_server:*:*:*:*:*:*:*:*",
		Match:               `server:\s*litespeed`,
		VersionExtraction:   `litespeed(?:\s|/)([\w\.-]+)`,
		ExcludePatterns:     []string{`apache`, `nginx`, `iis`},
		SoftExcludePatterns: []string{`error`, `forbidden`, `unavailable`},
		PatternStrength:     0.85,
		PortBonuses:         []int{80, 443, 8080, 8443},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"LiteSpeed 5.4", "Server: LiteSpeed/5.4.12", 80, "5.4.12", true},
		{"LiteSpeed 6.0", "Server: LiteSpeed/6.0.9", 443, "6.0.9", true},
		{"LiteSpeed without version", "Server: LiteSpeed", 80, "", true},
		{"Apache banner (should reject)", "Server: Apache/2.4.52", 80, "", false},
		{"nginx banner (should reject)", "Server: nginx/1.21.6", 80, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := rb.Resolve(context.TODO(), Input{Protocol: "http", Banner: tc.banner, Port: tc.port})
			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "LiteSpeed Web Server" {
					t.Fatalf("expected LiteSpeed Web Server, got %s", res.Product)
				}
				if res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_Tomcat(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "http.tomcat",
		Protocol:            "http",
		Product:             "Apache Tomcat",
		Vendor:              "Apache Software Foundation",
		CPE:                 "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
		Match:               `server:\s*(?:apache-coyote|tomcat)`,
		VersionExtraction:   `(?:tomcat|apache-coyote)/([\d\.]+)`,
		ExcludePatterns:     []string{`nginx`, `iis`, `litespeed`},
		SoftExcludePatterns: []string{`error`, `forbidden`, `unavailable`},
		PatternStrength:     0.85,
		PortBonuses:         []int{8080, 8443, 8009},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"Tomcat 9.0", "Server: Apache-Coyote/9.0.65", 8080, "9.0.65", true},
		{"Tomcat 8.5", "Server: Tomcat/8.5.82", 8080, "8.5.82", true},
		{"Tomcat 10.1 on 8443", "Server: Apache-Coyote/10.1.0", 8443, "10.1.0", true},
		{"Tomcat without version", "Server: Tomcat", 8080, "", true},
		{"nginx banner (should reject)", "Server: nginx/1.21.6", 8080, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := rb.Resolve(context.TODO(), Input{Protocol: "http", Banner: tc.banner, Port: tc.port})
			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "Apache Tomcat" {
					t.Fatalf("expected Apache Tomcat, got %s", res.Product)
				}
				if res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

// Database Services Tests (Phase 4)

func TestResolve_PostgreSQL(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "db.postgresql",
		Protocol:            "postgresql",
		Product:             "PostgreSQL",
		Vendor:              "PostgreSQL Global Development Group",
		CPE:                 "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
		Match:               `postgres`,
		VersionExtraction:   `postgres(?:ql)?\s+([\d\.]+)`,
		ExcludePatterns:     []string{`mysql`, `mongodb`, `redis`, `memcached`},
		SoftExcludePatterns: []string{`error`, `denied`, `refused`, `unavailable`},
		PatternStrength:     0.88,
		PortBonuses:         []int{5432, 5433},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"PostgreSQL 14.5", "PostgreSQL 14.5 on x86_64-pc-linux-gnu", 5432, "14.5", true},
		{"PostgreSQL 13.8", "postgres 13.8", 5433, "13.8", true},
		{"PostgreSQL without version", "PostgreSQL Database", 5432, "", true},
		{"MySQL banner (should reject)", "mysql version 8.0.30", 3306, "", false},
		{"Redis banner (should reject)", "redis_version:7.0.5", 6379, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "postgresql", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "PostgreSQL" {
					t.Fatalf("expected PostgreSQL, got %s", res.Product)
				}
				if res.Vendor != "PostgreSQL Global Development Group" {
					t.Fatalf("expected PostgreSQL Global Development Group, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_Redis(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "db.redis",
		Protocol:            "redis",
		Product:             "Redis",
		Vendor:              "Redis Ltd",
		CPE:                 "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*",
		Match:               `redis_version:`,
		VersionExtraction:   `redis_version:([\d\.]+)`,
		ExcludePatterns:     []string{`mysql`, `postgres`, `mongodb`, `memcached`},
		SoftExcludePatterns: []string{`error`, `denied`, `noauth`, `unavailable`},
		PatternStrength:     0.90,
		PortBonuses:         []int{6379, 6380},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"Redis 7.0.5", "redis_version:7.0.5", 6379, "7.0.5", true},
		{"Redis 6.2.7", "redis_version:6.2.7", 6380, "6.2.7", true},
		{"Redis info response", "redis_version:5.0.14\r\nredis_mode:standalone", 6379, "5.0.14", true},
		{"PostgreSQL banner (should reject)", "PostgreSQL 14.5", 5432, "", false},
		{"MongoDB banner (should reject)", "mongodb version 6.0.2", 27017, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "redis", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "Redis" {
					t.Fatalf("expected Redis, got %s", res.Product)
				}
				if res.Vendor != "Redis Ltd" {
					t.Fatalf("expected Redis Ltd, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_MongoDB(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "db.mongodb",
		Protocol:            "mongodb",
		Product:             "MongoDB",
		Vendor:              "MongoDB Inc",
		CPE:                 "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*",
		Match:               `mongodb|"version"`,
		VersionExtraction:   `(?:version[\s:"]+|mongodb[\s/]+)([\d\.]+)`,
		ExcludePatterns:     []string{`mysql`, `postgres`, `redis`, `memcached`},
		SoftExcludePatterns: []string{`error`, `denied`, `unauthorized`, `unavailable`},
		PatternStrength:     0.88,
		PortBonuses:         []int{27017, 27018, 27019},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"MongoDB 6.0.2", "mongodb version 6.0.2", 27017, "6.0.2", true},
		{"MongoDB JSON response", `{"version":"5.0.14"}`, 27017, "5.0.14", true},
		{"MongoDB buildInfo", "MongoDB version:4.4.18", 27018, "4.4.18", true},
		{"Redis banner (should reject)", "redis_version:7.0.5", 6379, "", false},
		{"MySQL banner (should reject)", "mysql version 8.0.30", 3306, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "mongodb", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "MongoDB" {
					t.Fatalf("expected MongoDB, got %s", res.Product)
				}
				if res.Vendor != "MongoDB Inc" {
					t.Fatalf("expected MongoDB Inc, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_Memcached(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "db.memcached",
		Protocol:            "memcached",
		Product:             "Memcached",
		Vendor:              "Memcached",
		CPE:                 "cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*",
		Match:               `version\s+[\d\.]+`,
		VersionExtraction:   `version\s+([\d\.]+)`,
		ExcludePatterns:     []string{`mysql`, `postgres`, `redis`, `mongodb`},
		SoftExcludePatterns: []string{`error`, `denied`, `refused`, `unavailable`},
		PatternStrength:     0.85,
		PortBonuses:         []int{11211, 11212},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"Memcached 1.6.17", "VERSION 1.6.17", 11211, "1.6.17", true},
		{"Memcached stats", "STAT version 1.5.22", 11211, "1.5.22", true},
		{"Memcached 1.4.39", "version 1.4.39", 11212, "1.4.39", true},
		{"Redis banner (should reject)", "redis_version:7.0.5", 6379, "", false},
		{"PostgreSQL banner (should reject)", "PostgreSQL 14.5", 5432, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "memcached", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "Memcached" {
					t.Fatalf("expected Memcached, got %s", res.Product)
				}
				if res.Vendor != "Memcached" {
					t.Fatalf("expected Memcached, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_Elasticsearch(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "db.elasticsearch",
		Protocol:            "http",
		Product:             "Elasticsearch",
		Vendor:              "Elastic",
		CPE:                 "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*",
		Match:               `elasticsearch|"version"`,
		VersionExtraction:   `(?:elasticsearch|version)[\s:"]+([\d\.]+)`,
		ExcludePatterns:     []string{`mysql`, `postgres`, `redis`, `mongodb`},
		SoftExcludePatterns: []string{`error`, `denied`, `unauthorized`, `unavailable`},
		PatternStrength:     0.88,
		PortBonuses:         []int{9200, 9300},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"Elasticsearch 8.5.3", "elasticsearch 8.5.3", 9200, "8.5.3", true},
		{"Elasticsearch JSON", `{"version":"7.17.7"}`, 9200, "7.17.7", true},
		{"Elasticsearch cluster info", "elasticsearch version:8.4.2", 9300, "8.4.2", true},
		{"Redis banner (should reject)", "redis_version:7.0.5", 6379, "", false},
		{"MongoDB banner (should reject)", "mongodb version 6.0.2", 27017, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "http", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "Elasticsearch" {
					t.Fatalf("expected Elasticsearch, got %s", res.Product)
				}
				if res.Vendor != "Elastic" {
					t.Fatalf("expected Elastic, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

// SSH Services Tests (Phase 4)

func TestResolve_OpenSSH(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "ssh.openssh",
		Protocol:            "ssh",
		Product:             "OpenSSH",
		Vendor:              "OpenBSD",
		CPE:                 "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
		Match:               `ssh-\d\.\d+-openssh_`,
		VersionExtraction:   `openssh_([\d\.p]+)`,
		ExcludePatterns:     []string{`dropbear`, `libssh`, `rosssh`},
		SoftExcludePatterns: []string{`error`, `refused`, `denied`},
		PatternStrength:     0.90,
		PortBonuses:         []int{22, 2222},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"OpenSSH 8.9", "SSH-2.0-OpenSSH_8.9", 22, "8.9", true},
		{"OpenSSH 7.4p1", "SSH-2.0-OpenSSH_7.4p1 Ubuntu-10", 22, "7.4p1", true},
		{"OpenSSH 9.0 on 2222", "SSH-2.0-OpenSSH_9.0", 2222, "9.0", true},
		{"Dropbear banner (should reject)", "SSH-2.0-dropbear_2020.81", 22, "", false},
		{"libssh banner (should reject)", "SSH-2.0-libssh-0.9.6", 22, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "ssh", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "OpenSSH" {
					t.Fatalf("expected OpenSSH, got %s", res.Product)
				}
				if res.Vendor != "OpenBSD" {
					t.Fatalf("expected OpenBSD, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_Dropbear(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "ssh.dropbear",
		Protocol:            "ssh",
		Product:             "Dropbear SSH",
		Vendor:              "Matt Johnston",
		CPE:                 "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:*:*:*:*:*:*:*:*",
		Match:               `dropbear`,
		VersionExtraction:   `dropbear[_-]([\d\.]+)`,
		ExcludePatterns:     []string{`openssh`, `libssh`},
		SoftExcludePatterns: []string{`error`, `refused`, `denied`},
		PatternStrength:     0.88,
		PortBonuses:         []int{22, 2222},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"Dropbear 2020.81", "SSH-2.0-dropbear_2020.81", 22, "2020.81", true},
		{"Dropbear 2022.83", "SSH-2.0-dropbear-2022.83", 2222, "2022.83", true},
		{"Dropbear without version", "SSH-2.0-dropbear", 22, "", true},
		{"OpenSSH banner (should reject)", "SSH-2.0-OpenSSH_8.9", 22, "", false},
		{"libssh banner (should reject)", "SSH-2.0-libssh-0.9.6", 22, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "ssh", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "Dropbear SSH" {
					t.Fatalf("expected Dropbear SSH, got %s", res.Product)
				}
				if res.Vendor != "Matt Johnston" {
					t.Fatalf("expected Matt Johnston, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_libssh(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "ssh.libssh",
		Protocol:            "ssh",
		Product:             "libssh",
		Vendor:              "libssh.org",
		CPE:                 "cpe:2.3:a:libssh:libssh:*:*:*:*:*:*:*:*",
		Match:               `libssh`,
		VersionExtraction:   `libssh[_-]([\d\.]+)`,
		ExcludePatterns:     []string{`openssh`, `dropbear`},
		SoftExcludePatterns: []string{`error`, `refused`, `denied`},
		PatternStrength:     0.88,
		PortBonuses:         []int{22, 2222},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"libssh 0.9.6", "SSH-2.0-libssh-0.9.6", 22, "0.9.6", true},
		{"libssh 0.10.4", "SSH-2.0-libssh_0.10.4", 2222, "0.10.4", true},
		{"libssh without version", "SSH-2.0-libssh", 22, "", true},
		{"OpenSSH banner (should reject)", "SSH-2.0-OpenSSH_8.9", 22, "", false},
		{"Dropbear banner (should reject)", "SSH-2.0-dropbear_2020.81", 22, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "ssh", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "libssh" {
					t.Fatalf("expected libssh, got %s", res.Product)
				}
				if res.Vendor != "libssh.org" {
					t.Fatalf("expected libssh.org, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

// Mail Servers Tests (Phase 4)

func TestResolve_Postfix(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "smtp.postfix",
		Protocol:            "smtp",
		Product:             "Postfix",
		Vendor:              "Postfix Project",
		CPE:                 "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*",
		Match:               `esmtp postfix`,
		VersionExtraction:   `postfix\s+([\d\.]+)`,
		ExcludePatterns:     []string{`exim`, `sendmail`, `dovecot`},
		SoftExcludePatterns: []string{`error`, `relay denied`, `unavailable`},
		PatternStrength:     0.88,
		PortBonuses:         []int{25, 587, 465},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"Postfix 3.5.9", "220 mail.example.com ESMTP Postfix 3.5.9", 25, "3.5.9", true},
		{"Postfix 3.7.2 on 587", "220 smtp.example.com ESMTP Postfix 3.7.2", 587, "3.7.2", true},
		{"Postfix no version", "220 mail.example.com ESMTP Postfix", 25, "", true},
		{"Exim banner (should reject)", "220 mail.example.com ESMTP Exim 4.96", 25, "", false},
		{"Sendmail banner (should reject)", "220 mail.example.com ESMTP Sendmail 8.17.1", 25, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "smtp", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "Postfix" {
					t.Fatalf("expected Postfix, got %s", res.Product)
				}
				if res.Vendor != "Postfix Project" {
					t.Fatalf("expected Postfix Project, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_Exim(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "smtp.exim",
		Protocol:            "smtp",
		Product:             "Exim",
		Vendor:              "Exim Project",
		CPE:                 "cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*",
		Match:               `exim`,
		VersionExtraction:   `exim\s+([\d\.]+)`,
		ExcludePatterns:     []string{`postfix`, `sendmail`, `dovecot`},
		SoftExcludePatterns: []string{`error`, `relay denied`, `unavailable`},
		PatternStrength:     0.88,
		PortBonuses:         []int{25, 587, 465},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"Exim 4.96", "220 mail.example.com ESMTP Exim 4.96 Ubuntu", 25, "4.96", true},
		{"Exim 4.94.2 on 587", "220 smtp.example.com ESMTP Exim 4.94.2", 587, "4.94.2", true},
		{"Exim no version", "220 mail.example.com ESMTP Exim", 25, "", true},
		{"Postfix banner (should reject)", "220 mail.example.com ESMTP Postfix", 25, "", false},
		{"Sendmail banner (should reject)", "220 mail.example.com ESMTP Sendmail 8.17.1", 25, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "smtp", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "Exim" {
					t.Fatalf("expected Exim, got %s", res.Product)
				}
				if res.Vendor != "Exim Project" {
					t.Fatalf("expected Exim Project, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_Sendmail(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "smtp.sendmail",
		Protocol:            "smtp",
		Product:             "Sendmail",
		Vendor:              "Sendmail Consortium",
		CPE:                 "cpe:2.3:a:sendmail:sendmail:*:*:*:*:*:*:*:*",
		Match:               `sendmail`,
		VersionExtraction:   `sendmail\s+([\d\.]+)`,
		ExcludePatterns:     []string{`postfix`, `exim`, `dovecot`},
		SoftExcludePatterns: []string{`error`, `relay denied`, `unavailable`},
		PatternStrength:     0.88,
		PortBonuses:         []int{25, 587, 465},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"Sendmail 8.17.1", "220 mail.example.com ESMTP Sendmail 8.17.1", 25, "8.17.1", true},
		{"Sendmail 8.15.2 on 587", "220 smtp.example.com ESMTP Sendmail 8.15.2", 587, "8.15.2", true},
		{"Sendmail no version", "220 mail.example.com ESMTP Sendmail ready", 25, "", true},
		{"Postfix banner (should reject)", "220 mail.example.com ESMTP Postfix", 25, "", false},
		{"Exim banner (should reject)", "220 mail.example.com ESMTP Exim 4.96", 25, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "smtp", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "Sendmail" {
					t.Fatalf("expected Sendmail, got %s", res.Product)
				}
				if res.Vendor != "Sendmail Consortium" {
					t.Fatalf("expected Sendmail Consortium, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_Dovecot(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "smtp.dovecot",
		Protocol:            "smtp",
		Product:             "Dovecot",
		Vendor:              "Dovecot Project",
		CPE:                 "cpe:2.3:a:dovecot:dovecot:*:*:*:*:*:*:*:*",
		Match:               `dovecot`,
		VersionExtraction:   `dovecot\s+(?:ready\.?\s+)?([\d\.]+)`,
		ExcludePatterns:     []string{`postfix`, `exim`, `sendmail`},
		SoftExcludePatterns: []string{`error`, `denied`, `unavailable`},
		PatternStrength:     0.88,
		PortBonuses:         []int{143, 993, 110, 995},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"Dovecot 2.3.19", "* OK [CAPABILITY IMAP4rev1] Dovecot ready 2.3.19", 143, "2.3.19", true},
		{"Dovecot 2.3.16 on 993", "* OK Dovecot 2.3.16 ready", 993, "2.3.16", true},
		{"Dovecot no version", "* OK Dovecot ready", 143, "", true},
		{"Postfix banner (should reject)", "220 mail.example.com ESMTP Postfix", 143, "", false},
		{"Exim banner (should reject)", "220 mail.example.com ESMTP Exim 4.96", 143, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "smtp", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "Dovecot" {
					t.Fatalf("expected Dovecot, got %s", res.Product)
				}
				if res.Vendor != "Dovecot Project" {
					t.Fatalf("expected Dovecot Project, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

// FTP Servers Tests (Phase 4)

func TestResolve_PureFTPd(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "ftp.pureftpd",
		Protocol:            "ftp",
		Product:             "Pure-FTPd",
		Vendor:              "PureFTPd Project",
		CPE:                 "cpe:2.3:a:pureftpd:pure-ftpd:*:*:*:*:*:*:*:*",
		Match:               `pure-ftpd`,
		VersionExtraction:   `pure-ftpd\s+([\d\.]+)`,
		ExcludePatterns:     []string{`proftpd`, `vsftpd`},
		SoftExcludePatterns: []string{`error`, `denied`, `unavailable`},
		PatternStrength:     0.88,
		PortBonuses:         []int{21, 2121},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"Pure-FTPd 1.0.49", "220 Welcome to Pure-FTPd 1.0.49", 21, "1.0.49", true},
		{"Pure-FTPd 1.0.50 on 2121", "220 Pure-FTPd 1.0.50 at your service", 2121, "1.0.50", true},
		{"Pure-FTPd no version", "220 Welcome to Pure-FTPd", 21, "", true},
		{"ProFTPD banner (should reject)", "220 ProFTPD 1.3.7 Server ready", 21, "", false},
		{"vsftpd banner (should reject)", "220 (vsFTPd 3.0.5)", 21, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "ftp", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "Pure-FTPd" {
					t.Fatalf("expected Pure-FTPd, got %s", res.Product)
				}
				if res.Vendor != "PureFTPd Project" {
					t.Fatalf("expected PureFTPd Project, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_ProFTPD(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "ftp.proftpd",
		Protocol:            "ftp",
		Product:             "ProFTPD",
		Vendor:              "ProFTPD Project",
		CPE:                 "cpe:2.3:a:proftpd:proftpd:*:*:*:*:*:*:*:*",
		Match:               `proftpd`,
		VersionExtraction:   `proftpd\s+([\d\.]+)`,
		ExcludePatterns:     []string{`pure-ftpd`, `vsftpd`},
		SoftExcludePatterns: []string{`error`, `denied`, `unavailable`},
		PatternStrength:     0.88,
		PortBonuses:         []int{21, 2121},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"ProFTPD 1.3.7", "220 ProFTPD 1.3.7 Server ready", 21, "1.3.7", true},
		{"ProFTPD 1.3.6 on 2121", "220 Welcome to ProFTPD 1.3.6 Server", 2121, "1.3.6", true},
		{"ProFTPD no version", "220 ProFTPD Server ready", 21, "", true},
		{"Pure-FTPd banner (should reject)", "220 Welcome to Pure-FTPd 1.0.49", 21, "", false},
		{"vsftpd banner (should reject)", "220 (vsFTPd 3.0.5)", 21, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "ftp", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "ProFTPD" {
					t.Fatalf("expected ProFTPD, got %s", res.Product)
				}
				if res.Vendor != "ProFTPD Project" {
					t.Fatalf("expected ProFTPD Project, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_vsftpd(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "ftp.vsftpd",
		Protocol:            "ftp",
		Product:             "vsftpd",
		Vendor:              "vsftpd Project",
		CPE:                 "cpe:2.3:a:vsftpd:vsftpd:*:*:*:*:*:*:*:*",
		Match:               `vsftpd`,
		VersionExtraction:   `vsftpd\s+([\d\.]+)`,
		ExcludePatterns:     []string{`pure-ftpd`, `proftpd`},
		SoftExcludePatterns: []string{`error`, `denied`, `unavailable`},
		PatternStrength:     0.88,
		PortBonuses:         []int{21, 2121},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"vsftpd 3.0.5", "220 (vsFTPd 3.0.5)", 21, "3.0.5", true},
		{"vsftpd 3.0.3 on 2121", "220 Welcome to vsFTPd 3.0.3 Server", 2121, "3.0.3", true},
		{"vsftpd no version", "220 (vsFTPd ready)", 21, "", true},
		{"Pure-FTPd banner (should reject)", "220 Welcome to Pure-FTPd 1.0.49", 21, "", false},
		{"ProFTPD banner (should reject)", "220 ProFTPD 1.3.7 Server ready", 21, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "ftp", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "vsftpd" {
					t.Fatalf("expected vsftpd, got %s", res.Product)
				}
				if res.Vendor != "vsftpd Project" {
					t.Fatalf("expected vsftpd Project, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

// Other Services Tests (Phase 4)

func TestResolve_RDP(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "rdp.microsoft",
		Protocol:            "rdp",
		Product:             "Microsoft RDP",
		Vendor:              "Microsoft",
		CPE:                 "cpe:2.3:a:microsoft:remote_desktop_protocol:*:*:*:*:*:*:*:*",
		Match:               `rdp|remote desktop`,
		VersionExtraction:   `(?:protocol|rdp)\s+([\d\.]+)`,
		ExcludePatterns:     []string{`vnc`, `telnet`},
		SoftExcludePatterns: []string{`error`, `denied`, `unavailable`},
		PatternStrength:     0.88,
		PortBonuses:         []int{3389},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"RDP 10.0", "Remote Desktop Protocol 10.0", 3389, "10.0", true},
		{"RDP 8.1 on 3389", "RDP 8.1 ready", 3389, "8.1", true},
		{"RDP no version", "Remote Desktop ready", 3389, "", true},
		{"VNC banner (should reject)", "RFB 003.008", 3389, "", false},
		{"Telnet banner (should reject)", "Telnet service ready", 3389, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "rdp", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "Microsoft RDP" {
					t.Fatalf("expected Microsoft RDP, got %s", res.Product)
				}
				if res.Vendor != "Microsoft" {
					t.Fatalf("expected Microsoft, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_VNC(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "vnc.realvnc",
		Protocol:            "vnc",
		Product:             "VNC",
		Vendor:              "RealVNC",
		CPE:                 "cpe:2.3:a:realvnc:vnc:*:*:*:*:*:*:*:*",
		Match:               `rfb|vnc`,
		VersionExtraction:   `(?:rfb|vnc)\s+([\d\.]+)`,
		ExcludePatterns:     []string{`rdp`, `telnet`},
		SoftExcludePatterns: []string{`error`, `denied`, `unavailable`},
		PatternStrength:     0.88,
		PortBonuses:         []int{5900, 5901, 5902},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"VNC RFB 003.008", "RFB 003.008", 5900, "003.008", true},
		{"VNC 6.0 on 5901", "VNC 6.0 ready", 5901, "6.0", true},
		{"VNC no version", "RFB ready", 5900, "", true},
		{"RDP banner (should reject)", "Remote Desktop Protocol 10.0", 5900, "", false},
		{"Telnet banner (should reject)", "Telnet service ready", 5900, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "vnc", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "VNC" {
					t.Fatalf("expected VNC, got %s", res.Product)
				}
				if res.Vendor != "RealVNC" {
					t.Fatalf("expected RealVNC, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_Telnet(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "telnet.generic",
		Protocol:            "telnet",
		Product:             "Telnet",
		Vendor:              "Generic",
		CPE:                 "cpe:2.3:a:telnet:telnet:*:*:*:*:*:*:*:*",
		Match:               `telnet`,
		VersionExtraction:   `telnet\s+([\d\.]+)`,
		ExcludePatterns:     []string{`ssh`, `rdp`, `vnc`},
		SoftExcludePatterns: []string{`error`, `denied`, `unavailable`},
		PatternStrength:     0.85,
		PortBonuses:         []int{23, 2323},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"Telnet 1.0", "Telnet 1.0 service ready", 23, "1.0", true},
		{"Telnet on 2323", "Welcome to Telnet service", 2323, "", true},
		{"Telnet no version", "Telnet ready", 23, "", true},
		{"SSH banner (should reject)", "SSH-2.0-OpenSSH_8.9", 23, "", false},
		{"RDP banner (should reject)", "Remote Desktop Protocol 10.0", 23, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "telnet", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "Telnet" {
					t.Fatalf("expected Telnet, got %s", res.Product)
				}
				if res.Vendor != "Generic" {
					t.Fatalf("expected Generic, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_SNMP(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "snmp.net-snmp",
		Protocol:            "snmp",
		Product:             "Net-SNMP",
		Vendor:              "Net-SNMP Project",
		CPE:                 "cpe:2.3:a:net-snmp:net-snmp:*:*:*:*:*:*:*:*",
		Match:               `snmp|net-snmp`,
		VersionExtraction:   `(?:snmp|net-snmp)\s+([\d\.]+)`,
		ExcludePatterns:     []string{`ssh`, `http`},
		SoftExcludePatterns: []string{`error`, `denied`, `timeout`},
		PatternStrength:     0.88,
		PortBonuses:         []int{161, 162},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"Net-SNMP 5.9", "Net-SNMP 5.9 agent ready", 161, "5.9", true},
		{"SNMP 5.7 on 162", "SNMP 5.7 daemon", 162, "5.7", true},
		{"SNMP no version", "SNMP agent ready", 161, "", true},
		{"SSH banner (should reject)", "SSH-2.0-OpenSSH_8.9", 161, "", false},
		{"HTTP banner (should reject)", "HTTP/1.1 200 OK", 161, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "snmp", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "Net-SNMP" {
					t.Fatalf("expected Net-SNMP, got %s", res.Product)
				}
				if res.Vendor != "Net-SNMP Project" {
					t.Fatalf("expected Net-SNMP Project, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}

func TestResolve_SMB(t *testing.T) {
	rules := []StaticRule{{
		ID:                  "smb.samba",
		Protocol:            "smb",
		Product:             "Samba",
		Vendor:              "Samba Project",
		CPE:                 "cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*",
		Match:               `samba|smb`,
		VersionExtraction:   `(?:samba|smb)\s+([\d\.]+)`,
		ExcludePatterns:     []string{`http`, `ftp`},
		SoftExcludePatterns: []string{`error`, `denied`, `unavailable`},
		PatternStrength:     0.88,
		PortBonuses:         []int{445, 139},
	}}
	rb := NewRuleBasedResolver(rules)

	testCases := []struct {
		name            string
		banner          string
		port            int
		expectedVersion string
		shouldMatch     bool
	}{
		{"Samba 4.15", "Samba 4.15 file server", 445, "4.15", true},
		{"SMB 4.13 on 139", "SMB 4.13 service ready", 139, "4.13", true},
		{"Samba no version", "Samba ready", 445, "", true},
		{"HTTP banner (should reject)", "HTTP/1.1 200 OK", 445, "", false},
		{"FTP banner (should reject)", "220 Welcome to Pure-FTPd", 445, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			input := Input{Protocol: "smb", Banner: tc.banner, Port: tc.port}
			res, err := rb.Resolve(ctx, input)

			if tc.shouldMatch {
				if err != nil {
					t.Fatalf("expected match, got error: %v", err)
				}
				if res.Product != "Samba" {
					t.Fatalf("expected Samba, got %s", res.Product)
				}
				if res.Vendor != "Samba Project" {
					t.Fatalf("expected Samba Project, got %s", res.Vendor)
				}
				if tc.expectedVersion != "" && res.Version != tc.expectedVersion {
					t.Fatalf("expected version %s, got %s", tc.expectedVersion, res.Version)
				}
			} else if err == nil {
				t.Fatalf("expected no match, but got result: %+v", res)
			}
		})
	}
}
