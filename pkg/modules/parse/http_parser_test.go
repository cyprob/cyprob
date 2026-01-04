// pkg/modules/parse/http_parser_test.go
package parse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHSTS(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected *HSTSInfo
	}{
		{
			name:  "full HSTS with all directives",
			value: "max-age=31536000; includeSubDomains; preload",
			expected: &HSTSInfo{
				Present:           true,
				MaxAge:            31536000,
				IncludeSubDomains: true,
				Preload:           true,
			},
		},
		{
			name:  "HSTS without includeSubDomains",
			value: "max-age=31536000",
			expected: &HSTSInfo{
				Present:           true,
				MaxAge:            31536000,
				IncludeSubDomains: false,
				Preload:           false,
			},
		},
		{
			name:  "HSTS with short max-age",
			value: "max-age=3600; includeSubDomains",
			expected: &HSTSInfo{
				Present:           true,
				MaxAge:            3600,
				IncludeSubDomains: true,
				Preload:           false,
			},
		},
		{
			name:  "HSTS with extra spaces",
			value: "max-age=31536000 ;  includeSubDomains  ;  preload",
			expected: &HSTSInfo{
				Present:           true,
				MaxAge:            31536000,
				IncludeSubDomains: true,
				Preload:           true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseHSTS(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseCSP(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected *CSPInfo
	}{
		{
			name:  "basic CSP with default-src",
			value: "default-src 'self'",
			expected: &CSPInfo{
				Present: true,
				Directives: map[string]string{
					"default-src": "'self'",
				},
				UnsafeInline: false,
				UnsafeEval:   false,
			},
		},
		{
			name:  "CSP with unsafe-inline",
			value: "default-src 'self'; script-src 'self' 'unsafe-inline'",
			expected: &CSPInfo{
				Present: true,
				Directives: map[string]string{
					"default-src": "'self'",
					"script-src":  "'self' 'unsafe-inline'",
				},
				UnsafeInline: true,
				UnsafeEval:   false,
			},
		},
		{
			name:  "CSP with unsafe-eval",
			value: "default-src 'self'; script-src 'unsafe-eval'",
			expected: &CSPInfo{
				Present: true,
				Directives: map[string]string{
					"default-src": "'self'",
					"script-src":  "'unsafe-eval'",
				},
				UnsafeInline: false,
				UnsafeEval:   true,
			},
		},
		{
			name:  "CSP with both unsafe-inline and unsafe-eval",
			value: "script-src 'unsafe-inline' 'unsafe-eval' https://example.com",
			expected: &CSPInfo{
				Present: true,
				Directives: map[string]string{
					"script-src": "'unsafe-inline' 'unsafe-eval' https://example.com",
				},
				UnsafeInline: true,
				UnsafeEval:   true,
			},
		},
		{
			name:  "complex CSP",
			value: "default-src 'none'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src *",
			expected: &CSPInfo{
				Present: true,
				Directives: map[string]string{
					"default-src": "'none'",
					"script-src":  "'self' https://cdn.example.com",
					"style-src":   "'self' 'unsafe-inline'",
					"img-src":     "*",
				},
				UnsafeInline: true,
				UnsafeEval:   false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCSP(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseSecurityHeaders_Perfect(t *testing.T) {
	headers := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
		"Content-Security-Policy":   "default-src 'self'",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"X-Xss-Protection":          "1; mode=block",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Permissions-Policy":        "geolocation=(), microphone=()",
	}

	result := parseSecurityHeaders(headers)
	require.NotNil(t, result)

	assert.Equal(t, 100, result.SecurityScore)
	assert.Empty(t, result.MissingHeaders)
	assert.NotNil(t, result.HSTS)
	assert.True(t, result.HSTS.Present)
	assert.Equal(t, 31536000, result.HSTS.MaxAge)
	assert.True(t, result.HSTS.IncludeSubDomains)
	assert.True(t, result.HSTS.Preload)
	assert.NotNil(t, result.CSP)
	assert.False(t, result.CSP.UnsafeInline)
	assert.False(t, result.CSP.UnsafeEval)
}

func TestParseSecurityHeaders_NoHeaders(t *testing.T) {
	headers := map[string]string{}

	result := parseSecurityHeaders(headers)
	require.NotNil(t, result)

	// Score deductions: 20 (HSTS) + 15 (CSP) + 15 (X-Frame) + 10 (X-Content-Type) + 5 (X-XSS) + 5 (Referrer) + 5 (Permissions) = 75
	// Result: 100 - 75 = 25
	assert.Equal(t, 25, result.SecurityScore)
	assert.Len(t, result.MissingHeaders, 7)
	assert.Contains(t, result.MissingHeaders, "Strict-Transport-Security")
	assert.Contains(t, result.MissingHeaders, "Content-Security-Policy")
	assert.Contains(t, result.MissingHeaders, "X-Frame-Options")
	assert.Contains(t, result.MissingHeaders, "X-Content-Type-Options")
	assert.Contains(t, result.MissingHeaders, "X-XSS-Protection")
	assert.Contains(t, result.MissingHeaders, "Referrer-Policy")
	assert.Contains(t, result.MissingHeaders, "Permissions-Policy")
	assert.NotEmpty(t, result.Recommendations)
}

func TestParseSecurityHeaders_WeakHSTS(t *testing.T) {
	headers := map[string]string{
		"Strict-Transport-Security": "max-age=3600",
	}

	result := parseSecurityHeaders(headers)
	require.NotNil(t, result)

	assert.NotNil(t, result.HSTS)
	assert.Equal(t, 3600, result.HSTS.MaxAge)
	assert.False(t, result.HSTS.IncludeSubDomains)
	assert.Contains(t, result.Recommendations, "HSTS max-age should be at least 31536000 (1 year)")
	assert.Contains(t, result.Recommendations, "HSTS should include 'includeSubDomains' directive")
	assert.Less(t, result.SecurityScore, 100)
}

func TestParseSecurityHeaders_UnsafeCSP(t *testing.T) {
	headers := map[string]string{
		"Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
	}

	result := parseSecurityHeaders(headers)
	require.NotNil(t, result)

	assert.NotNil(t, result.CSP)
	assert.True(t, result.CSP.UnsafeInline)
	assert.True(t, result.CSP.UnsafeEval)
	assert.Contains(t, result.Recommendations, "CSP contains 'unsafe-inline', consider using nonces or hashes")
	assert.Contains(t, result.Recommendations, "CSP contains 'unsafe-eval', remove if possible for better security")
	assert.Less(t, result.SecurityScore, 100)
}

func TestParseSecurityHeaders_InvalidXFrameOptions(t *testing.T) {
	headers := map[string]string{
		"X-Frame-Options": "ALLOW-FROM https://example.com",
	}

	result := parseSecurityHeaders(headers)
	require.NotNil(t, result)

	assert.Equal(t, "ALLOW-FROM https://example.com", result.XFrameOptions)
	assert.Contains(t, result.Recommendations, "X-Frame-Options should be DENY or SAMEORIGIN")
	assert.Less(t, result.SecurityScore, 100)
}

func TestParseSecurityHeaders_PartialHeaders(t *testing.T) {
	headers := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
		"X-Frame-Options":           "SAMEORIGIN",
		"X-Content-Type-Options":    "nosniff",
	}

	result := parseSecurityHeaders(headers)
	require.NotNil(t, result)

	assert.Equal(t, 70, result.SecurityScore)
	assert.Len(t, result.MissingHeaders, 4)
	assert.Contains(t, result.MissingHeaders, "Content-Security-Policy")
	assert.Contains(t, result.MissingHeaders, "X-XSS-Protection")
	assert.Contains(t, result.MissingHeaders, "Referrer-Policy")
	assert.Contains(t, result.MissingHeaders, "Permissions-Policy")
}

func TestParseSecurityHeaders_ScoreClamping(t *testing.T) {
	// Test that score is properly calculated (should be 25 for no headers)
	headers := map[string]string{}

	result := parseSecurityHeaders(headers)
	require.NotNil(t, result)

	assert.Equal(t, 25, result.SecurityScore)
	assert.GreaterOrEqual(t, result.SecurityScore, 0)
}
