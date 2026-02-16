package parse

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Mock data helpers
func mockTargetData(target string, port int, product, banner string, headers map[string]string) *targetData {
	return &targetData{
		Target:      target,
		Port:        port,
		Product:     product,
		Banner:      banner,
		HTTPHeaders: headers,
	}
}

func TestGenerateTags_ProductMapping(t *testing.T) {
	// Setup module (Init logic loads rules via sync.Once)
	mod := newTechTaggerModule()

	// Case 1: Known Product (Apache)
	data := mockTargetData("192.168.1.1", 80, "Apache", "", nil)
	tags := mod.generateTags(data)

	assert.Contains(t, tags, "apache")
	assert.Contains(t, tags, "http_server")
	assert.Contains(t, tags, "web_server")
}

func TestGenerateTags_RegexHeader(t *testing.T) {
	mod := newTechTaggerModule()

	// Case 2: Header Match (Nginx)
	headers := map[string]string{
		"Server": "nginx/1.18.0",
		"Date":   "Mon, 26 Jul 2021 12:00:00 GMT",
	}
	data := mockTargetData("192.168.1.2", 80, "", "", headers)
	tags := mod.generateTags(data)

	assert.Contains(t, tags, "nginx")
}

func TestGenerateTags_RegexBody(t *testing.T) {
	mod := newTechTaggerModule()

	// Case 3: Body Match (WordPress)
	// Using a specific indicator like wp-content
	body := "<html><head><link rel='stylesheet' href='/wp-content/themes/twentytwenty/style.css'></head><body>...</body></html>"
	data := mockTargetData("192.168.1.3", 80, "", body, nil)
	tags := mod.generateTags(data)

	assert.Contains(t, tags, "wordpress")
}

func TestGenerateTags_MultipleMatches(t *testing.T) {
	mod := newTechTaggerModule()

	// Case 4: Multiple Matches (Apache + PHP + WordPress)
	headers := map[string]string{
		"Server":       "Apache/2.4.41 (Ubuntu)",
		"X-Powered-By": "PHP/7.4.3",
	}
	// Direct valid body for WordPress
	body := "<link href='/wp-content/style.css'>"
	data := mockTargetData("192.168.1.4", 80, "Apache", body, headers)
	tags := mod.generateTags(data)

	// Check core tags
	assert.Contains(t, tags, "apache")    // From Product Map + Header Regex
	assert.Contains(t, tags, "php")       // From Header Regex (X-Powered-By)
	assert.Contains(t, tags, "wordpress") // From Body Regex (wp-content)
	assert.Contains(t, tags, "ubuntu")    // From Header Regex (Server string)
}

func TestExecute_EndToEnd(t *testing.T) {
	mod := newTechTaggerModule()

	// Prepare Inputs
	inputs := make(map[string]any)

	// 1. Fingerprint Input
	fpList := []any{
		FingerprintParsedInfo{Target: "10.0.0.1", Port: 22, Product: "OpenSSH", Version: "8.2p1"},
	}
	inputs["service.fingerprint.details"] = fpList

	// 2. HTTP Input
	httpList := []any{
		HTTPParsedInfo{
			Target: "10.0.0.1", Port: 80,
			Headers:   map[string]string{"Server": "nginx", "X-Powered-By": "PHP"},
			RawBanner: "<html>...</html>",
		},
	}
	inputs["service.http.details"] = httpList

	outputChan := make(chan engine.ModuleOutput, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := mod.Execute(ctx, inputs, outputChan)
	assert.NoError(t, err)
	close(outputChan)

	// Collect outputs
	results := make(map[string]TechTagResult)
	for out := range outputChan {
		if res, ok := out.Data.(TechTagResult); ok {
			key := fmt.Sprintf("%s:%d", res.Target, res.Port)
			results[key] = res
		}
	}

	// Verify SSH tags
	sshRes, exists := results["10.0.0.1:22"]
	assert.True(t, exists)
	assert.Contains(t, sshRes.Tags, "ssh")
	assert.Contains(t, sshRes.Tags, "secure_shell")

	// Verify HTTP tags (Nginx + PHP)
	httpRes, exists := results["10.0.0.1:80"]
	assert.True(t, exists)
	assert.Contains(t, httpRes.Tags, "nginx")
	assert.Contains(t, httpRes.Tags, "php")

	for _, res := range results {
		for _, tag := range res.Tags {
			assert.True(t, IsCanonicalTechTag(tag), "non-canonical tag emitted: %s", tag)
		}
	}
}

func TestTechTagCatalog_AllRulesAndProductTagsAreCanonical(t *testing.T) {
	t.Parallel()

	var cfg TechRulesConfig
	require.NoError(t, yaml.Unmarshal(techQueriesYAML, &cfg))
	require.NotEmpty(t, cfg.Rules)

	for _, rule := range cfg.Rules {
		normalized, ok := NormalizeTechTag(rule.Name)
		require.Truef(t, ok, "rule %q not in canonical dictionary", rule.Name)
		require.Truef(t, IsCanonicalTechTag(normalized), "rule %q resolved to non-canonical %q", rule.Name, normalized)
	}

	require.NotEmpty(t, productToTags)
	for product, tags := range productToTags {
		for _, tag := range tags {
			require.Truef(t, IsCanonicalTechTag(tag), "product %q contains non-canonical tag %q", product, tag)
		}
	}
}
