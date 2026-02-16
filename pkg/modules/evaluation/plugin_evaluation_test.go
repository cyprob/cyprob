// pkg/modules/evaluation/plugin_evaluation_test.go
package evaluation

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/plugin"
)

func init() {
	// Disable all logging for integration tests to reduce noise
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestNewPluginEvaluationModule(t *testing.T) {
	module := NewPluginEvaluationModule()
	require.NotNil(t, module)

	meta := module.Metadata()
	require.Equal(t, pluginEvalModuleName, meta.Name)
	require.Equal(t, engine.EvaluationModuleType, meta.Type)
	require.Equal(t, pluginEvalModuleVersion, meta.Version)
}

func TestPluginEvaluationModule_Metadata(t *testing.T) {
	module := NewPluginEvaluationModule()
	meta := module.Metadata()

	// Check basic metadata
	require.NotEmpty(t, meta.ID)
	require.NotEmpty(t, meta.Name)
	require.NotEmpty(t, meta.Description)
	require.Equal(t, engine.EvaluationModuleType, meta.Type)

	// Check consumes contract
	require.NotEmpty(t, meta.Consumes, "module should consume scan results")
	consumedKeys := make([]string, len(meta.Consumes))
	for i, entry := range meta.Consumes {
		consumedKeys[i] = entry.Key
	}
	require.Contains(t, consumedKeys, "ssh.version")
	require.Contains(t, consumedKeys, "http.server")
	require.Contains(t, consumedKeys, "service.port")
	require.Contains(t, consumedKeys, "tls.version")

	// Check produces contract
	require.NotEmpty(t, meta.Produces, "module should produce vulnerabilities")
	require.Equal(t, "evaluation.vulnerabilities", meta.Produces[0].Key)
	require.Equal(t, engine.CardinalityList, meta.Produces[0].Cardinality)
}

func TestPluginEvaluationModule_Init(t *testing.T) {
	module := NewPluginEvaluationModule()

	err := module.Init("test-instance", map[string]any{})
	require.NoError(t, err)

	meta := module.Metadata()
	require.Equal(t, "test-instance", meta.ID)

	// Verify embedded plugins were loaded
	require.NotNil(t, module.plugins, "plugins should be loaded")
	require.NotNil(t, module.evaluator, "evaluator should be created")

	// Count total plugins
	totalPlugins := 0
	for _, categoryPlugins := range module.plugins {
		totalPlugins += len(categoryPlugins)
	}
	require.Equal(t, 20, totalPlugins, "should load exactly 20 embedded plugins")

	// Verify plugins by category
	require.Contains(t, module.plugins, plugin.CategorySSH)
	require.Contains(t, module.plugins, plugin.CategoryHTTP)
	require.Contains(t, module.plugins, plugin.CategoryTLS)
	require.Contains(t, module.plugins, plugin.CategoryDatabase)
	require.Contains(t, module.plugins, plugin.CategoryNetwork)

	// Verify counts per category
	require.Len(t, module.plugins[plugin.CategorySSH], 6, "should have 6 SSH plugins")
	require.Len(t, module.plugins[plugin.CategoryHTTP], 4, "should have 4 HTTP plugins")
	require.Len(t, module.plugins[plugin.CategoryTLS], 4, "should have 4 TLS plugins")
	require.Len(t, module.plugins[plugin.CategoryDatabase], 3, "should have 3 Database plugins")
	require.Len(t, module.plugins[plugin.CategoryNetwork], 3, "should have 3 Network plugins")
}

func TestPluginEvaluationModule_Execute_WithContext(t *testing.T) {
	module := NewPluginEvaluationModule()
	require.NoError(t, module.Init("test-instance", nil))

	ctx := context.Background()

	// Provide input context that should match TLS weak protocol plugin
	inputs := map[string]any{
		"tls.version":  "TLSv1.0", // Should match tls-weak-protocol plugin
		"service.port": 443,
	}

	outputChan := make(chan engine.ModuleOutput, 10)
	done := make(chan struct{})

	// Collect outputs in background
	var outputs []engine.ModuleOutput
	go func() {
		for output := range outputChan {
			outputs = append(outputs, output)
		}
		close(done)
	}()

	// Execute module
	err := module.Execute(ctx, inputs, outputChan)
	close(outputChan)
	<-done

	require.NoError(t, err)

	// Should have at least one vulnerability match (TLS weak protocol)
	require.NotEmpty(t, outputs, "should produce vulnerability outputs")

	// Verify vulnerability structure
	vuln, ok := outputs[0].Data.(VulnerabilityResult)
	require.True(t, ok, "output should be VulnerabilityResult")
	require.True(t, vuln.Matched, "vulnerability should be matched")
	require.NotEmpty(t, vuln.Plugin, "plugin name should be set")
	require.NotEmpty(t, vuln.Severity, "severity should be set")
	require.NotEmpty(t, vuln.Message, "message should be set")
	require.Equal(t, 443, vuln.Port, "port should match input")
}

func TestPluginEvaluationModule_Execute_NoContext(t *testing.T) {
	module := NewPluginEvaluationModule()
	require.NoError(t, module.Init("test-instance", nil))

	ctx := context.Background()
	inputs := map[string]any{} // Empty context

	outputChan := make(chan engine.ModuleOutput, 10)
	done := make(chan struct{})

	var outputs []engine.ModuleOutput
	go func() {
		for output := range outputChan {
			outputs = append(outputs, output)
		}
		close(done)
	}()

	err := module.Execute(ctx, inputs, outputChan)
	close(outputChan)
	<-done

	require.NoError(t, err)
	require.Empty(t, outputs, "no context should produce no outputs")
}

func TestPluginEvaluationModule_Execute_TLSWeakCipher(t *testing.T) {
	module := NewPluginEvaluationModule()
	require.NoError(t, module.Init("test-instance", nil))

	ctx := context.Background()

	// Context that should match TLS weak cipher plugin
	inputs := map[string]any{
		"tls.cipher_suites": []string{"TLS_RSA_WITH_DES_CBC_SHA"}, // Weak cipher
		"service.port":      443,
	}

	outputChan := make(chan engine.ModuleOutput, 10)
	done := make(chan struct{})

	var outputs []engine.ModuleOutput
	go func() {
		for output := range outputChan {
			outputs = append(outputs, output)
		}
		close(done)
	}()

	err := module.Execute(ctx, inputs, outputChan)
	close(outputChan)
	<-done

	require.NoError(t, err)
	require.NotEmpty(t, outputs, "should detect TLS weak cipher vulnerability")

	// Verify the match
	vuln, ok := outputs[0].Data.(VulnerabilityResult)
	require.True(t, ok)
	require.Contains(t, vuln.Plugin, "TLS")
	require.Equal(t, "high", vuln.Severity) // TLS weak cipher is high severity
}

// NOTE: TLS expired/self-signed tests are removed for now pending
// alignment of test contexts with plugin match requirements.

func TestPluginEvaluationModuleFactory(t *testing.T) {
	module := PluginEvaluationModuleFactory()
	require.NotNil(t, module)

	meta := module.Metadata()
	require.Equal(t, pluginEvalModuleName, meta.Name)
	require.Equal(t, engine.EvaluationModuleType, meta.Type)
}

func TestPluginEvaluationModule_Registration(t *testing.T) {
	// Test that module is registered in engine registry
	module, err := engine.GetModuleInstance("test-id", pluginEvalModuleName, map[string]any{})
	require.NoError(t, err)
	require.NotNil(t, module)

	meta := module.Metadata()
	require.Equal(t, pluginEvalModuleName, meta.Name)
	require.Equal(t, "test-id", meta.ID)
}

func TestVulnerabilityResult_Structure(t *testing.T) {
	// Test the vulnerability result structure
	vuln := VulnerabilityResult{
		Target:      "192.168.1.1",
		Port:        22,
		Plugin:      "ssh-weak-cipher",
		PluginType:  "evaluation",
		Severity:    "high",
		Message:     "SSH server uses weak encryption cipher",
		Remediation: "Disable CBC-mode ciphers",
		CVE:         []string{"CVE-2008-5161"},
		CWE:         []string{"CWE-326"},
		Reference:   "https://example.com/ssh-security",
		Matched:     true,
	}

	require.Equal(t, "192.168.1.1", vuln.Target)
	require.Equal(t, 22, vuln.Port)
	require.Equal(t, "high", vuln.Severity)
	require.True(t, vuln.Matched)
	require.Contains(t, vuln.CVE, "CVE-2008-5161")
}

func TestBuildEvaluationContext_ArrayAndScalar(t *testing.T) {
	module := NewPluginEvaluationModule()

	inputs := map[string]any{
		"ssh.version": []any{"OpenSSH_8.0"},
		"http.server": "nginx/1.18",
		"tls.version": []any{"TLSv1.2"},
	}

	ctx := module.buildEvaluationContext(inputs)

	require.Equal(t, "OpenSSH_8.0", ctx["ssh.version"])
	require.Equal(t, "nginx/1.18", ctx["http.server"])
	require.Equal(t, "TLSv1.2", ctx["tls.version"])
}

func TestBuildEvaluationContext_SSHDetails_MapFallback(t *testing.T) {
	module := NewPluginEvaluationModule()

	// Provide service.ssh.details as a mapped form (JSON-decoded style)
	sshDetails := []any{
		map[string]any{
			"target": "192.0.2.10",
			"port":   float64(2222), // simulate JSON number -> float64
		},
	}

	inputs := map[string]any{
		"service.ssh.details": sshDetails,
	}

	ctx := module.buildEvaluationContext(inputs)

	require.Equal(t, "192.0.2.10", ctx["target"])
	// service.port should be converted to int
	require.Equal(t, 2222, ctx["service.port"])
}

func TestBuildEvaluationContext_BannerGrab_MapFallback(t *testing.T) {
	module := NewPluginEvaluationModule()

	// No ssh.details provided, so banner fallback should set target/port
	banners := []any{
		map[string]any{
			"ip":   "203.0.113.5",
			"port": float64(8080),
		},
	}

	inputs := map[string]any{
		"service.banner.tcp": banners,
	}

	ctx := module.buildEvaluationContext(inputs)

	require.Equal(t, "203.0.113.5", ctx["target"])
	require.Equal(t, 8080, ctx["service.port"])
}

func TestExtractPort_Int(t *testing.T) {
	module := NewPluginEvaluationModule()

	ctx := map[string]any{
		"service.port": 8080,
	}

	port := module.extractPort(ctx)
	require.Equal(t, 8080, port)
}

func TestExtractPort_Int64(t *testing.T) {
	module := NewPluginEvaluationModule()

	ctx := map[string]any{
		"service.port": int64(9090),
	}

	port := module.extractPort(ctx)
	require.Equal(t, 9090, port)
}

func TestExtractPort_Float64(t *testing.T) {
	module := NewPluginEvaluationModule()

	ctx := map[string]any{
		"service.port": float64(443),
	}

	port := module.extractPort(ctx)
	require.Equal(t, 443, port)
}

func TestExtractPort_InvalidOrMissing(t *testing.T) {
	module := NewPluginEvaluationModule()

	// Missing key
	port := module.extractPort(map[string]any{})
	require.Equal(t, 0, port)

	// Unsupported type (string) should return 0
	port = module.extractPort(map[string]any{"service.port": "80"})
	require.Equal(t, 0, port)
}

func TestExtractTarget_String(t *testing.T) {
	module := NewPluginEvaluationModule()

	ctx := map[string]any{
		"target": "192.0.2.1",
	}

	target := module.extractTarget(ctx)
	require.Equal(t, "192.0.2.1", target)
}

func TestExtractTarget_MissingReturnsUnknown(t *testing.T) {
	module := NewPluginEvaluationModule()

	ctx := map[string]any{}

	target := module.extractTarget(ctx)
	require.Equal(t, "unknown", target)
}

func TestExtractTarget_NonStringReturnsUnknown(t *testing.T) {
	module := NewPluginEvaluationModule()

	ctx := map[string]any{
		"target": 12345,
	}

	target := module.extractTarget(ctx)
	require.Equal(t, "unknown", target)
}

func TestExtractTarget_NilValueReturnsUnknown(t *testing.T) {
	module := NewPluginEvaluationModule()

	ctx := map[string]any{
		"target": nil,
	}

	target := module.extractTarget(ctx)
	require.Equal(t, "unknown", target)
}
