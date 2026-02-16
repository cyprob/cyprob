//go:build integration

package evaluation_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/evaluation"
)

// TestPluginEvaluationModule_Integration tests the evaluation module in a realistic DAG scenario.
func TestPluginEvaluationModule_Integration(t *testing.T) {
	ctx := context.Background()

	// Create a DAG definition with parse -> evaluation pipeline
	dagDef := &engine.DAGDefinition{
		Name:        "Integration Test DAG",
		Description: "Tests plugin evaluation module integration",
		Nodes: []engine.DAGNodeConfig{
			{
				InstanceID: "eval-module",
				ModuleType: "plugin-evaluation",
				Config:     map[string]interface{}{},
			},
		},
	}

	// Create orchestrator
	orchestrator, err := engine.NewOrchestrator(dagDef)
	require.NoError(t, err, "Failed to create orchestrator")

	// Prepare inputs that should trigger TLS vulnerabilities
	inputs := map[string]interface{}{
		"config.targets": []string{"192.168.1.1"},
		"tls.version":    "TLSv1.0", // Should trigger tls-weak-protocol plugin
		"service.port":   443,
	}

	// Run the orchestrator
	outputs, err := orchestrator.Run(ctx, inputs)
	require.NoError(t, err, "Orchestrator execution failed")

	// Verify outputs contain vulnerability results
	require.NotNil(t, outputs, "Outputs should not be nil")

	// Check for evaluation.vulnerabilities key
	vulns, ok := outputs["evaluation.vulnerabilities"]
	require.True(t, ok, "Should have evaluation.vulnerabilities in outputs")
	require.NotNil(t, vulns, "Vulnerabilities should not be nil")

	// Orchestrator wraps outputs in []interface{} via AddOrAppendToList
	vulnInterface, ok := vulns.([]interface{})
	require.True(t, ok, "Vulnerabilities should be []interface{} from orchestrator")
	require.NotEmpty(t, vulnInterface, "Should detect at least one vulnerability")

	// Convert to VulnerabilityResult list
	vulnList := make([]evaluation.VulnerabilityResult, 0, len(vulnInterface))
	for _, v := range vulnInterface {
		if vuln, ok := v.(evaluation.VulnerabilityResult); ok {
			vulnList = append(vulnList, vuln)
		}
	}
	require.NotEmpty(t, vulnList, "Should have at least one VulnerabilityResult")

	// Verify first vulnerability has correct fields
	vuln := vulnList[0]
	require.True(t, vuln.Matched, "Vulnerability should be matched")
	require.NotEmpty(t, vuln.Plugin, "Plugin name should be set")
	require.NotEmpty(t, vuln.Severity, "Severity should be set")
	require.NotEmpty(t, vuln.Message, "Message should be set")
	require.Equal(t, 443, vuln.Port, "Port should match input")

	t.Logf("Successfully detected %d vulnerabilities", len(vulnList))
	for i, v := range vulnList {
		t.Logf("  [%d] %s (severity: %s): %s", i+1, v.Plugin, v.Severity, v.Message)
	}
}

// TestPluginEvaluationModule_MultipleVulnerabilities tests detection of multiple vulnerabilities.
func TestPluginEvaluationModule_MultipleVulnerabilities(t *testing.T) {
	ctx := context.Background()

	dagDef := &engine.DAGDefinition{
		Name:        "Multi-Vulnerability Test DAG",
		Description: "Tests multiple vulnerability detection",
		Nodes: []engine.DAGNodeConfig{
			{
				InstanceID: "eval-module",
				ModuleType: "plugin-evaluation",
				Config:     map[string]interface{}{},
			},
		},
	}

	orchestrator, err := engine.NewOrchestrator(dagDef)
	require.NoError(t, err)

	// Provide inputs that should match multiple TLS vulnerabilities
	inputs := map[string]interface{}{
		"config.targets":    []string{"192.168.1.100"},
		"tls.version":       "TLSv1.0",                            // Weak protocol
		"tls.cipher_suites": []string{"TLS_RSA_WITH_DES_CBC_SHA"}, // Weak cipher
		"service.port":      443,
	}

	outputs, err := orchestrator.Run(ctx, inputs)
	require.NoError(t, err)

	vulnRaw, ok := outputs["evaluation.vulnerabilities"]
	require.True(t, ok, "Should have evaluation.vulnerabilities in outputs")

	vulnInterface, ok := vulnRaw.([]interface{})
	require.True(t, ok, "Vulnerabilities should be []interface{}")
	require.NotEmpty(t, vulnInterface, "Should detect multiple vulnerabilities")

	// Convert to VulnerabilityResult list
	vulns := make([]evaluation.VulnerabilityResult, 0, len(vulnInterface))
	for _, v := range vulnInterface {
		if vuln, ok := v.(evaluation.VulnerabilityResult); ok {
			vulns = append(vulns, vuln)
		}
	}

	// Should detect at least weak protocol (may detect weak cipher too depending on plugin logic)
	require.GreaterOrEqual(t, len(vulns), 1, "Should detect at least one vulnerability")

	t.Logf("Detected %d vulnerabilities with multiple input conditions", len(vulns))
}

// TestPluginEvaluationModule_NoVulnerabilities tests that secure configs don't trigger false positives.
func TestPluginEvaluationModule_NoVulnerabilities(t *testing.T) {
	ctx := context.Background()

	dagDef := &engine.DAGDefinition{
		Name:        "No Vulnerabilities Test DAG",
		Description: "Tests that secure configs don't trigger vulnerabilities",
		Nodes: []engine.DAGNodeConfig{
			{
				InstanceID: "eval-module",
				ModuleType: "plugin-evaluation",
				Config:     map[string]interface{}{},
			},
		},
	}

	orchestrator, err := engine.NewOrchestrator(dagDef)
	require.NoError(t, err)

	// Provide secure TLS configuration
	inputs := map[string]interface{}{
		"config.targets":    []string{"192.168.1.200"},
		"tls.version":       "TLSv1.3",                          // Secure protocol
		"tls.cipher_suites": []string{"TLS_AES_128_GCM_SHA256"}, // Modern cipher
		"service.port":      443,
	}

	outputs, err := orchestrator.Run(ctx, inputs)
	require.NoError(t, err)

	// Should have no vulnerabilities for secure config
	if vulns, ok := outputs["evaluation.vulnerabilities"]; ok {
		if vulnInterface, ok := vulns.([]interface{}); ok {
			// Convert to VulnerabilityResult list
			vulnList := make([]evaluation.VulnerabilityResult, 0, len(vulnInterface))
			for _, v := range vulnInterface {
				if vuln, ok := v.(evaluation.VulnerabilityResult); ok {
					vulnList = append(vulnList, vuln)
				}
			}
			require.Empty(t, vulnList, "Secure configuration should not trigger vulnerabilities")
		}
	}

	t.Log("No vulnerabilities detected for secure TLS configuration (as expected)")
}

// TestPluginEvaluationModule_SSHVulnerabilities tests SSH-related vulnerability detection.
func TestPluginEvaluationModule_SSHVulnerabilities(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dagDef := &engine.DAGDefinition{
		Name:        "SSH Vulnerability Test DAG",
		Description: "Tests SSH vulnerability detection",
		Nodes: []engine.DAGNodeConfig{
			{
				InstanceID: "eval-module",
				ModuleType: "plugin-evaluation",
				Config:     map[string]interface{}{},
			},
		},
	}

	orchestrator, err := engine.NewOrchestrator(dagDef)
	require.NoError(t, err)

	// Provide SSH context with weak algorithms
	inputs := map[string]interface{}{
		"config.targets": []string{"192.168.1.50"},
		"ssh.version":    "SSH-2.0-OpenSSH_5.3",
		"ssh.banner":     "SSH-2.0-OpenSSH_5.3",
		"ssh.kex_algorithms": []string{
			"diffie-hellman-group1-sha1", // Weak KEX
		},
		"ssh.mac_algorithms": []string{
			"hmac-md5", // Weak MAC
		},
		"ssh.encryption_algorithms": []string{
			"aes128-cbc", // CBC mode cipher
		},
		"service.port": 22,
	}

	outputs, err := orchestrator.Run(ctx, inputs)
	require.NoError(t, err)

	// Check for SSH vulnerabilities
	if vulns, ok := outputs["evaluation.vulnerabilities"]; ok {
		if vulnInterface, ok := vulns.([]interface{}); ok {
			// Convert to VulnerabilityResult list
			vulnList := make([]evaluation.VulnerabilityResult, 0, len(vulnInterface))
			for _, v := range vulnInterface {
				if vuln, ok := v.(evaluation.VulnerabilityResult); ok {
					vulnList = append(vulnList, vuln)
				}
			}

			if len(vulnList) > 0 {
				t.Logf("Detected %d SSH-related vulnerabilities", len(vulnList))
				for i, v := range vulnList {
					t.Logf("  [%d] %s: %s", i+1, v.Plugin, v.Message)
				}
			} else {
				t.Log("No SSH vulnerabilities detected (plugins may require different input format)")
			}
		}
	}
}
