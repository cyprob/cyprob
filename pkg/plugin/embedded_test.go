// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadEmbeddedPlugins(t *testing.T) {
	plugins, err := LoadEmbeddedPlugins()
	require.NoError(t, err)
	require.NotNil(t, plugins)

	// Verify we have plugins in expected categories
	require.NotEmpty(t, plugins, "should have embedded plugins")

	// Check SSH category
	sshPlugins, ok := plugins[CategorySSH]
	require.True(t, ok, "should have SSH category")
	require.GreaterOrEqual(t, len(sshPlugins), 4, "should have at least 4 SSH plugins")

	// Check HTTP category
	httpPlugins, ok := plugins[CategoryHTTP]
	require.True(t, ok, "should have HTTP category")
	require.GreaterOrEqual(t, len(httpPlugins), 4, "should have at least 4 HTTP plugins")

	// Check TLS category
	tlsPlugins, ok := plugins[CategoryTLS]
	require.True(t, ok, "should have TLS category")
	require.GreaterOrEqual(t, len(tlsPlugins), 4, "should have at least 4 TLS plugins")

	// Check Database category
	dbPlugins, ok := plugins[CategoryDatabase]
	require.True(t, ok, "should have Database category")
	require.GreaterOrEqual(t, len(dbPlugins), 3, "should have at least 3 Database plugins")

	// Verify all plugins are valid
	for category, catPlugins := range plugins {
		for _, plugin := range catPlugins {
			require.NotEmpty(t, plugin.Name, "plugin name should not be empty")
			require.NotEmpty(t, plugin.Version, "plugin version should not be empty")
			require.NotEmpty(t, plugin.Author, "plugin author should not be empty")
			require.NotNil(t, plugin.Metadata, "plugin metadata should not be nil")
			t.Logf("Category %s: %s v%s", category.String(), plugin.Name, plugin.Version)
		}
	}
}

func TestLoadEmbeddedPluginsByCategory(t *testing.T) {
	tests := []struct {
		name        string
		category    Category
		minExpected int
		shouldHave  bool
	}{
		{"SSH plugins", CategorySSH, 4, true},
		{"HTTP plugins", CategoryHTTP, 4, true},
		{"TLS plugins", CategoryTLS, 4, true},
		{"Database plugins", CategoryDatabase, 3, true},
		{"Network plugins", CategoryNetwork, 0, true}, // Misconfig mapped to Network
		{"IoT plugins", CategoryIoT, 0, false},        // No IoT plugins yet
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugins, err := LoadEmbeddedPluginsByCategory(tt.category)
			require.NoError(t, err)

			if tt.shouldHave && tt.minExpected > 0 {
				require.GreaterOrEqual(t, len(plugins), tt.minExpected,
					"should have at least %d plugins for category %s", tt.minExpected, tt.category.String())
			}

			// Verify plugin structure
			for _, plugin := range plugins {
				require.NotEmpty(t, plugin.Name)
				require.NotEmpty(t, plugin.Version)
				require.Equal(t, EvaluationType, plugin.Type, "embedded plugins should be evaluation type")
			}
		})
	}
}

func TestLoadAllEmbeddedPlugins(t *testing.T) {
	plugins, err := LoadAllEmbeddedPlugins()
	require.NoError(t, err)
	require.NotNil(t, plugins)
	require.GreaterOrEqual(t, len(plugins), 18, "should have at least 18 embedded plugins")

	// Verify unique plugin names
	names := make(map[string]bool)
	for _, plugin := range plugins {
		require.False(t, names[plugin.Name], "plugin name should be unique: %s", plugin.Name)
		names[plugin.Name] = true
	}
}

func TestGetEmbeddedPluginCount(t *testing.T) {
	count, err := GetEmbeddedPluginCount()
	require.NoError(t, err)
	require.GreaterOrEqual(t, count, 18, "should have at least 18 embedded plugins")
	t.Logf("Total embedded plugins: %d", count)
}

func TestDetermineCategoryFromPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected Category
	}{
		{"SSH plugin", "embedded/ssh/ssh-weak-cipher.yaml", CategorySSH},
		{"HTTP plugin", "embedded/http/http-missing-headers.yaml", CategoryHTTP},
		{"TLS plugin", "embedded/tls/tls-weak-cipher.yaml", CategoryTLS},
		{"Database plugin", "embedded/database/mysql-default-creds.yaml", CategoryDatabase},
		{"Misconfig plugin", "embedded/misconfig/open-telnet.yaml", CategoryNetwork},
		{"Unknown category", "embedded/unknown/test.yaml", CategoryMisc},
		{"Invalid path", "test.yaml", CategoryMisc},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			category := determineCategoryFromPath(tt.path)
			require.Equal(t, tt.expected, category)
		})
	}
}

func TestEmbeddedPluginContent(t *testing.T) {
	// Test specific plugins to ensure they have expected content
	plugins, err := LoadAllEmbeddedPlugins()
	require.NoError(t, err)

	// Find SSH weak cipher plugin
	var sshWeakCipher *YAMLPlugin
	for _, p := range plugins {
		if p.Name == "SSH Weak Encryption Cipher" {
			sshWeakCipher = p
			break
		}
	}

	require.NotNil(t, sshWeakCipher, "should find SSH weak cipher plugin")
	require.Equal(t, "1.0.0", sshWeakCipher.Version)
	require.Equal(t, "cyprob-security", sshWeakCipher.Author)
	require.Equal(t, HighSeverity, sshWeakCipher.Metadata.Severity)
	require.Contains(t, sshWeakCipher.Metadata.Tags, "ssh")
	require.Contains(t, sshWeakCipher.Metadata.Tags, "crypto")
	require.NotEmpty(t, sshWeakCipher.Match.Rules, "should have match rules")
	require.NotEmpty(t, sshWeakCipher.Output.Message, "should have output message")
	require.NotEmpty(t, sshWeakCipher.Output.Remediation, "should have remediation")
}

func TestEmbeddedPluginsHaveRequiredFields(t *testing.T) {
	plugins, err := LoadAllEmbeddedPlugins()
	require.NoError(t, err)

	for _, plugin := range plugins {
		t.Run(plugin.Name, func(t *testing.T) {
			// Required fields
			require.NotEmpty(t, plugin.Name, "name is required")
			require.NotEmpty(t, plugin.Version, "version is required")
			require.NotEmpty(t, plugin.Author, "author is required")
			require.Equal(t, EvaluationType, plugin.Type, "type should be evaluation")

			// Metadata
			require.NotNil(t, plugin.Metadata, "metadata is required")
			require.NotEmpty(t, plugin.Metadata.Severity, "severity is required")
			require.NotEmpty(t, plugin.Metadata.Tags, "tags are required")

			// Triggers
			require.NotEmpty(t, plugin.Triggers, "triggers are required")

			// Match rules
			require.NotNil(t, plugin.Match, "match block is required")
			require.NotEmpty(t, plugin.Match.Rules, "match rules are required")

			// Output
			require.True(t, plugin.Output.Vulnerability, "embedded plugins should mark vulnerabilities")
			require.NotEmpty(t, plugin.Output.Message, "output message is required")
			require.NotEmpty(t, plugin.Output.Remediation, "remediation is required")
		})
	}
}
