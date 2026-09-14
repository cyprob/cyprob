// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoader_Load(t *testing.T) {
	tmpDir := t.TempDir()

	// Create valid YAML plugin
	validYAML := `id: test-plugin
name: Test Plugin
version: 1.0.0
type: evaluation
author: cyprob-test

metadata:
  severity: high
  tags: [test, ssh]
  cve: CVE-2024-TEST

triggers:
  - data_key: ssh.version
    condition: exists
    value: true

match:
  logic: AND
  rules:
    - field: ssh.version
      operator: version_lt
      value: "8.0"

output:
  vulnerability: true
  message: "Test vulnerability found"
  remediation: "Upgrade SSH"
`

	yamlPath := filepath.Join(tmpDir, "test.yaml")
	err := os.WriteFile(yamlPath, []byte(validYAML), 0o644)
	require.NoError(t, err)

	loader := NewLoader(tmpDir)

	// Test loading YAML
	plugin, err := loader.Load(yamlPath)
	require.NoError(t, err)
	require.NotNil(t, plugin)
	require.Equal(t, "Test Plugin", plugin.Name)
	require.Equal(t, "1.0.0", plugin.Version)
	require.Equal(t, EvaluationType, plugin.Type)
	require.Equal(t, "cyprob-test", plugin.Author)
	require.Equal(t, HighSeverity, plugin.Metadata.Severity)
	require.Equal(t, "CVE-2024-TEST", plugin.Metadata.CVE)
	require.Len(t, plugin.Triggers, 1)
	require.NotNil(t, plugin.Match)
	require.Equal(t, "Test vulnerability found", plugin.Output.Message)

	// Test cache
	cached, ok := loader.GetCached(yamlPath)
	require.True(t, ok)
	require.Equal(t, plugin, cached)
}

func TestLoader_Load_JSON(t *testing.T) {
	tmpDir := t.TempDir()

	// Create valid JSON plugin
	validJSON := `{
  "id": "test-json-plugin",
  "name": "Test JSON Plugin",
  "version": "1.0.0",
  "type": "evaluation",
  "author": "cyprob-test",
  "metadata": {
    "severity": "medium",
    "tags": ["test", "http"]
  },
  "triggers": [
    {
      "data_key": "http.server",
      "condition": "exists",
      "value": true
    }
  ],
  "match": {
    "logic": "OR",
    "rules": [
      {
        "field": "http.server",
        "operator": "contains",
        "value": "Apache"
      }
    ]
  },
  "output": {
    "vulnerability": true,
    "message": "Apache server detected"
  }
}`

	jsonPath := filepath.Join(tmpDir, "test.json")
	err := os.WriteFile(jsonPath, []byte(validJSON), 0o644)
	require.NoError(t, err)

	loader := NewLoader(tmpDir)

	// Test loading JSON
	plugin, err := loader.Load(jsonPath)
	require.NoError(t, err)
	require.NotNil(t, plugin)
	require.Equal(t, "Test JSON Plugin", plugin.Name)
	require.Equal(t, "1.0.0", plugin.Version)
	require.Equal(t, MediumSeverity, plugin.Metadata.Severity)
}

func TestLoader_Load_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()

	invalidYAML := `id: invalid
name: Invalid
invalid yaml syntax here {{{
`

	yamlPath := filepath.Join(tmpDir, "invalid.yaml")
	err := os.WriteFile(yamlPath, []byte(invalidYAML), 0o644)
	require.NoError(t, err)

	loader := NewLoader(tmpDir)

	_, err = loader.Load(yamlPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse YAML plugin")
}

func TestLoader_Load_ValidationFailure(t *testing.T) {
	tmpDir := t.TempDir()

	// Missing required fields
	invalidYAML := `id: invalid-plugin
name: Invalid Plugin
# Missing version, type, author, etc.
`

	yamlPath := filepath.Join(tmpDir, "invalid.yaml")
	err := os.WriteFile(yamlPath, []byte(invalidYAML), 0o644)
	require.NoError(t, err)

	loader := NewLoader(tmpDir)

	_, err = loader.Load(yamlPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "plugin validation failed")
}

func TestLoader_Load_UnsupportedExtension(t *testing.T) {
	tmpDir := t.TempDir()

	txtPath := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(txtPath, []byte("test"), 0o644)
	require.NoError(t, err)

	loader := NewLoader(tmpDir)

	_, err = loader.Load(txtPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported file extension")
}

func TestLoader_LoadAll(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple plugins
	plugin1 := `id: plugin-1
name: Plugin 1
version: 1.0.0
type: evaluation
author: test
metadata:
  severity: high
  tags: [test]
output:
  vulnerability: true
  message: "Test 1"
`

	plugin2 := `id: plugin-2
name: Plugin 2
version: 1.0.0
type: evaluation
author: test
metadata:
  severity: medium
  tags: [test]
output:
  vulnerability: true
  message: "Test 2"
`

	err := os.WriteFile(filepath.Join(tmpDir, "plugin1.yaml"), []byte(plugin1), 0o644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tmpDir, "plugin2.yml"), []byte(plugin2), 0o644)
	require.NoError(t, err)

	// Create a non-plugin file (should be ignored)
	err = os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("readme"), 0o644)
	require.NoError(t, err)

	loader := NewLoader(tmpDir)

	plugins, err := loader.LoadAll(tmpDir)
	require.NoError(t, err)
	require.Len(t, plugins, 2)

	// Verify plugins
	names := []string{plugins[0].Name, plugins[1].Name}
	require.Contains(t, names, "Plugin 1")
	require.Contains(t, names, "Plugin 2")
}

func TestLoader_LoadRecursive(t *testing.T) {
	tmpDir := t.TempDir()

	// Create directory structure
	subDir := filepath.Join(tmpDir, "subdir")
	err := os.MkdirAll(subDir, 0o755)
	require.NoError(t, err)

	// Create plugins in both directories
	plugin1 := `id: root-plugin
name: Root Plugin
version: 1.0.0
type: evaluation
author: test
metadata:
  severity: high
  tags: [test]
output:
  vulnerability: true
  message: "Root plugin"
`

	plugin2 := `id: sub-plugin
name: Sub Plugin
version: 1.0.0
type: evaluation
author: test
metadata:
  severity: medium
  tags: [test]
output:
  vulnerability: true
  message: "Sub plugin"
`

	err = os.WriteFile(filepath.Join(tmpDir, "plugin1.yaml"), []byte(plugin1), 0o644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(subDir, "plugin2.yaml"), []byte(plugin2), 0o644)
	require.NoError(t, err)

	loader := NewLoader(tmpDir)

	plugins, err := loader.LoadRecursive(tmpDir)
	require.NoError(t, err)
	require.Len(t, plugins, 2)

	// Verify plugins
	names := []string{plugins[0].Name, plugins[1].Name}
	require.Contains(t, names, "Root Plugin")
	require.Contains(t, names, "Sub Plugin")
}

func TestLoader_Load_FileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	loader := NewLoader(tmpDir)

	_, err := loader.Load(filepath.Join(tmpDir, "nonexistent.yaml"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read plugin file")
}

func TestLoader_Load_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()

	invalidJSON := `{"name": "Invalid", invalid json here}`
	jsonPath := filepath.Join(tmpDir, "invalid.json")
	err := os.WriteFile(jsonPath, []byte(invalidJSON), 0o644)
	require.NoError(t, err)

	loader := NewLoader(tmpDir)

	_, err = loader.Load(jsonPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse JSON plugin")
}

func TestLoader_LoadAll_DirectoryNotFound(t *testing.T) {
	loader := NewLoader("/tmp")

	_, err := loader.LoadAll("/nonexistent/directory/path")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read directory")
}

func TestLoader_LoadAll_WithSubdirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create subdirectory (should be skipped)
	subDir := filepath.Join(tmpDir, "subdir")
	err := os.MkdirAll(subDir, 0o755)
	require.NoError(t, err)

	// Create plugin in root
	plugin1 := `id: plugin-1
name: Plugin 1
version: 1.0.0
type: evaluation
author: test
metadata:
  severity: high
  tags: [test]
output:
  vulnerability: true
  message: "Test 1"
`
	err = os.WriteFile(filepath.Join(tmpDir, "plugin1.yaml"), []byte(plugin1), 0o644)
	require.NoError(t, err)

	// Create plugin in subdirectory (should NOT be loaded by LoadAll)
	plugin2 := `id: plugin-2
name: Plugin 2
version: 1.0.0
type: evaluation
author: test
metadata:
  severity: medium
  tags: [test]
output:
  vulnerability: true
  message: "Test 2"
`
	err = os.WriteFile(filepath.Join(subDir, "plugin2.yaml"), []byte(plugin2), 0o644)
	require.NoError(t, err)

	loader := NewLoader(tmpDir)

	// LoadAll should only load root-level plugins
	plugins, err := loader.LoadAll(tmpDir)
	require.NoError(t, err)
	require.Len(t, plugins, 1)
	require.Equal(t, "Plugin 1", plugins[0].Name)
}

func TestLoader_LoadAll_WithErrors(t *testing.T) {
	tmpDir := t.TempDir()

	// Create valid plugin
	validPlugin := `id: valid-plugin
name: Valid Plugin
version: 1.0.0
type: evaluation
author: test
metadata:
  severity: high
  tags: [test]
output:
  vulnerability: true
  message: "Valid"
`
	err := os.WriteFile(filepath.Join(tmpDir, "valid.yaml"), []byte(validPlugin), 0o644)
	require.NoError(t, err)

	// Create invalid plugin (missing required fields)
	invalidPlugin := `id: invalid-plugin
name: Invalid Plugin
# Missing version and other required fields
`
	err = os.WriteFile(filepath.Join(tmpDir, "invalid.yaml"), []byte(invalidPlugin), 0o644)
	require.NoError(t, err)

	loader := NewLoader(tmpDir)

	// Should return valid plugins but also return error
	plugins, err := loader.LoadAll(tmpDir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to load")
	require.Len(t, plugins, 1) // Only valid plugin loaded
	require.Equal(t, "Valid Plugin", plugins[0].Name)
}

func TestLoader_LoadRecursive_WithErrors(t *testing.T) {
	tmpDir := t.TempDir()

	// Create valid plugin in root
	validPlugin := `id: valid-plugin
name: Valid Plugin
version: 1.0.0
type: evaluation
author: test
metadata:
  severity: high
  tags: [test]
output:
  vulnerability: true
  message: "Valid"
`
	err := os.WriteFile(filepath.Join(tmpDir, "valid.yaml"), []byte(validPlugin), 0o644)
	require.NoError(t, err)

	// Create subdirectory with invalid plugin
	subDir := filepath.Join(tmpDir, "subdir")
	err = os.MkdirAll(subDir, 0o755)
	require.NoError(t, err)

	invalidPlugin := `id: invalid
name: Invalid
# Missing required fields
`
	err = os.WriteFile(filepath.Join(subDir, "invalid.yaml"), []byte(invalidPlugin), 0o644)
	require.NoError(t, err)

	loader := NewLoader(tmpDir)

	// Should return valid plugins but also return error
	plugins, err := loader.LoadRecursive(tmpDir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to load")
	require.Len(t, plugins, 1) // Only valid plugin loaded
	require.Equal(t, "Valid Plugin", plugins[0].Name)
}

func TestLoader_LoadRecursive_IgnoresNonPluginFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create plugin
	validPlugin := `id: valid-plugin
name: Valid Plugin
version: 1.0.0
type: evaluation
author: test
metadata:
  severity: high
  tags: [test]
output:
  vulnerability: true
  message: "Valid"
`
	err := os.WriteFile(filepath.Join(tmpDir, "plugin.yaml"), []byte(validPlugin), 0o644)
	require.NoError(t, err)

	// Create non-plugin files (should be ignored)
	err = os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("readme"), 0o644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tmpDir, "config.toml"), []byte("config"), 0o644)
	require.NoError(t, err)

	loader := NewLoader(tmpDir)

	plugins, err := loader.LoadRecursive(tmpDir)
	require.NoError(t, err)
	require.Len(t, plugins, 1)
	require.Equal(t, "Valid Plugin", plugins[0].Name)
}

func TestLoader_LoadRecursive_WalkError(t *testing.T) {
	loader := NewLoader("/tmp")

	// Non-existent path should cause walk error
	_, err := loader.LoadRecursive("/nonexistent/directory/path")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to walk directory")
}

func TestLoader_ClearCache(t *testing.T) {
	tmpDir := t.TempDir()

	validYAML := `id: test
name: Test
version: 1.0.0
type: evaluation
author: test
metadata:
  severity: high
  tags: [test]
output:
  vulnerability: true
  message: "Test"
`

	yamlPath := filepath.Join(tmpDir, "test.yaml")
	err := os.WriteFile(yamlPath, []byte(validYAML), 0o644)
	require.NoError(t, err)

	loader := NewLoader(tmpDir)

	// Load plugin
	_, err = loader.Load(yamlPath)
	require.NoError(t, err)

	// Verify cached
	_, ok := loader.GetCached(yamlPath)
	require.True(t, ok)

	// Clear cache
	loader.ClearCache()

	// Verify cache cleared
	_, ok = loader.GetCached(yamlPath)
	require.False(t, ok)
}
