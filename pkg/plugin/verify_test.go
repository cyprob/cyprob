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

func TestNewVerifier(t *testing.T) {
	v := NewVerifier()
	require.NotNil(t, v)
	require.Equal(t, "sha256", v.Algorithm)
}

func TestVerifier_ComputeChecksum(t *testing.T) {
	// Create test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	testData := []byte("Hello, World!")
	err := os.WriteFile(testFile, testData, 0o644)
	require.NoError(t, err)

	v := NewVerifier()
	checksum, err := v.ComputeChecksum(testFile)
	require.NoError(t, err)
	require.NotEmpty(t, checksum)

	// Verify format: "sha256:..."
	require.Contains(t, checksum, "sha256:")
	require.Len(t, checksum, 71) // "sha256:" (7 chars) + 64 hex chars

	// Known SHA-256 of "Hello, World!"
	expectedChecksum := "sha256:dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
	require.Equal(t, expectedChecksum, checksum)
}

func TestVerifier_ComputeChecksum_EmptyPath(t *testing.T) {
	v := NewVerifier()
	checksum, err := v.ComputeChecksum("")
	require.Error(t, err)
	require.Empty(t, checksum)
	require.Contains(t, err.Error(), "file path cannot be empty")
}

func TestVerifier_ComputeChecksum_FileNotFound(t *testing.T) {
	v := NewVerifier()
	checksum, err := v.ComputeChecksum("/nonexistent/file.txt")
	require.Error(t, err)
	require.Empty(t, checksum)
	require.Contains(t, err.Error(), "failed to open file")
}

func TestVerifier_VerifyFile_Success(t *testing.T) {
	// Create test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	testData := []byte("Hello, World!")
	err := os.WriteFile(testFile, testData, 0o644)
	require.NoError(t, err)

	v := NewVerifier()

	// Compute expected checksum
	expectedChecksum, err := v.ComputeChecksum(testFile)
	require.NoError(t, err)

	// Verify file
	verified, err := v.VerifyFile(testFile, expectedChecksum)
	require.NoError(t, err)
	require.True(t, verified)
}

func TestVerifier_VerifyFile_Mismatch(t *testing.T) {
	// Create test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	testData := []byte("Hello, World!")
	err := os.WriteFile(testFile, testData, 0o644)
	require.NoError(t, err)

	v := NewVerifier()

	// Wrong checksum
	wrongChecksum := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	verified, err := v.VerifyFile(testFile, wrongChecksum)
	require.NoError(t, err)
	require.False(t, verified)
}

func TestVerifier_VerifyFile_EmptyPath(t *testing.T) {
	v := NewVerifier()
	verified, err := v.VerifyFile("", "sha256:abc")
	require.Error(t, err)
	require.False(t, verified)
	require.Contains(t, err.Error(), "file path cannot be empty")
}

func TestVerifier_VerifyFile_EmptyChecksum(t *testing.T) {
	v := NewVerifier()
	verified, err := v.VerifyFile("/some/file.txt", "")
	require.Error(t, err)
	require.False(t, verified)
	require.Contains(t, err.Error(), "expected checksum cannot be empty")
}

func TestVerifier_VerifyFile_WithoutPrefix(t *testing.T) {
	// Create test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	testData := []byte("Hello, World!")
	err := os.WriteFile(testFile, testData, 0o644)
	require.NoError(t, err)

	v := NewVerifier()

	// Checksum without "sha256:" prefix
	expectedChecksum := "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
	verified, err := v.VerifyFile(testFile, expectedChecksum)
	require.NoError(t, err)
	require.True(t, verified)
}

func TestVerifier_VerifyPlugin_Success(t *testing.T) {
	// Create test plugin file
	tmpDir := t.TempDir()
	pluginFile := filepath.Join(tmpDir, "plugin.yaml")
	pluginYAML := `id: test-plugin
name: test-plugin
version: 1.0.0
type: evaluation
author: test
metadata:
  severity: high
  tags: [test]
output:
  message: Test
`
	err := os.WriteFile(pluginFile, []byte(pluginYAML), 0o644)
	require.NoError(t, err)

	// Load plugin
	loader := NewLoader(tmpDir)
	plugin, err := loader.Load(pluginFile)
	require.NoError(t, err)

	v := NewVerifier()

	// Compute checksum
	expectedChecksum, err := v.ComputeChecksum(pluginFile)
	require.NoError(t, err)

	// Verify plugin
	verified, err := v.VerifyPlugin(plugin, expectedChecksum)
	require.NoError(t, err)
	require.True(t, verified)
}

func TestVerifier_VerifyPlugin_NilPlugin(t *testing.T) {
	v := NewVerifier()
	verified, err := v.VerifyPlugin(nil, "sha256:abc")
	require.Error(t, err)
	require.False(t, verified)
	require.Contains(t, err.Error(), "plugin cannot be nil")
}

func TestVerifier_VerifyPlugin_EmptyFilePath(t *testing.T) {
	plugin := &YAMLPlugin{
		Name:     "test",
		FilePath: "", // No file path
	}

	v := NewVerifier()
	verified, err := v.VerifyPlugin(plugin, "sha256:abc")
	require.Error(t, err)
	require.False(t, verified)
	require.Contains(t, err.Error(), "file path is empty")
}

func TestVerifier_VerifyAll(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple plugin files
	plugins := []*YAMLPlugin{}
	checksums := make(map[string]string)

	for i := 1; i <= 3; i++ {
		pluginFile := filepath.Join(tmpDir, "plugin"+string(rune('0'+i))+".yaml")
		pluginYAML := `id: test-plugin
name: plugin` + string(rune('0'+i)) + `
version: 1.0.0
type: evaluation
author: test
metadata:
  severity: high
  tags: [test]
output:
  message: Test
`
		err := os.WriteFile(pluginFile, []byte(pluginYAML), 0o644)
		require.NoError(t, err)

		// Load plugin
		loader := NewLoader(tmpDir)
		plugin, err := loader.Load(pluginFile)
		require.NoError(t, err)
		plugins = append(plugins, plugin)

		// Compute checksum
		v := NewVerifier()
		checksum, err := v.ComputeChecksum(pluginFile)
		require.NoError(t, err)
		checksums[plugin.Name] = checksum
	}

	// Verify all
	v := NewVerifier()
	results := v.VerifyAll(plugins, checksums)
	require.Len(t, results, 3)

	// All should be verified
	for _, result := range results {
		require.True(t, result.Verified)
		require.NoError(t, result.Error)
	}
}

func TestVerifier_VerifyAll_MissingChecksum(t *testing.T) {
	tmpDir := t.TempDir()

	// Create plugin
	pluginFile := filepath.Join(tmpDir, "plugin.yaml")
	pluginYAML := `id: test-plugin
name: test-plugin
version: 1.0.0
type: evaluation
author: test
metadata:
  severity: high
  tags: [test]
output:
  message: Test
`
	err := os.WriteFile(pluginFile, []byte(pluginYAML), 0o644)
	require.NoError(t, err)

	loader := NewLoader(tmpDir)
	plugin, err := loader.Load(pluginFile)
	require.NoError(t, err)

	// Verify without checksum
	v := NewVerifier()
	results := v.VerifyAll([]*YAMLPlugin{plugin}, map[string]string{})
	require.Len(t, results, 1)

	result := results["test-plugin"]
	require.NotNil(t, result)
	require.False(t, result.Verified)
	require.Error(t, result.Error)
	require.Contains(t, result.Error.Error(), "no checksum found")
}

func TestVerifier_VerifyAll_WrongChecksum(t *testing.T) {
	tmpDir := t.TempDir()

	// Create plugin
	pluginFile := filepath.Join(tmpDir, "plugin.yaml")
	pluginYAML := `id: test-plugin
name: test-plugin
version: 1.0.0
type: evaluation
author: test
metadata:
  severity: high
  tags: [test]
output:
  message: Test
`
	err := os.WriteFile(pluginFile, []byte(pluginYAML), 0o644)
	require.NoError(t, err)

	loader := NewLoader(tmpDir)
	plugin, err := loader.Load(pluginFile)
	require.NoError(t, err)

	// Verify with wrong checksum
	v := NewVerifier()
	checksums := map[string]string{
		"test-plugin": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	results := v.VerifyAll([]*YAMLPlugin{plugin}, checksums)
	require.Len(t, results, 1)

	result := results["test-plugin"]
	require.NotNil(t, result)
	require.False(t, result.Verified)
	require.NoError(t, result.Error) // No error, just not verified
}

func TestParseChecksum_WithPrefix(t *testing.T) {
	algo, hex, err := ParseChecksum("sha256:abc123def456")
	require.NoError(t, err)
	require.Equal(t, "sha256", algo)
	require.Equal(t, "abc123def456", hex)
}

func TestParseChecksum_WithoutPrefix(t *testing.T) {
	algo, hex, err := ParseChecksum("abc123def456")
	require.NoError(t, err)
	require.Equal(t, "sha256", algo) // Default
	require.Equal(t, "abc123def456", hex)
}

func TestParseChecksum_Empty(t *testing.T) {
	algo, hex, err := ParseChecksum("")
	require.Error(t, err)
	require.Empty(t, algo)
	require.Empty(t, hex)
	require.Contains(t, err.Error(), "checksum cannot be empty")
}

func TestFormatChecksum(t *testing.T) {
	checksum := FormatChecksum("sha256", "abc123def456")
	require.Equal(t, "sha256:abc123def456", checksum)
}

func TestVerifier_NormalizeChecksum(t *testing.T) {
	v := NewVerifier()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "with prefix",
			input:    "sha256:abc123",
			expected: "abc123",
		},
		{
			name:     "without prefix",
			input:    "abc123",
			expected: "abc123",
		},
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.normalizeChecksum(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}
