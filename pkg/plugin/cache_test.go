// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestNewCacheManager(t *testing.T) {
	// Create temporary cache directory
	cacheDir := t.TempDir()

	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)
	require.NotNil(t, cm)
	require.Equal(t, cacheDir, cm.cacheDir)
	require.NotNil(t, cm.registry)

	// Verify directory was created
	info, err := os.Stat(cacheDir)
	require.NoError(t, err)
	require.True(t, info.IsDir())
}

func TestNewCacheManager_EmptyPath(t *testing.T) {
	cm, err := NewCacheManager("")
	require.Error(t, err)
	require.Nil(t, cm)
	require.Contains(t, err.Error(), "cache directory cannot be empty")
}

func TestNewCacheManager_LoadsExistingPlugins(t *testing.T) {
	// Create cache directory with pre-existing plugins
	cacheDir := t.TempDir()

	// Create plugin structure manually (simulate previous downloads)
	plugin1Dir := filepath.Join(cacheDir, "test-plugin-1", "1.0.0")
	require.NoError(t, os.MkdirAll(plugin1Dir, 0o755))

	plugin1 := &YAMLPlugin{
		ID:      "test-plugin-1",
		Name:    "test-plugin-1",
		Version: "1.0.0",
		Type:    "evaluation",
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: "high",
			Tags:     []string{"test"},
		},
		Triggers: []Trigger{
			{DataKey: "test.key", Condition: "exists", Value: true},
		},
		Match: &MatchBlock{
			Logic: "OR",
			Rules: []MatchRule{
				{Field: "test.field", Operator: "equals", Value: "test"},
			},
		},
		Output: OutputBlock{
			Vulnerability: true,
			Message:       "Test",
			Remediation:   "Fix it",
		},
	}

	data, err := yaml.Marshal(plugin1)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(plugin1Dir, "plugin.yaml"), data, 0o644))

	// Create second plugin
	plugin2Dir := filepath.Join(cacheDir, "test-plugin-2", "2.0.0")
	require.NoError(t, os.MkdirAll(plugin2Dir, 0o755))

	plugin2 := &YAMLPlugin{
		ID:      "test-plugin-2",
		Name:    "test-plugin-2",
		Version: "2.0.0",
		Type:    "evaluation",
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: "critical",
			Tags:     []string{"test2"},
		},
		Triggers: []Trigger{
			{DataKey: "test.key2", Condition: "exists", Value: true},
		},
		Match: &MatchBlock{
			Logic: "AND",
			Rules: []MatchRule{
				{Field: "test.field2", Operator: "contains", Value: "value"},
			},
		},
		Output: OutputBlock{
			Vulnerability: true,
			Message:       "Test2",
			Remediation:   "Fix it too",
		},
	}

	data2, err := yaml.Marshal(plugin2)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(plugin2Dir, "plugin.yaml"), data2, 0o644))

	// Create CacheManager - should load existing plugins
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)
	require.NotNil(t, cm)

	// Verify plugins were loaded into registry
	loaded1, found1 := cm.Get("test-plugin-1")
	require.True(t, found1, "test-plugin-1 should be loaded from disk")
	require.Equal(t, "1.0.0", loaded1.Version)

	loaded2, found2 := cm.Get("test-plugin-2")
	require.True(t, found2, "test-plugin-2 should be loaded from disk")
	require.Equal(t, "2.0.0", loaded2.Version)

	// Verify registry size
	all := cm.List()
	require.Len(t, all, 2, "should have 2 plugins loaded")
}

func TestCacheManager_Add(t *testing.T) {
	cacheDir := t.TempDir()
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	plugin := &YAMLPlugin{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Output: OutputBlock{Message: "Test"},
	}

	entry, err := cm.Add(context.Background(), plugin, "sha256:abc123", "https://example.com/plugin.yaml")
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, "test-plugin", entry.Name)
	require.Equal(t, "1.0.0", entry.Version)
	require.Equal(t, "sha256:abc123", entry.Checksum)
	require.Equal(t, "https://example.com/plugin.yaml", entry.DownloadURL)
	require.False(t, entry.CachedAt.IsZero())
	require.False(t, entry.LastUsed.IsZero())

	// Verify directory was created
	expectedDir := filepath.Join(cacheDir, "test-plugin", "1.0.0")
	info, err := os.Stat(expectedDir)
	require.NoError(t, err)
	require.True(t, info.IsDir())

	// Verify plugin in registry
	cachedPlugin, exists := cm.Get("test-plugin")
	require.True(t, exists)
	require.Equal(t, "test-plugin", cachedPlugin.Name)
}

func TestCacheManager_Add_NilPlugin(t *testing.T) {
	cacheDir := t.TempDir()
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	entry, err := cm.Add(context.Background(), nil, "sha256:abc", "https://example.com")
	require.Error(t, err)
	require.Nil(t, entry)
	require.Contains(t, err.Error(), "cannot cache nil plugin")
}

func TestCacheManager_Add_InvalidPlugin(t *testing.T) {
	cacheDir := t.TempDir()
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	// Plugin missing required fields
	plugin := &YAMLPlugin{
		ID:   "invalid-plugin",
		Name: "invalid-plugin",
		// Missing version, type, author, etc.
	}

	entry, err := cm.Add(context.Background(), plugin, "sha256:abc", "https://example.com")
	require.Error(t, err)
	require.Nil(t, entry)
	require.Contains(t, err.Error(), "validation failed")
}

func TestCacheManager_Add_Duplicate(t *testing.T) {
	cacheDir := t.TempDir()
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	plugin := &YAMLPlugin{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Output: OutputBlock{Message: "Test"},
	}

	// Add first time
	_, err = cm.Add(context.Background(), plugin, "sha256:abc123", "https://example.com/v1.yaml")
	require.NoError(t, err)

	// Add again with different checksum (simulates update)
	plugin.Version = "1.0.1"
	entry, err := cm.Add(context.Background(), plugin, "sha256:def456", "https://example.com/v2.yaml")
	require.NoError(t, err)
	require.Equal(t, "sha256:def456", entry.Checksum)
}

func TestCacheManager_Get(t *testing.T) {
	cacheDir := t.TempDir()
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	plugin := &YAMLPlugin{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Output: OutputBlock{Message: "Test"},
	}

	_, err = cm.Add(context.Background(), plugin, "sha256:abc", "https://example.com")
	require.NoError(t, err)

	// Get existing plugin
	cached, exists := cm.Get("test-plugin")
	require.True(t, exists)
	require.Equal(t, "test-plugin", cached.Name)

	// Get non-existent plugin
	_, exists = cm.Get("non-existent")
	require.False(t, exists)
}

func TestCacheManager_Remove(t *testing.T) {
	cacheDir := t.TempDir()
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	plugin := &YAMLPlugin{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Output: OutputBlock{Message: "Test"},
	}

	_, err = cm.Add(context.Background(), plugin, "sha256:abc", "https://example.com")
	require.NoError(t, err)

	// Verify plugin exists
	_, exists := cm.Get("test-plugin")
	require.True(t, exists)

	// Remove plugin
	err = cm.Remove(context.Background(), "test-plugin", "1.0.0")
	require.NoError(t, err)

	// Verify plugin is gone
	_, exists = cm.Get("test-plugin")
	require.False(t, exists)

	// Verify directory is removed
	pluginDir := filepath.Join(cacheDir, "test-plugin", "1.0.0")
	_, err = os.Stat(pluginDir)
	require.True(t, os.IsNotExist(err))
}

func TestCacheManager_Remove_NotFound(t *testing.T) {
	cacheDir := t.TempDir()
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	err = cm.Remove(context.Background(), "non-existent", "1.0.0")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func TestCacheManager_List(t *testing.T) {
	cacheDir := t.TempDir()
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	// Add multiple plugins
	for i := 1; i <= 3; i++ {
		pluginID := "plugin-" + string(rune('0'+i))
		plugin := &YAMLPlugin{
			ID:      pluginID,
			Name:    pluginID,
			Version: "1.0.0",
			Type:    EvaluationType,
			Author:  "test",
			Metadata: PluginMetadata{
				Severity: HighSeverity,
				Tags:     []string{"test"},
			},
			Output: OutputBlock{Message: "Test"},
		}
		_, err = cm.Add(context.Background(), plugin, "sha256:abc", "https://example.com")
		require.NoError(t, err)
	}

	plugins := cm.List()
	require.Len(t, plugins, 3)
}

func TestCacheManager_Clear(t *testing.T) {
	cacheDir := t.TempDir()
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	// Add plugins
	plugin := &YAMLPlugin{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Output: OutputBlock{Message: "Test"},
	}

	_, err = cm.Add(context.Background(), plugin, "sha256:abc", "https://example.com")
	require.NoError(t, err)

	// Verify plugin exists
	require.Len(t, cm.List(), 1)

	// Clear cache
	err = cm.Clear(context.Background())
	require.NoError(t, err)

	// Verify cache is empty
	require.Len(t, cm.List(), 0)

	// Verify directories are removed
	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestCacheManager_Size(t *testing.T) {
	cacheDir := t.TempDir()
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	// Initial size should be 0
	size, err := cm.Size(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(0), size)

	// Create test file in cache
	testFile := filepath.Join(cacheDir, "test.txt")
	testData := []byte("Hello, World!")
	err = os.WriteFile(testFile, testData, 0o644)
	require.NoError(t, err)

	// Size should include test file
	size, err = cm.Size(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(len(testData)), size)
}

func TestCacheManager_Prune(t *testing.T) {
	cacheDir := t.TempDir()
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	// Add old plugin
	oldPluginDir := filepath.Join(cacheDir, "old-plugin", "1.0.0")
	err = os.MkdirAll(oldPluginDir, 0o755)
	require.NoError(t, err)

	// Set modification time to 2 days ago
	oldTime := time.Now().Add(-48 * time.Hour)
	err = os.Chtimes(filepath.Join(cacheDir, "old-plugin"), oldTime, oldTime)
	require.NoError(t, err)

	// Add recent plugin
	recentPlugin := &YAMLPlugin{
		ID:      "recent-plugin",
		Name:    "recent-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Output: OutputBlock{Message: "Test"},
	}
	_, err = cm.Add(context.Background(), recentPlugin, "sha256:abc", "https://example.com")
	require.NoError(t, err)

	// Prune plugins older than 24 hours
	removed, err := cm.Prune(context.Background(), 24*time.Hour)
	require.NoError(t, err)
	require.Equal(t, 1, removed)

	// Verify old plugin is removed
	_, err = os.Stat(oldPluginDir)
	require.True(t, os.IsNotExist(err))

	// Verify recent plugin still exists
	recentPluginDir := filepath.Join(cacheDir, "recent-plugin", "1.0.0")
	_, err = os.Stat(recentPluginDir)
	require.NoError(t, err)
}

func TestCacheManager_LoadFromDisk(t *testing.T) {
	cacheDir := t.TempDir()

	// Create test plugin files
	pluginDir := filepath.Join(cacheDir, "test-plugin", "1.0.0")
	err := os.MkdirAll(pluginDir, 0o755)
	require.NoError(t, err)

	pluginYAML := `id: test-plugin
name: test-plugin
version: 1.0.0
type: evaluation
author: test
metadata:
  severity: high
  tags:
    - test
output:
  vulnerability: true
  message: Test finding
`
	pluginFile := filepath.Join(pluginDir, "plugin.yaml")
	err = os.WriteFile(pluginFile, []byte(pluginYAML), 0o644)
	require.NoError(t, err)

	// Create cache manager - automatically loads from disk
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	// Verify plugin was loaded during initialization
	plugin, exists := cm.Get("test-plugin")
	require.True(t, exists, "plugin should be loaded automatically")
	require.Equal(t, "test-plugin", plugin.Name)
	require.Equal(t, "1.0.0", plugin.Version)
}

func TestCacheManager_LoadFromDisk_WithErrors(t *testing.T) {
	cacheDir := t.TempDir()

	// Create valid plugin
	validDir := filepath.Join(cacheDir, "valid-plugin", "1.0.0")
	err := os.MkdirAll(validDir, 0o755)
	require.NoError(t, err)

	validYAML := `id: valid-plugin
name: valid-plugin
version: 1.0.0
type: evaluation
author: test
metadata:
  severity: high
  tags: [test]
output:
  message: Valid
`
	err = os.WriteFile(filepath.Join(validDir, "plugin.yaml"), []byte(validYAML), 0o644)
	require.NoError(t, err)

	// Create invalid plugin
	invalidDir := filepath.Join(cacheDir, "invalid-plugin", "1.0.0")
	err = os.MkdirAll(invalidDir, 0o755)
	require.NoError(t, err)

	invalidYAML := `id: invalid-plugin
name: invalid-plugin
version: 1.0.0
# Missing required fields
`
	err = os.WriteFile(filepath.Join(invalidDir, "plugin.yaml"), []byte(invalidYAML), 0o644)
	require.NoError(t, err)

	// Create cache manager - loads from disk automatically
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	// Verify valid plugin loaded (invalid one silently ignored)
	validPlugin, exists := cm.Get("valid-plugin")
	require.True(t, exists, "valid plugin should be loaded")
	require.Equal(t, "valid-plugin", validPlugin.Name)

	// Verify invalid plugin not loaded
	_, exists = cm.Get("invalid-plugin")
	require.False(t, exists, "invalid plugin should not be loaded")
}

func TestNewCacheManager_CreateDirError(t *testing.T) {
	// Create a file where the cache directory should be
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "file-not-dir")
	err := os.WriteFile(filePath, []byte("test"), 0o644)
	require.NoError(t, err)

	// Try to create cache manager with path that has a file in the way
	cachePath := filepath.Join(filePath, "cache")
	cm, err := NewCacheManager(cachePath)
	require.Error(t, err)
	require.Nil(t, cm)
	require.Contains(t, err.Error(), "failed to create cache directory")
}

func TestCacheManager_Add_MkdirError(t *testing.T) {
	// Create a file where plugin directory should be
	cacheDir := t.TempDir()
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	// Create a file that will block mkdir
	blockingFile := filepath.Join(cacheDir, "blocked-plugin")
	err = os.WriteFile(blockingFile, []byte("blocking"), 0o644)
	require.NoError(t, err)

	plugin := &YAMLPlugin{
		ID:      "blocked-plugin",
		Name:    "blocked-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Output: OutputBlock{Message: "Test"},
	}

	entry, err := cm.Add(context.Background(), plugin, "sha256:abc", "https://example.com")
	require.Error(t, err)
	require.Nil(t, entry)
	require.Contains(t, err.Error(), "failed to create plugin cache directory")
}

func TestCacheManager_Remove_NonExistentPlugin(t *testing.T) {
	cacheDir := t.TempDir()
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	// Try to remove plugin that doesn't exist in cache directory
	err = cm.Remove(context.Background(), "nonexistent-plugin", "1.0.0")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found in cache")
}

func TestCacheManager_Size_ReadDirError(t *testing.T) {
	// Create cache manager with non-existent directory
	cm := &CacheManager{
		cacheDir: "/nonexistent/path/that/does/not/exist",
		registry: NewYAMLRegistry(),
	}

	size, err := cm.Size(context.Background())
	require.Error(t, err)
	require.Equal(t, int64(0), size)
}

func TestCacheManager_Clear_ReadDirError(t *testing.T) {
	// Create cache manager with non-existent directory
	cm := &CacheManager{
		cacheDir: "/nonexistent/path/that/does/not/exist",
		registry: NewYAMLRegistry(),
	}

	err := cm.Clear(context.Background())
	require.Error(t, err)
}

func TestCacheManager_Prune_ReadDirError(t *testing.T) {
	// Create cache manager with non-existent directory
	cm := &CacheManager{
		cacheDir: "/nonexistent/path/that/does/not/exist",
		registry: NewYAMLRegistry(),
	}

	removed, err := cm.Prune(context.Background(), 24*time.Hour)
	require.Error(t, err)
	require.Equal(t, 0, removed)
}

func TestCacheManager_ListEntries_AllPresent(t *testing.T) {
	cacheDir := t.TempDir()
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	plugins := []*YAMLPlugin{
		{
			ID:      "entry-plugin-1",
			Name:    "entry-plugin-1",
			Version: "1.0.0",
			Type:    EvaluationType,
			Author:  "test",
			Metadata: PluginMetadata{
				Severity: HighSeverity,
				Tags:     []string{"test"},
			},
			Output: OutputBlock{Message: "Test1"},
		},
		{
			ID:      "entry-plugin-2",
			Name:    "entry-plugin-2",
			Version: "2.0.0",
			Type:    EvaluationType,
			Author:  "test",
			Metadata: PluginMetadata{
				Severity: HighSeverity,
				Tags:     []string{"test"},
			},
			Output: OutputBlock{Message: "Test2"},
		},
	}

	for _, p := range plugins {
		_, err := cm.Add(context.Background(), p, "sha256:abc", "https://example.com")
		require.NoError(t, err)
	}

	entries := cm.ListEntries(context.Background())
	require.Len(t, entries, 2)

	// Verify entries correspond to added plugins
	names := map[string]bool{}
	for _, e := range entries {
		require.NotEmpty(t, e.Path)
		require.False(t, e.CachedAt.IsZero())
		names[e.Name] = true
	}
	require.True(t, names["entry-plugin-1"])
	require.True(t, names["entry-plugin-2"])
}

func TestCacheManager_ListEntries_SkipsMissingFile(t *testing.T) {
	cacheDir := t.TempDir()
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	// Add two plugins
	present := &YAMLPlugin{
		ID:      "present-plugin",
		Name:    "present-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Output: OutputBlock{Message: "Present"},
	}
	missing := &YAMLPlugin{
		ID:      "missing-plugin",
		Name:    "missing-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Output: OutputBlock{Message: "Missing"},
	}

	_, err = cm.Add(context.Background(), present, "sha256:one", "https://example.com")
	require.NoError(t, err)
	_, err = cm.Add(context.Background(), missing, "sha256:two", "https://example.com")
	require.NoError(t, err)

	// Remove the plugin.yaml for the "missing-plugin" to simulate a broken cache entry
	missingPath := filepath.Join(cacheDir, "missing-plugin", "1.0.0", "plugin.yaml")
	err = os.Remove(missingPath)
	require.NoError(t, err)

	entries := cm.ListEntries(context.Background())
	// Only the present-plugin should be returned
	require.Len(t, entries, 1)
	require.Equal(t, "present-plugin", entries[0].Name)
}

func TestCacheManager_NormalizedPaths(t *testing.T) {
	// Test that cache manager uses normalized names for file paths
	cacheDir := t.TempDir()
	cm, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	// Plugin with spaces in name
	plugin := &YAMLPlugin{
		ID:      "ssh-weak-cipher",
		Name:    "SSH Weak Cipher",
		Version: "1.0.0",
		Type:    "evaluation",
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: "high",
			Tags:     []string{"ssh", "crypto"},
		},
		Triggers: []Trigger{
			{DataKey: "ssh.cipher", Condition: "exists", Value: true},
		},
		Match: &MatchBlock{
			Logic: "OR",
			Rules: []MatchRule{
				{Field: "ssh.cipher", Operator: "equals", Value: "3des-cbc"},
			},
		},
		Output: OutputBlock{
			Vulnerability: true,
			Message:       "Weak cipher detected",
			Remediation:   "Use stronger cipher",
		},
	}

	// Add plugin
	entry, err := cm.Add(context.Background(), plugin, "sha256:test", "https://example.com")
	require.NoError(t, err)
	require.NotNil(t, entry)

	// Verify filesystem uses normalized name (ssh-weak-cipher, not "SSH Weak Cipher")
	normalizedPath := filepath.Join(cacheDir, "ssh-weak-cipher", "1.0.0", "plugin.yaml")
	_, err = os.Stat(normalizedPath)
	require.NoError(t, err, "File should exist at normalized path")

	// Verify we can retrieve using original name
	retrieved, found := cm.Get("ssh-weak-cipher")
	require.True(t, found)
	require.Equal(t, "SSH Weak Cipher", retrieved.Name)

	// Verify GetEntry works with both forms
	entry1, err := cm.GetEntry(context.Background(), "ssh-weak-cipher", "1.0.0")
	require.NoError(t, err)
	require.Equal(t, normalizedPath, entry1.Path)
}
