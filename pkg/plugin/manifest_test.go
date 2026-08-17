// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewManifestManager(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)
	require.NotNil(t, mm)
	require.Equal(t, manifestPath, mm.manifestPath)
}

func TestNewManifestManager_EmptyPath(t *testing.T) {
	mm, err := NewManifestManager("")
	require.Error(t, err)
	require.Nil(t, mm)
	require.Contains(t, err.Error(), "manifest path cannot be empty")
}

func TestManifestManager_Load_NewFile(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Load non-existent file (should create empty manifest)
	err = mm.Load()
	require.NoError(t, err)
	require.NotNil(t, mm.manifest)
	require.Equal(t, "1.0", mm.manifest.Version)
	require.NotNil(t, mm.manifest.Plugins)
	require.Empty(t, mm.manifest.Plugins)
}

func TestManifestManager_Load_ExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	// Create manifest file
	manifest := &Manifest{
		Version:     "1.0",
		LastUpdated: time.Now(),
		Plugins: map[string]*ManifestEntry{
			"test-plugin": {
				Name:    "test-plugin",
				Version: "1.0.0",
			},
		},
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	require.NoError(t, err)
	err = os.WriteFile(manifestPath, data, 0o644)
	require.NoError(t, err)

	// Load existing file
	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	err = mm.Load()
	require.NoError(t, err)
	require.NotNil(t, mm.manifest)
	require.Len(t, mm.manifest.Plugins, 1)
	require.Contains(t, mm.manifest.Plugins, "test-plugin")
}

func TestManifestManager_Load_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	// Create invalid JSON file
	err := os.WriteFile(manifestPath, []byte("invalid json"), 0o644)
	require.NoError(t, err)

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	err = mm.Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse manifest")
}

func TestManifestManager_Save(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Load empty manifest
	err = mm.Load()
	require.NoError(t, err)

	// Add entry
	entry := &ManifestEntry{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
		Type:    "evaluation",
		Author:  "test",
	}
	err = mm.Add(entry)
	require.NoError(t, err)

	// Save
	err = mm.Save()
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(manifestPath)
	require.NoError(t, err)

	// Verify content
	data, err := os.ReadFile(manifestPath)
	require.NoError(t, err)

	var loaded Manifest
	err = json.Unmarshal(data, &loaded)
	require.NoError(t, err)
	require.Len(t, loaded.Plugins, 1)
	require.Contains(t, loaded.Plugins, "test-plugin")
}

func TestManifestManager_Save_NotLoaded(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Try to save without loading
	err = mm.Save()
	require.Error(t, err)
	require.Contains(t, err.Error(), "manifest not loaded")
}

func TestManifestManager_Add(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	entry := &ManifestEntry{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
		Type:    "evaluation",
		Author:  "test",
	}

	err = mm.Add(entry)
	require.NoError(t, err)

	// Verify entry was added
	retrieved, err := mm.Get("test-plugin")
	require.NoError(t, err)
	require.Equal(t, "test-plugin", retrieved.Name)
}

func TestManifestManager_Add_NilEntry(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	err = mm.Add(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "manifest entry cannot be nil")
}

func TestManifestManager_Add_EmptyName(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	entry := &ManifestEntry{
		ID:   "", // Empty ID
		Name: "", // Empty name
	}

	err = mm.Add(entry)
	require.Error(t, err)
	require.Contains(t, err.Error(), "plugin ID cannot be empty")
}

func TestManifestManager_Remove(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Add entry
	entry := &ManifestEntry{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
	}
	err = mm.Add(entry)
	require.NoError(t, err)

	// Remove entry
	err = mm.Remove("test-plugin")
	require.NoError(t, err)

	// Verify entry was removed
	_, err = mm.Get("test-plugin")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found in manifest")
}

func TestManifestManager_Remove_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	err = mm.Load()
	require.NoError(t, err)

	err = mm.Remove("non-existent")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found in manifest")
}

func TestManifestManager_Remove_EmptyName(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	err = mm.Load()
	require.NoError(t, err)

	err = mm.Remove("")
	require.Error(t, err)
	require.Contains(t, err.Error(), "plugin ID cannot be empty")
}

func TestManifestManager_Get(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Add entry
	entry := &ManifestEntry{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
		Author:  "test",
	}
	err = mm.Add(entry)
	require.NoError(t, err)

	// Get entry
	retrieved, err := mm.Get("test-plugin")
	require.NoError(t, err)
	require.Equal(t, "test-plugin", retrieved.Name)
	require.Equal(t, "1.0.0", retrieved.Version)
	require.Equal(t, "test", retrieved.Author)
}

func TestManifestManager_Get_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	err = mm.Load()
	require.NoError(t, err)

	_, err = mm.Get("non-existent")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found in manifest")
}

func TestManifestManager_List(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Add multiple entries
	for i := 1; i <= 3; i++ {
		pluginName := "plugin-" + string(rune('0'+i))
		entry := &ManifestEntry{
			ID:      pluginName,
			Name:    pluginName,
			Version: "1.0.0",
		}
		err = mm.Add(entry)
		require.NoError(t, err)
	}

	// List entries
	entries, err := mm.List()
	require.NoError(t, err)
	require.Len(t, entries, 3)
}

func TestManifestManager_List_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	entries, err := mm.List()
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestManifestManager_Update(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Add entry
	entry := &ManifestEntry{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
	}
	err = mm.Add(entry)
	require.NoError(t, err)

	// Update entry
	updatedEntry := &ManifestEntry{
		Name:    "test-plugin",
		Version: "2.0.0",
	}
	err = mm.Update("test-plugin", updatedEntry)
	require.NoError(t, err)

	// Verify update
	retrieved, err := mm.Get("test-plugin")
	require.NoError(t, err)
	require.Equal(t, "2.0.0", retrieved.Version)
}

func TestManifestManager_Update_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	err = mm.Load()
	require.NoError(t, err)

	entry := &ManifestEntry{
		ID:   "non-existent",
		Name: "non-existent",
	}

	err = mm.Update("non-existent", entry)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found in manifest")
}

func TestManifestManager_Update_NilEntry(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	err = mm.Load()
	require.NoError(t, err)

	err = mm.Update("test", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "manifest entry cannot be nil")
}

func TestManifestManager_Clear(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Add entries
	for i := 1; i <= 3; i++ {
		pluginName := "plugin-" + string(rune('0'+i))
		entry := &ManifestEntry{
			ID:      pluginName,
			Name:    pluginName,
			Version: "1.0.0",
		}
		err = mm.Add(entry)
		require.NoError(t, err)
	}

	// Clear
	err = mm.Clear()
	require.NoError(t, err)

	// Verify cleared
	entries, err := mm.List()
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestManifestManager_Count(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Initial count
	count, err := mm.Count()
	require.NoError(t, err)
	require.Equal(t, 0, count)

	// Add entries
	for i := 1; i <= 3; i++ {
		pluginName := "plugin-" + string(rune('0'+i))
		entry := &ManifestEntry{
			ID:   pluginName,
			Name: pluginName,
		}
		err = mm.Add(entry)
		require.NoError(t, err)
	}

	// Count after adding
	count, err = mm.Count()
	require.NoError(t, err)
	require.Equal(t, 3, count)
}

func TestManifestManager_SetGetRegistryURL(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Set URL
	testURL := "https://registry.cyprob.io/plugins"
	err = mm.SetRegistryURL(testURL)
	require.NoError(t, err)

	// Get URL
	url, err := mm.GetRegistryURL()
	require.NoError(t, err)
	require.Equal(t, testURL, url)
}

func TestNewManifestEntryFromPlugin(t *testing.T) {
	plugin := &YAMLPlugin{
		ID:       "test-plugin",
		Name:     "test-plugin",
		Version:  "1.0.0",
		Type:     EvaluationType,
		Author:   "test-author",
		FilePath: "/path/to/plugin.yaml",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"ssh", "security"},
		},
	}

	checksum := "sha256:abc123"
	downloadURL := "https://example.com/plugin.yaml"

	entry := NewManifestEntryFromPlugin(plugin, checksum, downloadURL)
	require.NotNil(t, entry)
	require.Equal(t, "test-plugin", entry.Name)
	require.Equal(t, "1.0.0", entry.Version)
	require.Equal(t, "evaluation", entry.Type)
	require.Equal(t, "test-author", entry.Author)
	require.Equal(t, checksum, entry.Checksum)
	require.Equal(t, downloadURL, entry.DownloadURL)
	require.Equal(t, "/path/to/plugin.yaml", entry.Path)
	require.Equal(t, []string{"ssh", "security"}, entry.Tags)
	require.Equal(t, "high", entry.Severity)
	require.False(t, entry.InstalledAt.IsZero())
}

func TestManifestManager_SaveAndLoad_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	// Create and save manifest
	mm1, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	entry := &ManifestEntry{
		ID:          "test-plugin",
		Name:        "test-plugin",
		Version:     "1.0.0",
		Type:        "evaluation",
		Author:      "test",
		Checksum:    "sha256:abc123",
		DownloadURL: "https://example.com/plugin.yaml",
		InstalledAt: time.Now(),
		Tags:        []string{"ssh", "security"},
		Severity:    "high",
	}
	err = mm1.Add(entry)
	require.NoError(t, err)

	err = mm1.SetRegistryURL("https://registry.cyprob.io")
	require.NoError(t, err)

	err = mm1.Save()
	require.NoError(t, err)

	// Load in new manager
	mm2, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	err = mm2.Load()
	require.NoError(t, err)

	// Verify loaded data
	loaded, err := mm2.Get("test-plugin")
	require.NoError(t, err)
	require.Equal(t, entry.Name, loaded.Name)
	require.Equal(t, entry.Version, loaded.Version)
	require.Equal(t, entry.Checksum, loaded.Checksum)
	require.Equal(t, entry.Tags, loaded.Tags)

	url, err := mm2.GetRegistryURL()
	require.NoError(t, err)
	require.Equal(t, "https://registry.cyprob.io", url)
}

func TestManifestManager_Add_AutoLoad(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Add without explicit Load() - should auto-load
	entry := &ManifestEntry{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
	}
	err = mm.Add(entry)
	require.NoError(t, err)

	// Verify manifest was loaded
	require.NotNil(t, mm.manifest)
}

func TestManifestManager_MultipleOperationsWithoutLoad(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// All operations should auto-load if needed

	// Get (auto-loads)
	_, err = mm.Get("non-existent")
	require.Error(t, err)
	require.NotNil(t, mm.manifest)

	// Add
	entry := &ManifestEntry{ID: "plugin1", Name: "plugin1", Version: "1.0"}
	err = mm.Add(entry)
	require.NoError(t, err)

	// List
	entries, err := mm.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)

	// Count
	count, err := mm.Count()
	require.NoError(t, err)
	require.Equal(t, 1, count)

	// Update
	updatedEntry := &ManifestEntry{Name: "plugin1", Version: "2.0"}
	err = mm.Update("plugin1", updatedEntry)
	require.NoError(t, err)

	// Clear
	err = mm.Clear()
	require.NoError(t, err)

	// Count after clear
	count, err = mm.Count()
	require.NoError(t, err)
	require.Equal(t, 0, count)
}

func TestManifestManager_Update_EmptyName(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	err = mm.Load()
	require.NoError(t, err)

	entry := &ManifestEntry{ID: "test", Name: "test", Version: "1.0"}
	err = mm.Update("", entry)
	require.Error(t, err)
	require.Contains(t, err.Error(), "plugin ID cannot be empty")
}

func TestManifestManager_ConcurrentReadOperations(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Add test data
	for i := 1; i <= 10; i++ {
		pluginName := "plugin-" + string(rune('0'+i))
		entry := &ManifestEntry{
			ID:      pluginName,
			Name:    pluginName,
			Version: "1.0.0",
		}
		err = mm.Add(entry)
		require.NoError(t, err)
	}

	// Save to disk
	err = mm.Save()
	require.NoError(t, err)

	// Concurrent reads from different managers
	const numReaders = 5
	done := make(chan bool, numReaders)

	for range numReaders {
		go func() {
			manager, err := NewManifestManager(manifestPath)
			if err != nil {
				done <- false
				return
			}

			err = manager.Load()
			if err != nil {
				done <- false
				return
			}

			entries, err := manager.List()
			if err != nil || len(entries) != 10 {
				done <- false
				return
			}

			done <- true
		}()
	}

	// Wait for all readers
	for range numReaders {
		require.True(t, <-done)
	}
}

func TestManifestManager_AddDuplicateOverwrites(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Add first version
	entry1 := &ManifestEntry{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
	}
	err = mm.Add(entry1)
	require.NoError(t, err)

	// Add same plugin with different version (should overwrite)
	entry2 := &ManifestEntry{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "2.0.0",
	}
	err = mm.Add(entry2)
	require.NoError(t, err)

	// Verify overwritten
	retrieved, err := mm.Get("test-plugin")
	require.NoError(t, err)
	require.Equal(t, "2.0.0", retrieved.Version)

	// Should still have only one entry
	count, err := mm.Count()
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestManifestManager_SaveUpdatesTimestamp(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	err = mm.Load()
	require.NoError(t, err)

	firstTimestamp := mm.manifest.LastUpdated

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Save again
	err = mm.Save()
	require.NoError(t, err)

	// Timestamp should be updated
	require.True(t, mm.manifest.LastUpdated.After(firstTimestamp))
}

func TestManifestEntry_AllFields(t *testing.T) {
	now := time.Now()
	entry := &ManifestEntry{
		ID:           "test-plugin",
		Name:         "Test Plugin",
		Version:      "1.0.0",
		Type:         "evaluation",
		Author:       "test-author",
		Checksum:     "sha256:abc123",
		DownloadURL:  "https://example.com/plugin.yaml",
		InstalledAt:  now,
		LastVerified: now,
		Path:         "/path/to/plugin.yaml",
		Tags:         []string{"ssh", "security"},
		Severity:     "high",
	}

	// Verify all fields are set correctly
	require.Equal(t, "test-plugin", entry.ID)
	require.Equal(t, "Test Plugin", entry.Name)
	require.Equal(t, "1.0.0", entry.Version)
	require.Equal(t, "evaluation", entry.Type)
	require.Equal(t, "test-author", entry.Author)
	require.Equal(t, "sha256:abc123", entry.Checksum)
	require.Equal(t, "https://example.com/plugin.yaml", entry.DownloadURL)
	require.Equal(t, now, entry.InstalledAt)
	require.Equal(t, now, entry.LastVerified)
	require.Equal(t, "/path/to/plugin.yaml", entry.Path)
	require.Equal(t, []string{"ssh", "security"}, entry.Tags)
	require.Equal(t, "high", entry.Severity)
}

func TestManifest_EmptyPluginsMap(t *testing.T) {
	updatedAt := time.Now()
	manifest := &Manifest{
		Version:     "1.0",
		LastUpdated: updatedAt,
		Plugins:     make(map[string]*ManifestEntry),
		RegistryURL: "https://registry.example.com",
	}

	require.NotNil(t, manifest.Plugins)
	require.Empty(t, manifest.Plugins)
	require.Equal(t, "1.0", manifest.Version)
	require.Equal(t, updatedAt, manifest.LastUpdated)
	require.Equal(t, "https://registry.example.com", manifest.RegistryURL)
}

func TestManifestManager_RemoveAndReAdd(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Add entry
	entry := &ManifestEntry{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
	}
	err = mm.Add(entry)
	require.NoError(t, err)

	// Remove
	err = mm.Remove("test-plugin")
	require.NoError(t, err)

	// Re-add
	err = mm.Add(entry)
	require.NoError(t, err)

	// Verify re-added
	retrieved, err := mm.Get("test-plugin")
	require.NoError(t, err)
	require.Equal(t, "test-plugin", retrieved.Name)
}

func TestManifestManager_ListPreservesData(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Add entries with full data
	entry1 := &ManifestEntry{
		ID:          "plugin1",
		Name:        "plugin1",
		Version:     "1.0.0",
		Checksum:    "sha256:abc",
		DownloadURL: "https://example.com/1",
		Tags:        []string{"tag1"},
	}
	entry2 := &ManifestEntry{
		ID:          "plugin2",
		Name:        "plugin2",
		Version:     "2.0.0",
		Checksum:    "sha256:def",
		DownloadURL: "https://example.com/2",
		Tags:        []string{"tag2"},
	}

	err = mm.Add(entry1)
	require.NoError(t, err)
	err = mm.Add(entry2)
	require.NoError(t, err)

	// List all
	entries, err := mm.List()
	require.NoError(t, err)
	require.Len(t, entries, 2)

	// Verify all data is preserved
	foundPlugin1 := false
	foundPlugin2 := false

	for _, entry := range entries {
		if entry.Name == "plugin1" {
			foundPlugin1 = true
			require.Equal(t, "1.0.0", entry.Version)
			require.Equal(t, "sha256:abc", entry.Checksum)
			require.Equal(t, []string{"tag1"}, entry.Tags)
		}
		if entry.Name == "plugin2" {
			foundPlugin2 = true
			require.Equal(t, "2.0.0", entry.Version)
			require.Equal(t, "sha256:def", entry.Checksum)
			require.Equal(t, []string{"tag2"}, entry.Tags)
		}
	}

	require.True(t, foundPlugin1)
	require.True(t, foundPlugin2)
}

func TestGetRegistryURL_AutoLoad(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	// Create manifest file with registry URL
	manifest := &Manifest{
		Version:     "1.0",
		LastUpdated: time.Now(),
		Plugins:     make(map[string]*ManifestEntry),
		RegistryURL: "https://registry.cyprob.io",
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	require.NoError(t, err)
	err = os.WriteFile(manifestPath, data, 0o644)
	require.NoError(t, err)

	// Create manager without loading
	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)
	require.Nil(t, mm.manifest) // Not loaded yet

	// GetRegistryURL should auto-load
	url, err := mm.GetRegistryURL()
	require.NoError(t, err)
	require.Equal(t, "https://registry.cyprob.io", url)
	require.NotNil(t, mm.manifest) // Now loaded
}

func TestGetRegistryURL_LoadError(t *testing.T) {
	// Use invalid path that will cause Load() to fail
	invalidPath := "/dev/null/invalid/path/registry.json"

	mm := &ManifestManager{
		manifestPath: invalidPath,
		manifest:     nil, // Not loaded
	}

	// GetRegistryURL should fail to load
	url, err := mm.GetRegistryURL()
	require.Error(t, err)
	require.Empty(t, url)
	require.Contains(t, err.Error(), "failed to load manifest")
}

func TestSetRegistryURL_LoadError(t *testing.T) {
	// Use invalid path that will cause Load() to fail
	invalidPath := "/dev/null/invalid/path/registry.json"

	mm := &ManifestManager{
		manifestPath: invalidPath,
		manifest:     nil, // Not loaded
	}

	// SetRegistryURL should fail to load
	err := mm.SetRegistryURL("https://registry.cyprob.io")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to load manifest")
}

func TestCount_LoadError(t *testing.T) {
	// Use invalid path that will cause Load() to fail
	invalidPath := "/dev/null/invalid/path/registry.json"

	mm := &ManifestManager{
		manifestPath: invalidPath,
		manifest:     nil, // Not loaded
	}

	// Count should fail to load
	count, err := mm.Count()
	require.Error(t, err)
	require.Equal(t, 0, count)
	require.Contains(t, err.Error(), "failed to load manifest")
}

func TestClear_LoadError(t *testing.T) {
	// Use invalid path that will cause Load() to fail
	invalidPath := "/dev/null/invalid/path/registry.json"

	mm := &ManifestManager{
		manifestPath: invalidPath,
		manifest:     nil, // Not loaded
	}

	// Clear should fail to load
	err := mm.Clear()
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to load manifest")
}

func TestUpdate_LoadError(t *testing.T) {
	// Use invalid path that will cause Load() to fail
	invalidPath := "/dev/null/invalid/path/registry.json"

	mm := &ManifestManager{
		manifestPath: invalidPath,
		manifest:     nil, // Not loaded
	}

	entry := &ManifestEntry{
		ID:      "test",
		Name:    "test",
		Version: "1.0",
	}

	// Update should fail to load
	err := mm.Update("test", entry)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to load manifest")
}

func TestList_LoadError(t *testing.T) {
	// Use invalid path that will cause Load() to fail
	invalidPath := "/dev/null/invalid/path/registry.json"

	mm := &ManifestManager{
		manifestPath: invalidPath,
		manifest:     nil, // Not loaded
	}

	// List should fail to load
	entries, err := mm.List()
	require.Error(t, err)
	require.Nil(t, entries)
	require.Contains(t, err.Error(), "failed to load manifest")
}

func TestGet_LoadError(t *testing.T) {
	// Use invalid path that will cause Load() to fail
	invalidPath := "/dev/null/invalid/path/registry.json"

	mm := &ManifestManager{
		manifestPath: invalidPath,
		manifest:     nil, // Not loaded
	}

	// Get should fail to load
	entry, err := mm.Get("test")
	require.Error(t, err)
	require.Nil(t, entry)
	require.Contains(t, err.Error(), "failed to load manifest")
}

func TestRemove_LoadError(t *testing.T) {
	// Use invalid path that will cause Load() to fail
	invalidPath := "/dev/null/invalid/path/registry.json"

	mm := &ManifestManager{
		manifestPath: invalidPath,
		manifest:     nil, // Not loaded
	}

	// Remove should fail to load
	err := mm.Remove("test")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to load manifest")
}

func TestAdd_LoadError(t *testing.T) {
	// Use invalid path that will cause Load() to fail
	invalidPath := "/dev/null/invalid/path/registry.json"

	mm := &ManifestManager{
		manifestPath: invalidPath,
		manifest:     nil, // Not loaded
	}

	entry := &ManifestEntry{
		ID:      "test",
		Name:    "test",
		Version: "1.0",
	}

	// Add should fail to load
	err := mm.Add(entry)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to load manifest")
}

func TestNewManifestManager_CreateDirError(t *testing.T) {
	// Try to create manifest in a file (not directory)
	tmpDir := t.TempDir()
	fileAsDir := filepath.Join(tmpDir, "file-not-dir")

	// Create a file
	err := os.WriteFile(fileAsDir, []byte("test"), 0o644)
	require.NoError(t, err)

	// Try to create manifest inside the file (should fail)
	manifestPath := filepath.Join(fileAsDir, "subdir", "registry.json")
	mm, err := NewManifestManager(manifestPath)
	require.Error(t, err)
	require.Nil(t, mm)
	require.Contains(t, err.Error(), "failed to create manifest directory")
}

func TestManifestManager_Save_WriteError(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	err = mm.Load()
	require.NoError(t, err)

	// Change manifest path to read-only directory
	readOnlyDir := filepath.Join(tmpDir, "readonly")
	err = os.Mkdir(readOnlyDir, 0o444) // Read-only
	require.NoError(t, err)

	mm.manifestPath = filepath.Join(readOnlyDir, "registry.json")

	// Try to save (should fail due to permission)
	err = mm.Save()
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to write manifest")

	// Cleanup: restore permissions
	_ = os.Chmod(readOnlyDir, 0o755)
}

func TestManifestManager_Load_ReadError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a directory with same name as manifest file
	manifestPath := filepath.Join(tmpDir, "registry.json")
	err := os.Mkdir(manifestPath, 0o755)
	require.NoError(t, err)

	mm, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Try to load (should fail because it's a directory, not file)
	err = mm.Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read manifest")
}
