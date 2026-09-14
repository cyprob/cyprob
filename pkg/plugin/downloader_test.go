// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestNewDownloader(t *testing.T) {
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	downloader := NewDownloader(cache)
	require.NotNil(t, downloader)
	require.NotNil(t, downloader.httpClient)
	require.NotNil(t, downloader.cache)
	require.Len(t, downloader.sources, 1)
	require.Equal(t, "official", downloader.sources[0].Name)
}

func TestNewDownloader_WithOptions(t *testing.T) {
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	customClient := &http.Client{Timeout: 10 * time.Second}
	customSources := []PluginSource{
		{Name: "custom", URL: "https://custom.example.com", Enabled: true, Priority: 1},
	}

	downloader := NewDownloader(cache,
		WithHTTPClient(customClient),
		WithSources(customSources),
	)

	require.NotNil(t, downloader)
	require.Equal(t, customClient, downloader.httpClient)
	require.Len(t, downloader.sources, 1)
	require.Equal(t, "custom", downloader.sources[0].Name)
}

func TestDownloader_FetchManifest(t *testing.T) {
	manifest := PluginManifest{
		Version: "1.0",
		Plugins: []PluginManifestEntry{
			{
				ID:          "test-plugin",
				Name:        "test-plugin",
				Version:     "1.0.0",
				Description: "Test plugin",
				Author:      "test-author",
				Categories:  []Category{CategorySSH},
				URL:         "https://example.com/plugin.yaml",
				Checksum:    "sha256:abc123",
				Size:        1024,
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = yaml.NewEncoder(w).Encode(manifest)
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	downloader := NewDownloader(cache)
	source := PluginSource{
		Name:    "test",
		URL:     server.URL,
		Enabled: true,
	}

	ctx := context.Background()
	fetchedManifest, err := downloader.FetchManifest(ctx, source)
	require.NoError(t, err)
	require.NotNil(t, fetchedManifest)
	require.Equal(t, "1.0", fetchedManifest.Version)
	require.Len(t, fetchedManifest.Plugins, 1)
	require.Equal(t, "test-plugin", fetchedManifest.Plugins[0].Name)
}

func TestDownloader_FetchManifest_WithMirrors(t *testing.T) {
	manifest := PluginManifest{
		Version: "1.0",
		Plugins: []PluginManifestEntry{},
	}

	// Primary server fails
	failingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failingServer.Close()

	// Mirror succeeds
	mirrorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = yaml.NewEncoder(w).Encode(manifest)
	}))
	defer mirrorServer.Close()

	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	downloader := NewDownloader(cache)
	source := PluginSource{
		Name:    "test",
		URL:     failingServer.URL,
		Mirrors: []string{mirrorServer.URL},
		Enabled: true,
	}

	ctx := context.Background()
	fetchedManifest, err := downloader.FetchManifest(ctx, source)
	require.NoError(t, err)
	require.NotNil(t, fetchedManifest)
}

func TestDownloader_FetchManifest_AllFail(t *testing.T) {
	failingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failingServer.Close()

	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	downloader := NewDownloader(cache)
	source := PluginSource{
		Name:    "test",
		URL:     failingServer.URL,
		Mirrors: []string{failingServer.URL},
		Enabled: true,
	}

	ctx := context.Background()
	fetchedManifest, err := downloader.FetchManifest(ctx, source)
	require.Error(t, err)
	require.Nil(t, fetchedManifest)
	require.Contains(t, err.Error(), "failed to fetch manifest from test")
}

func TestDownloader_Download(t *testing.T) {
	// Create test plugin
	plugin := &YAMLPlugin{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test-author",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Output: OutputBlock{Message: "Test vulnerability detected"},
	}

	pluginData, err := yaml.Marshal(plugin)
	require.NoError(t, err)

	// Calculate checksum
	hash := sha256.Sum256(pluginData)
	checksum := "sha256:" + hex.EncodeToString(hash[:])

	// Setup servers
	pluginServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pluginData)
	}))
	defer pluginServer.Close()

	manifest := PluginManifest{
		Version: "1.0",
		Plugins: []PluginManifestEntry{
			{
				ID:         "test-plugin",
				Name:       "test-plugin",
				Version:    "1.0.0",
				Categories: []Category{CategorySSH},
				URL:        pluginServer.URL + "/test-plugin.yaml",
				Checksum:   checksum,
				Size:       int64(len(pluginData)),
			},
		},
	}

	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = yaml.NewEncoder(w).Encode(manifest)
	}))
	defer manifestServer.Close()

	// Create downloader
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	source := PluginSource{
		Name:    "test",
		URL:     manifestServer.URL,
		Enabled: true,
	}

	downloader := NewDownloader(cache, WithSources([]PluginSource{source}))

	// Download plugin
	ctx := context.Background()
	entry, err := downloader.Download(ctx, "test-plugin", "1.0.0")
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, "test-plugin", entry.ID)
	require.Equal(t, "test-plugin", entry.Name)
	require.Equal(t, "1.0.0", entry.Version)
	require.Equal(t, checksum, entry.Checksum)

	// Verify it's in cache
	cachedEntry, err := cache.GetEntry(context.Background(), "test-plugin", "1.0.0")
	require.NoError(t, err)
	require.Equal(t, entry.Name, cachedEntry.Name)
}

func TestDownloader_Download_AlreadyCached(t *testing.T) {
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	// Add plugin to cache
	plugin := &YAMLPlugin{
		ID:      "cached-plugin",
		Name:    "cached-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: MediumSeverity,
			Tags:     []string{"test"},
		},
		Output: OutputBlock{Message: "Test"},
	}

	_, err = cache.Add(context.Background(), plugin, "sha256:abc123", "https://example.com")
	require.NoError(t, err)

	downloader := NewDownloader(cache)
	ctx := context.Background()

	// Download should return cached entry without hitting network
	entry, err := downloader.Download(ctx, "cached-plugin", "1.0.0")
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, "cached-plugin", entry.Name)
}

func TestDownloader_Download_NotFound(t *testing.T) {
	manifest := PluginManifest{
		Version: "1.0",
		Plugins: []PluginManifestEntry{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = yaml.NewEncoder(w).Encode(manifest)
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	source := PluginSource{
		Name:    "test",
		URL:     server.URL,
		Enabled: true,
	}

	downloader := NewDownloader(cache, WithSources([]PluginSource{source}))
	ctx := context.Background()

	entry, err := downloader.Download(ctx, "nonexistent-plugin", "1.0.0")
	require.Error(t, err)
	require.Nil(t, entry)
	require.Contains(t, err.Error(), "not found in any source")
}

func TestDownloader_Download_ChecksumMismatch(t *testing.T) {
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

	pluginData, err := yaml.Marshal(plugin)
	require.NoError(t, err)

	pluginServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pluginData)
	}))
	defer pluginServer.Close()

	manifest := PluginManifest{
		Version: "1.0",
		Plugins: []PluginManifestEntry{
			{
				ID:       "test-plugin",
				Name:     "test-plugin",
				Version:  "1.0.0",
				URL:      pluginServer.URL,
				Checksum: "sha256:wrong_checksum_here", // Wrong checksum
			},
		},
	}

	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = yaml.NewEncoder(w).Encode(manifest)
	}))
	defer manifestServer.Close()

	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	source := PluginSource{
		Name:    "test",
		URL:     manifestServer.URL,
		Enabled: true,
	}

	downloader := NewDownloader(cache, WithSources([]PluginSource{source}))
	ctx := context.Background()

	entry, err := downloader.Download(ctx, "test-plugin", "1.0.0")
	require.Error(t, err)
	require.Nil(t, entry)
	require.Contains(t, err.Error(), "checksum verification failed")
}

func TestDownloader_DownloadByCategory(t *testing.T) {
	// Create test plugins
	plugins := []*YAMLPlugin{
		{
			ID:      "ssh-plugin-1",
			Name:    "ssh-plugin-1",
			Version: "1.0.0",
			Type:    EvaluationType,
			Author:  "test",
			Metadata: PluginMetadata{
				Severity: HighSeverity,
				Tags:     []string{"ssh"},
			},
			Output: OutputBlock{Message: "SSH vuln 1"},
		},
		{
			ID:      "ssh-plugin-2",
			Name:    "ssh-plugin-2",
			Version: "1.0.0",
			Type:    EvaluationType,
			Author:  "test",
			Metadata: PluginMetadata{
				Severity: MediumSeverity,
				Tags:     []string{"ssh"},
			},
			Output: OutputBlock{Message: "SSH vuln 2"},
		},
	}

	// Setup plugin server
	pluginServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range plugins {
			if r.URL.Path == fmt.Sprintf("/%s.yaml", p.Name) {
				w.WriteHeader(http.StatusOK)
				_ = yaml.NewEncoder(w).Encode(p)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer pluginServer.Close()

	// Create manifest
	manifestEntries := []PluginManifestEntry{}
	for _, p := range plugins {
		data, _ := yaml.Marshal(p)
		hash := sha256.Sum256(data)
		checksum := "sha256:" + hex.EncodeToString(hash[:])

		manifestEntries = append(manifestEntries, PluginManifestEntry{
			ID:         p.ID,
			Name:       p.Name,
			Version:    p.Version,
			Categories: []Category{CategorySSH},
			URL:        pluginServer.URL + "/" + p.Name + ".yaml",
			Checksum:   checksum,
		})
	}

	manifest := PluginManifest{
		Version: "1.0",
		Plugins: manifestEntries,
	}

	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = yaml.NewEncoder(w).Encode(manifest)
	}))
	defer manifestServer.Close()

	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	source := PluginSource{
		Name:    "test",
		URL:     manifestServer.URL,
		Enabled: true,
	}

	downloader := NewDownloader(cache, WithSources([]PluginSource{source}))
	ctx := context.Background()

	entries, err := downloader.DownloadByCategory(ctx, CategorySSH)
	require.NoError(t, err)
	require.Len(t, entries, 2)
}

func TestDownloader_DownloadByCategory_NoPlugins(t *testing.T) {
	manifest := PluginManifest{
		Version: "1.0",
		Plugins: []PluginManifestEntry{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = yaml.NewEncoder(w).Encode(manifest)
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	source := PluginSource{
		Name:    "test",
		URL:     server.URL,
		Enabled: true,
	}

	downloader := NewDownloader(cache, WithSources([]PluginSource{source}))
	ctx := context.Background()

	entries, err := downloader.DownloadByCategory(ctx, CategorySSH)
	// When no plugins are found, it returns empty list without error
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestDownloader_Update(t *testing.T) {
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	// Add old version to cache
	oldPlugin := &YAMLPlugin{
		ID:      "update-test",
		Name:    "update-test",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Output: OutputBlock{Message: "Old version"},
	}
	_, err = cache.Add(context.Background(), oldPlugin, "sha256:old", "https://example.com")
	require.NoError(t, err)

	// Create new version
	newPlugin := &YAMLPlugin{
		ID:      "update-test",
		Name:    "update-test",
		Version: "2.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Output: OutputBlock{Message: "New version"},
	}
	newPluginData, _ := yaml.Marshal(newPlugin)
	hash := sha256.Sum256(newPluginData)
	newChecksum := "sha256:" + hex.EncodeToString(hash[:])

	pluginServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(newPluginData)
	}))
	defer pluginServer.Close()

	manifest := PluginManifest{
		Version: "1.0",
		Plugins: []PluginManifestEntry{
			{
				ID:       "update-test",
				Name:     "update-test",
				Version:  "2.0.0",
				URL:      pluginServer.URL,
				Checksum: newChecksum,
			},
		},
	}

	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = yaml.NewEncoder(w).Encode(manifest)
	}))
	defer manifestServer.Close()

	source := PluginSource{
		Name:    "test",
		URL:     manifestServer.URL,
		Enabled: true,
	}

	downloader := NewDownloader(cache, WithSources([]PluginSource{source}))
	ctx := context.Background()

	updated, err := downloader.Update(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, updated)

	// Verify new version is cached
	entry, err := cache.GetEntry(context.Background(), "update-test", "2.0.0")
	require.NoError(t, err)
	require.Equal(t, "2.0.0", entry.Version)

	// Verify old version is removed
	_, err = cache.GetEntry(context.Background(), "update-test", "1.0.0")
	require.Error(t, err)
}

func TestVerifyChecksum(t *testing.T) {
	data := []byte("test data")
	hash := sha256.Sum256(data)
	validChecksum := "sha256:" + hex.EncodeToString(hash[:])

	tests := []struct {
		name        string
		data        []byte
		checksum    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid checksum",
			data:        data,
			checksum:    validChecksum,
			expectError: false,
		},
		{
			name:        "invalid format",
			data:        data,
			checksum:    "invalid",
			expectError: true,
			errorMsg:    "invalid checksum format",
		},
		{
			name:        "unsupported algorithm",
			data:        data,
			checksum:    "md5:abc123",
			expectError: true,
			errorMsg:    "unsupported checksum algorithm",
		},
		{
			name:        "checksum mismatch",
			data:        data,
			checksum:    "sha256:wrong",
			expectError: true,
			errorMsg:    "checksum mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyChecksum(tt.data, tt.checksum)
			if tt.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDownloader_Update_NoUpdatesAvailable(t *testing.T) {
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	// Add plugin to cache
	plugin := &YAMLPlugin{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: MediumSeverity,
			Tags:     []string{"test"},
		},
		Output: OutputBlock{Message: "Test"},
	}
	_, err = cache.Add(context.Background(), plugin, "sha256:test", "https://example.com")
	require.NoError(t, err)

	// Manifest returns same version
	manifest := PluginManifest{
		Version: "1.0",
		Plugins: []PluginManifestEntry{
			{
				ID:      "test-plugin",
				Name:    "test-plugin",
				Version: "1.0.0", // Same version
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = yaml.NewEncoder(w).Encode(manifest)
	}))
	defer server.Close()

	source := PluginSource{
		Name:    "test",
		URL:     server.URL,
		Enabled: true,
	}

	downloader := NewDownloader(cache, WithSources([]PluginSource{source}))
	ctx := context.Background()

	updated, err := downloader.Update(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, updated) // No updates
}

func TestDownloader_Update_ManifestFetchError(t *testing.T) {
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	// Add plugin to cache
	plugin := &YAMLPlugin{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: MediumSeverity,
			Tags:     []string{"test"},
		},
		Output: OutputBlock{Message: "Test"},
	}
	_, err = cache.Add(context.Background(), plugin, "sha256:test", "https://example.com")
	require.NoError(t, err)

	// Server returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	source := PluginSource{
		Name:    "test",
		URL:     server.URL,
		Enabled: true,
	}

	downloader := NewDownloader(cache, WithSources([]PluginSource{source}))
	ctx := context.Background()

	updated, err := downloader.Update(ctx)
	require.NoError(t, err) // Continues despite error
	require.Equal(t, 0, updated)
}

func TestDownloader_Download_InvalidYAML(t *testing.T) {
	invalidYAML := []byte("invalid: yaml: content: [")
	hash := sha256.Sum256(invalidYAML)
	correctChecksum := "sha256:" + hex.EncodeToString(hash[:])

	// Plugin server returns invalid YAML
	pluginServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(invalidYAML)
	}))
	defer pluginServer.Close()

	manifest := PluginManifest{
		Version: "1.0",
		Plugins: []PluginManifestEntry{
			{
				ID:       "test-plugin",
				Name:     "test-plugin",
				Version:  "1.0.0",
				URL:      pluginServer.URL,
				Checksum: correctChecksum, // Correct checksum for invalid YAML
			},
		},
	}

	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = yaml.NewEncoder(w).Encode(manifest)
	}))
	defer manifestServer.Close()

	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	source := PluginSource{
		Name:    "test",
		URL:     manifestServer.URL,
		Enabled: true,
	}

	downloader := NewDownloader(cache, WithSources([]PluginSource{source}))
	ctx := context.Background()

	entry, err := downloader.Download(ctx, "test-plugin", "1.0.0")
	require.Error(t, err)
	require.Nil(t, entry)
	require.Contains(t, err.Error(), "failed to parse plugin")
}

func TestDownloader_FetchManifest_InvalidYAML(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid yaml [[["))
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	downloader := NewDownloader(cache)
	source := PluginSource{
		Name:    "test",
		URL:     server.URL,
		Enabled: true,
	}

	ctx := context.Background()
	manifest, err := downloader.FetchManifest(ctx, source)
	require.Error(t, err)
	require.Nil(t, manifest)
	require.Contains(t, err.Error(), "failed to decode manifest")
}

// Error path tests for downloadFile function

func TestDownloader_downloadFile_InvalidURL(t *testing.T) {
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	downloader := NewDownloader(cache)
	ctx := context.Background()

	// Invalid URL with control characters that fail NewRequestWithContext
	invalidURL := "http://example.com/\x00invalid"
	data, err := downloader.downloadFile(ctx, invalidURL)
	require.Error(t, err)
	require.Nil(t, data)
	require.Contains(t, err.Error(), "failed to create request")
}

func TestDownloader_downloadFile_ContextCancelled(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("test data"))
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	downloader := NewDownloader(cache)

	// Create context that cancels immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	data, err := downloader.downloadFile(ctx, server.URL)
	require.Error(t, err)
	require.Nil(t, data)
	// WithRetry returns context.Canceled directly for canceled contexts
	require.ErrorIs(t, err, context.Canceled)
}

func TestDownloader_downloadFile_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	downloader := NewDownloader(cache)
	ctx := context.Background()

	data, err := downloader.downloadFile(ctx, server.URL)
	require.Error(t, err)
	require.Nil(t, data)
	require.Contains(t, err.Error(), "unexpected status code: 404")
}

// Error path tests for fetchManifestFromURL function

func TestDownloader_fetchManifestFromURL_InvalidURL(t *testing.T) {
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	downloader := NewDownloader(cache)
	ctx := context.Background()

	// Invalid URL with control characters
	invalidURL := "http://example.com/\x00invalid"
	manifest, err := downloader.fetchManifestFromURL(ctx, invalidURL)
	require.Error(t, err)
	require.Nil(t, manifest)
	require.Contains(t, err.Error(), "failed to create request")
}

func TestDownloader_fetchManifestFromURL_NetworkError(t *testing.T) {
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	downloader := NewDownloader(cache)
	ctx := context.Background()

	// Use invalid host to trigger network error
	invalidHost := "http://invalid-host-that-does-not-exist-12345.com"
	manifest, err := downloader.fetchManifestFromURL(ctx, invalidHost)
	require.Error(t, err)
	require.Nil(t, manifest)
	require.Contains(t, err.Error(), "failed to fetch manifest")
}

func TestDownloader_fetchManifestFromURL_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	downloader := NewDownloader(cache)
	ctx := context.Background()

	manifest, err := downloader.fetchManifestFromURL(ctx, server.URL)
	require.Error(t, err)
	require.Nil(t, manifest)
	require.Contains(t, err.Error(), "unexpected status code: 500")
}

// Error path tests for Download function

func TestDownloader_Download_DownloadFileError(t *testing.T) {
	manifest := PluginManifest{
		Version: "1.0",
		Plugins: []PluginManifestEntry{
			{
				ID:       "test-plugin",
				Name:     "test-plugin",
				Version:  "1.0.0",
				URL:      "http://invalid-host-does-not-exist-12345.com/plugin.yaml",
				Checksum: "sha256:abc123",
			},
		},
	}

	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = yaml.NewEncoder(w).Encode(manifest)
	}))
	defer manifestServer.Close()

	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	source := PluginSource{
		Name:    "test",
		URL:     manifestServer.URL,
		Enabled: true,
	}

	downloader := NewDownloader(cache, WithSources([]PluginSource{source}))
	ctx := context.Background()

	entry, err := downloader.Download(ctx, "test-plugin", "1.0.0")
	require.Error(t, err)
	require.Nil(t, entry)
	require.Contains(t, err.Error(), "failed to download plugin")
}

// Error path tests for DownloadByCategory function

func TestDownloader_DownloadByCategory_AllManifestsFail(t *testing.T) {
	// Create server that returns 500 error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	source := PluginSource{
		Name:    "test",
		URL:     server.URL,
		Enabled: true,
	}

	downloader := NewDownloader(cache, WithSources([]PluginSource{source}))
	ctx := context.Background()

	entries, err := downloader.DownloadByCategory(ctx, CategorySSH)
	require.NoError(t, err) // Should not error, just return empty
	require.Empty(t, entries)
}

func TestDownloader_DownloadByCategory_PartialDownloadFailure(t *testing.T) {
	// Create two plugins: one with valid URL, one with invalid
	plugin1 := &YAMLPlugin{
		ID:      "valid-plugin",
		Name:    "valid-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"ssh"},
		},
		Output: OutputBlock{Message: "Test"},
	}

	plugin1Data, err := yaml.Marshal(plugin1)
	require.NoError(t, err)

	hash1 := sha256.Sum256(plugin1Data)
	checksum1 := "sha256:" + hex.EncodeToString(hash1[:])

	// Valid plugin server
	pluginServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(plugin1Data)
	}))
	defer pluginServer.Close()

	manifest := PluginManifest{
		Version: "1.0",
		Plugins: []PluginManifestEntry{
			{
				ID:         "valid-plugin",
				Name:       "valid-plugin",
				Version:    "1.0.0",
				Categories: []Category{CategorySSH},
				URL:        pluginServer.URL + "/valid.yaml",
				Checksum:   checksum1,
			},
			{
				ID:         "invalid-plugin",
				Name:       "invalid-plugin",
				Version:    "1.0.0",
				Categories: []Category{CategorySSH},
				URL:        "http://invalid-host-12345.com/invalid.yaml",
				Checksum:   "sha256:invalid",
			},
		},
	}

	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = yaml.NewEncoder(w).Encode(manifest)
	}))
	defer manifestServer.Close()

	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	source := PluginSource{
		Name:    "test",
		URL:     manifestServer.URL,
		Enabled: true,
	}

	downloader := NewDownloader(cache, WithSources([]PluginSource{source}))
	ctx := context.Background()

	// DownloadByCategory continues on error, so it succeeds with only valid plugin
	entries, err := downloader.DownloadByCategory(ctx, CategorySSH)
	require.NoError(t, err)    // No error, just logs and continues
	require.Len(t, entries, 1) // Only the valid plugin downloaded
	require.Equal(t, "valid-plugin", entries[0].Name)
}

// Error path tests for Update function

func TestDownloader_Update_DownloadError(t *testing.T) {
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	// Add plugin to cache
	plugin := &YAMLPlugin{
		ID:      "test-plugin",
		Name:    "test-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: MediumSeverity,
			Tags:     []string{"test"},
		},
		Output: OutputBlock{Message: "Test"},
	}

	_, err = cache.Add(context.Background(), plugin, "sha256:abc123", "https://example.com")
	require.NoError(t, err)

	// Create manifest with newer version but invalid download URL
	manifest := PluginManifest{
		Version: "1.0",
		Plugins: []PluginManifestEntry{
			{
				ID:       "test-plugin",
				Name:     "test-plugin",
				Version:  "2.0.0", // Newer version
				URL:      "http://invalid-host-12345.com/plugin.yaml",
				Checksum: "sha256:newchecksum",
			},
		},
	}

	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = yaml.NewEncoder(w).Encode(manifest)
	}))
	defer manifestServer.Close()

	source := PluginSource{
		Name:    "test",
		URL:     manifestServer.URL,
		Enabled: true,
	}

	downloader := NewDownloader(cache, WithSources([]PluginSource{source}))
	ctx := context.Background()

	count, err := downloader.Update(ctx)
	require.Error(t, err)
	require.Equal(t, 0, count)
	require.Contains(t, err.Error(), "failed to update test-plugin")
}
