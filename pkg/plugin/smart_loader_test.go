// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestNewSmartLoader(t *testing.T) {
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)
	downloader := NewDownloader(cache)

	loader := NewSmartLoader(downloader, cache)
	require.NotNil(t, loader)
	require.Equal(t, downloader, loader.downloader)
	require.Equal(t, cache, loader.cache)
}

func TestSmartLoader_DetermineCategories(t *testing.T) {
	loader := &SmartLoader{}

	tests := []struct {
		name     string
		context  LoadContext
		expected []Category
	}{
		{
			name:     "empty context",
			context:  LoadContext{},
			expected: []Category{},
		},
		{
			name: "SSH port",
			context: LoadContext{
				Ports: []int{22},
			},
			expected: []Category{CategorySSH},
		},
		{
			name: "HTTP ports",
			context: LoadContext{
				Ports: []int{80, 443},
			},
			expected: []Category{CategoryHTTP, CategoryWeb, CategoryTLS},
		},
		{
			name: "service names",
			context: LoadContext{
				Services: []string{"ssh", "mysql"},
			},
			expected: []Category{CategorySSH, CategoryDatabase},
		},
		{
			name: "explicit categories",
			context: LoadContext{
				Categories: []Category{CategoryIoT, CategoryNetwork},
			},
			expected: []Category{CategoryIoT, CategoryNetwork},
		},
		{
			name: "mixed context",
			context: LoadContext{
				Ports:      []int{22},
				Services:   []string{"mysql"},
				Categories: []Category{CategoryWeb},
			},
			expected: []Category{CategorySSH, CategoryDatabase, CategoryWeb},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			categories := loader.determineCategories(tt.context)

			// Convert to maps for comparison (order doesn't matter)
			expectedMap := make(map[Category]bool)
			for _, cat := range tt.expected {
				expectedMap[cat] = true
			}

			gotMap := make(map[Category]bool)
			for _, cat := range categories {
				gotMap[cat] = true
			}

			require.Equal(t, expectedMap, gotMap)
		})
	}
}

func TestSmartLoader_LoadForContext(t *testing.T) {
	// Setup test server with manifest
	sshPlugin := &YAMLPlugin{
		ID:      "ssh-test",
		Name:    "ssh-test",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"ssh"},
		},
		Triggers: []Trigger{
			{DataKey: "ssh/version", Condition: "exists"},
		},
		Output: OutputBlock{Message: "SSH plugin"},
	}

	sshData, _ := yaml.Marshal(sshPlugin)
	sshHash := sha256.Sum256(sshData)
	sshChecksum := "sha256:" + hex.EncodeToString(sshHash[:])

	pluginServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ssh-test.yaml" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(sshData)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer pluginServer.Close()

	manifest := PluginManifest{
		Version: "1.0",
		Plugins: []PluginManifestEntry{
			{
				ID:         "ssh-test",
				Name:       "ssh-test",
				Version:    "1.0.0",
				Categories: []Category{CategorySSH},
				URL:        pluginServer.URL + "/ssh-test.yaml",
				Checksum:   sshChecksum,
			},
		},
	}

	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = yaml.NewEncoder(w).Encode(manifest)
	}))
	defer manifestServer.Close()

	// Create smart loader
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)

	source := PluginSource{
		Name:    "test",
		URL:     manifestServer.URL,
		Enabled: true,
	}
	downloader := NewDownloader(cache, WithSources([]PluginSource{source}))
	loader := NewSmartLoader(downloader, cache)

	// Load for SSH context
	ctx := context.Background()
	loadCtx := LoadContext{
		Ports: []int{22},
	}

	count, err := loader.LoadForContext(ctx, loadCtx)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	// Verify plugin is loaded
	plugins := loader.GetLoadedPlugins()
	require.Len(t, plugins, 1)
	require.Equal(t, "ssh-test", plugins[0].Name)
}

func TestSmartLoader_LoadForContext_EmptyContext(t *testing.T) {
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)
	downloader := NewDownloader(cache)
	loader := NewSmartLoader(downloader, cache)

	ctx := context.Background()
	loadCtx := LoadContext{} // Empty context

	count, err := loader.LoadForContext(ctx, loadCtx)
	require.NoError(t, err)
	require.Equal(t, 0, count) // No plugins loaded
}

func TestSmartLoader_LoadAll(t *testing.T) {
	// Create test plugin
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

	pluginData, _ := yaml.Marshal(plugin)
	hash := sha256.Sum256(pluginData)
	checksum := "sha256:" + hex.EncodeToString(hash[:])

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
				Categories: []Category{CategoryMisc},
				URL:        pluginServer.URL,
				Checksum:   checksum,
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
	loader := NewSmartLoader(downloader, cache)

	ctx := context.Background()
	count, err := loader.LoadAll(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	plugins := loader.GetLoadedPlugins()
	require.Len(t, plugins, 1)
}

func TestSmartLoader_LoadCategory(t *testing.T) {
	plugin := &YAMLPlugin{
		ID:      "ssh-plugin",
		Name:    "ssh-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"ssh"},
		},
		Output: OutputBlock{Message: "SSH test"},
	}

	pluginData, _ := yaml.Marshal(plugin)
	hash := sha256.Sum256(pluginData)
	checksum := "sha256:" + hex.EncodeToString(hash[:])

	pluginServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pluginData)
	}))
	defer pluginServer.Close()

	manifest := PluginManifest{
		Version: "1.0",
		Plugins: []PluginManifestEntry{
			{
				ID:         "ssh-plugin",
				Name:       "ssh-plugin",
				Version:    "1.0.0",
				Categories: []Category{CategorySSH},
				URL:        pluginServer.URL,
				Checksum:   checksum,
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
	loader := NewSmartLoader(downloader, cache)

	ctx := context.Background()
	count, err := loader.LoadCategory(ctx, CategorySSH)
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestSmartLoader_LoadCategory_Invalid(t *testing.T) {
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)
	downloader := NewDownloader(cache)
	loader := NewSmartLoader(downloader, cache)

	ctx := context.Background()
	count, err := loader.LoadCategory(ctx, Category("invalid"))
	require.Error(t, err)
	require.Equal(t, 0, count)
	require.Contains(t, err.Error(), "invalid category")
}

func TestSmartLoader_GetLoadedPlugins(t *testing.T) {
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)
	downloader := NewDownloader(cache)
	loader := NewSmartLoader(downloader, cache)

	// Initially empty
	plugins := loader.GetLoadedPlugins()
	require.Empty(t, plugins)

	// Add a plugin to cache
	plugin := &YAMLPlugin{
		ID:      "test",
		Name:    "test",
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

	// Now should have one plugin
	plugins = loader.GetLoadedPlugins()
	require.Len(t, plugins, 1)
	require.Equal(t, "test", plugins[0].Name)
}

func TestSmartLoader_GetLoadedPluginsByCategory(t *testing.T) {
	cacheDir := t.TempDir()
	cache, err := NewCacheManager(cacheDir)
	require.NoError(t, err)
	downloader := NewDownloader(cache)
	loader := NewSmartLoader(downloader, cache)

	// Add plugins with different categories
	sshPlugin := &YAMLPlugin{
		ID:      "ssh-plugin",
		Name:    "ssh-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"ssh"},
		},
		Triggers: []Trigger{
			{DataKey: "ssh/version", Condition: "exists"},
		},
		Output: OutputBlock{Message: "SSH"},
	}

	httpPlugin := &YAMLPlugin{
		ID:      "http-plugin",
		Name:    "http-plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: MediumSeverity,
			Tags:     []string{"http"},
		},
		Triggers: []Trigger{
			{DataKey: "http/server", Condition: "exists"},
		},
		Output: OutputBlock{Message: "HTTP"},
	}

	_, err = cache.Add(context.Background(), sshPlugin, "sha256:ssh", "https://example.com")
	require.NoError(t, err)
	_, err = cache.Add(context.Background(), httpPlugin, "sha256:http", "https://example.com")
	require.NoError(t, err)

	// Get SSH plugins
	sshPlugins := loader.GetLoadedPluginsByCategory(CategorySSH)
	require.Len(t, sshPlugins, 1)
	require.Equal(t, "ssh-plugin", sshPlugins[0].Name)

	// Get HTTP plugins
	httpPlugins := loader.GetLoadedPluginsByCategory(CategoryHTTP)
	require.Len(t, httpPlugins, 1)
	require.Equal(t, "http-plugin", httpPlugins[0].Name)

	// Get Database plugins (none)
	dbPlugins := loader.GetLoadedPluginsByCategory(CategoryDatabase)
	require.Empty(t, dbPlugins)
}

func TestHasCategory(t *testing.T) {
	tests := []struct {
		name     string
		plugin   *YAMLPlugin
		category Category
		expected bool
	}{
		{
			name: "SSH by data key",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "ssh/version"},
				},
			},
			category: CategorySSH,
			expected: true,
		},
		{
			name: "HTTP by data key",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "http/server"},
				},
			},
			category: CategoryHTTP,
			expected: true,
		},
		{
			name: "Database by tag",
			plugin: &YAMLPlugin{
				Metadata: PluginMetadata{
					Tags: []string{"database", "mysql"},
				},
			},
			category: CategoryDatabase,
			expected: true,
		},
		{
			name: "TLS by data key",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "tls/cipher"},
				},
			},
			category: CategoryTLS,
			expected: true,
		},
		{
			name: "TLS by SSL keyword",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "ssl/version"},
				},
			},
			category: CategoryTLS,
			expected: true,
		},
		{
			name: "IoT by MQTT",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "mqtt/topic"},
				},
			},
			category: CategoryIoT,
			expected: true,
		},
		{
			name: "IoT by CoAP",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "coap/endpoint"},
				},
			},
			category: CategoryIoT,
			expected: true,
		},
		{
			name: "Network by FTP",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "ftp/banner"},
				},
			},
			category: CategoryNetwork,
			expected: true,
		},
		{
			name: "Network by Telnet",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "telnet/banner"},
				},
			},
			category: CategoryNetwork,
			expected: true,
		},
		{
			name: "Network by SMTP",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "smtp/server"},
				},
			},
			category: CategoryNetwork,
			expected: true,
		},
		{
			name: "Network by DNS",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "dns/version"},
				},
			},
			category: CategoryNetwork,
			expected: true,
		},
		{
			name: "Database by postgres keyword",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "postgres/version"},
				},
			},
			category: CategoryDatabase,
			expected: true,
		},
		{
			name: "Database by mongodb keyword",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "mongodb/version"},
				},
			},
			category: CategoryDatabase,
			expected: true,
		},
		{
			name: "Database by redis keyword",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "redis/info"},
				},
			},
			category: CategoryDatabase,
			expected: true,
		},
		{
			name: "Database by db keyword",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "db/connection"},
				},
			},
			category: CategoryDatabase,
			expected: true,
		},
		{
			name: "Web by web keyword",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "web/framework"},
				},
			},
			category: CategoryWeb,
			expected: true,
		},
		{
			name: "No match",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "other/key"},
				},
				Metadata: PluginMetadata{
					Tags: []string{"other"},
				},
			},
			category: CategorySSH,
			expected: false,
		},
		{
			name: "Misc default",
			plugin: &YAMLPlugin{
				Triggers: []Trigger{
					{DataKey: "unknown/key"},
				},
			},
			category: CategoryMisc,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasCategory(tt.plugin, tt.category)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		s        string
		substr   string
		expected bool
	}{
		{"hello world", "world", true},
		{"hello world", "WORLD", true},
		{"HELLO WORLD", "world", true},
		{"hello", "goodbye", false},
		{"ssh/version", "ssh", true},
		{"HTTP/Server", "http", true},
		{"", "test", false},
		{"test", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			result := contains(tt.s, tt.substr)
			require.Equal(t, tt.expected, result, "contains(%q, %q)", tt.s, tt.substr)
		})
	}
}
