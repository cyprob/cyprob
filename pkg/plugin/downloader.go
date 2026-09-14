// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Note: PluginSource and PluginManifestEntry are now defined in service_types.go
// They are part of the service layer API.

// PluginManifest describes available plugins in a repository.
type PluginManifest struct {
	Version string                    `yaml:"version"`
	Plugins []PluginManifestEntry     `yaml:"plugins"`
	Index   map[string][]PluginDigest `yaml:"index"` // category -> plugins
}

// PluginDigest is a compact reference to a plugin.
type PluginDigest struct {
	Name     string `yaml:"name"`
	Version  string `yaml:"version"`
	Checksum string `yaml:"checksum"`
}

// Downloader handles fetching plugins from remote sources.
type Downloader struct {
	sources     []PluginSource
	httpClient  *http.Client
	cache       *CacheManager
	retryConfig RetryConfig
}

// DownloaderOption configures the Downloader.
type DownloaderOption func(*Downloader)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) DownloaderOption {
	return func(d *Downloader) {
		d.httpClient = client
	}
}

// WithSources sets the plugin sources.
func WithSources(sources []PluginSource) DownloaderOption {
	return func(d *Downloader) {
		d.sources = sources
	}
}

// WithRetryConfig sets the retry configuration for network operations.
func WithRetryConfig(config RetryConfig) DownloaderOption {
	return func(d *Downloader) {
		d.retryConfig = config
	}
}

// NewDownloader creates a new plugin downloader.
func NewDownloader(cache *CacheManager, opts ...DownloaderOption) *Downloader {
	d := &Downloader{
		cache: cache,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		sources: []PluginSource{
			{
				Name:     "official",
				URL:      "https://plugins.pentora.ai/manifest.yaml",
				Enabled:  true,
				Priority: 1,
				Mirrors: []string{
					"https://raw.githubusercontent.com/pentora-ai/pentora-plugins/main/manifest.yaml",
				},
			},
		},
		retryConfig: DefaultRetryConfig(),
	}

	for _, opt := range opts {
		opt(d)
	}

	return d
}

// FetchManifest retrieves the plugin manifest from a source.
func (d *Downloader) FetchManifest(ctx context.Context, source PluginSource) (*PluginManifest, error) {
	urls := []string{source.URL}
	urls = append(urls, source.Mirrors...)

	var lastErr error
	for _, url := range urls {
		manifest, err := d.fetchManifestFromURL(ctx, url)
		if err == nil {
			return manifest, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("failed to fetch manifest from %s: %w", source.Name, lastErr)
}

func (d *Downloader) fetchManifestFromURL(ctx context.Context, url string) (*PluginManifest, error) {
	var manifest *PluginManifest

	err := WithRetry(ctx, d.retryConfig, func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := d.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to fetch manifest: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}

		var m PluginManifest
		if err := yaml.NewDecoder(resp.Body).Decode(&m); err != nil {
			return fmt.Errorf("failed to decode manifest: %w", err)
		}

		manifest = &m
		return nil
	})
	if err != nil {
		return nil, err
	}

	return manifest, nil
}

// Download fetches a plugin from remote sources and adds it to the cache.
func (d *Downloader) Download(ctx context.Context, id, version string) (*CacheEntry, error) {
	// Check if already cached
	if entry, err := d.cache.GetEntry(ctx, id, version); err == nil {
		return entry, nil
	}

	// Find plugin in manifests
	var manifestEntry *PluginManifestEntry
	var sourceName string

	for _, source := range d.sources {
		if !source.Enabled {
			continue
		}

		manifest, err := d.FetchManifest(ctx, source)
		if err != nil {
			continue // Try next source
		}

		for _, plugin := range manifest.Plugins {
			if plugin.ID == id && (version == "" || plugin.Version == version) {
				manifestEntry = &plugin
				sourceName = source.Name
				break
			}
		}

		if manifestEntry != nil {
			break
		}
	}

	if manifestEntry == nil {
		return nil, fmt.Errorf("plugin '%s' version '%s' not found in any source", id, version)
	}
	// Download plugin file
	pluginData, err := d.downloadFile(ctx, manifestEntry.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to download plugin: %w", err)
	}

	// Verify checksum
	if err := verifyChecksum(pluginData, manifestEntry.Checksum); err != nil {
		return nil, fmt.Errorf("checksum verification failed: %w", err)
	}

	// Parse plugin
	var yamlPlugin YAMLPlugin
	if err := yaml.Unmarshal(pluginData, &yamlPlugin); err != nil {
		return nil, fmt.Errorf("failed to parse plugin: %w", err)
	}

	// Add to cache (pass raw data to preserve checksum)
	sourceURL := fmt.Sprintf("%s (source: %s)", manifestEntry.URL, sourceName)
	entry, err := d.cache.Add(ctx, &yamlPlugin, manifestEntry.Checksum, sourceURL, pluginData)
	if err != nil {
		return nil, fmt.Errorf("failed to cache plugin: %w", err)
	}

	return entry, nil
}

// DownloadByCategory fetches all plugins for a given category.
func (d *Downloader) DownloadByCategory(ctx context.Context, category Category) ([]*CacheEntry, error) {
	entries := make([]*CacheEntry, 0)

	for _, source := range d.sources {
		if !source.Enabled {
			continue
		}

		manifest, err := d.FetchManifest(ctx, source)
		if err != nil {
			// Log error but continue with next source
			continue
		}

		// Find plugins in this category
		for _, plugin := range manifest.Plugins {
			hasCategory := slices.Contains(plugin.Categories, category)

			if !hasCategory {
				continue
			}

			// Download plugin
			entry, err := d.Download(ctx, plugin.Name, plugin.Version)
			if err != nil {
				// Log error but continue with next plugin
				continue
			}

			entries = append(entries, entry)
		}
	}

	// Return entries even if empty (no error if category just has no plugins)
	return entries, nil
}

// Update refreshes all cached plugins to their latest versions.
func (d *Downloader) Update(ctx context.Context) (int, error) {
	cached := d.cache.List()
	updated := 0

	for _, entry := range cached {
		// Find latest version in manifests
		var latestVersion string
		var latestManifest *PluginManifestEntry

		for _, source := range d.sources {
			if !source.Enabled {
				continue
			}

			manifest, err := d.FetchManifest(ctx, source)
			if err != nil {
				continue
			}

			for _, plugin := range manifest.Plugins {
				if plugin.Name == entry.Name {
					if latestVersion == "" || plugin.Version > latestVersion {
						latestVersion = plugin.Version
						latestManifest = &plugin
					}
				}
			}
		}

		if latestManifest == nil || latestVersion == entry.Version {
			continue // No update available
		}

		// Download new version
		if _, err := d.Download(ctx, entry.Name, latestVersion); err != nil {
			return updated, fmt.Errorf("failed to update %s: %w", entry.Name, err)
		}

		// Remove old version
		if err := d.cache.Remove(ctx, entry.Name, entry.Version); err != nil {
			return updated, fmt.Errorf("failed to remove old version of %s: %w", entry.Name, err)
		}

		updated++
	}

	return updated, nil
}

func (d *Downloader) downloadFile(ctx context.Context, url string) ([]byte, error) {
	var data []byte

	err := WithRetry(ctx, d.retryConfig, func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := d.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to download: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}

		d, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}

		data = d
		return nil
	})
	if err != nil {
		return nil, err
	}

	return data, nil
}

func verifyChecksum(data []byte, expectedChecksum string) error {
	// Expected format: "sha256:hex"
	parts := strings.SplitN(expectedChecksum, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid checksum format: %s", expectedChecksum)
	}

	algorithm := parts[0]
	expectedHex := parts[1]

	if algorithm != "sha256" {
		return fmt.Errorf("unsupported checksum algorithm: %s", algorithm)
	}

	hash := sha256.Sum256(data)
	actualHex := hex.EncodeToString(hash[:])

	if actualHex != expectedHex {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHex, actualHex)
	}

	return nil
}
