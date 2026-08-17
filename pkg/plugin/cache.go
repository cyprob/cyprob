// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// CacheManager manages plugin download cache.
// Default cache location: XDG cache dir (e.g., ~/.cache/cyprob/plugins/cache).
type CacheManager struct {
	// Base cache directory (e.g., ~/.cache/cyprob/plugins/cache/)
	cacheDir string

	// Registry for tracking cached plugins
	registry *YAMLRegistry
}

// NewCacheManager creates a new cache manager.
// It scans the cache directory and loads existing plugins into the registry.
func NewCacheManager(cacheDir string) (*CacheManager, error) {
	if cacheDir == "" {
		return nil, fmt.Errorf("cache directory cannot be empty")
	}

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	cm := &CacheManager{
		cacheDir: cacheDir,
		registry: NewYAMLRegistry(),
	}

	// Load existing plugins from disk into registry
	// This prevents re-downloading already cached plugins
	// Use background context for initialization - no cancellation needed during startup
	_, _ = cm.LoadFromDisk(context.Background()) // Ignore errors - partial load is acceptable

	return cm, nil
}

// CacheEntry represents metadata about a cached plugin.
type CacheEntry struct {
	ID          string    // Plugin ID
	Name        string    // Plugin name (for display)
	Version     string    // Plugin version
	Path        string    // Path to cached YAML file
	Checksum    string    // SHA-256 checksum
	DownloadURL string    // Original download URL
	CachedAt    time.Time // When it was cached
	LastUsed    time.Time // Last access time
}

// Add adds a plugin to the cache.
// Returns the cache entry for the plugin.
// If rawData is provided, it will be written as-is to preserve checksums.
// If rawData is nil, the plugin will be marshaled to YAML.
func (c *CacheManager) Add(ctx context.Context, plugin *YAMLPlugin, checksum, downloadURL string, rawData ...[]byte) (*CacheEntry, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if plugin == nil {
		return nil, fmt.Errorf("cannot cache nil plugin")
	}

	// Validate plugin before caching
	if err := plugin.Validate(); err != nil {
		return nil, fmt.Errorf("plugin validation failed: %w", err)
	}

	// Create plugin-specific cache directory
	// Structure: cache/<plugin-id>/<version>/plugin.yaml
	pluginDir := filepath.Join(c.cacheDir, plugin.ID, plugin.Version)
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create plugin cache directory: %w", err)
	}

	// Cache file path
	cachePath := filepath.Join(pluginDir, "plugin.yaml")

	// Write plugin to disk (use raw data if provided to preserve checksum)
	var data []byte
	var err error
	if len(rawData) > 0 && rawData[0] != nil {
		data = rawData[0]
	} else {
		data, err = yaml.Marshal(plugin)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal plugin: %w", err)
		}
	}
	if err := os.WriteFile(cachePath, data, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write plugin to cache: %w", err)
	}

	// Register in cache registry
	if err := c.registry.Register(plugin); err != nil {
		// If already exists, unregister and re-register
		_ = c.registry.Unregister(plugin.Name)
		if err := c.registry.Register(plugin); err != nil {
			return nil, fmt.Errorf("failed to register plugin in cache: %w", err)
		}
	}

	now := time.Now()
	entry := &CacheEntry{
		ID:          plugin.ID,
		Name:        plugin.Name,
		Version:     plugin.Version,
		Path:        cachePath,
		Checksum:    checksum,
		DownloadURL: downloadURL,
		CachedAt:    now,
		LastUsed:    now,
	}

	return entry, nil
}

// Get retrieves a cached plugin by ID.
func (c *CacheManager) Get(id string) (*YAMLPlugin, bool) {
	return c.registry.Get(id)
}

// GetEntry retrieves a cache entry by ID and version.
func (c *CacheManager) GetEntry(ctx context.Context, id, version string) (*CacheEntry, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	plugin, found := c.registry.Get(id)
	if !found {
		return nil, fmt.Errorf("plugin '%s' not found in cache", id)
	}

	if plugin.Version != version {
		return nil, fmt.Errorf("plugin '%s' found but version mismatch: expected %s, got %s", id, version, plugin.Version)
	}

	pluginDir := filepath.Join(c.cacheDir, id, version)
	cachePath := filepath.Join(pluginDir, "plugin.yaml")

	// Check if cache file exists
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("cache file not found for plugin '%s' version '%s'", id, version)
	}

	// Get file info for timestamps
	info, err := os.Stat(cachePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat cache file: %w", err)
	}

	entry := &CacheEntry{
		ID:       id,
		Name:     plugin.Name,
		Version:  version,
		Path:     cachePath,
		CachedAt: info.ModTime(),
		LastUsed: info.ModTime(),
	}

	return entry, nil
}

// Remove removes a plugin from the cache.
func (c *CacheManager) Remove(ctx context.Context, id, version string) error {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return err
	}

	// Check if cache directory exists for this version
	pluginDir := filepath.Join(c.cacheDir, id, version)
	if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
		return fmt.Errorf("plugin '%s' version '%s' not found in cache", id, version)
	}

	// Remove cache directory for this specific version
	if err := os.RemoveAll(pluginDir); err != nil {
		return fmt.Errorf("failed to remove cache directory: %w", err)
	}

	// Check if this is the version currently in the registry
	currentPlugin, found := c.registry.Get(id)
	if found && currentPlugin.Version == version {
		// Only unregister if we're removing the currently registered version
		if err := c.registry.Unregister(id); err != nil {
			return fmt.Errorf("failed to unregister plugin: %w", err)
		}
	}

	// Clean up parent directory if empty
	parentDir := filepath.Join(c.cacheDir, id)
	entries, err := os.ReadDir(parentDir)
	if err == nil && len(entries) == 0 {
		_ = os.Remove(parentDir)
	}

	return nil
}

// List returns all cached plugins.
func (c *CacheManager) List() []*YAMLPlugin {
	return c.registry.List()
}

// ListEntries returns all cache entries.
func (c *CacheManager) ListEntries(ctx context.Context) []*CacheEntry {
	plugins := c.registry.List()
	entries := make([]*CacheEntry, 0, len(plugins))

	for _, plugin := range plugins {
		// Check context cancellation in loop
		if err := ctx.Err(); err != nil {
			return entries // Return partial results on cancellation
		}
		entry, err := c.GetEntry(ctx, plugin.ID, plugin.Version)
		if err == nil {
			entries = append(entries, entry)
		}
	}

	return entries
}

// Clear removes all cached plugins.
func (c *CacheManager) Clear(ctx context.Context) error {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return err
	}

	// Remove all plugin directories
	entries, err := os.ReadDir(c.cacheDir)
	if err != nil {
		return fmt.Errorf("failed to read cache directory: %w", err)
	}

	for _, entry := range entries {
		// Check context cancellation in loop
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			pluginDir := filepath.Join(c.cacheDir, entry.Name())
			if err := os.RemoveAll(pluginDir); err != nil {
				return fmt.Errorf("failed to remove plugin directory %s: %w", entry.Name(), err)
			}
		}
	}

	// Clear registry
	c.registry.Clear()

	return nil
}

// Size returns the total size of the cache in bytes.
func (c *CacheManager) Size(ctx context.Context) (int64, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	var totalSize int64

	err := filepath.Walk(c.cacheDir, func(path string, info os.FileInfo, err error) error {
		// Check context cancellation in walk function
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("failed to calculate cache size: %w", err)
	}

	return totalSize, nil
}

// Prune removes unused cached plugins older than the specified duration.
// This is useful for cleaning up stale cache entries.
func (c *CacheManager) Prune(ctx context.Context, olderThan time.Duration) (int, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	cutoffTime := time.Now().Add(-olderThan)
	removed := 0

	entries, err := os.ReadDir(c.cacheDir)
	if err != nil {
		return 0, fmt.Errorf("failed to read cache directory: %w", err)
	}

	for _, entry := range entries {
		// Check context cancellation in loop
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		if !entry.IsDir() {
			continue
		}

		pluginDir := filepath.Join(c.cacheDir, entry.Name())

		// Check modification time
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoffTime) {
			// Remove plugin from cache
			versions, err := os.ReadDir(pluginDir)
			if err != nil {
				continue
			}

			for _, versionEntry := range versions {
				if versionEntry.IsDir() {
					versionDir := filepath.Join(pluginDir, versionEntry.Name())
					if err := os.RemoveAll(versionDir); err != nil {
						continue
					}
					removed++
				}
			}

			// Remove plugin directory if empty
			remaining, err := os.ReadDir(pluginDir)
			if err == nil && len(remaining) == 0 {
				_ = os.Remove(pluginDir)
			}

			// Unregister from registry
			_ = c.registry.Unregister(entry.Name())
		}
	}

	return removed, nil
}

// LoadFromDisk loads all cached plugins from disk into the registry.
func (c *CacheManager) LoadFromDisk(ctx context.Context) (int, []error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return 0, []error{err}
	}

	loader := NewLoader(c.cacheDir)
	plugins, err := loader.LoadRecursive(c.cacheDir)
	if err != nil {
		// Partial success - some plugins loaded, some failed
		loadedCount, regErrors := c.registry.RegisterBulk(plugins)
		var allErrors []error
		allErrors = append(allErrors, fmt.Errorf("load errors: %w", err))
		allErrors = append(allErrors, regErrors...)
		return loadedCount, allErrors
	}

	// All plugins loaded successfully
	return c.registry.RegisterBulk(plugins)
}
