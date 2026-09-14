// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Manifest represents the plugin registry manifest (registry.json).
// This file tracks all installed plugins and their metadata.
type Manifest struct {
	// Version of the manifest format
	Version string `json:"version"`

	// LastUpdated timestamp
	LastUpdated time.Time `json:"last_updated"`

	// Plugins map (plugin ID -> ManifestEntry)
	Plugins map[string]*ManifestEntry `json:"plugins"`

	// RegistryURL is the upstream plugin registry URL
	RegistryURL string `json:"registry_url,omitempty"`
}

// ManifestEntry represents a single plugin entry in the manifest.
type ManifestEntry struct {
	// Plugin metadata
	ID      string `json:"id"` // Unique plugin identifier (slug)
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	Author  string `json:"author"`

	// Installation info
	Checksum     string    `json:"checksum"`
	DownloadURL  string    `json:"download_url"`
	InstalledAt  time.Time `json:"installed_at"`
	LastVerified time.Time `json:"last_verified,omitzero"`

	// File path (relative to plugin directory)
	Path string `json:"path"`

	// Tags for categorization
	Tags []string `json:"tags,omitempty"`

	// Severity (for evaluation plugins)
	Severity string `json:"severity,omitempty"`
}

// ManifestManager manages the plugin registry manifest file.
type ManifestManager struct {
	// Path to manifest file (registry.json)
	manifestPath string

	// In-memory manifest
	manifest *Manifest
}

// NewManifestManager creates a new manifest manager.
func NewManifestManager(manifestPath string) (*ManifestManager, error) {
	if manifestPath == "" {
		return nil, fmt.Errorf("manifest path cannot be empty")
	}

	// Ensure parent directory exists
	dir := filepath.Dir(manifestPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create manifest directory: %w", err)
	}

	return &ManifestManager{
		manifestPath: manifestPath,
		manifest:     nil, // Loaded on demand
	}, nil
}

// Load loads the manifest from disk.
// If the file doesn't exist, returns an empty manifest.
func (m *ManifestManager) Load() error {
	// Check if manifest file exists
	if _, err := os.Stat(m.manifestPath); os.IsNotExist(err) {
		// Create new empty manifest
		m.manifest = &Manifest{
			Version:     "1.0",
			LastUpdated: time.Now(),
			Plugins:     make(map[string]*ManifestEntry),
		}
		return nil
	}

	// Read manifest file
	data, err := os.ReadFile(m.manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest: %w", err)
	}

	// Parse JSON
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("failed to parse manifest: %w", err)
	}

	m.manifest = &manifest
	return nil
}

// Save writes the manifest to disk.
func (m *ManifestManager) Save() error {
	if m.manifest == nil {
		return fmt.Errorf("manifest not loaded")
	}

	// Update timestamp
	m.manifest.LastUpdated = time.Now()

	// Marshal to JSON (pretty-printed)
	data, err := json.MarshalIndent(m.manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	// Write to file
	if err := os.WriteFile(m.manifestPath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// Reload reloads the manifest from disk, discarding the in-memory cache.
// This is used by the file watcher to pick up external changes (e.g., CLI updates).
func (m *ManifestManager) Reload() error {
	// Force reload by clearing cache first
	m.manifest = nil
	return m.Load()
}

// Add adds a plugin entry to the manifest.
func (m *ManifestManager) Add(entry *ManifestEntry) error {
	if m.manifest == nil {
		if err := m.Load(); err != nil {
			return fmt.Errorf("failed to load manifest: %w", err)
		}
	}

	if entry == nil {
		return fmt.Errorf("manifest entry cannot be nil")
	}

	if entry.ID == "" {
		return fmt.Errorf("plugin ID cannot be empty")
	}

	if entry.Name == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}

	// Add to manifest (use ID as key)
	m.manifest.Plugins[entry.ID] = entry

	return nil
}

// Remove removes a plugin entry from the manifest by ID.
func (m *ManifestManager) Remove(id string) error {
	if m.manifest == nil {
		if err := m.Load(); err != nil {
			return fmt.Errorf("failed to load manifest: %w", err)
		}
	}

	if id == "" {
		return fmt.Errorf("plugin ID cannot be empty")
	}

	if _, exists := m.manifest.Plugins[id]; !exists {
		return fmt.Errorf("plugin '%s' not found in manifest", id)
	}

	delete(m.manifest.Plugins, id)

	return nil
}

// Get retrieves a plugin entry from the manifest by ID.
func (m *ManifestManager) Get(id string) (*ManifestEntry, error) {
	if m.manifest == nil {
		if err := m.Load(); err != nil {
			return nil, fmt.Errorf("failed to load manifest: %w", err)
		}
	}

	entry, exists := m.manifest.Plugins[id]
	if !exists {
		return nil, fmt.Errorf("plugin '%s' not found in manifest", id)
	}

	return entry, nil
}

// List returns all plugin entries in the manifest.
func (m *ManifestManager) List() ([]*ManifestEntry, error) {
	if m.manifest == nil {
		if err := m.Load(); err != nil {
			return nil, fmt.Errorf("failed to load manifest: %w", err)
		}
	}

	entries := make([]*ManifestEntry, 0, len(m.manifest.Plugins))
	for _, entry := range m.manifest.Plugins {
		entries = append(entries, entry)
	}

	return entries, nil
}

// Update updates an existing plugin entry in the manifest.
func (m *ManifestManager) Update(id string, entry *ManifestEntry) error {
	if m.manifest == nil {
		if err := m.Load(); err != nil {
			return fmt.Errorf("failed to load manifest: %w", err)
		}
	}

	if id == "" {
		return fmt.Errorf("plugin ID cannot be empty")
	}

	if entry == nil {
		return fmt.Errorf("manifest entry cannot be nil")
	}

	if _, exists := m.manifest.Plugins[id]; !exists {
		return fmt.Errorf("plugin '%s' not found in manifest", id)
	}

	m.manifest.Plugins[id] = entry

	return nil
}

// Clear removes all plugin entries from the manifest.
func (m *ManifestManager) Clear() error {
	if m.manifest == nil {
		if err := m.Load(); err != nil {
			return fmt.Errorf("failed to load manifest: %w", err)
		}
	}

	m.manifest.Plugins = make(map[string]*ManifestEntry)

	return nil
}

// Count returns the number of plugins in the manifest.
func (m *ManifestManager) Count() (int, error) {
	if m.manifest == nil {
		if err := m.Load(); err != nil {
			return 0, fmt.Errorf("failed to load manifest: %w", err)
		}
	}

	return len(m.manifest.Plugins), nil
}

// SetRegistryURL sets the upstream registry URL.
func (m *ManifestManager) SetRegistryURL(url string) error {
	if m.manifest == nil {
		if err := m.Load(); err != nil {
			return fmt.Errorf("failed to load manifest: %w", err)
		}
	}

	m.manifest.RegistryURL = url

	return nil
}

// GetRegistryURL returns the upstream registry URL.
func (m *ManifestManager) GetRegistryURL() (string, error) {
	if m.manifest == nil {
		if err := m.Load(); err != nil {
			return "", fmt.Errorf("failed to load manifest: %w", err)
		}
	}

	return m.manifest.RegistryURL, nil
}

// NewManifestEntryFromPlugin creates a ManifestEntry from a YAMLPlugin.
func NewManifestEntryFromPlugin(plugin *YAMLPlugin, checksum, downloadURL string) *ManifestEntry {
	return &ManifestEntry{
		Name:        plugin.Name,
		Version:     plugin.Version,
		Type:        string(plugin.Type),
		Author:      plugin.Author,
		Checksum:    checksum,
		DownloadURL: downloadURL,
		InstalledAt: time.Now(),
		Path:        plugin.FilePath,
		Tags:        plugin.Metadata.Tags,
		Severity:    string(plugin.Metadata.Severity),
	}
}
