// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Loader loads YAML plugins from disk.
type Loader struct {
	// Base directory for plugins
	baseDir string

	// Loaded plugins cache
	plugins map[string]*YAMLPlugin
}

// NewLoader creates a new plugin loader.
func NewLoader(baseDir string) *Loader {
	return &Loader{
		baseDir: baseDir,
		plugins: make(map[string]*YAMLPlugin),
	}
}

// Load loads a YAML plugin from a file path.
// Supports both YAML and JSON formats.
func (l *Loader) Load(filePath string) (*YAMLPlugin, error) {
	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin file: %w", err)
	}

	// Parse based on extension
	var plugin YAMLPlugin
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &plugin); err != nil {
			return nil, fmt.Errorf("failed to parse YAML plugin: %w", err)
		}

	case ".json":
		if err := json.Unmarshal(data, &plugin); err != nil {
			return nil, fmt.Errorf("failed to parse JSON plugin: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported file extension: %s (must be .yaml, .yml, or .json)", ext)
	}

	// Set internal fields
	plugin.FilePath = filePath
	plugin.LoadedAt = time.Now()

	// Validate plugin
	if err := plugin.Validate(); err != nil {
		return nil, fmt.Errorf("plugin validation failed: %w", err)
	}

	// Cache the plugin
	l.plugins[filePath] = &plugin

	return &plugin, nil
}

// LoadAll loads all YAML plugins from a directory (non-recursive).
func (l *Loader) LoadAll(dirPath string) ([]*YAMLPlugin, error) {
	// Read directory
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var plugins []*YAMLPlugin
	var errors []error

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Check extension
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			continue
		}

		// Load plugin
		filePath := filepath.Join(dirPath, entry.Name())
		plugin, err := l.Load(filePath)
		if err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", entry.Name(), err))
			continue
		}

		plugins = append(plugins, plugin)
	}

	// Return error if any plugins failed to load
	if len(errors) > 0 {
		return plugins, fmt.Errorf("failed to load %d plugins: %v", len(errors), errors)
	}

	return plugins, nil
}

// LoadRecursive loads all YAML plugins from a directory recursively.
func (l *Loader) LoadRecursive(rootPath string) ([]*YAMLPlugin, error) {
	var plugins []*YAMLPlugin
	var errors []error

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Check extension
		ext := strings.ToLower(filepath.Ext(info.Name()))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}

		// Load plugin
		plugin, err := l.Load(path)
		if err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", path, err))
			return nil // Continue walking
		}

		plugins = append(plugins, plugin)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	// Return error if any plugins failed to load
	if len(errors) > 0 {
		return plugins, fmt.Errorf("failed to load %d plugins: %v", len(errors), errors)
	}

	return plugins, nil
}

// GetCached returns a cached plugin by file path.
func (l *Loader) GetCached(filePath string) (*YAMLPlugin, bool) {
	plugin, ok := l.plugins[filePath]
	return plugin, ok
}

// ClearCache clears the plugin cache.
func (l *Loader) ClearCache() {
	l.plugins = make(map[string]*YAMLPlugin)
}
