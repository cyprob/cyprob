// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

//go:embed embedded/**/*.yaml
var embeddedPlugins embed.FS

// LoadEmbeddedPlugins loads all embedded plugins from the binary.
// Returns a map of category to plugins for efficient category-based access.
func LoadEmbeddedPlugins() (map[Category][]*YAMLPlugin, error) {
	plugins := make(map[Category][]*YAMLPlugin)

	logger := log.With().Str("component", "embedded-loader").Logger()
	logger.Info().Msg("Loading embedded plugins from binary")

	// Walk through all embedded plugin files
	err := fs.WalkDir(embeddedPlugins, "embedded", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-YAML files
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		// Read plugin file
		data, err := embeddedPlugins.ReadFile(path)
		if err != nil {
			logger.Warn().Str("path", path).Err(err).Msg("Failed to read embedded plugin")
			return nil // Continue with other plugins
		}

		// Parse YAML plugin directly from bytes
		var yamlPlugin YAMLPlugin
		if err := yaml.Unmarshal(data, &yamlPlugin); err != nil {
			logger.Warn().Str("path", path).Err(err).Msg("Failed to parse embedded plugin")
			return nil // Continue with other plugins
		}

		// Determine category from directory structure
		// Path format: embedded/<category>/<plugin-name>.yaml
		category := determineCategoryFromPath(path)

		// Add to category map
		plugins[category] = append(plugins[category], &yamlPlugin)

		logger.Debug().
			Str("plugin", yamlPlugin.Name).
			Str("version", yamlPlugin.Version).
			Str("category", category.String()).
			Str("path", path).
			Msg("Loaded embedded plugin")

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk embedded plugins: %w", err)
	}

	// Log summary
	totalCount := 0
	for cat, catPlugins := range plugins {
		count := len(catPlugins)
		totalCount += count
		logger.Info().
			Str("category", cat.String()).
			Int("count", count).
			Msg("Loaded embedded plugins for category")
	}

	logger.Info().Int("total", totalCount).Msg("Embedded plugins loaded successfully")

	return plugins, nil
}

// LoadEmbeddedPluginsByCategory loads embedded plugins for a specific category.
func LoadEmbeddedPluginsByCategory(category Category) ([]*YAMLPlugin, error) {
	all, err := LoadEmbeddedPlugins()
	if err != nil {
		return nil, err
	}

	plugins, ok := all[category]
	if !ok {
		return []*YAMLPlugin{}, nil // Return empty slice if category not found
	}

	return plugins, nil
}

// LoadAllEmbeddedPlugins loads all embedded plugins as a flat list.
func LoadAllEmbeddedPlugins() ([]*YAMLPlugin, error) {
	categorized, err := LoadEmbeddedPlugins()
	if err != nil {
		return nil, err
	}

	// Flatten the map into a single slice
	var all []*YAMLPlugin
	for _, catPlugins := range categorized {
		all = append(all, catPlugins...)
	}

	return all, nil
}

// GetEmbeddedPluginCount returns the total number of embedded plugins.
func GetEmbeddedPluginCount() (int, error) {
	plugins, err := LoadAllEmbeddedPlugins()
	if err != nil {
		return 0, err
	}
	return len(plugins), nil
}

// determineCategoryFromPath extracts category from embedded path.
// Path format: embedded/<category>/<plugin-name>.yaml
func determineCategoryFromPath(path string) Category {
	// Remove "embedded/" prefix and get directory name
	parts := strings.Split(filepath.ToSlash(path), "/")
	if len(parts) < 2 {
		return CategoryMisc
	}

	categoryName := parts[1] // e.g., "ssh", "http", "tls"

	// Map directory name to Category
	switch categoryName {
	case "ssh":
		return CategorySSH
	case "http":
		return CategoryHTTP
	case "tls":
		return CategoryTLS
	case "database":
		return CategoryDatabase
	case "misconfig":
		return CategoryNetwork // Misconfig plugins go under Network category
	default:
		return CategoryMisc
	}
}
