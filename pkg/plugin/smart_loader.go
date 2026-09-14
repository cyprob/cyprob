// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"context"
	"fmt"
)

// SmartLoader provides context-aware plugin loading.
// It loads only relevant plugins based on detected services and ports.
type SmartLoader struct {
	downloader *Downloader
	cache      *CacheManager
}

// NewSmartLoader creates a new smart loader.
func NewSmartLoader(downloader *Downloader, cache *CacheManager) *SmartLoader {
	return &SmartLoader{
		downloader: downloader,
		cache:      cache,
	}
}

// LoadContext represents the scanning context for smart loading.
type LoadContext struct {
	Ports      []int      // Detected open ports
	Services   []string   // Detected service names
	Categories []Category // Explicitly requested categories
}

// LoadForContext loads plugins relevant to the given context.
// It determines which categories are needed based on ports/services,
// downloads missing plugins, and returns the loaded plugin count.
func (sl *SmartLoader) LoadForContext(ctx context.Context, loadCtx LoadContext) (int, error) {
	// Determine required categories
	categories := sl.determineCategories(loadCtx)
	if len(categories) == 0 {
		return 0, nil // No categories needed
	}

	// Download plugins for each category if not already cached
	// Download automatically adds to cache registry
	totalLoaded := 0
	for _, category := range categories {
		entries, err := sl.downloader.DownloadByCategory(ctx, category)
		if err != nil {
			// Log error but continue with other categories
			continue
		}
		totalLoaded += len(entries)
	}

	return totalLoaded, nil
}

// determineCategories calculates which categories are needed based on the context.
func (sl *SmartLoader) determineCategories(loadCtx LoadContext) []Category {
	categorySet := make(map[Category]bool)

	// Add explicitly requested categories
	for _, cat := range loadCtx.Categories {
		categorySet[cat] = true
	}

	// Add categories based on detected ports
	for _, port := range loadCtx.Ports {
		for _, cat := range PortToCategories(port) {
			categorySet[cat] = true
		}
	}

	// Add categories based on detected services
	for _, service := range loadCtx.Services {
		for _, cat := range ServiceToCategories(service) {
			categorySet[cat] = true
		}
	}

	// Convert set to slice
	categories := make([]Category, 0, len(categorySet))
	for cat := range categorySet {
		categories = append(categories, cat)
	}

	return categories
}

// LoadAll loads all available plugins from all categories.
func (sl *SmartLoader) LoadAll(ctx context.Context) (int, error) {
	allCategories := AllCategories()

	// Download all categories (automatically adds to cache registry)
	totalLoaded := 0
	for _, category := range allCategories {
		entries, err := sl.downloader.DownloadByCategory(ctx, category)
		if err != nil {
			// Log error but continue with other categories
			continue
		}
		totalLoaded += len(entries)
	}

	return totalLoaded, nil
}

// LoadCategory loads plugins for a specific category.
func (sl *SmartLoader) LoadCategory(ctx context.Context, category Category) (int, error) {
	if !category.IsValid() {
		return 0, fmt.Errorf("invalid category: %s", category)
	}

	// Download plugins for this category (automatically adds to cache registry)
	entries, err := sl.downloader.DownloadByCategory(ctx, category)
	if err != nil {
		return 0, fmt.Errorf("failed to download category %s: %w", category, err)
	}

	// Return count of plugins in this category
	return len(entries), nil
}

// GetLoadedPlugins returns all currently loaded plugins.
func (sl *SmartLoader) GetLoadedPlugins() []*YAMLPlugin {
	return sl.cache.List()
}

// GetLoadedPluginsByCategory returns loaded plugins filtered by category.
func (sl *SmartLoader) GetLoadedPluginsByCategory(category Category) []*YAMLPlugin {
	all := sl.cache.List()
	filtered := make([]*YAMLPlugin, 0)

	for _, plugin := range all {
		// Check if plugin has metadata with categories
		if hasCategory(plugin, category) {
			filtered = append(filtered, plugin)
		}
	}

	return filtered
}

// hasCategory checks if a plugin belongs to a category.
// This is a heuristic based on plugin metadata.
func hasCategory(plugin *YAMLPlugin, category Category) bool {
	// Check trigger data keys for category hints
	for _, trigger := range plugin.Triggers {
		dataKey := trigger.DataKey

		// Match based on data key patterns
		switch category {
		case CategorySSH:
			if contains(dataKey, "ssh") {
				return true
			}
		case CategoryHTTP, CategoryWeb:
			if contains(dataKey, "http") || contains(dataKey, "web") {
				return true
			}
		case CategoryTLS:
			if contains(dataKey, "tls") || contains(dataKey, "ssl") {
				return true
			}
		case CategoryDatabase:
			if contains(dataKey, "mysql") || contains(dataKey, "postgres") ||
				contains(dataKey, "mongodb") || contains(dataKey, "redis") ||
				contains(dataKey, "database") || contains(dataKey, "db") {
				return true
			}
		case CategoryIoT:
			if contains(dataKey, "mqtt") || contains(dataKey, "coap") || contains(dataKey, "iot") {
				return true
			}
		case CategoryNetwork:
			if contains(dataKey, "ftp") || contains(dataKey, "telnet") ||
				contains(dataKey, "smtp") || contains(dataKey, "dns") {
				return true
			}
		}
	}

	// Check tags in metadata
	for _, tag := range plugin.Metadata.Tags {
		if CategoryFromString(tag) == category {
			return true
		}
	}

	// Default to misc if no specific category found
	return category == CategoryMisc
}

// contains checks if a string contains a substring (case-insensitive).
func contains(s, substr string) bool {
	// Simple case-insensitive contains check
	sLower := ""
	substrLower := ""

	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			sLower += string(r + 32)
		} else {
			sLower += string(r)
		}
	}

	for _, r := range substr {
		if r >= 'A' && r <= 'Z' {
			substrLower += string(r + 32)
		} else {
			substrLower += string(r)
		}
	}

	for i := 0; i <= len(sLower)-len(substrLower); i++ {
		if sLower[i:i+len(substrLower)] == substrLower {
			return true
		}
	}

	return false
}
