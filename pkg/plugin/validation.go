// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// Validation helper functions for plugin service inputs.
// These functions provide defense-in-depth by validating inputs at the service layer,
// regardless of whether CLI/API has already validated them.

// pluginIDPattern matches valid plugin IDs:
// - Lowercase alphanumeric, hyphens, underscores
// - Must start with letter
// - Length: 3-63 characters (total)
var pluginIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,62}$`)

// validateTarget validates a plugin target (category or plugin ID).
//
// Returns:
//   - error if target is empty or invalid format
//   - nil if target is valid
func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("%w: target cannot be empty", ErrInvalidOption)
	}

	// Check if target is whitespace-only
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("%w: target cannot be whitespace-only", ErrInvalidOption)
	}

	// Target can be a category or plugin ID
	// Categories are already validated via Category.IsValid()
	// Plugin IDs must match pattern
	cat := Category(target)
	if cat.IsValid() {
		// Valid category
		return nil
	}

	// Not a category, validate as plugin ID
	if !pluginIDPattern.MatchString(target) {
		return fmt.Errorf("%w: invalid plugin ID format '%s' (must be lowercase alphanumeric with hyphens/underscores, 3-63 chars, starting with letter)", ErrInvalidOption, target)
	}

	return nil
}

// validateCategory validates a category option.
//
// Returns:
//   - error if category is specified but invalid
//   - nil if category is empty (optional) or valid
func validateCategory(category Category) error {
	// Empty category is valid (means "no filter")
	if category == "" {
		return nil
	}

	if !category.IsValid() {
		validCategories := make([]string, 0, len(AllCategories()))
		for _, cat := range AllCategories() {
			validCategories = append(validCategories, string(cat))
		}
		return fmt.Errorf("%w: invalid category '%s' (valid: %s)", ErrInvalidOption, category, strings.Join(validCategories, ", "))
	}

	return nil
}

// validateSource validates a plugin source name.
//
// Returns:
//   - error if source is whitespace-only or contains invalid characters
//   - nil if source is empty (means "all sources") or valid
func validateSource(source string) error {
	// Empty source is valid (means "all sources")
	if source == "" {
		return nil
	}

	// Check if source is whitespace-only
	if strings.TrimSpace(source) == "" {
		return fmt.Errorf("%w: source cannot be whitespace-only", ErrInvalidOption)
	}

	// Source names should be alphanumeric with hyphens/underscores
	// More permissive than plugin IDs (can start with number, longer)
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(source) {
		return fmt.Errorf("%w: invalid source name '%s' (must be alphanumeric with hyphens/underscores)", ErrInvalidOption, source)
	}

	return nil
}

// validateVersion validates a semantic version string.
//
// Returns:
//   - error if version is specified but invalid semver
//   - nil if version is empty (means "latest") or valid semver
func validateVersion(version string) error {
	// Empty version is valid (means "latest")
	if version == "" {
		return nil
	}

	// Check if version is whitespace-only
	if strings.TrimSpace(version) == "" {
		return fmt.Errorf("%w: version cannot be whitespace-only", ErrInvalidOption)
	}

	// Validate semver format
	_, err := semver.NewVersion(version)
	if err != nil {
		return fmt.Errorf("%w: invalid version format '%s' (must be valid semver): %v", ErrInvalidOption, version, err)
	}

	return nil
}

// validatePluginID validates a plugin ID for operations that require it.
//
// Returns:
//   - error if pluginID is empty or invalid format
//   - nil if pluginID is valid
func validatePluginID(pluginID string) error {
	if pluginID == "" {
		return fmt.Errorf("%w: plugin ID cannot be empty", ErrInvalidOption)
	}

	// Check if pluginID is whitespace-only
	if strings.TrimSpace(pluginID) == "" {
		return fmt.Errorf("%w: plugin ID cannot be whitespace-only", ErrInvalidOption)
	}

	if !pluginIDPattern.MatchString(pluginID) {
		return fmt.Errorf("%w: invalid plugin ID format '%s' (must be lowercase alphanumeric with hyphens/underscores, 3-63 chars, starting with letter)", ErrInvalidOption, pluginID)
	}

	return nil
}
