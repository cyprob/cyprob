// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

// Shared constants for plugin validation across CLI, API, and Service layers.
// These constants ensure consistent validation logic in defense-in-depth approach.

import "slices"

// ValidSources defines the allowed plugin source names.
// These are the officially supported plugin repositories.
var ValidSources = []string{
	"official", // Official plugin repository (the actual endpoint is resolved via config, not this comment)
	"github",   // GitHub mirror fallback
}

// MaxRequestBodySize defines the maximum allowed size for API request bodies.
// This prevents memory exhaustion from large malicious payloads.
const MaxRequestBodySize = 2 << 20 // 2 MB

// IsValidSource checks if a source name is in the whitelist.
//
// Returns:
//   - true if source is in ValidSources
//   - false otherwise
//
// Example:
//
//	if !plugin.IsValidSource("official") {
//	    return fmt.Errorf("invalid source")
//	}
func IsValidSource(source string) bool {
	return slices.Contains(ValidSources, source)
}

// IsValidCategory checks if a category is valid.
//
// This is a convenience wrapper around Category.IsValid() for use in
// validation layers that work with string types.
//
// Returns:
//   - true if category is valid (exists in AllCategories())
//   - false otherwise
//
// Example:
//
//	if !plugin.IsValidCategory("ssh") {
//	    return fmt.Errorf("invalid category")
//	}
func IsValidCategory(category string) bool {
	return Category(category).IsValid()
}

// GetValidCategories returns a list of all valid category names as strings.
//
// This is useful for generating error messages with allowed values.
//
// Example:
//
//	validCats := plugin.GetValidCategories()
//	fmt.Printf("Valid categories: %s", strings.Join(validCats, ", "))
func GetValidCategories() []string {
	categories := AllCategories()
	result := make([]string, 0, len(categories))
	for _, cat := range categories {
		result = append(result, string(cat))
	}
	return result
}
