// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidSources(t *testing.T) {
	t.Run("contains expected sources", func(t *testing.T) {
		require.Contains(t, ValidSources, "official")
		require.Contains(t, ValidSources, "github")
		require.Len(t, ValidSources, 2, "Should have exactly 2 valid sources")
	})
}

func TestMaxRequestBodySize(t *testing.T) {
	t.Run("is 2MB", func(t *testing.T) {
		expected := 2 << 20 // 2 MB = 2097152 bytes
		require.Equal(t, expected, MaxRequestBodySize)
		require.Equal(t, 2097152, MaxRequestBodySize)
	})
}

func TestIsValidSource(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected bool
	}{
		{
			name:     "valid source - official",
			source:   "official",
			expected: true,
		},
		{
			name:     "valid source - github",
			source:   "github",
			expected: true,
		},
		{
			name:     "invalid source - custom",
			source:   "custom",
			expected: false,
		},
		{
			name:     "invalid source - empty",
			source:   "",
			expected: false,
		},
		{
			name:     "invalid source - uppercase",
			source:   "OFFICIAL",
			expected: false,
		},
		{
			name:     "invalid source - whitespace",
			source:   " official ",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidSource(tt.source)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidCategory(t *testing.T) {
	tests := []struct {
		name     string
		category string
		expected bool
	}{
		{
			name:     "valid category - ssh",
			category: "ssh",
			expected: true,
		},
		{
			name:     "valid category - http",
			category: "http",
			expected: true,
		},
		{
			name:     "valid category - tls",
			category: "tls",
			expected: true,
		},
		{
			name:     "valid category - database",
			category: "database",
			expected: true,
		},
		{
			name:     "valid category - network",
			category: "network",
			expected: true,
		},
		{
			name:     "valid category - misc",
			category: "misc",
			expected: true,
		},
		{
			name:     "invalid category - custom",
			category: "custom",
			expected: false,
		},
		{
			name:     "invalid category - empty",
			category: "",
			expected: false,
		},
		{
			name:     "invalid category - uppercase",
			category: "SSH",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidCategory(tt.category)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestGetValidCategories(t *testing.T) {
	t.Run("returns all categories", func(t *testing.T) {
		categories := GetValidCategories()

		require.NotEmpty(t, categories)
		require.Contains(t, categories, "ssh")
		require.Contains(t, categories, "http")
		require.Contains(t, categories, "tls")
		require.Contains(t, categories, "database")
		require.Contains(t, categories, "network")
		require.Contains(t, categories, "misc")
	})

	t.Run("returns correct count", func(t *testing.T) {
		categories := GetValidCategories()
		allCategories := AllCategories()

		require.Equal(t, len(allCategories), len(categories),
			"GetValidCategories() should return same count as AllCategories()")
	})

	t.Run("all returned values are valid", func(t *testing.T) {
		categories := GetValidCategories()

		for _, cat := range categories {
			require.True(t, IsValidCategory(cat),
				"Category %q from GetValidCategories() should be valid", cat)
		}
	})
}
