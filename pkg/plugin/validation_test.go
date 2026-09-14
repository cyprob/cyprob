// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateTarget(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
		errType error
	}{
		// Valid cases
		{name: "valid category ssh", target: "ssh", wantErr: false},
		{name: "valid category http", target: "http", wantErr: false},
		{name: "valid plugin ID lowercase", target: "ssh-weak-cipher", wantErr: false},
		{name: "valid plugin ID with underscore", target: "http_version_check", wantErr: false},
		{name: "valid plugin ID min length", target: "abc", wantErr: false},
		{name: "valid plugin ID max length", target: "a" + strings.Repeat("b", 62), wantErr: false}, // 63 chars total

		// Invalid cases - empty/whitespace
		{name: "empty target", target: "", wantErr: true, errType: ErrInvalidOption},
		{name: "whitespace-only target", target: "   ", wantErr: true, errType: ErrInvalidOption},
		{name: "tab-only target", target: "\t", wantErr: true, errType: ErrInvalidOption},

		// Invalid cases - format
		{name: "uppercase letters", target: "SSH-Plugin", wantErr: true, errType: ErrInvalidOption},
		{name: "starts with number", target: "1plugin", wantErr: true, errType: ErrInvalidOption},
		{name: "starts with hyphen", target: "-plugin", wantErr: true, errType: ErrInvalidOption},
		{name: "contains spaces", target: "my plugin", wantErr: true, errType: ErrInvalidOption},
		{name: "contains special chars", target: "plugin@test", wantErr: true, errType: ErrInvalidOption},
		{name: "too short", target: "ab", wantErr: true, errType: ErrInvalidOption},
		{name: "too long", target: "a" + strings.Repeat("b", 63), wantErr: true, errType: ErrInvalidOption}, // 64 chars total
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTarget(tt.target)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					require.ErrorIs(t, err, tt.errType)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateCategory(t *testing.T) {
	tests := []struct {
		name     string
		category Category
		wantErr  bool
		errType  error
	}{
		// Valid cases
		{name: "empty category (optional)", category: "", wantErr: false},
		{name: "valid category ssh", category: CategorySSH, wantErr: false},
		{name: "valid category http", category: CategoryHTTP, wantErr: false},
		{name: "valid category tls", category: CategoryTLS, wantErr: false},
		{name: "valid category database", category: CategoryDatabase, wantErr: false},

		// Invalid cases
		{name: "invalid category", category: "invalid", wantErr: true, errType: ErrInvalidOption},
		{name: "uppercase category", category: "SSH", wantErr: true, errType: ErrInvalidOption},
		{name: "typo category", category: "htttp", wantErr: true, errType: ErrInvalidOption},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCategory(tt.category)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					require.ErrorIs(t, err, tt.errType)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateSource(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		wantErr bool
		errType error
	}{
		// Valid cases
		{name: "empty source (optional)", source: "", wantErr: false},
		{name: "valid source lowercase", source: "official", wantErr: false},
		{name: "valid source with hyphen", source: "my-repo", wantErr: false},
		{name: "valid source with underscore", source: "my_repo", wantErr: false},
		{name: "valid source mixed case", source: "MyRepo", wantErr: false},
		{name: "valid source with numbers", source: "repo2024", wantErr: false},
		{name: "valid source starts with number", source: "2024repo", wantErr: false},

		// Invalid cases
		{name: "whitespace-only source", source: "   ", wantErr: true, errType: ErrInvalidOption},
		{name: "source with spaces", source: "my repo", wantErr: true, errType: ErrInvalidOption},
		{name: "source with special chars", source: "repo@test", wantErr: true, errType: ErrInvalidOption},
		{name: "source with dots", source: "my.repo", wantErr: true, errType: ErrInvalidOption},
		{name: "source with slashes", source: "my/repo", wantErr: true, errType: ErrInvalidOption},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSource(tt.source)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					require.ErrorIs(t, err, tt.errType)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantErr bool
		errType error
	}{
		// Valid cases
		{name: "empty version (optional)", version: "", wantErr: false},
		{name: "valid semver major.minor.patch", version: "1.0.0", wantErr: false},
		{name: "valid semver with v prefix", version: "v1.2.3", wantErr: false},
		{name: "valid semver with prerelease", version: "1.0.0-alpha", wantErr: false},
		{name: "valid semver with build metadata", version: "1.0.0+20240101", wantErr: false},

		// Invalid cases
		{name: "whitespace-only version", version: "   ", wantErr: true, errType: ErrInvalidOption},
		{name: "invalid semver text", version: "latest", wantErr: true, errType: ErrInvalidOption},
		{name: "invalid semver random", version: "abc", wantErr: true, errType: ErrInvalidOption},
		{name: "invalid semver with letters", version: "1.2.x", wantErr: true, errType: ErrInvalidOption},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVersion(tt.version)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					require.ErrorIs(t, err, tt.errType)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidatePluginID(t *testing.T) {
	tests := []struct {
		name     string
		pluginID string
		wantErr  bool
		errType  error
	}{
		// Valid cases
		{name: "valid plugin ID lowercase", pluginID: "ssh-weak-cipher", wantErr: false},
		{name: "valid plugin ID with underscore", pluginID: "http_check", wantErr: false},
		{name: "valid plugin ID min length", pluginID: "abc", wantErr: false},

		// Invalid cases
		{name: "empty plugin ID", pluginID: "", wantErr: true, errType: ErrInvalidOption},
		{name: "whitespace-only plugin ID", pluginID: "   ", wantErr: true, errType: ErrInvalidOption},
		{name: "uppercase plugin ID", pluginID: "SSH-Plugin", wantErr: true, errType: ErrInvalidOption},
		{name: "starts with number", pluginID: "1plugin", wantErr: true, errType: ErrInvalidOption},
		{name: "contains spaces", pluginID: "my plugin", wantErr: true, errType: ErrInvalidOption},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePluginID(tt.pluginID)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					require.ErrorIs(t, err, tt.errType)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidationErrorTypes(t *testing.T) {
	// Ensure all validation errors are ErrInvalidOption
	err := validateTarget("")
	require.True(t, errors.Is(err, ErrInvalidOption), "validateTarget should return ErrInvalidOption")

	err = validateCategory("invalid")
	require.True(t, errors.Is(err, ErrInvalidOption), "validateCategory should return ErrInvalidOption")

	err = validateSource("   ")
	require.True(t, errors.Is(err, ErrInvalidOption), "validateSource should return ErrInvalidOption")

	err = validateVersion("invalid")
	require.True(t, errors.Is(err, ErrInvalidOption), "validateVersion should return ErrInvalidOption")

	err = validatePluginID("")
	require.True(t, errors.Is(err, ErrInvalidOption), "validatePluginID should return ErrInvalidOption")
}
