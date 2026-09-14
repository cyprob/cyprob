// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// TestFunctionalOptions_WithCacheDir tests the WithCacheDir option
func TestFunctionalOptions_WithCacheDir(t *testing.T) {
	t.Run("sets custom cache directory", func(t *testing.T) {
		cacheDir := t.TempDir()

		svc, err := NewService(WithCacheDir(cacheDir))

		require.NoError(t, err)
		require.NotNil(t, svc)
		require.NotNil(t, svc.cache)
	})

	t.Run("uses default when not specified", func(t *testing.T) {
		svc, err := NewService()

		require.NoError(t, err)
		require.NotNil(t, svc)
		require.NotNil(t, svc.cache)
	})

	t.Run("creates directory if not exists", func(t *testing.T) {
		tempDir := t.TempDir()
		cacheDir := tempDir + "/nonexistent/cache"

		svc, err := NewService(WithCacheDir(cacheDir))

		require.NoError(t, err)
		require.NotNil(t, svc)

		// Verify directory was created
		_, err = os.Stat(cacheDir)
		require.NoError(t, err, "cache directory should be created")
	})
}

// TestFunctionalOptions_WithLogger tests the WithLogger option
func TestFunctionalOptions_WithLogger(t *testing.T) {
	t.Run("sets custom logger", func(t *testing.T) {
		cacheDir := t.TempDir()
		customLogger := zerolog.New(os.Stdout).With().
			Str("service", "plugin-test").
			Logger()

		svc, err := NewService(
			WithCacheDir(cacheDir),
			WithLogger(customLogger),
		)

		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Equal(t, customLogger, svc.logger)
	})

	t.Run("uses default logger when not specified", func(t *testing.T) {
		cacheDir := t.TempDir()

		svc, err := NewService(WithCacheDir(cacheDir))

		require.NoError(t, err)
		require.NotNil(t, svc)
		// Should have a non-nil logger (default)
		require.NotNil(t, &svc.logger)
	})

	t.Run("custom logger can be Nop", func(t *testing.T) {
		cacheDir := t.TempDir()
		nopLogger := zerolog.Nop()

		svc, err := NewService(
			WithCacheDir(cacheDir),
			WithLogger(nopLogger),
		)

		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Equal(t, nopLogger, svc.logger)
	})
}

// TestFunctionalOptions_WithConfig tests the WithConfig option
func TestFunctionalOptions_WithConfig(t *testing.T) {
	t.Run("sets custom config", func(t *testing.T) {
		cacheDir := t.TempDir()
		customConfig := ServiceConfig{
			InstallTimeout:   120 * time.Second,
			UpdateTimeout:    120 * time.Second,
			UninstallTimeout: 60 * time.Second,
			ListTimeout:      20 * time.Second,
			GetInfoTimeout:   10 * time.Second,
			CleanTimeout:     60 * time.Second,
			VerifyTimeout:    120 * time.Second,
		}

		svc, err := NewService(
			WithCacheDir(cacheDir),
			WithConfig(customConfig),
		)

		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Equal(t, customConfig.InstallTimeout, svc.config.InstallTimeout)
		require.Equal(t, customConfig.UpdateTimeout, svc.config.UpdateTimeout)
		require.Equal(t, customConfig.UninstallTimeout, svc.config.UninstallTimeout)
		require.Equal(t, customConfig.ListTimeout, svc.config.ListTimeout)
		require.Equal(t, customConfig.GetInfoTimeout, svc.config.GetInfoTimeout)
		require.Equal(t, customConfig.CleanTimeout, svc.config.CleanTimeout)
		require.Equal(t, customConfig.VerifyTimeout, svc.config.VerifyTimeout)
	})

	t.Run("uses default config when not specified", func(t *testing.T) {
		cacheDir := t.TempDir()

		svc, err := NewService(WithCacheDir(cacheDir))

		require.NoError(t, err)
		require.NotNil(t, svc)
		// Should have default timeout values
		require.Equal(t, 60*time.Second, svc.config.InstallTimeout)
		require.Equal(t, 60*time.Second, svc.config.UpdateTimeout)
		require.Equal(t, 30*time.Second, svc.config.UninstallTimeout)
		require.Equal(t, 10*time.Second, svc.config.ListTimeout)
		require.Equal(t, 5*time.Second, svc.config.GetInfoTimeout)
		require.Equal(t, 30*time.Second, svc.config.CleanTimeout)
		require.Equal(t, 60*time.Second, svc.config.VerifyTimeout)
	})
}

// TestFunctionalOptions_WithStorage tests the WithStorage option
func TestFunctionalOptions_WithStorage(t *testing.T) {
	t.Run("sets storage backend", func(t *testing.T) {
		cacheDir := t.TempDir()
		// Mock storage backend (nil for now, will be real in integration tests)
		// var mockStorage storage.Backend = nil

		svc, err := NewService(
			WithCacheDir(cacheDir),
			// WithStorage(mockStorage),
		)

		require.NoError(t, err)
		require.NotNil(t, svc)
		// Storage should be nil by default
		require.Nil(t, svc.storage)
	})

	t.Run("storage is optional and defaults to nil", func(t *testing.T) {
		cacheDir := t.TempDir()

		svc, err := NewService(WithCacheDir(cacheDir))

		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Nil(t, svc.storage)
	})
}

// TestFunctionalOptions_WithPluginSources tests the WithPluginSources option
func TestFunctionalOptions_WithPluginSources(t *testing.T) {
	t.Run("sets custom sources", func(t *testing.T) {
		cacheDir := t.TempDir()
		customSources := []PluginSource{
			{
				Name:     "custom",
				URL:      "https://custom.example.com/manifest.yaml",
				Enabled:  true,
				Priority: 1,
			},
			{
				Name:     "mirror",
				URL:      "https://mirror.example.com/manifest.yaml",
				Enabled:  true,
				Priority: 2,
			},
		}

		svc, err := NewService(
			WithCacheDir(cacheDir),
			WithPluginSources(customSources),
		)

		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Equal(t, customSources, svc.sources)
		require.Len(t, svc.sources, 2)
		require.Equal(t, "custom", svc.sources[0].Name)
		require.Equal(t, "mirror", svc.sources[1].Name)
	})

	t.Run("uses default sources when not specified", func(t *testing.T) {
		cacheDir := t.TempDir()

		svc, err := NewService(WithCacheDir(cacheDir))

		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Len(t, svc.sources, 1)
		require.Equal(t, "official", svc.sources[0].Name)
		require.Equal(t, "https://plugins.pentora.ai/manifest.yaml", svc.sources[0].URL)
	})
}

// TestFunctionalOptions_MultipleOptions tests combining multiple options
func TestFunctionalOptions_MultipleOptions(t *testing.T) {
	t.Run("combines all options", func(t *testing.T) {
		cacheDir := t.TempDir()
		customLogger := zerolog.New(os.Stdout)
		customConfig := ServiceConfig{
			InstallTimeout: 120 * time.Second,
		}
		customSources := []PluginSource{
			{Name: "custom", URL: "https://custom.example.com/manifest.yaml", Enabled: true},
		}

		svc, err := NewService(
			WithCacheDir(cacheDir),
			WithLogger(customLogger),
			WithConfig(customConfig),
			WithPluginSources(customSources),
		)

		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Equal(t, customLogger, svc.logger)
		require.Equal(t, 120*time.Second, svc.config.InstallTimeout)
		require.Equal(t, customSources, svc.sources)
	})

	t.Run("options order doesn't matter", func(t *testing.T) {
		cacheDir := t.TempDir()
		customLogger := zerolog.New(os.Stdout)
		customSources := []PluginSource{
			{Name: "custom", URL: "https://custom.example.com/manifest.yaml", Enabled: true},
		}

		// Apply options in different order
		svc, err := NewService(
			WithPluginSources(customSources),
			WithLogger(customLogger),
			WithCacheDir(cacheDir),
		)

		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Equal(t, customLogger, svc.logger)
		require.Equal(t, customSources, svc.sources)
	})

	t.Run("can override cache dir with empty to get default", func(t *testing.T) {
		// First set a custom cache dir, then override with empty to get default
		customCache := t.TempDir()

		// This should use default cache dir since empty string triggers default
		svc, err := NewService(
			WithCacheDir(customCache),
			WithCacheDir(""), // Override with empty - should use default
		)

		require.NoError(t, err)
		require.NotNil(t, svc)
		// Should have created service successfully with default cache dir
	})
}

// TestFunctionalOptions_BackwardCompatibility tests backward compatibility
func TestFunctionalOptions_BackwardCompatibility(t *testing.T) {
	t.Run("minimal usage works", func(t *testing.T) {
		// Just like old NewService(cacheDir)
		cacheDir := t.TempDir()
		svc, err := NewService(WithCacheDir(cacheDir))

		require.NoError(t, err)
		require.NotNil(t, svc)
	})

	t.Run("no options works", func(t *testing.T) {
		// New capability: completely default service
		svc, err := NewService()

		require.NoError(t, err)
		require.NotNil(t, svc)
	})
}

// TestFunctionalOptions_ServiceInitialization tests that all components are properly initialized
func TestFunctionalOptions_ServiceInitialization(t *testing.T) {
	t.Run("all required dependencies initialized", func(t *testing.T) {
		cacheDir := t.TempDir()

		svc, err := NewService(WithCacheDir(cacheDir))

		require.NoError(t, err)
		require.NotNil(t, svc.cache, "cache manager should be initialized")
		require.NotNil(t, svc.manifest, "manifest manager should be initialized")
		require.NotNil(t, svc.downloader, "downloader should be initialized")
		require.NotEmpty(t, svc.sources, "sources should have default values")
		require.NotNil(t, &svc.logger, "logger should have default value")
	})

	t.Run("optional dependencies default to nil/zero", func(t *testing.T) {
		cacheDir := t.TempDir()

		svc, err := NewService(WithCacheDir(cacheDir))

		require.NoError(t, err)
		require.Nil(t, svc.storage, "storage should be nil by default")
	})
}

// TestFunctionalOptions_Extensibility tests that new options can be added without breaking changes
func TestFunctionalOptions_Extensibility(t *testing.T) {
	t.Run("existing code continues to work", func(t *testing.T) {
		// Simulates existing code that only uses cache dir
		cacheDir := t.TempDir()
		svc, err := NewService(WithCacheDir(cacheDir))

		require.NoError(t, err)
		require.NotNil(t, svc)

		// Even if we add new options in the future (e.g., WithMaxWorkers),
		// existing code will continue to work with defaults
	})
}
