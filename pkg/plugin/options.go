// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"github.com/rs/zerolog"

	"github.com/cyprob/cyprob/pkg/storage"
)

// ServiceOption is a functional option for configuring Service.
//
// This pattern allows for extensible, backward-compatible API evolution.
// Adding new options doesn't break existing code.
//
// Example:
//
//	svc, err := plugin.NewService(
//	    plugin.WithCacheDir("/tmp/cache"),
//	    plugin.WithLogger(customLogger),
//	    plugin.WithConfig(cfg),
//	)
type ServiceOption func(*serviceOptions)

// serviceOptions holds configuration for service creation.
// This is an internal type; users interact via ServiceOption functions.
type serviceOptions struct {
	cacheDir string
	logger   *zerolog.Logger
	config   *ServiceConfig
	storage  storage.Backend
	sources  []PluginSource
}

// WithCacheDir sets the plugin cache directory.
//
// Default: XDG cache (e.g., ~/.cache/vulntor/plugins/cache on Linux/macOS, %LocalAppData%/Vulntor/Cache/plugins/cache on Windows)
//
// Example:
//
//	svc, err := plugin.NewService(
//	    plugin.WithCacheDir("/var/cache/vulntor/plugins"),
//	)
func WithCacheDir(dir string) ServiceOption {
	return func(opts *serviceOptions) {
		opts.cacheDir = dir
	}
}

// WithLogger sets a custom logger for the service.
//
// Default: zerolog default logger
//
// Example:
//
//	customLogger := zerolog.New(os.Stdout).With().
//	    Str("service", "plugin").
//	    Logger()
//	svc, err := plugin.NewService(
//	    plugin.WithLogger(customLogger),
//	)
func WithLogger(logger zerolog.Logger) ServiceOption {
	return func(opts *serviceOptions) {
		opts.logger = &logger
	}
}

// WithConfig sets custom service configuration (timeouts, limits).
//
// Default: DefaultConfig()
//
// Example:
//
//	cfg := plugin.ServiceConfig{
//	    InstallTimeout: 120 * time.Second,
//	}
//	svc, err := plugin.NewService(
//	    plugin.WithConfig(cfg),
//	)
func WithConfig(config ServiceConfig) ServiceOption {
	return func(opts *serviceOptions) {
		opts.config = &config
	}
}

// WithStorage sets an optional storage backend for advanced features.
//
// The storage backend enables features like:
//   - Storing plugin metadata in database
//   - Cross-referencing plugins with scan results
//   - Multi-tenancy support (Enterprise)
//
// Example:
//
//	backend, _ := storage.NewBackend(ctx, cfg)
//	svc, err := plugin.NewService(
//	    plugin.WithStorage(backend),
//	)
func WithStorage(backend storage.Backend) ServiceOption {
	return func(opts *serviceOptions) {
		opts.storage = backend
	}
}

// WithPluginSources sets custom plugin sources for the service.
//
// This allows using alternative plugin repositories or mirrors.
//
// Default: Official Vulntor plugin repository
//
// Note: This is different from downloader.WithSources() which configures
// the downloader component. This option configures the service-level sources.
//
// Example:
//
//	customSources := []plugin.PluginSource{
//	    {Name: "enterprise", URL: "https://enterprise.example.com/plugins.yaml", Enabled: true},
//	}
//	svc, err := plugin.NewService(
//	    plugin.WithPluginSources(customSources),
//	)
func WithPluginSources(sources []PluginSource) ServiceOption {
	return func(opts *serviceOptions) {
		opts.sources = sources
	}
}
