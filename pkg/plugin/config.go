// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import "time"

// ServiceConfig holds configuration for plugin service operations.
//
// Timeout values control how long operations can run before being canceled.
// These defaults balance responsiveness with allowing operations to complete:
// - Install/Update: Network-intensive, need longer timeouts
// - List/GetInfo: Local operations, should be quick
// - Clean/Verify: Filesystem I/O, moderate timeouts
//
// Configuration sources (in order of precedence):
//  1. Explicit WithConfig() call
//  2. Environment variables (CYPROB_PLUGIN_*_TIMEOUT)
//  3. Config file (plugin.install_timeout, etc.)
//  4. Default values
//
// Example:
//
//	cfg := plugin.ServiceConfig{
//	    InstallTimeout: 120 * time.Second,
//	    UpdateTimeout:  120 * time.Second,
//	}
//	svc := plugin.NewService(cacheDir).WithConfig(cfg)
type ServiceConfig struct {
	// InstallTimeout is the maximum duration for Install() operations.
	// Default: 60 seconds (network download + disk write)
	InstallTimeout time.Duration

	// UpdateTimeout is the maximum duration for Update() operations.
	// Default: 60 seconds (network download for multiple plugins)
	UpdateTimeout time.Duration

	// UninstallTimeout is the maximum duration for Uninstall() operations.
	// Default: 30 seconds (disk removal + manifest update)
	UninstallTimeout time.Duration

	// ListTimeout is the maximum duration for List() operations.
	// Default: 10 seconds (local manifest read)
	ListTimeout time.Duration

	// GetInfoTimeout is the maximum duration for GetInfo() operations.
	// Default: 5 seconds (local manifest read + dir size calculation)
	GetInfoTimeout time.Duration

	// CleanTimeout is the maximum duration for Clean() operations.
	// Default: 30 seconds (filesystem traversal + deletion)
	CleanTimeout time.Duration

	// VerifyTimeout is the maximum duration for Verify() operations.
	// Default: 60 seconds (checksum calculation for multiple files)
	VerifyTimeout time.Duration
}

// DefaultConfig returns a ServiceConfig with sensible default timeout values.
//
// These defaults are designed for typical plugin operations:
// - Network operations (Install/Update): 60s
// - Disk operations (Uninstall/Clean): 30s
// - Read operations (List/GetInfo): 5-10s
// - Verification (Verify): 60s
//
// Override defaults using WithConfig() or environment variables.
func DefaultConfig() ServiceConfig {
	return ServiceConfig{
		InstallTimeout:   60 * time.Second,
		UpdateTimeout:    60 * time.Second,
		UninstallTimeout: 30 * time.Second,
		ListTimeout:      10 * time.Second,
		GetInfoTimeout:   5 * time.Second,
		CleanTimeout:     30 * time.Second,
		VerifyTimeout:    60 * time.Second,
	}
}
