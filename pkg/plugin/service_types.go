// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import "time"

// DTO Evolution Policy
//
// These types form the public API contract used by CLI, HTTP API, and future gRPC.
// To avoid breaking existing clients, follow these rules:
//
// 1. Additive-only changes:
//    - You MAY add new optional fields
//    - You MAY NOT remove or rename existing fields
//    - Breaking changes require a new API version (v2)
//
// 2. Zero-value semantics:
//    - New fields MUST have safe zero-value behavior
//    - Zero-value MUST preserve existing behavior
//    - Use `omitempty` for optional JSON fields
//
// 3. Examples:
//    ✓ Adding `Timeout time.Duration` (zero = no timeout, preserves old behavior)
//    ✓ Adding `Tags []string \`json:"tags,omitempty"\`` (zero = empty, backward compatible)
//    ✗ Removing `Force bool` (old clients still send it)
//    ✗ Making an optional field required (old clients don't send it)
//
// See Issue #92 for background and rationale.

// Service layer types for plugin operations
// These types are used by the service layer to abstract business logic
// from the CMD and API layers.

// PluginError represents a per-plugin error in bulk operations.
// Used for partial failure scenarios where some plugins succeed and others fail.
//
// Example:
//
//	PluginError{
//	    PluginID:   "ssh-weak-cipher",
//	    Error:      "checksum mismatch",
//	    Code:       "CHECKSUM_MISMATCH",
//	    Suggestion: "retry with --force to re-download",
//	}
type PluginError struct {
	// PluginID is the unique identifier of the plugin (e.g., "ssh-weak-cipher")
	PluginID string `json:"plugin_id"`

	// Error is the human-readable error message
	Error string `json:"error"`

	// Code is the machine-readable error code from the project's error taxonomy
	// Examples: PLUGIN_NOT_FOUND, CHECKSUM_MISMATCH, SOURCE_NOT_AVAILABLE
	Code string `json:"code"`

	// Suggestion is an actionable suggestion for resolving the error
	// Examples: "retry with --force", "check network connection"
	Suggestion string `json:"suggestion,omitempty"`
}

// InstallOptions holds parameters for Install operation
type InstallOptions struct {
	// Source specifies which plugin source to use (empty = all sources)
	Source string

	// Force reinstalls plugins even if already cached
	Force bool

	// DryRun simulates installation without actually downloading
	DryRun bool

	// Category filter for bulk installs (optional)
	Category Category
}

// InstallResult holds results of Install operation
type InstallResult struct {
	// InstalledCount is the number of plugins successfully installed
	InstalledCount int

	// SkippedCount is the number of plugins already installed (not forced)
	SkippedCount int

	// FailedCount is the number of plugins that failed to install
	FailedCount int

	// Plugins contains information about installed plugins
	Plugins []*PluginInfo

	// Errors contains all errors encountered during installation
	// Each error includes plugin ID, error message, error code, and actionable suggestion
	// Collected for partial failure scenarios per project policy
	Errors []PluginError
}

// UpdateOptions holds parameters for Update operation
type UpdateOptions struct {
	// Source specifies which plugin source to use (empty = all sources)
	Source string

	// Category filter for bulk updates (optional)
	Category Category

	// Force re-downloads plugins even if already cached
	Force bool

	// DryRun simulates update without actually downloading
	DryRun bool
}

// UpdateResult holds results of Update operation
type UpdateResult struct {
	// UpdatedCount is the number of plugins successfully updated/downloaded
	UpdatedCount int

	// SkippedCount is the number of plugins already cached (not forced)
	SkippedCount int

	// FailedCount is the number of plugins that failed to download
	FailedCount int

	// Plugins contains information about updated plugins
	Plugins []*PluginInfo

	// Errors contains all errors encountered during update
	// Each error includes plugin ID, error message, error code, and actionable suggestion
	// Collected for partial failure scenarios per project policy
	Errors []PluginError
}

// UninstallOptions holds parameters for Uninstall operation
type UninstallOptions struct {
	// All uninstalls all plugins if true
	All bool

	// Category filter for bulk uninstall (optional)
	Category Category
}

// UninstallResult holds results of Uninstall operation
type UninstallResult struct {
	// RemovedCount is the number of plugins successfully removed
	RemovedCount int

	// FailedCount is the number of plugins that failed to uninstall
	FailedCount int

	// RemainingCount is the number of plugins remaining after uninstall
	RemainingCount int

	// Errors contains all errors encountered during uninstall
	// Each error includes plugin ID, error message, error code, and actionable suggestion
	// Collected for partial failure scenarios (ADR-0003)
	Errors []PluginError
}

// PluginInfo holds detailed information about a plugin
// Used for List and GetInfo operations
type PluginInfo struct {
	// Plugin metadata
	ID       string
	Name     string
	Version  string
	Type     string
	Author   string
	Severity string
	Tags     []string

	// Installation info
	Checksum     string
	DownloadURL  string
	InstalledAt  time.Time
	LastVerified time.Time

	// File system info
	Path      string
	CacheDir  string
	CacheSize int64 // Size in bytes
}

// CleanOptions holds parameters for Clean operation
type CleanOptions struct {
	// OlderThan specifies the minimum age for cache entries to be removed
	OlderThan time.Duration

	// DryRun simulates cleaning without actually deleting files
	DryRun bool
}

// CleanResult holds results of Clean operation
type CleanResult struct {
	// RemovedCount is the number of cache entries removed
	RemovedCount int

	// SizeBefore is the cache size before cleaning (in bytes)
	SizeBefore int64

	// SizeAfter is the cache size after cleaning (in bytes)
	SizeAfter int64

	// Freed is the amount of disk space freed (in bytes)
	Freed int64
}

// VerifyOptions holds parameters for Verify operation
type VerifyOptions struct {
	// PluginID specifies a single plugin to verify (empty = verify all)
	PluginID string
}

// VerifyResult holds results of Verify operation
type VerifyResult struct {
	// TotalCount is the total number of plugins verified
	TotalCount int

	// SuccessCount is the number of plugins that passed verification
	SuccessCount int

	// FailedCount is the number of plugins that failed verification
	FailedCount int

	// Results contains individual verification results
	Results []PluginVerifyResult
}

// PluginVerifyResult holds verification result for a single plugin
type PluginVerifyResult struct {
	// Plugin information
	ID      string
	Version string

	// Verification status
	Valid bool

	// Error if verification failed
	Error error

	// ErrorType categorizes the failure (missing, checksum, other)
	ErrorType string
}

// PluginSource represents a remote plugin repository
type PluginSource struct {
	// Name of the source (e.g., "official", "community")
	Name string `yaml:"name"`

	// URL of the manifest file
	URL string `yaml:"url"`

	// Enabled indicates if this source is active
	Enabled bool `yaml:"enabled"`

	// Priority for conflict resolution (lower number = higher priority)
	Priority int `yaml:"priority"`

	// Mirrors are alternative URLs for redundancy
	Mirrors []string `yaml:"mirrors,omitempty"`
}

// PluginManifestEntry describes a plugin in the remote manifest
type PluginManifestEntry struct {
	// Plugin metadata
	ID          string `json:"id" yaml:"id"` // Unique plugin identifier (slug)
	Name        string `yaml:"name" json:"name"`
	Version     string `yaml:"version" json:"version"`
	Description string `yaml:"description" json:"description"`
	Author      string `yaml:"author" json:"author"`

	// Categorization
	Categories []Category `yaml:"categories" json:"categories"`

	// Download info
	URL      string `yaml:"url" json:"url"`           // Download URL
	Checksum string `yaml:"checksum" json:"checksum"` // sha256:hex
	Size     int64  `yaml:"size" json:"size"`         // File size in bytes
}
