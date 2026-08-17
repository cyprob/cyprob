// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import "errors"

// Service layer errors
// These are domain-specific errors that can be checked using errors.Is()

var (
	// ErrPluginNotFound is returned when a requested plugin cannot be found
	// CLI exit code: 4, HTTP status: 404
	ErrPluginNotFound = errors.New("plugin not found")

	// ErrPluginAlreadyInstalled is returned when trying to install an already cached plugin without force
	// CLI exit code: 1, HTTP status: 409
	ErrPluginAlreadyInstalled = errors.New("plugin already installed")

	// ErrPluginNotInstalled is returned when trying to operate on a plugin that isn't installed
	// CLI exit code: 4, HTTP status: 404
	ErrPluginNotInstalled = errors.New("plugin not installed")

	// ErrInvalidCategory is returned when an invalid category is specified
	// CLI exit code: 2, HTTP status: 400
	ErrInvalidCategory = errors.New("invalid category")

	// ErrInvalidPluginID is returned when a plugin ID is malformed
	// CLI exit code: 2, HTTP status: 400
	ErrInvalidPluginID = errors.New("invalid plugin ID")

	// ErrNoPluginsFound is returned when no plugins match the criteria
	// CLI exit code: 4, HTTP status: 404
	ErrNoPluginsFound = errors.New("no plugins found")

	// ErrSourceNotAvailable is returned when a plugin source cannot be reached
	// CLI exit code: 7, HTTP status: 503
	ErrSourceNotAvailable = errors.New("plugin source not available")

	// ErrChecksumMismatch is returned when downloaded plugin checksum doesn't match
	// CLI exit code: 1, HTTP status: 500
	ErrChecksumMismatch = errors.New("checksum mismatch")

	// ErrInvalidInput is returned when input validation fails
	// CLI exit code: 2, HTTP status: 400
	ErrInvalidInput = errors.New("invalid input")

	// ErrUnavailable indicates the service is temporarily unavailable
	// (e.g., remote repository unreachable, network issues).
	// CLI exit code: 7, HTTP status: 503
	ErrUnavailable = errors.New("service unavailable")

	// ErrConflict indicates a version or state conflict
	// (e.g., plugin already installed with different version).
	// CLI exit code: 1, HTTP status: 409
	ErrConflict = errors.New("version conflict")

	// ErrPartialFailure indicates some operations succeeded while others failed.
	// Used for batch operations (e.g., update multiple plugins).
	// CLI exit code: 8, HTTP status: 200 (with errors[] field in response body)
	ErrPartialFailure = errors.New("partial failure")

	// ErrInvalidOption is a general error for invalid input parameters or options.
	// This is an alias for ErrInvalidInput for consistency with ADR-0001.
	// CLI exit code: 2, HTTP status: 400
	ErrInvalidOption = ErrInvalidInput
)

// IsNotFound checks if error is a "not found" error
func IsNotFound(err error) bool {
	return errors.Is(err, ErrPluginNotFound) || errors.Is(err, ErrPluginNotInstalled)
}

// IsAlreadyExists checks if error is an "already exists" error
func IsAlreadyExists(err error) bool {
	return errors.Is(err, ErrPluginAlreadyInstalled)
}

// IsInvalidInput checks if error is an "invalid input" error
func IsInvalidInput(err error) bool {
	return errors.Is(err, ErrInvalidCategory) || errors.Is(err, ErrInvalidPluginID) || errors.Is(err, ErrInvalidInput)
}

// ExitCode returns the appropriate CLI exit code for the given error.
// Exit code conventions (as defined in ADR-0001):
//   - 0: Success
//   - 1: General error (default)
//   - 2: Invalid usage/input
//   - 4: Not found
//   - 7: Service unavailable
//   - 8: Partial failure
//
// Example:
//
//	err := svc.Install(ctx, target, opts)
//	os.Exit(plugin.ExitCode(err))
func ExitCode(err error) int {
	if err == nil {
		return 0
	}

	switch {
	// Invalid input/usage errors → exit 2
	case errors.Is(err, ErrInvalidInput),
		errors.Is(err, ErrInvalidCategory),
		errors.Is(err, ErrInvalidPluginID):
		return 2

	// Not found errors → exit 4
	case errors.Is(err, ErrPluginNotFound),
		errors.Is(err, ErrPluginNotInstalled),
		errors.Is(err, ErrNoPluginsFound):
		return 4

	// Service unavailable errors → exit 7
	case errors.Is(err, ErrSourceNotAvailable),
		errors.Is(err, ErrUnavailable):
		return 7

	// Partial failure → exit 8
	case errors.Is(err, ErrPartialFailure):
		return 8

	// All other errors (conflict, checksum, unknown) → exit 1
	default:
		return 1
	}
}

// HTTPStatus returns the appropriate HTTP status code for the given error.
// Status code mapping (as defined in ADR-0001):
//   - 200: Success (or partial failure with errors[] in response)
//   - 400: Bad Request (invalid input)
//   - 404: Not Found (plugin doesn't exist)
//   - 409: Conflict (version conflict, already installed)
//   - 500: Internal Server Error (default)
//   - 503: Service Unavailable (temporary failure)
//
// Example:
//
//	err := svc.Install(ctx, target, opts)
//	if err != nil {
//	    status := plugin.HTTPStatus(err)
//	    http.Error(w, err.Error(), status)
//	}
func HTTPStatus(err error) int {
	if err == nil {
		return 200
	}

	switch {
	// Invalid input → 400 Bad Request
	case errors.Is(err, ErrInvalidInput),
		errors.Is(err, ErrInvalidCategory),
		errors.Is(err, ErrInvalidPluginID):
		return 400

	// Not found → 404 Not Found
	case errors.Is(err, ErrPluginNotFound),
		errors.Is(err, ErrPluginNotInstalled),
		errors.Is(err, ErrNoPluginsFound):
		return 404

	// Conflict → 409 Conflict
	case errors.Is(err, ErrPluginAlreadyInstalled),
		errors.Is(err, ErrConflict):
		return 409

	// Service unavailable → 503 Service Unavailable
	case errors.Is(err, ErrSourceNotAvailable),
		errors.Is(err, ErrUnavailable):
		return 503

	// Partial failure → 200 OK (with errors[] in response body)
	case errors.Is(err, ErrPartialFailure):
		return 200

	// All other errors (checksum, unknown) → 500 Internal Server Error
	default:
		return 500
	}
}

// GetSuggestion returns an actionable suggestion for resolving the given error.
// Used by CLI and API to provide helpful guidance to users on partial failures.
//
// Example:
//
//	err := svc.Install(ctx, target, opts)
//	suggestion := plugin.GetSuggestion(err)
//	fmt.Printf("Suggestion: %s\n", suggestion)
func GetSuggestion(err error) string {
	if err == nil {
		return ""
	}

	switch {
	case errors.Is(err, ErrPluginNotFound):
		return "list available plugins with: cyprob plugin list"
	case errors.Is(err, ErrPluginNotInstalled):
		return "install the plugin first with: cyprob plugin install <name>"
	case errors.Is(err, ErrNoPluginsFound):
		return "check plugin category and try: cyprob plugin update"
	case errors.Is(err, ErrInvalidCategory):
		return "valid categories: ssh, http, tls, database, network, misc"
	case errors.Is(err, ErrInvalidPluginID):
		return "use lowercase letters, numbers, and hyphens only"
	case errors.Is(err, ErrSourceNotAvailable), errors.Is(err, ErrUnavailable):
		return "retry with different source: --source github"
	case errors.Is(err, ErrChecksumMismatch):
		return "retry with --force to re-download"
	case errors.Is(err, ErrPluginAlreadyInstalled):
		return "use --force to reinstall"
	case errors.Is(err, ErrConflict):
		return "uninstall existing version and reinstall"
	case errors.Is(err, ErrPartialFailure):
		return "use --output json for full error details"
	default:
		return "check logs for more details"
	}
}

// ErrorCode returns the machine-readable error code string for API responses.
// These codes are used in JSON error responses to enable programmatic error handling.
//
// Example JSON response:
//
//	{
//	  "error": "Not Found",
//	  "code": "PLUGIN_NOT_FOUND",
//	  "message": "Plugin 'ssh-weak-cipher' not found"
//	}
func ErrorCode(err error) string {
	if err == nil {
		return ""
	}

	switch {
	case errors.Is(err, ErrPluginNotFound):
		return "PLUGIN_NOT_FOUND"
	case errors.Is(err, ErrPluginNotInstalled):
		return "PLUGIN_NOT_INSTALLED"
	case errors.Is(err, ErrNoPluginsFound):
		return "NO_PLUGINS_FOUND"
	case errors.Is(err, ErrInvalidInput):
		return "INVALID_INPUT"
	case errors.Is(err, ErrInvalidCategory):
		return "INVALID_CATEGORY"
	case errors.Is(err, ErrInvalidPluginID):
		return "INVALID_PLUGIN_ID"
	case errors.Is(err, ErrSourceNotAvailable):
		return "SOURCE_NOT_AVAILABLE"
	case errors.Is(err, ErrUnavailable):
		return "SERVICE_UNAVAILABLE"
	case errors.Is(err, ErrPluginAlreadyInstalled):
		return "PLUGIN_ALREADY_INSTALLED"
	case errors.Is(err, ErrConflict):
		return "VERSION_CONFLICT"
	case errors.Is(err, ErrPartialFailure):
		return "PARTIAL_FAILURE"
	case errors.Is(err, ErrChecksumMismatch):
		return "CHECKSUM_MISMATCH"
	default:
		return "INTERNAL_ERROR"
	}
}
