package api

import (
	"errors"
	"time"
)

// Sentinel errors for configuration validation
var (
	// ErrInvalidTimeout is returned when a timeout value is invalid (negative).
	ErrInvalidTimeout = errors.New("invalid timeout: must be >= 0")
)

// Config holds API-level configuration.
// This includes timeout settings for request handling.
type Config struct {
	// HandlerTimeout is the maximum duration for an API handler to complete.
	// If a handler exceeds this timeout, it will return HTTP 504 Gateway Timeout.
	//
	// This timeout is applied at the handler level ONLY if the request context
	// doesn't already have a deadline. This allows:
	// - Middleware to set shorter timeouts (takes precedence)
	// - Service-layer timeouts to apply (if handler doesn't set one)
	// - Clients to control timeouts via request headers
	//
	// Default: 30 seconds
	// Environment variable: CYPROB_API_HANDLER_TIMEOUT
	HandlerTimeout time.Duration
}

// DefaultConfig returns the default API configuration with sensible timeout values.
//
// Default timeouts are chosen based on expected operation complexity:
// - HandlerTimeout: 30s (covers most operations including plugin install/update)
//
// These timeouts can be overridden via:
// 1. Environment variables (CYPROB_API_HANDLER_TIMEOUT)
// 2. Config file (api.handler_timeout)
// 3. Request context deadline (set by middleware/client)
func DefaultConfig() Config {
	return Config{
		HandlerTimeout: 30 * time.Second,
	}
}

// Validate checks that the configuration is valid.
// Returns an error if any configuration value is invalid.
func (c Config) Validate() error {
	if c.HandlerTimeout < 0 {
		return ErrInvalidTimeout
	}
	return nil
}
