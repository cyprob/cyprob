// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

// This file implements retry logic with exponential backoff for network operations.
//
// Network operations can fail transiently due to temporary connectivity issues,
// rate limiting, or service unavailability. This package provides a configurable
// retry mechanism to handle such failures gracefully.
//
// Features:
//   - Exponential backoff: Wait time doubles after each retry (configurable)
//   - Jitter: Random ±25% variation to prevent thundering herd
//   - Context-aware: Respects context cancellation and timeout
//   - Configurable: Max attempts, initial wait, max wait, multiplier
//
// Usage:
//
//	config := plugin.RetryConfig{
//	    MaxAttempts: 3,
//	    InitialWait: 1 * time.Second,
//	    MaxWait:     30 * time.Second,
//	    Multiplier:  2.0,
//	    Jitter:      true,
//	}
//
//	err := plugin.WithRetry(ctx, config, func(ctx context.Context) error {
//	    // Your network operation here
//	    return downloadFile(ctx, url)
//	})
//
// Integration with Downloader:
//
// The Downloader uses retry logic for all HTTP operations (manifest fetch, plugin download).
// By default, it uses DefaultRetryConfig() which provides sensible defaults (3 attempts,
// exponential backoff with jitter). You can customize this via WithRetryConfig():
//
//	downloader := NewDownloader(cache, WithRetryConfig(plugin.NoRetry()))
//
// Integration with Service:
//
// The Service layer exposes WithRetry() to configure retry behavior for all plugin operations:
//
//	svc := plugin.NewService(cacheDir).WithRetry(customConfig)
//
// This recreates the internal downloader with the new retry configuration.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strings"
	"time"
)

// RetryConfig defines retry behavior for network operations.
type RetryConfig struct {
	// MaxAttempts is the maximum number of retry attempts (0 = no retries, 1 = one retry, etc.)
	// Default: 3 attempts (initial + 2 retries)
	MaxAttempts int

	// InitialWait is the initial wait time before first retry
	// Default: 1 second
	InitialWait time.Duration

	// MaxWait is the maximum wait time between retries
	// Default: 30 seconds
	MaxWait time.Duration

	// Multiplier for exponential backoff (must be >= 1.0)
	// Default: 2.0 (doubles wait time on each retry)
	Multiplier float64

	// Jitter adds randomness to prevent thundering herd
	// When true, adds up to ±25% randomness to wait time
	// Default: true
	Jitter bool
}

// DefaultRetryConfig returns sensible defaults for retry behavior.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 3,
		InitialWait: 1 * time.Second,
		MaxWait:     30 * time.Second,
		Multiplier:  2.0,
		Jitter:      true,
	}
}

// NoRetry returns a config that disables retries.
func NoRetry() RetryConfig {
	return RetryConfig{
		MaxAttempts: 0,
	}
}

// Validate checks if the retry config is valid.
func (rc RetryConfig) Validate() error {
	if rc.MaxAttempts < 0 {
		return fmt.Errorf("MaxAttempts must be >= 0, got %d", rc.MaxAttempts)
	}

	// If MaxAttempts is 0 (NoRetry), skip other validations
	if rc.MaxAttempts == 0 {
		return nil
	}

	if rc.InitialWait < 0 {
		return fmt.Errorf("InitialWait must be >= 0, got %v", rc.InitialWait)
	}
	if rc.MaxWait < 0 {
		return fmt.Errorf("MaxWait must be >= 0, got %v", rc.MaxWait)
	}
	if rc.Multiplier < 1.0 {
		return fmt.Errorf("multiplier must be >= 1.0, got %f", rc.Multiplier)
	}
	if rc.MaxWait > 0 && rc.InitialWait > rc.MaxWait {
		return fmt.Errorf("InitialWait (%v) must be <= MaxWait (%v)", rc.InitialWait, rc.MaxWait)
	}
	return nil
}

// calculateWait computes the wait time for a given attempt number.
func (rc RetryConfig) calculateWait(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}

	// Exponential backoff: initialWait * multiplier^(attempt-1)
	wait := float64(rc.InitialWait) * math.Pow(rc.Multiplier, float64(attempt-1))

	// Cap at MaxWait
	if rc.MaxWait > 0 && wait > float64(rc.MaxWait) {
		wait = float64(rc.MaxWait)
	}

	// Add jitter (±25% randomness)
	if rc.Jitter {
		jitterRange := wait * 0.25
		jitter := (rand.Float64() * 2 * jitterRange) - jitterRange
		wait += jitter
	}

	// Ensure non-negative
	if wait < 0 {
		wait = 0
	}

	return time.Duration(wait)
}

// RetryFunc is a function that may fail and should be retried.
type RetryFunc func(ctx context.Context) error

// isRetryableError determines if an error should be retried.
//
// Retryable errors:
//   - Network connectivity errors (connection refused, timeout, DNS failure)
//   - Temporary HTTP errors (502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout)
//
// Non-retryable errors:
//   - Client errors (400, 401, 403, 404)
//   - Permanent server errors (500, 501)
//   - Context cancellation
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Don't retry context errors
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Check for network errors (connection refused, timeout, etc.)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// Check error message for common network failures
	errMsg := strings.ToLower(err.Error())
	networkErrors := []string{
		"connection refused",
		"connection reset",
		"no such host",
		"network is unreachable",
		"temporary failure",
		"i/o timeout",
		"timeout",
	}

	for _, netErr := range networkErrors {
		if strings.Contains(errMsg, netErr) {
			return true
		}
	}

	// Check for HTTP status code errors
	// Only retry 502, 503, 504 (temporary server errors)
	if strings.Contains(errMsg, "unexpected status code: 502") ||
		strings.Contains(errMsg, "unexpected status code: 503") ||
		strings.Contains(errMsg, "unexpected status code: 504") {
		return true
	}

	// Don't retry other HTTP status codes (400, 401, 403, 404, 500, etc.)
	if strings.Contains(errMsg, "unexpected status code:") {
		return false
	}

	// Default: don't retry unknown errors
	return false
}

// WithRetry executes fn with retry logic according to the config.
//
// Only retryable errors trigger a retry (network connectivity issues, temporary server errors).
// Non-retryable errors (400, 404, 500, etc.) fail immediately without retry.
//
// Returns:
//   - nil if fn succeeds on any attempt
//   - last error if all attempts fail or error is non-retryable
//
// The function respects context cancellation and will stop retrying
// if the context is canceled.
func WithRetry(ctx context.Context, config RetryConfig, fn RetryFunc) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid retry config: %w", err)
	}

	var lastErr error
	maxAttempts := config.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = 1 // At least try once
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Check context before each attempt
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Execute function
		err := fn(ctx)
		if err == nil {
			return nil // Success
		}

		lastErr = err

		// Check if error is retryable
		if !isRetryableError(err) {
			// Non-retryable error, fail immediately
			return err
		}

		// Don't wait after last attempt
		if attempt < maxAttempts-1 {
			wait := config.calculateWait(attempt + 1)

			// Wait with context cancellation support
			select {
			case <-time.After(wait):
				// Continue to next attempt
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return fmt.Errorf("max attempts (%d) exceeded: %w", maxAttempts, lastErr)
}
