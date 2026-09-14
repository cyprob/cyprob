// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRetryConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  RetryConfig
		wantErr bool
	}{
		{
			name:    "valid default config",
			config:  DefaultRetryConfig(),
			wantErr: false,
		},
		{
			name:    "valid no retry",
			config:  NoRetry(),
			wantErr: false,
		},
		{
			name: "negative max attempts",
			config: RetryConfig{
				MaxAttempts: -1,
			},
			wantErr: true,
		},
		{
			name: "negative initial wait",
			config: RetryConfig{
				MaxAttempts: 3,
				InitialWait: -1 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "negative max wait",
			config: RetryConfig{
				MaxAttempts: 3,
				InitialWait: 1 * time.Second,
				MaxWait:     -1 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "multiplier less than 1",
			config: RetryConfig{
				MaxAttempts: 3,
				InitialWait: 1 * time.Second,
				MaxWait:     10 * time.Second,
				Multiplier:  0.5,
			},
			wantErr: true,
		},
		{
			name: "initial wait greater than max wait",
			config: RetryConfig{
				MaxAttempts: 3,
				InitialWait: 10 * time.Second,
				MaxWait:     5 * time.Second,
				Multiplier:  2.0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRetryConfig_calculateWait(t *testing.T) {
	config := RetryConfig{
		InitialWait: 1 * time.Second,
		MaxWait:     10 * time.Second,
		Multiplier:  2.0,
		Jitter:      false, // Disable jitter for predictable tests
	}

	tests := []struct {
		name    string
		attempt int
		want    time.Duration
	}{
		{
			name:    "attempt 0",
			attempt: 0,
			want:    0,
		},
		{
			name:    "attempt 1 - initial wait",
			attempt: 1,
			want:    1 * time.Second,
		},
		{
			name:    "attempt 2 - doubled",
			attempt: 2,
			want:    2 * time.Second,
		},
		{
			name:    "attempt 3 - quadrupled",
			attempt: 3,
			want:    4 * time.Second,
		},
		{
			name:    "attempt 4 - capped at max",
			attempt: 4,
			want:    8 * time.Second,
		},
		{
			name:    "attempt 5 - still capped",
			attempt: 5,
			want:    10 * time.Second, // Capped at MaxWait
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.calculateWait(tt.attempt)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestRetryConfig_calculateWait_WithJitter(t *testing.T) {
	config := RetryConfig{
		InitialWait: 1 * time.Second,
		MaxWait:     10 * time.Second,
		Multiplier:  2.0,
		Jitter:      true,
	}

	// With jitter enabled, we can't predict exact values
	// but we can verify they're within expected range
	for attempt := 1; attempt <= 3; attempt++ {
		multiplier := 1 << uint(attempt-1) // 1, 2, 4, ...
		baseWait := float64(config.InitialWait) * float64(multiplier)
		minWait := time.Duration(baseWait * 0.75) // -25% jitter
		maxWait := time.Duration(baseWait * 1.25) // +25% jitter

		got := config.calculateWait(attempt)
		require.GreaterOrEqual(t, got, minWait, "attempt %d", attempt)
		require.LessOrEqual(t, got, maxWait, "attempt %d", attempt)
	}
}

func TestWithRetry_Success(t *testing.T) {
	config := DefaultRetryConfig()
	ctx := context.Background()

	callCount := 0
	fn := func(ctx context.Context) error {
		callCount++
		return nil // Success on first attempt
	}

	err := WithRetry(ctx, config, fn)
	require.NoError(t, err)
	require.Equal(t, 1, callCount, "should succeed on first attempt")
}

func TestWithRetry_SuccessAfterRetries(t *testing.T) {
	config := RetryConfig{
		MaxAttempts: 3,
		InitialWait: 10 * time.Millisecond,
		MaxWait:     100 * time.Millisecond,
		Multiplier:  2.0,
		Jitter:      false,
	}
	ctx := context.Background()

	callCount := 0
	fn := func(ctx context.Context) error {
		callCount++
		if callCount < 3 {
			return errors.New("connection refused") // Retryable error
		}
		return nil // Success on third attempt
	}

	err := WithRetry(ctx, config, fn)
	require.NoError(t, err)
	require.Equal(t, 3, callCount, "should succeed on third attempt")
}

func TestWithRetry_MaxAttemptsExceeded(t *testing.T) {
	config := RetryConfig{
		MaxAttempts: 3,
		InitialWait: 10 * time.Millisecond,
		MaxWait:     100 * time.Millisecond,
		Multiplier:  2.0,
		Jitter:      false,
	}
	ctx := context.Background()

	callCount := 0
	expectedErr := errors.New("connection refused") // Retryable error
	fn := func(ctx context.Context) error {
		callCount++
		return expectedErr
	}

	err := WithRetry(ctx, config, fn)
	require.Error(t, err)
	require.Equal(t, 3, callCount, "should attempt exactly 3 times")
	require.ErrorIs(t, err, expectedErr)
	require.Contains(t, err.Error(), "max attempts (3) exceeded")
}

func TestWithRetry_ContextCancellation(t *testing.T) {
	config := RetryConfig{
		MaxAttempts: 10,
		InitialWait: 100 * time.Millisecond,
		MaxWait:     1 * time.Second,
		Multiplier:  2.0,
		Jitter:      false,
	}

	ctx, cancel := context.WithCancel(context.Background())

	callCount := 0
	fn := func(ctx context.Context) error {
		callCount++
		if callCount == 2 {
			cancel() // Cancel after second attempt
		}
		return errors.New("connection refused") // Retryable error
	}

	err := WithRetry(ctx, config, fn)
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
	require.LessOrEqual(t, callCount, 3, "should stop after context cancellation")
}

func TestWithRetry_NoRetry(t *testing.T) {
	config := NoRetry()
	ctx := context.Background()

	callCount := 0
	fn := func(ctx context.Context) error {
		callCount++
		return errors.New("failure")
	}

	err := WithRetry(ctx, config, fn)
	require.Error(t, err)
	require.Equal(t, 1, callCount, "should attempt exactly once with NoRetry")
}

func TestWithRetry_InvalidConfig(t *testing.T) {
	config := RetryConfig{
		MaxAttempts: -1, // Invalid
	}
	ctx := context.Background()

	fn := func(ctx context.Context) error {
		return nil
	}

	err := WithRetry(ctx, config, fn)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid retry config")
}

func TestWithRetry_BackoffTiming(t *testing.T) {
	config := RetryConfig{
		MaxAttempts: 3,
		InitialWait: 50 * time.Millisecond,
		MaxWait:     200 * time.Millisecond,
		Multiplier:  2.0,
		Jitter:      false,
	}
	ctx := context.Background()

	callTimes := make([]time.Time, 0)
	fn := func(ctx context.Context) error {
		callTimes = append(callTimes, time.Now())
		return errors.New("connection refused") // Retryable error
	}

	start := time.Now()
	_ = WithRetry(ctx, config, fn)
	duration := time.Since(start)

	require.Len(t, callTimes, 3, "should make 3 attempts")

	// Verify wait times between attempts
	// Expected: 0ms, 50ms wait, 100ms wait
	// Total: ~150ms
	require.GreaterOrEqual(t, duration, 140*time.Millisecond, "total duration should be >= 140ms")
	require.LessOrEqual(t, duration, 250*time.Millisecond, "total duration should be <= 250ms (with tolerance)")

	// Check individual waits
	if len(callTimes) >= 2 {
		firstWait := callTimes[1].Sub(callTimes[0])
		require.GreaterOrEqual(t, firstWait, 40*time.Millisecond, "first wait ~50ms")
		require.LessOrEqual(t, firstWait, 80*time.Millisecond, "first wait ~50ms")
	}

	if len(callTimes) >= 3 {
		secondWait := callTimes[2].Sub(callTimes[1])
		require.GreaterOrEqual(t, secondWait, 90*time.Millisecond, "second wait ~100ms")
		require.LessOrEqual(t, secondWait, 150*time.Millisecond, "second wait ~100ms")
	}
}

func TestWithRetry_NonRetryableError_HTTP404(t *testing.T) {
	config := DefaultRetryConfig()
	ctx := context.Background()

	callCount := 0
	expectedErr := errors.New("unexpected status code: 404")
	fn := func(ctx context.Context) error {
		callCount++
		return expectedErr
	}

	err := WithRetry(ctx, config, fn)
	require.Error(t, err)
	require.Equal(t, 1, callCount, "should not retry 404 errors")
	require.ErrorIs(t, err, expectedErr)
}

func TestWithRetry_RetryableError_HTTP503(t *testing.T) {
	config := RetryConfig{
		MaxAttempts: 3,
		InitialWait: 10 * time.Millisecond,
		MaxWait:     100 * time.Millisecond,
		Multiplier:  2.0,
		Jitter:      false,
	}
	ctx := context.Background()

	callCount := 0
	fn := func(ctx context.Context) error {
		callCount++
		return errors.New("unexpected status code: 503") // Retryable
	}

	err := WithRetry(ctx, config, fn)
	require.Error(t, err)
	require.Equal(t, 3, callCount, "should retry 503 errors")
}
