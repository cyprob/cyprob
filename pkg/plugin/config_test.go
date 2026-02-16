// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/plugin"
)

func TestDefaultConfig(t *testing.T) {
	cfg := plugin.DefaultConfig()

	// Verify all timeout fields have sensible defaults
	require.Equal(t, 60*time.Second, cfg.InstallTimeout, "InstallTimeout should be 60s")
	require.Equal(t, 60*time.Second, cfg.UpdateTimeout, "UpdateTimeout should be 60s")
	require.Equal(t, 30*time.Second, cfg.UninstallTimeout, "UninstallTimeout should be 30s")
	require.Equal(t, 10*time.Second, cfg.ListTimeout, "ListTimeout should be 10s")
	require.Equal(t, 5*time.Second, cfg.GetInfoTimeout, "GetInfoTimeout should be 5s")
	require.Equal(t, 30*time.Second, cfg.CleanTimeout, "CleanTimeout should be 30s")
	require.Equal(t, 60*time.Second, cfg.VerifyTimeout, "VerifyTimeout should be 60s")
}

func TestServiceConfig_CustomValues(t *testing.T) {
	cfg := plugin.ServiceConfig{
		InstallTimeout:   120 * time.Second,
		UpdateTimeout:    90 * time.Second,
		UninstallTimeout: 45 * time.Second,
		ListTimeout:      15 * time.Second,
		GetInfoTimeout:   10 * time.Second,
		CleanTimeout:     60 * time.Second,
		VerifyTimeout:    120 * time.Second,
	}

	// Verify custom values are preserved
	require.Equal(t, 120*time.Second, cfg.InstallTimeout)
	require.Equal(t, 90*time.Second, cfg.UpdateTimeout)
	require.Equal(t, 45*time.Second, cfg.UninstallTimeout)
	require.Equal(t, 15*time.Second, cfg.ListTimeout)
	require.Equal(t, 10*time.Second, cfg.GetInfoTimeout)
	require.Equal(t, 60*time.Second, cfg.CleanTimeout)
	require.Equal(t, 120*time.Second, cfg.VerifyTimeout)
}
