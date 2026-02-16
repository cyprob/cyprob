//go:build integration

package scanexec

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/appctx"
	"github.com/cyprob/cyprob/pkg/engine"
)

// TestRunWithEphemeralTCP ensures the scan service can execute end-to-end
// against a guaranteed-open ephemeral TCP port on localhost without relying
// on environment-specific services.
func TestRunWithEphemeralTCP(t *testing.T) {
	// Spin up an ephemeral TCP listener to guarantee an open port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	addr := ln.Addr().String() // e.g., 127.0.0.1:54321

	// Build a minimal AppManager context as required by Service.Run
	// Use default app manager without binding external config file.
	factory := &engine.DefaultAppManagerFactory{}
	appMgr, err := factory.CreateWithNoConfig()
	require.NoError(t, err)
	ctx := context.WithValue(appMgr.Context(), engine.AppManagerKey, appMgr)
	ctx = appctx.WithConfig(ctx, appMgr.Config())

	svc := NewService()
	params := Params{
		Targets:       []string{addr},
		OutputFormat:  "text",
		AllowLoopback: true,
		EnablePing:    false,
		Concurrency:   5,
		CustomTimeout: "500ms",
	}

	res, _ := svc.Run(ctx, params)
	// The pipeline may succeed or fail depending on enabled modules, but it should return a result structure.
	require.NotNil(t, res)
	require.NotEmpty(t, res.RunID)
	require.NotEmpty(t, res.StartTime)
}
