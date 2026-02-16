package app

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/config"
	"github.com/cyprob/cyprob/pkg/server/api"
)

// Mock workspace
type mockWorkspace struct{}

func (m *mockWorkspace) ListScans() ([]api.ScanMetadata, error) {
	return []api.ScanMetadata{}, nil
}

func (m *mockWorkspace) GetScan(id string) (*api.ScanDetail, error) {
	return nil, nil
}

func TestNew(t *testing.T) {
	cfg := config.ServerConfig{
		Addr:         "127.0.0.1",
		Port:         9999,
		UIEnabled:    true,
		APIEnabled:   true,
		JobsEnabled:  true,
		Concurrency:  2,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	deps := &Deps{
		Workspace: &mockWorkspace{},
		Config:    nil, // Not needed for this test
		Logger:    zerolog.Nop(),
	}

	app, err := New(context.Background(), cfg, deps)
	require.NoError(t, err)
	require.NotNil(t, app)
	require.NotNil(t, app.HTTP)
	require.NotNil(t, app.Jobs)
	require.Equal(t, "127.0.0.1:9999", app.HTTP.Addr)
}

func TestNew_DisabledComponents(t *testing.T) {
	cfg := config.ServerConfig{
		Addr:         "127.0.0.1",
		Port:         9998,
		UIEnabled:    false,
		APIEnabled:   false,
		JobsEnabled:  false,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	deps := &Deps{
		Workspace: &mockWorkspace{},
		Config:    nil, // Not needed for this test
		Logger:    zerolog.Nop(),
	}

	app, err := New(context.Background(), cfg, deps)
	require.NoError(t, err)
	require.NotNil(t, app)
	require.NotNil(t, app.HTTP)
	require.Nil(t, app.Jobs, "Jobs should be nil when disabled")
}

func TestApp_Lifecycle(t *testing.T) {
	cfg := config.ServerConfig{
		Addr:         "127.0.0.1",
		Port:         9997,
		UIEnabled:    false,
		APIEnabled:   true,
		JobsEnabled:  true,
		Concurrency:  1,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	deps := &Deps{
		Workspace: &mockWorkspace{},
		Config:    nil, // Not needed for this test
		Logger:    zerolog.Nop(),
	}

	app, err := New(context.Background(), cfg, deps)
	require.NoError(t, err)

	// Start in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	appErr := make(chan error, 1)
	go func() {
		appErr <- app.Run(ctx)
	}()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)
	require.True(t, app.Ready.Load())

	// Test health endpoint
	resp, err := http.Get("http://127.0.0.1:9997/healthz")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Test readiness endpoint
	resp, err = http.Get("http://127.0.0.1:9997/readyz")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Trigger shutdown
	cancel()

	// Wait for graceful shutdown
	select {
	case err := <-appErr:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown timeout")
	}

	require.False(t, app.Ready.Load())
}

func TestApp_LifecycleWithoutJobs(t *testing.T) {
	cfg := config.ServerConfig{
		Addr:         "127.0.0.1",
		Port:         9996,
		UIEnabled:    false,
		APIEnabled:   true,
		JobsEnabled:  false,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	deps := &Deps{
		Workspace: &mockWorkspace{},
		Config:    nil, // Not needed for this test
		Logger:    zerolog.Nop(),
	}

	app, err := New(context.Background(), cfg, deps)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	appErr := make(chan error, 1)
	go func() {
		appErr <- app.Run(ctx)
	}()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)
	require.True(t, app.Ready.Load())

	// Test health endpoint
	resp, err := http.Get("http://127.0.0.1:9996/healthz")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Trigger shutdown
	cancel()

	// Wait for graceful shutdown
	select {
	case err := <-appErr:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown timeout")
	}
}
