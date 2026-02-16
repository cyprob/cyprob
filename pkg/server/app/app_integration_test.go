//go:build integration

package app_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/config"
	"github.com/cyprob/cyprob/pkg/server/api"
	"github.com/cyprob/cyprob/pkg/server/app"
	"github.com/cyprob/cyprob/pkg/storage"
)

func init() {
	// Disable all logging for integration tests to reduce noise
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

// mockWorkspace implements api.WorkspaceInterface for integration testing
type mockWorkspace struct {
	scans map[string]*api.ScanDetail
}

func newMockWorkspace() *mockWorkspace {
	return &mockWorkspace{
		scans: map[string]*api.ScanDetail{
			"scan-001": {
				ID:        "scan-001",
				StartTime: "2025-01-01T00:00:00Z",
				EndTime:   "2025-01-01T00:05:00Z",
				Status:    "completed",
				Results: map[string]interface{}{
					"hosts_found": 10,
					"ports_open":  25,
				},
			},
			"scan-002": {
				ID:        "scan-002",
				StartTime: "2025-01-02T00:00:00Z",
				Status:    "running",
				Results: map[string]interface{}{
					"hosts_found": 5,
				},
			},
		},
	}
}

func (m *mockWorkspace) ListScans() ([]api.ScanMetadata, error) {
	var scans []api.ScanMetadata
	for id, detail := range m.scans {
		scans = append(scans, api.ScanMetadata{
			ID:        id,
			StartTime: detail.StartTime,
			Status:    detail.Status,
			Targets:   len(detail.Results),
		})
	}
	return scans, nil
}

func (m *mockWorkspace) GetScan(id string) (*api.ScanDetail, error) {
	scan, ok := m.scans[id]
	if !ok {
		// Return storage.NotFoundError so API handler returns 404
		return nil, &storage.NotFoundError{
			ResourceType: "scan",
			ResourceID:   id,
		}
	}
	return scan, nil
}

// TestServerFullLifecycle performs a comprehensive integration test of the server runtime.
//
// This test:
//   - Starts a real HTTP server with API and UI handlers
//   - Starts background job workers
//   - Makes real HTTP requests to all endpoints
//   - Verifies readiness transitions
//   - Tests graceful shutdown
//
// Run with: go test -tags=integration -v ./pkg/server/app
func TestServerFullLifecycle(t *testing.T) {
	// Use a random port to avoid conflicts
	port := 19997

	// Configure server
	cfg := config.ServerConfig{
		Addr:         "127.0.0.1",
		Port:         port,
		UIEnabled:    true,
		APIEnabled:   true,
		JobsEnabled:  true,
		Concurrency:  2,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		UI: config.UIConfig{
			AssetsPath: "", // Production mode (embedded assets)
		},
		Auth: config.AuthConfig{
			Mode: "none", // Disable auth for integration tests
		},
	}

	// Prepare dependencies
	deps := &app.Deps{
		Workspace: newMockWorkspace(),
		Config:    nil, // Not needed for this test
		Logger:    zerolog.Nop(),
	}

	// Create server app
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverApp, err := app.New(ctx, cfg, deps)
	require.NoError(t, err, "Failed to create server app")
	require.NotNil(t, serverApp)

	// Start server in background
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- serverApp.Run(ctx)
	}()

	// Wait for server to be ready
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	require.Eventually(t, func() bool {
		resp, err := http.Get(baseURL + "/healthz")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 2*time.Second, 50*time.Millisecond, "Server did not start in time")

	t.Log("✅ Server started successfully")

	// Test 1: Health endpoint (always available)
	t.Run("Healthz", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/healthz")
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		body := make([]byte, 2)
		resp.Body.Read(body)
		require.Equal(t, "OK", string(body))

		t.Log("✅ /healthz responding correctly")
	})

	// Test 2: Readiness endpoint (ready after startup)
	t.Run("Readyz", func(t *testing.T) {
		// Should be ready now
		resp, err := http.Get(baseURL + "/readyz")
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		body := make([]byte, 5)
		resp.Body.Read(body)
		require.Equal(t, "Ready", string(body))

		t.Log("✅ /readyz returning ready state")
	})

	// Test 3: API - List scans
	t.Run("API_ListScans", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/api/v1/scans")
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "application/json", resp.Header.Get("Content-Type"))

		var scans []api.ScanMetadata
		err = json.NewDecoder(resp.Body).Decode(&scans)
		require.NoError(t, err)
		require.Len(t, scans, 2, "Expected 2 scans")

		t.Logf("✅ /api/v1/scans returned %d scans", len(scans))
	})

	// Test 4: API - Get scan by ID
	t.Run("API_GetScan", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/api/v1/scans/scan-001")
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var scan api.ScanDetail
		err = json.NewDecoder(resp.Body).Decode(&scan)
		require.NoError(t, err)
		require.Equal(t, "scan-001", scan.ID)
		require.Equal(t, "completed", scan.Status)
		require.NotEmpty(t, scan.Results)

		t.Logf("✅ /api/v1/scans/scan-001 returned scan details")
	})

	// Test 5: API - 404 for non-existent scan
	t.Run("API_GetScan_NotFound", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/api/v1/scans/nonexistent")
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusNotFound, resp.StatusCode)

		t.Log("✅ /api/v1/scans/nonexistent correctly returns 404")
	})

	// Test 6: UI endpoint (should serve index.html)
	t.Run("UI_Root", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/")
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
		// Content-Type should be text/html for index.html
		contentType := resp.Header.Get("Content-Type")
		require.Contains(t, contentType, "text/html", "Root should serve HTML")

		t.Log("✅ / serving UI index.html")
	})

	// Test 7: CORS headers
	t.Run("CORS_Headers", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/api/v1/scans")
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
		require.NotEmpty(t, resp.Header.Get("Access-Control-Allow-Methods"))

		t.Log("✅ CORS headers present")
	})

	// Test 8: OPTIONS preflight request
	t.Run("CORS_Preflight", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodOptions, baseURL+"/api/v1/scans", nil)
		require.NoError(t, err)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		t.Log("✅ OPTIONS preflight handled correctly")
	})

	// Test 9: Graceful shutdown
	t.Run("GracefulShutdown", func(t *testing.T) {
		// Trigger shutdown
		cancel()

		// Wait for server to shutdown
		select {
		case err := <-serverErr:
			require.NoError(t, err, "Server shutdown should complete without error")
		case <-time.After(5 * time.Second):
			t.Fatal("Server shutdown timeout")
		}

		// Verify server is not accepting new connections
		_, err := http.Get(baseURL + "/healthz")
		require.Error(t, err, "Server should not accept connections after shutdown")

		t.Log("✅ Graceful shutdown completed")
	})

	t.Log("🎉 Full server lifecycle test completed successfully!")
}

// TestServerWithoutUI tests server with UI disabled
func TestServerWithoutUI(t *testing.T) {
	port := 19998

	cfg := config.ServerConfig{
		Addr:        "127.0.0.1",
		Port:        port,
		UIEnabled:   false, // UI disabled
		APIEnabled:  true,
		JobsEnabled: false,
		Concurrency: 1,
		ReadTimeout: 10 * time.Second,
		Auth: config.AuthConfig{
			Mode: "none", // Disable auth for tests
		},
	}

	deps := &app.Deps{
		Workspace: newMockWorkspace(),
		Logger:    zerolog.Nop(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverApp, err := app.New(ctx, cfg, deps)
	require.NoError(t, err)

	go serverApp.Run(ctx)

	// Wait for server
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	require.Eventually(t, func() bool {
		resp, err := http.Get(baseURL + "/healthz")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 2*time.Second, 50*time.Millisecond)

	// API should work
	resp, err := http.Get(baseURL + "/api/v1/scans")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	t.Log("✅ Server with UI disabled works correctly")

	// Cleanup
	cancel()
	time.Sleep(100 * time.Millisecond)
}

// TestServerWithoutAPI tests server with API disabled
func TestServerWithoutAPI(t *testing.T) {
	port := 19999

	cfg := config.ServerConfig{
		Addr:        "127.0.0.1",
		Port:        port,
		UIEnabled:   true,
		APIEnabled:  false, // API disabled
		JobsEnabled: false,
		Concurrency: 1,
		ReadTimeout: 10 * time.Second,
		Auth: config.AuthConfig{
			Mode: "none", // Disable auth for tests
		},
	}

	deps := &app.Deps{
		Workspace: newMockWorkspace(),
		Logger:    zerolog.Nop(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverApp, err := app.New(ctx, cfg, deps)
	require.NoError(t, err)

	go serverApp.Run(ctx)

	// Wait for server
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	require.Eventually(t, func() bool {
		resp, err := http.Get(baseURL + "/healthz")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 2*time.Second, 50*time.Millisecond)

	// Health should still work
	resp, err := http.Get(baseURL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	t.Log("✅ Server with API disabled works correctly")

	// Cleanup
	cancel()
	time.Sleep(100 * time.Millisecond)
}
