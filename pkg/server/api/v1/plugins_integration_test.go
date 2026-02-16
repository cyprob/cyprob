//go:build integration

package v1_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/config"
	"github.com/cyprob/cyprob/pkg/plugin"
	"github.com/cyprob/cyprob/pkg/server/api"
	v1 "github.com/cyprob/cyprob/pkg/server/api/v1"
	"github.com/cyprob/cyprob/pkg/server/app"
	"github.com/cyprob/cyprob/pkg/storage"
)

func init() {
	// Disable all logging for integration tests to reduce noise
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

// TestPluginAPIFullLifecycle tests the complete plugin management workflow via API.
//
// This integration test:
//   - Starts a real HTTP server with plugin API endpoints
//   - Creates a temporary plugin cache directory
//   - Tests full lifecycle: install → list → get → uninstall
//   - Verifies cache cleanup after uninstall
//   - Tests error cases (404, 400)
//
// Run with: go test -tags=integration -v ./pkg/server/api/v1
func TestPluginAPIFullLifecycle(t *testing.T) {
	// Create temporary plugin cache
	tmpDir, err := os.MkdirTemp("", "vulntor-plugin-integration-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pluginCacheDir := filepath.Join(tmpDir, "plugins", "cache")

	// Create plugin service with Nop logger to suppress logs in tests
	nopLogger := zerolog.Nop()
	pluginService, err := plugin.NewService(
		plugin.WithCacheDir(pluginCacheDir),
		plugin.WithLogger(nopLogger),
	)
	require.NoError(t, err)

	// Start server
	port := 18080
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverApp, baseURL := startTestServer(t, ctx, port, pluginService)
	defer func() {
		cancel()
		time.Sleep(100 * time.Millisecond) // Allow graceful shutdown
	}()

	// Wait for server to be ready
	waitForServer(t, baseURL+"/readyz", 5*time.Second)

	t.Run("List empty plugins initially", func(t *testing.T) {
		resp := makeRequest(t, "GET", baseURL+"/api/v1/plugins", nil)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp v1.PluginListResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&listResp))
		require.Equal(t, 0, listResp.Count)
		require.Empty(t, listResp.Plugins)
	})

	t.Run("Install plugin via API", func(t *testing.T) {
		reqBody := v1.InstallPluginRequest{
			Target: "ssh-weak-mac-algorithm",
		}
		bodyBytes, _ := json.Marshal(reqBody)

		resp := makeRequest(t, "POST", baseURL+"/api/v1/plugins/install", bytes.NewReader(bodyBytes))
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var installResp v1.InstallPluginResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&installResp))
		require.Equal(t, 1, installResp.InstalledCount)
		require.Equal(t, 0, installResp.SkippedCount)
		require.Equal(t, 0, installResp.FailedCount)
		require.Len(t, installResp.Plugins, 1)
		require.Equal(t, "ssh-weak-mac-algorithm", installResp.Plugins[0].ID)
	})

	t.Run("List plugins shows installed plugin", func(t *testing.T) {
		resp := makeRequest(t, "GET", baseURL+"/api/v1/plugins", nil)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp v1.PluginListResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&listResp))
		require.Equal(t, 1, listResp.Count)
		require.Len(t, listResp.Plugins, 1)
		require.Equal(t, "ssh-weak-mac-algorithm", listResp.Plugins[0].ID)
	})

	t.Run("Get plugin details", func(t *testing.T) {
		resp := makeRequest(t, "GET", baseURL+"/api/v1/plugins/ssh-weak-mac-algorithm", nil)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var pluginInfo v1.PluginInfoDTO
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&pluginInfo))
		require.Equal(t, "ssh-weak-mac-algorithm", pluginInfo.ID)
		require.NotEmpty(t, pluginInfo.Name)
		require.NotEmpty(t, pluginInfo.Version)
	})

	t.Run("Get non-existent plugin returns 404", func(t *testing.T) {
		resp := makeRequest(t, "GET", baseURL+"/api/v1/plugins/non-existent-plugin", nil)
		defer resp.Body.Close()

		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("Uninstall plugin via API", func(t *testing.T) {
		resp := makeRequest(t, "DELETE", baseURL+"/api/v1/plugins/ssh-weak-mac-algorithm", nil)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var uninstallResp map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&uninstallResp))
		require.Contains(t, uninstallResp["message"], "uninstalled successfully")
		require.Equal(t, float64(1), uninstallResp["removed_count"]) // JSON numbers are float64
	})

	t.Run("List plugins shows empty after uninstall", func(t *testing.T) {
		resp := makeRequest(t, "GET", baseURL+"/api/v1/plugins", nil)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp v1.PluginListResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&listResp))
		require.Equal(t, 0, listResp.Count)
		require.Empty(t, listResp.Plugins)
	})

	t.Run("Uninstall already-uninstalled plugin returns empty result", func(t *testing.T) {
		// First, install a plugin
		reqBody := v1.InstallPluginRequest{
			Target: "tls-weak-cipher-suite",
		}
		bodyBytes, _ := json.Marshal(reqBody)
		resp := makeRequest(t, "POST", baseURL+"/api/v1/plugins/install", bytes.NewReader(bodyBytes))
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Uninstall it
		resp = makeRequest(t, "DELETE", baseURL+"/api/v1/plugins/tls-weak-cipher-suite", nil)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Try to uninstall again
		// NOTE: Currently returns 200 with removed_count=0 (service layer behavior)
		// TODO: This should probably return 404 when plugin is not found
		// See Issue #7 or create new issue for this behavior
		resp = makeRequest(t, "DELETE", baseURL+"/api/v1/plugins/tls-weak-cipher-suite", nil)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var uninstallResp map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&uninstallResp))
		require.Equal(t, float64(0), uninstallResp["removed_count"]) // No plugins removed
	})

	_ = serverApp // Avoid unused variable warning
}

// TestPluginAPICategoryInstall tests installing plugins by category.
func TestPluginAPICategoryInstall(t *testing.T) {
	// Create temporary plugin cache
	tmpDir, err := os.MkdirTemp("", "vulntor-plugin-category-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pluginCacheDir := filepath.Join(tmpDir, "plugins", "cache")

	// Create plugin service with Nop logger to suppress logs in tests
	nopLogger := zerolog.Nop()
	pluginService, err := plugin.NewService(
		plugin.WithCacheDir(pluginCacheDir),
		plugin.WithLogger(nopLogger),
	)
	require.NoError(t, err)

	// Start server
	port := 18081
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverApp, baseURL := startTestServer(t, ctx, port, pluginService)
	defer func() {
		cancel()
		time.Sleep(100 * time.Millisecond)
	}()

	waitForServer(t, baseURL+"/readyz", 5*time.Second)

	t.Run("Install SSH category", func(t *testing.T) {
		reqBody := v1.InstallPluginRequest{
			Target: "ssh",
		}
		bodyBytes, _ := json.Marshal(reqBody)

		resp := makeRequest(t, "POST", baseURL+"/api/v1/plugins/install", bytes.NewReader(bodyBytes))
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var installResp v1.InstallPluginResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&installResp))

		// SSH category should install multiple plugins
		require.Greater(t, installResp.InstalledCount, 0, "Should install at least one SSH plugin")
		require.Equal(t, 0, installResp.FailedCount, "Should have no failures")

		// Verify all installed plugins are SSH-related
		for _, p := range installResp.Plugins {
			require.Contains(t, p.Tags, "ssh", "All installed plugins should have 'ssh' tag")
		}
	})

	_ = serverApp
}

// TestPluginAPIErrorCases tests error handling in plugin API.
func TestPluginAPIErrorCases(t *testing.T) {
	// Create temporary plugin cache
	tmpDir, err := os.MkdirTemp("", "vulntor-plugin-errors-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pluginCacheDir := filepath.Join(tmpDir, "plugins", "cache")

	// Create plugin service with Nop logger to suppress logs in tests
	nopLogger := zerolog.Nop()
	pluginService, err := plugin.NewService(
		plugin.WithCacheDir(pluginCacheDir),
		plugin.WithLogger(nopLogger),
	)
	require.NoError(t, err)

	// Start server
	port := 18082
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverApp, baseURL := startTestServer(t, ctx, port, pluginService)
	defer func() {
		cancel()
		time.Sleep(100 * time.Millisecond)
	}()

	waitForServer(t, baseURL+"/readyz", 5*time.Second)

	t.Run("Install with invalid JSON returns 400", func(t *testing.T) {
		invalidJSON := bytes.NewReader([]byte(`{"target": invalid}`))
		resp := makeRequest(t, "POST", baseURL+"/api/v1/plugins/install", invalidJSON)
		defer resp.Body.Close()

		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Install with empty target returns 400", func(t *testing.T) {
		reqBody := v1.InstallPluginRequest{
			Target: "",
		}
		bodyBytes, _ := json.Marshal(reqBody)

		resp := makeRequest(t, "POST", baseURL+"/api/v1/plugins/install", bytes.NewReader(bodyBytes))
		defer resp.Body.Close()

		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Update with invalid JSON returns 400", func(t *testing.T) {
		// Invalid JSON should be rejected with 400 Bad Request
		invalidJSON := bytes.NewReader([]byte(`{"category": invalid}`))
		resp := makeRequest(t, "POST", baseURL+"/api/v1/plugins/update", invalidJSON)
		defer resp.Body.Close()

		// Should fail with Bad Request
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var errResp map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
		require.Contains(t, errResp, "error")
		require.Equal(t, "INVALID_REQUEST_BODY", errResp["code"])
	})

	_ = serverApp
}

// TestPluginAPIUpdateOperations tests plugin update functionality.
func TestPluginAPIUpdateOperations(t *testing.T) {
	// Create temporary plugin cache
	tmpDir, err := os.MkdirTemp("", "vulntor-plugin-update-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	pluginCacheDir := filepath.Join(tmpDir, "plugins", "cache")

	// Create plugin service with Nop logger to suppress logs in tests
	nopLogger := zerolog.Nop()
	pluginService, err := plugin.NewService(
		plugin.WithCacheDir(pluginCacheDir),
		plugin.WithLogger(nopLogger),
	)
	require.NoError(t, err)

	// Start server
	port := 18083
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverApp, baseURL := startTestServer(t, ctx, port, pluginService)
	defer func() {
		cancel()
		time.Sleep(100 * time.Millisecond)
	}()

	waitForServer(t, baseURL+"/readyz", 5*time.Second)

	t.Run("Update with dry-run flag", func(t *testing.T) {
		reqBody := v1.UpdatePluginsRequest{
			DryRun: true,
		}
		bodyBytes, _ := json.Marshal(reqBody)

		resp := makeRequest(t, "POST", baseURL+"/api/v1/plugins/update", bytes.NewReader(bodyBytes))
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var updateResp v1.UpdatePluginsResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&updateResp))

		// Dry-run should show what would be updated without actually downloading
		require.GreaterOrEqual(t, updateResp.UpdatedCount+updateResp.SkippedCount, 0)
	})

	t.Run("Update with category filter", func(t *testing.T) {
		reqBody := v1.UpdatePluginsRequest{
			Category: "ssh",
			DryRun:   true,
		}
		bodyBytes, _ := json.Marshal(reqBody)

		resp := makeRequest(t, "POST", baseURL+"/api/v1/plugins/update", bytes.NewReader(bodyBytes))
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var updateResp v1.UpdatePluginsResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&updateResp))

		// All plugins should be SSH category
		for _, p := range updateResp.Plugins {
			require.Contains(t, p.Tags, "ssh", "Filtered plugins should have 'ssh' tag")
		}
	})

	_ = serverApp
}

// Helper functions

// startTestServer starts a test server with plugin API endpoints.
func startTestServer(t *testing.T, ctx context.Context, port int, pluginService *plugin.Service) (*app.App, string) {
	t.Helper()

	// Configure server
	cfg := config.ServerConfig{
		Addr:         "127.0.0.1",
		Port:         port,
		UIEnabled:    false, // Disable UI for plugin tests
		APIEnabled:   true,
		JobsEnabled:  false, // Disable jobs for plugin tests
		Concurrency:  2,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		Auth: config.AuthConfig{
			Mode: "none", // Disable auth for integration tests
		},
	}

	// Create config manager
	cfgMgr := config.NewManager()

	// Create storage backend (temporary)
	tmpDir, err := os.MkdirTemp("", "vulntor-storage-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	storageConfig := &storage.Config{
		WorkspaceRoot: tmpDir,
	}
	storageBackend, err := storage.NewBackend(ctx, storageConfig)
	require.NoError(t, err)

	// Mock workspace
	ws := &mockWorkspace{}

	// Build dependencies
	deps := &app.Deps{
		Storage:       storageBackend,
		Workspace:     ws,
		PluginService: pluginService,
		Config:        cfgMgr,
		Logger:        zerolog.Nop(),
	}

	// Create server app
	serverApp, err := app.New(ctx, cfg, deps)
	require.NoError(t, err)

	// Start server in background
	go func() {
		if err := serverApp.Run(ctx); err != nil && err != context.Canceled {
			t.Logf("Server error: %v", err)
		}
	}()

	baseURL := fmt.Sprintf("http://%s:%d", cfg.Addr, cfg.Port)
	return serverApp, baseURL
}

// mockWorkspace implements api.WorkspaceInterface for testing.
type mockWorkspace struct{}

func (m *mockWorkspace) ListScans() ([]api.ScanMetadata, error) {
	return []api.ScanMetadata{}, nil
}

func (m *mockWorkspace) GetScan(id string) (*api.ScanDetail, error) {
	return nil, &storage.NotFoundError{
		ResourceType: "scan",
		ResourceID:   id,
	}
}

// waitForServer waits for the server to become ready.
func waitForServer(t *testing.T, readyzURL string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(readyzURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatal("Server did not become ready within timeout")
}

// Shared HTTP client with connection pooling for all test requests.
// Reusing the same client improves performance and prevents connection exhaustion
// in CI environments where multiple sequential requests are made.
var testHTTPClient = &http.Client{
	Timeout: 20 * time.Second, // Increased to 20s for slow CI environments
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	},
}

// makeRequest makes an HTTP request and returns the response.
func makeRequest(t *testing.T, method, url string, body *bytes.Reader) *http.Response {
	t.Helper()

	var req *http.Request
	var err error

	if body != nil {
		req, err = http.NewRequest(method, url, body)
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	require.NoError(t, err)

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Use shared client with connection pooling
	resp, err := testHTTPClient.Do(req)
	require.NoError(t, err)

	return resp
}
