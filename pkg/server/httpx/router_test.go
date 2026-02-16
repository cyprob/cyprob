package httpx

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/config"
	"github.com/cyprob/cyprob/pkg/plugin"
	"github.com/cyprob/cyprob/pkg/server/api"
)

func TestNewRouter(t *testing.T) {
	cfg := config.DefaultServerConfig()
	deps := &api.Deps{
		Ready: &atomic.Bool{},
	}
	router := NewRouter(cfg, deps)

	require.NotNil(t, router)
}

func TestNewRouter_HealthzMounted(t *testing.T) {
	cfg := config.DefaultServerConfig()
	deps := &api.Deps{
		Ready: &atomic.Bool{},
	}
	router := NewRouter(cfg, deps)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "OK", w.Body.String())
}

func TestHealthzHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	HealthzHandler(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "OK", w.Body.String())
}

func TestHealthzHandler_AlwaysReturnsOK(t *testing.T) {
	// Test multiple calls to ensure idempotency
	for range 5 {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		w := httptest.NewRecorder()

		HealthzHandler(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "OK", w.Body.String())
	}
}

func TestHealthzHandler_IgnoresRequestBody(t *testing.T) {
	// Health check should work regardless of request body
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	HealthzHandler(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

// mockPluginService is a minimal mock for testing router mount logic
type mockPluginService struct{}

func (m *mockPluginService) Install(ctx context.Context, target string, opts plugin.InstallOptions) (*plugin.InstallResult, error) {
	return &plugin.InstallResult{InstalledCount: 1}, nil
}

func (m *mockPluginService) Update(ctx context.Context, opts plugin.UpdateOptions) (*plugin.UpdateResult, error) {
	return &plugin.UpdateResult{UpdatedCount: 1}, nil
}

func (m *mockPluginService) List(ctx context.Context) ([]*plugin.PluginInfo, error) {
	return []*plugin.PluginInfo{}, nil
}

func (m *mockPluginService) GetInfo(ctx context.Context, id string) (*plugin.PluginInfo, error) {
	return &plugin.PluginInfo{ID: id}, nil
}

func (m *mockPluginService) Uninstall(ctx context.Context, target string, opts plugin.UninstallOptions) (*plugin.UninstallResult, error) {
	return &plugin.UninstallResult{RemovedCount: 1}, nil
}

// TestPluginRoutes_NotMounted_WhenServiceIsNil tests that plugin routes are NOT mounted when PluginService is nil
func TestPluginRoutes_NotMounted_WhenServiceIsNil(t *testing.T) {
	cfg := config.DefaultServerConfig()
	cfg.APIEnabled = true
	cfg.UIEnabled = false // Disable UI to avoid catch-all "/" route

	// Capture logs
	var buf bytes.Buffer
	log.Logger = zerolog.New(&buf).Level(zerolog.InfoLevel)

	deps := &api.Deps{
		Ready:         &atomic.Bool{},
		PluginService: nil, // No plugin service
		Config:        api.DefaultConfig(),
	}

	router := NewRouter(cfg, deps)

	// Try to access plugin endpoints - should return 404 (not found)
	pluginEndpoints := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/plugins/install"},
		{http.MethodPost, "/api/v1/plugins/update"},
		{http.MethodGet, "/api/v1/plugins"},
		{http.MethodGet, "/api/v1/plugins/test-plugin"},
		{http.MethodDelete, "/api/v1/plugins/test-plugin"},
	}

	for _, endpoint := range pluginEndpoints {
		req := httptest.NewRequest(endpoint.method, endpoint.path, nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Plugin routes should not be mounted, expecting 404 (Not Found)
		require.Equal(t, http.StatusNotFound, w.Code,
			"Expected 404 for %s %s when PluginService=nil, got %d", endpoint.method, endpoint.path, w.Code)
	}

	// Assert info log for skipping
	require.Contains(t, buf.String(), "PluginService not provided - skipping plugin API routes")
}

// TestPluginRoutes_NotMounted_WhenServiceWrongType verifies that when PluginService exists
// but does NOT implement v1.PluginService, routes are NOT mounted and a warning is logged.
func TestPluginRoutes_NotMounted_WhenServiceWrongType(t *testing.T) {
	cfg := config.DefaultServerConfig()
	cfg.APIEnabled = true
	cfg.UIEnabled = false // Disable UI to avoid catch-all "/" route

	// Capture logs
	var buf bytes.Buffer
	log.Logger = zerolog.New(&buf).Level(zerolog.InfoLevel)

	// Provide a wrong type for PluginService
	deps := &api.Deps{
		Ready:         &atomic.Bool{},
		PluginService: struct{}{}, // wrong type, does not satisfy v1.PluginService
		Config:        api.DefaultConfig(),
	}

	router := NewRouter(cfg, deps)

	// Try to access a plugin endpoint - should be 404 because routes not mounted
	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)

	// Assert warning log emitted
	logStr := buf.String()
	require.Contains(t, logStr, "PluginService type assertion failed")
	require.Contains(t, logStr, "httpx.router")
}

// TestPluginRoutes_Mounted_WhenServiceExists tests that plugin routes ARE mounted when PluginService is present
func TestPluginRoutes_Mounted_WhenServiceExists(t *testing.T) {
	cfg := config.DefaultServerConfig()
	cfg.APIEnabled = true
	cfg.UIEnabled = false // Disable UI to avoid catch-all "/" route

	mockSvc := &mockPluginService{}

	// Capture logs
	var buf bytes.Buffer
	log.Logger = zerolog.New(&buf).Level(zerolog.InfoLevel)

	deps := &api.Deps{
		Ready:         &atomic.Bool{},
		PluginService: mockSvc, // Plugin service exists
		Config:        api.DefaultConfig(),
	}

	router := NewRouter(cfg, deps)

	// Try to access plugin endpoints - should NOT return 404 (routes are mounted)
	// We expect other errors (400, 500, etc.) from the handlers themselves, not 404
	pluginEndpoints := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/plugins/install"},
		{http.MethodPost, "/api/v1/plugins/update"},
		{http.MethodGet, "/api/v1/plugins"},
		{http.MethodGet, "/api/v1/plugins/test-plugin"},
		{http.MethodDelete, "/api/v1/plugins/test-plugin"},
	}

	for _, endpoint := range pluginEndpoints {
		req := httptest.NewRequest(endpoint.method, endpoint.path, nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// Routes should be mounted, so NOT 404 (could be 400, 500, etc. from handler)
		require.NotEqual(t, http.StatusNotFound, w.Code,
			"Expected plugin route %s %s to be mounted (not 404), got %d", endpoint.method, endpoint.path, w.Code)
	}

	// Assert info log for mounting
	require.Contains(t, buf.String(), "mounting plugin API routes")
}

// TestPluginRoutes_NotMounted_WhenAPIDisabled tests that plugin routes are NOT mounted when APIEnabled=false
func TestPluginRoutes_NotMounted_WhenAPIDisabled(t *testing.T) {
	cfg := config.DefaultServerConfig()
	cfg.APIEnabled = false // API disabled
	cfg.UIEnabled = false  // Disable UI to avoid catch-all "/" route

	mockSvc := &mockPluginService{}
	deps := &api.Deps{
		Ready:         &atomic.Bool{},
		PluginService: mockSvc,
		Config:        api.DefaultConfig(),
	}

	router := NewRouter(cfg, deps)

	// Try to access plugin endpoints - should return 404 (API is disabled)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code, "Expected 404 when APIEnabled=false")
}
