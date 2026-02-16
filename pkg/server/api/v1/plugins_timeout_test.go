package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/plugin"
	"github.com/cyprob/cyprob/pkg/server/api"
)

// slowPluginService simulates slow operations that exceed timeout
type slowPluginService struct {
	delay time.Duration
}

func (s *slowPluginService) Install(ctx context.Context, target string, opts plugin.InstallOptions) (*plugin.InstallResult, error) {
	select {
	case <-time.After(s.delay):
		return &plugin.InstallResult{InstalledCount: 1}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *slowPluginService) Update(ctx context.Context, opts plugin.UpdateOptions) (*plugin.UpdateResult, error) {
	select {
	case <-time.After(s.delay):
		return &plugin.UpdateResult{UpdatedCount: 1}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *slowPluginService) Uninstall(ctx context.Context, target string, opts plugin.UninstallOptions) (*plugin.UninstallResult, error) {
	select {
	case <-time.After(s.delay):
		return &plugin.UninstallResult{RemovedCount: 1}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *slowPluginService) List(ctx context.Context) ([]*plugin.PluginInfo, error) {
	return []*plugin.PluginInfo{}, nil
}

func (s *slowPluginService) GetInfo(ctx context.Context, id string) (*plugin.PluginInfo, error) {
	return &plugin.PluginInfo{ID: id}, nil
}

// TestInstallPluginHandler_Timeout tests that handler returns 504 when operation exceeds timeout
func TestInstallPluginHandler_Timeout(t *testing.T) {
	// Create slow service that takes 2 seconds
	slowSvc := &slowPluginService{delay: 2 * time.Second}

	// Create handler with 100ms timeout
	config := api.Config{HandlerTimeout: 100 * time.Millisecond}
	handler := InstallPluginHandler(slowSvc, config)

	reqBody := InstallPluginRequest{
		Target: "ssh-weak-cipher",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/install", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should return 504 Gateway Timeout
	require.Equal(t, http.StatusGatewayTimeout, w.Code)
	require.Contains(t, w.Body.String(), "TIMEOUT")
	require.Contains(t, w.Body.String(), "Gateway Timeout")
	require.Contains(t, w.Body.String(), "100ms") // Timeout duration in message
}

// TestUpdatePluginsHandler_Timeout tests that handler returns 504 when operation exceeds timeout
func TestUpdatePluginsHandler_Timeout(t *testing.T) {
	// Create slow service that takes 2 seconds
	slowSvc := &slowPluginService{delay: 2 * time.Second}

	// Create handler with 100ms timeout
	config := api.Config{HandlerTimeout: 100 * time.Millisecond}
	handler := UpdatePluginsHandler(slowSvc, config)

	reqBody := UpdatePluginsRequest{
		Category: "ssh",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/update", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should return 504 Gateway Timeout
	require.Equal(t, http.StatusGatewayTimeout, w.Code)
	require.Contains(t, w.Body.String(), "TIMEOUT")
	require.Contains(t, w.Body.String(), "Gateway Timeout")
	require.Contains(t, w.Body.String(), "100ms")
}

// TestUninstallPluginHandler_Timeout tests that handler returns 504 when operation exceeds timeout
func TestUninstallPluginHandler_Timeout(t *testing.T) {
	// Create slow service that takes 2 seconds
	slowSvc := &slowPluginService{delay: 2 * time.Second}

	// Create handler with 100ms timeout
	config := api.Config{HandlerTimeout: 100 * time.Millisecond}
	handler := UninstallPluginHandler(slowSvc, config)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/plugins/ssh-weak-cipher", nil)
	req.SetPathValue("id", "ssh-weak-cipher")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should return 504 Gateway Timeout
	require.Equal(t, http.StatusGatewayTimeout, w.Code)
	require.Contains(t, w.Body.String(), "TIMEOUT")
	require.Contains(t, w.Body.String(), "Gateway Timeout")
	require.Contains(t, w.Body.String(), "100ms")
}

// TestInstallPluginHandler_NoTimeout_WhenDisabled tests that timeout is not applied when set to 0
func TestInstallPluginHandler_NoTimeout_WhenDisabled(t *testing.T) {
	// Create fast service
	mockSvc := &mockPluginService{
		installResult: &plugin.InstallResult{
			InstalledCount: 1,
			Plugins: []*plugin.PluginInfo{
				{ID: "ssh-weak-cipher", Name: "SSH Weak Cipher", Version: "1.0.0"},
			},
		},
	}

	// Create handler with timeout disabled (0)
	config := api.Config{HandlerTimeout: 0}
	handler := InstallPluginHandler(mockSvc, config)

	reqBody := InstallPluginRequest{
		Target: "ssh-weak-cipher",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/install", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should succeed
	require.Equal(t, http.StatusOK, w.Code)
}

// TestInstallPluginHandler_RespectsExistingDeadline tests that existing context deadline takes precedence
func TestInstallPluginHandler_RespectsExistingDeadline(t *testing.T) {
	// Create slow service that takes 500ms
	slowSvc := &slowPluginService{delay: 500 * time.Millisecond}

	// Create handler with 2s timeout (longer than request deadline)
	config := api.Config{HandlerTimeout: 2 * time.Second}
	handler := InstallPluginHandler(slowSvc, config)

	reqBody := InstallPluginRequest{
		Target: "ssh-weak-cipher",
	}
	bodyBytes, _ := json.Marshal(reqBody)

	// Create request with existing deadline of 100ms (shorter than handler timeout)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/install", bytes.NewReader(bodyBytes))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should timeout with request's 100ms deadline, not handler's 2s timeout
	require.Equal(t, http.StatusGatewayTimeout, w.Code)
	require.Contains(t, w.Body.String(), "TIMEOUT")
	// Note: Message will show handler timeout (2s) but actual timeout was from request context (100ms)
	// This is expected behavior - handler doesn't know if timeout came from its own deadline or request's
}
