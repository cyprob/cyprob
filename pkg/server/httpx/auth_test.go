package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/config"
)

func TestAuth_ValidToken(t *testing.T) {
	cfg := config.ServerConfig{
		Auth: config.AuthConfig{
			Mode:  "token",
			Token: "secret-token-123",
		},
	}

	handler := Auth(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	req.Header.Set("Authorization", "Bearer secret-token-123")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "success", w.Body.String())
}

func TestAuth_InvalidToken(t *testing.T) {
	cfg := config.ServerConfig{
		Auth: config.AuthConfig{
			Mode:  "token",
			Token: "secret-token-123",
		},
	}

	handler := Auth(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), "Invalid token")
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

func TestAuth_MissingToken(t *testing.T) {
	cfg := config.ServerConfig{
		Auth: config.AuthConfig{
			Mode:  "token",
			Token: "secret-token-123",
		},
	}

	handler := Auth(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	// No Authorization header
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), "Missing authorization header")
}

func TestAuth_HealthzSkipsAuth(t *testing.T) {
	cfg := config.ServerConfig{
		Auth: config.AuthConfig{
			Mode:  "token",
			Token: "secret-token-123",
		},
	}

	handler := Auth(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("healthy"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	// No Authorization header - should still work
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "healthy", w.Body.String())
}

func TestAuth_ReadyzSkipsAuth(t *testing.T) {
	cfg := config.ServerConfig{
		Auth: config.AuthConfig{
			Mode:  "token",
			Token: "secret-token-123",
		},
	}

	handler := Auth(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	// No Authorization header - should still work
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "ready", w.Body.String())
}

func TestAuth_NoneModeSkipsAuth(t *testing.T) {
	cfg := config.ServerConfig{
		Auth: config.AuthConfig{
			Mode: "none",
		},
	}

	handler := Auth(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	// No Authorization header - should work with mode=none
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "success", w.Body.String())
}

func TestAuth_CaseInsensitiveBearer(t *testing.T) {
	cfg := config.ServerConfig{
		Auth: config.AuthConfig{
			Mode:  "token",
			Token: "secret-token-123",
		},
	}

	handler := Auth(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name   string
		header string
		want   int
	}{
		{"lowercase bearer", "bearer secret-token-123", http.StatusOK},
		{"uppercase BEARER", "BEARER secret-token-123", http.StatusOK},
		{"mixed case Bearer", "Bearer secret-token-123", http.StatusOK},
		{"with extra spaces", "Bearer  secret-token-123  ", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
			req.Header.Set("Authorization", tt.header)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			require.Equal(t, tt.want, w.Code)
		})
	}
}

func TestAuth_InvalidAuthorizationFormat(t *testing.T) {
	cfg := config.ServerConfig{
		Auth: config.AuthConfig{
			Mode:  "token",
			Token: "secret-token-123",
		},
	}

	handler := Auth(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name   string
		header string
	}{
		{"no bearer prefix", "secret-token-123"},
		{"basic auth", "Basic dXNlcjpwYXNz"},
		{"empty bearer", "Bearer"},
		{"only bearer", "Bearer "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
			req.Header.Set("Authorization", tt.header)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			require.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"valid bearer", "Bearer secret-123", "secret-123"},
		{"uppercase BEARER", "BEARER secret-123", "secret-123"},
		{"with spaces", "Bearer  secret-123  ", "secret-123"},
		{"no bearer", "secret-123", ""},
		{"basic auth", "Basic dXNlcjpwYXNz", ""},
		{"empty", "", ""},
		{"bearer only", "Bearer", ""},
		{"bearer with space", "Bearer ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			got := extractBearerToken(req)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestIsHealthEndpoint(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/healthz", true},
		{"/readyz", true},
		{"/api/v1/scans", false},
		{"/", false},
		{"/health", false},
		{"/healthz/check", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isHealthEndpoint(tt.path)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestAuth_UnknownMode tests the edge case where an unknown auth mode
// is used (should not happen due to config validation, but defensive)
func TestAuth_UnknownMode(t *testing.T) {
	cfg := config.ServerConfig{
		Auth: config.AuthConfig{
			Mode: "unknown-mode", // Invalid mode bypassing validation
		},
	}

	handler := Auth(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("should not reach here"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should return 401 Unauthorized for unknown auth mode
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Body.String(), "Authentication configuration error")
}
