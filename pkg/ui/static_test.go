package ui

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/config"
)

func TestNewHandler_ProductionMode(t *testing.T) {
	cfg := config.ServerConfig{
		UI: config.UIConfig{
			AssetsPath: "", // Production mode (empty path)
		},
	}

	handler := NewHandler(cfg)
	require.NotNil(t, handler)
}

func TestNewHandler_DiskAssets(t *testing.T) {
	cfg := config.ServerConfig{
		UI: config.UIConfig{
			AssetsPath: "./testdata", // Disk path for development
		},
	}

	handler := NewHandler(cfg)
	require.NotNil(t, handler)
}

func TestShouldServeFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Should serve directly
		{"root", "/", true},
		{"index.html", "/index.html", true},
		{"js file", "/assets/main.js", true},
		{"css file", "/assets/style.css", true},
		{"png image", "/assets/logo.png", true},
		{"static asset", "/static/image.jpg", true},
		{"public asset", "/public/data.json", true},
		{"favicon", "/favicon.ico", true},
		{"manifest", "/manifest.json", true},
		{"robots", "/robots.txt", true},

		// Should fall back to index.html (SPA routes)
		{"dashboard route", "/dashboard", false},
		{"settings route", "/settings", false},
		{"nested route", "/settings/profile", false},
		{"user route", "/users/123", false},
		{"deep nested", "/app/settings/security", false},
		{"html route", "/about.html", false}, // Falls back for SPA
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldServeFile(tt.path)
			require.Equal(t, tt.expected, result, "shouldServeFile(%s) = %v, want %v", tt.path, result, tt.expected)
		})
	}
}

func TestFileExists(t *testing.T) {
	// Test with static.go (this file exists)
	require.True(t, FileExists("static.go"))

	// Test with non-existent file
	require.False(t, FileExists("nonexistent-file-12345.txt"))

	// Test with directory (should return false)
	require.False(t, FileExists("."))
}

func TestSPAHandler_ServeStaticFiles(t *testing.T) {
	// Create a mock file server
	mockFS := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate serving a static file
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("static file content"))
	})

	handler := spaHandler(mockFS)

	// Test serving a static asset
	req := httptest.NewRequest(http.MethodGet, "/assets/main.js", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "static file content", w.Body.String())
	require.Equal(t, "/assets/main.js", req.URL.Path) // Path unchanged
}

func TestSPAHandler_FallbackToIndex(t *testing.T) {
	// Create a mock file server that serves index.html for root
	mockFS := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>index</html>"))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})

	handler := spaHandler(mockFS)

	// Test SPA route fallback (e.g., /dashboard should serve index.html)
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "<html>index</html>", w.Body.String())
	require.Equal(t, "/", req.URL.Path) // Path rewritten to "/"
}

func TestSPAHandler_NestedRoutes(t *testing.T) {
	mockFS := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("index"))
		}
	})

	handler := spaHandler(mockFS)

	// Test nested SPA routes
	tests := []struct {
		name string
		path string
	}{
		{"settings route", "/settings"},
		{"nested settings", "/settings/profile"},
		{"deep nested", "/app/users/123/edit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, "index", w.Body.String())
			require.Equal(t, "/", req.URL.Path) // All rewritten to "/"
		})
	}
}

func TestShouldServeFile_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Additional edge cases
		{"favicon.ico", "/favicon.ico", true},
		{"favicon.png", "/favicon.png", true},
		{"nested assets", "/assets/js/app.js", true},
		{"query params", "/assets/main.js?v=123", true}, // Extension still .js
		{"double extension", "/file.tar.gz", true},
		{"dot file", "/.htaccess", true},
		{"empty extension html", "/about.html", false}, // HTML routes use SPA
		{"uppercase extension", "/IMAGE.PNG", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldServeFile(tt.path)
			require.Equal(t, tt.expected, result, "shouldServeFile(%s) = %v, want %v", tt.path, result, tt.expected)
		})
	}
}

// Note: Full integration test requires built UI assets
// To run manually:
//  1. cd ui && npm run build
//  2. go test ./pkg/ui -v
//
// The test below is skipped in CI until UI is built
func TestNewHandler_Integration(t *testing.T) {
	t.Skip("Requires built UI assets - run manually with 'make build-ui && go test'")

	// This would test actual file serving with built assets
	// Left as placeholder for manual testing
}
