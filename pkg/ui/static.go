package ui

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/cyprob/cyprob/pkg/config"
)

// NewHandler creates an HTTP handler for serving UI assets.
//
// Operating modes:
//   - Dev mode (cfg.UI.AssetsPath set): Serves from disk for hot reload
//   - Production mode: Serves from embedded FS (go:embed)
//
// The handler implements SPA fallback routing:
//   - Static files (*.js, *.css, etc.) are served directly
//   - Unknown routes fall back to index.html for client-side routing
func NewHandler(cfg config.ServerConfig) http.Handler {
	if cfg.UI.AssetsPath != "" {
		// Dev mode: serve from disk for hot reload
		log.Info().
			Str("component", "ui").
			Str("path", cfg.UI.AssetsPath).
			Msg("Serving UI from disk (dev mode)")

		return spaHandler(http.FileServer(http.Dir(cfg.UI.AssetsPath)))
	}

	// Production: serve from embedded FS
	log.Info().
		Str("component", "ui").
		Msg("Serving UI from embedded assets (production mode)")

	// Strip "dist/" prefix from embed.FS paths
	stripped, err := fs.Sub(DistFS, "dist")
	if err != nil {
		log.Fatal().
			Str("component", "ui").
			Err(err).
			Msg("Failed to create sub-FS for UI dist")
	}

	return spaHandler(http.FileServer(http.FS(stripped)))
}

// spaHandler wraps a file server to implement SPA fallback routing.
//
// If a requested file doesn't exist, serves index.html instead,
// allowing React Router to handle client-side routing.
//
// Example:
//   - /assets/main.js → serves main.js (file exists)
//   - /dashboard → serves index.html (route handled by React)
//   - /settings/profile → serves index.html (route handled by React)
func spaHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the absolute path to prevent directory traversal
		path := r.URL.Path

		// Skip SPA fallback for specific paths
		if shouldServeFile(path) {
			h.ServeHTTP(w, r)
			return
		}

		// For all other routes, serve index.html
		// This allows React Router to handle the routing
		r.URL.Path = "/"
		h.ServeHTTP(w, r)
	})
}

// shouldServeFile determines if a path should be served as-is
// or should fall back to index.html for SPA routing.
func shouldServeFile(path string) bool {
	// Serve root index.html
	if path == "/" || path == "/index.html" {
		return true
	}

	// Serve files with extensions (*.js, *.css, *.png, etc.)
	ext := filepath.Ext(path)
	if ext != "" && ext != ".html" {
		return true
	}

	// Serve files in known asset directories
	if strings.HasPrefix(path, "/assets/") ||
		strings.HasPrefix(path, "/static/") ||
		strings.HasPrefix(path, "/public/") {
		return true
	}

	// Check if favicon or manifest
	if strings.HasPrefix(path, "/favicon") ||
		path == "/manifest.json" ||
		path == "/robots.txt" {
		return true
	}

	// Everything else falls back to index.html (SPA routing)
	return false
}

// FileExists checks if a file exists and is not a directory.
// Used for conditional SPA fallback logic.
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
