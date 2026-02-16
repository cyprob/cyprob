package httpx

import (
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/cyprob/cyprob/pkg/config"
)

// Auth returns a middleware that enforces token-based authentication.
//
// Behavior:
//   - Skips authentication for health endpoints (/healthz, /readyz)
//   - In "none" mode (cfg.Auth.Mode="none"), skips authentication
//   - In "token" mode, validates Authorization: Bearer <token> header
//   - Returns 401 Unauthorized with JSON error if auth fails
//
// Example header: Authorization: Bearer secret-token-12345
func Auth(cfg config.ServerConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health endpoints (always accessible)
			if isHealthEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Skip auth if mode is "none"
			if cfg.Auth.Mode == "none" {
				next.ServeHTTP(w, r)
				return
			}

			// Token mode: validate Authorization header
			if cfg.Auth.Mode == "token" {
				token := extractBearerToken(r)
				if token == "" {
					log.Warn().
						Str("component", "auth").
						Str("path", r.URL.Path).
						Msg("Missing authorization header")
					writeUnauthorized(w, "Missing authorization header")
					return
				}

				if token != cfg.Auth.Token {
					log.Warn().
						Str("component", "auth").
						Str("path", r.URL.Path).
						Msg("Invalid token")
					writeUnauthorized(w, "Invalid token")
					return
				}

				// Token valid - proceed
				next.ServeHTTP(w, r)
				return
			}

			// Unknown auth mode (should not happen due to validation)
			log.Error().
				Str("component", "auth").
				Str("mode", cfg.Auth.Mode).
				Msg("Unknown auth mode")
			writeUnauthorized(w, "Authentication configuration error")
		})
	}
}

// isHealthEndpoint checks if path is a health check endpoint
func isHealthEndpoint(path string) bool {
	return path == "/healthz" || path == "/readyz"
}

// extractBearerToken extracts the token from Authorization: Bearer <token> header
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	// Expected format: "Bearer <token>"
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return strings.TrimSpace(parts[1])
}

// writeUnauthorized writes a 401 Unauthorized response with JSON body
func writeUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	// Simple JSON response (not using api.WriteError to avoid circular dependency)
	_, _ = w.Write([]byte(`{"error":"Unauthorized","message":"` + message + `"}`))
}
