package httpx

import (
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cyprob/cyprob/pkg/config"
)

// Chain applies middleware in order: Logger → Auth → Recovery → CORS → handler
//
// This ensures:
// 1. All requests are logged (even if they panic or fail auth)
// 2. Authentication is enforced before business logic
// 3. Panics are recovered and logged
// 4. CORS headers are set for all responses
func Chain(cfg config.ServerConfig, handler http.Handler) http.Handler {
	return Logger(Auth(cfg)(Recovery(CORS(handler))))
}

// Logger logs each HTTP request with method, path, status, and duration.
//
// Uses zerolog with "component=http" for filtering.
// Captures status code via responseWriter wrapper.
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap ResponseWriter to capture status code
		ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(ww, r)

		log.Info().
			Str("component", "http").
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status", ww.statusCode).
			Dur("duration", time.Since(start)).
			Msg("HTTP request")
	})
}

// Recovery catches panics and returns 500 Internal Server Error.
//
// Prevents server crashes from handler panics.
// Logs panic details with stack trace for debugging.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Error().
					Str("component", "http").
					Interface("error", err).
					Str("path", r.URL.Path).
					Msg("Panic recovered in HTTP handler")

				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// CORS adds Cross-Origin Resource Sharing headers for API endpoints.
//
// Allows requests from any origin (*) with common HTTP methods.
// Handles preflight OPTIONS requests automatically.
//
// Note: In production, consider restricting allowed origins.
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
