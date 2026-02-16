package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cyprob/cyprob/pkg/plugin"
	"github.com/cyprob/cyprob/pkg/server/api"
)

// DTO Evolution Policy
// These request/response DTOs are part of the public API contract used by CLI and HTTP API clients.
// To evolve them safely without breaking existing clients:
//
// 1) Additive-only changes
//    - You MAY add new optional fields
//    - You MAY NOT remove or rename existing fields
//    - Breaking changes require a new API version (v2)
//
// 2) Zero-value semantics
//    - New fields MUST have safe zero-value behavior
//    - Prefer `omitempty` for optional JSON fields to preserve old behavior
//    - Treat nil slices/maps/pointers as "absent" (distinct from empty) when applicable
//
// 3) Examples
//    ✓ Add `Tags []string \`json:"tags,omitempty"\`` (backward compatible)
//    ✗ Remove or rename existing fields (breaks older clients)

// formatSourceList formats a string slice as a comma-separated list.
// Helper function for generating user-friendly error messages.
func formatSourceList(items []string) string {
	return strings.Join(items, ", ")
}

// classifyInstallValidationError maps a validation error from ParseInstallPlugin
// to an API error code.
func classifyInstallValidationError(err error, req InstallPluginRequest) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "target") && strings.Contains(msg, "required"):
		return "TARGET_REQUIRED"
	case strings.Contains(msg, "source"):
		return "INVALID_SOURCE"
	case strings.Contains(msg, "id") || strings.Contains(msg, "format"):
		return "INVALID_PLUGIN_ID"
	default:
		return "INVALID_INPUT"
	}
}

// PluginService defines the interface for plugin operations.
// This allows for easy mocking in tests.
// This interface matches the pkg/plugin.Service methods.
type PluginService interface {
	Install(ctx context.Context, target string, opts plugin.InstallOptions) (*plugin.InstallResult, error)
	Update(ctx context.Context, opts plugin.UpdateOptions) (*plugin.UpdateResult, error)
	Uninstall(ctx context.Context, target string, opts plugin.UninstallOptions) (*plugin.UninstallResult, error)
	List(ctx context.Context) ([]*plugin.PluginInfo, error)
	GetInfo(ctx context.Context, id string) (*plugin.PluginInfo, error)
}

// InstallPluginRequest represents the request body for plugin installation
type InstallPluginRequest struct {
	// Target is the plugin ID or category to install
	Target string `json:"target"`

	// Force reinstall even if already installed
	Force bool `json:"force,omitempty"`

	// Source to download from (optional, defaults to all sources)
	Source string `json:"source,omitempty"`
}

// InstallPluginResponse represents the response for plugin installation
type InstallPluginResponse struct {
	// InstalledCount is the number of plugins successfully installed
	InstalledCount int `json:"installed_count"`

	// SkippedCount is the number of plugins skipped (already installed)
	SkippedCount int `json:"skipped_count"`

	// FailedCount is the number of plugins that failed to install
	FailedCount int `json:"failed_count"`

	// Plugins is the list of successfully installed plugins
	Plugins []PluginInfoDTO `json:"plugins"`

	// Errors contains detailed error information for failed plugins
	// Each error includes plugin ID, error message, error code, and actionable suggestion
	Errors []PluginErrorDTO `json:"errors,omitempty"`

	// PartialFailure indicates if some plugins succeeded while others failed
	PartialFailure bool `json:"partial_failure"`
}

// UpdatePluginsRequest represents the request body for plugin updates
type UpdatePluginsRequest struct {
	// Category filter (optional)
	Category string `json:"category,omitempty"`

	// Source filter (optional)
	Source string `json:"source,omitempty"`

	// Force re-download even if cached
	Force bool `json:"force,omitempty"`

	// DryRun simulates the update without actually downloading
	DryRun bool `json:"dry_run,omitempty"`
}

// UpdatePluginsResponse represents the response for plugin updates
type UpdatePluginsResponse struct {
	// UpdatedCount is the number of plugins downloaded
	UpdatedCount int `json:"updated_count"`

	// SkippedCount is the number of plugins skipped (already cached)
	SkippedCount int `json:"skipped_count"`

	// FailedCount is the number of plugins that failed to download
	FailedCount int `json:"failed_count"`

	// Plugins is the list of updated plugins
	Plugins []PluginInfoDTO `json:"plugins"`

	// Errors contains detailed error information for failed plugins
	// Each error includes plugin ID, error message, error code, and actionable suggestion
	Errors []PluginErrorDTO `json:"errors,omitempty"`

	// PartialFailure indicates if some plugins succeeded while others failed
	PartialFailure bool `json:"partial_failure"`
}

// PluginListResponse represents the response for listing plugins
type PluginListResponse struct {
	// Plugins is the list of installed plugins
	Plugins []PluginInfoDTO `json:"plugins"`

	// Count is the total number of plugins
	Count int `json:"count"`
}

// PluginErrorDTO represents a plugin error in API responses (ADR-0003)
type PluginErrorDTO struct {
	// PluginID is the unique identifier of the plugin that failed
	PluginID string `json:"plugin_id"`

	// Error is the human-readable error message
	Error string `json:"error"`

	// Code is the machine-readable error code (e.g., CHECKSUM_MISMATCH, SOURCE_NOT_AVAILABLE)
	Code string `json:"code"`

	// Suggestion is an actionable suggestion for resolving the error
	Suggestion string `json:"suggestion,omitempty"`
}

// PluginInfoDTO represents plugin information in API responses
type PluginInfoDTO struct {
	// ID is the unique plugin identifier
	ID string `json:"id"`

	// Name is the human-readable plugin name
	Name string `json:"name"`

	// Version is the plugin version
	Version string `json:"version"`

	// Type is the plugin type
	Type string `json:"type,omitempty"`

	// Author is the plugin author
	Author string `json:"author"`

	// Severity is the severity level (critical, high, medium, low)
	Severity string `json:"severity,omitempty"`

	// Tags are the plugin tags
	Tags []string `json:"tags,omitempty"`
}

// InstallPluginHandler handles POST /api/v1/plugins/install
//
// Installs one or more plugins by ID or category.
//
// Request body:
//
//	{
//	  "target": "ssh-weak-cipher",  // Plugin ID or category name
//	  "force": false,                 // Optional: force reinstall
//	  "source": "official"            // Optional: source filter
//	}
//
// Response format:
//
//	{
//	  "installed_count": 1,
//	  "skipped_count": 0,
//	  "failed_count": 0,
//	  "plugins": [{"id": "ssh-weak-cipher", "name": "...", ...}],
//	  "errors": []
//	}
//
// Returns 400 for invalid requests, 500 for server errors, 504 for timeout.
func InstallPluginHandler(pluginService PluginService, config api.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Setup structured logger with operation context
		logger := log.With().
			Str("component", "api.plugins").
			Str("op", "install").
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Logger()

		start := time.Now()
		var statusCode int
		defer func() {
			logger.Info().
				Int("status", statusCode).
				Dur("duration_ms", time.Since(start)).
				Msg("request completed")
		}()

		// Apply handler-level timeout (only if request context doesn't have deadline)
		ctx := r.Context()
		if _, hasDeadline := ctx.Deadline(); !hasDeadline && config.HandlerTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, config.HandlerTimeout)
			defer cancel()
		}

		// Defense-in-depth: Limit request body size (2MB)
		r.Body = http.MaxBytesReader(w, r.Body, plugin.MaxRequestBodySize)

		var req InstallPluginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			statusCode = http.StatusBadRequest
			logger.Error().
				Err(err).
				Str("error_code", "INVALID_REQUEST_BODY").
				Msg("failed to decode request")
			api.WriteJSONError(w, statusCode, "Bad Request", "INVALID_REQUEST_BODY", "invalid request body: "+err.Error())
			return
		}

		// Log request snapshot
		logger.Info().
			Str("target", req.Target).
			Str("source", req.Source).
			Bool("force", req.Force).
			Msg("install started")

			// Validate request fields (target/category/id, source)
		if err := ParseInstallPlugin(req); err != nil {
			statusCode = http.StatusBadRequest
			code := classifyInstallValidationError(err, req)
			logger.Error().Str("error_code", code).Msg("validation failed: install request")
			if code == "INVALID_SOURCE" {
				api.WriteJSONError(w, statusCode, "Bad Request", code,
					"invalid source '"+req.Source+"' (valid: "+formatSourceList(plugin.ValidSources)+")")
			} else {
				api.WriteJSONError(w, statusCode, "Bad Request", code, err.Error())
			}
			return
		}

		// Build install options
		opts := plugin.InstallOptions{
			Force:  req.Force,
			Source: req.Source,
		}

		// Call service with timeout context
		result, err := pluginService.Install(ctx, req.Target, opts)
		if err != nil {
			// Check if timeout occurred
			if ctx.Err() == context.DeadlineExceeded {
				statusCode = http.StatusGatewayTimeout
				logger.Error().
					Err(err).
					Str("error_code", "TIMEOUT").
					Msg("install failed: timeout")
				api.WriteJSONError(w, statusCode, "Gateway Timeout", "TIMEOUT",
					"operation timed out after "+config.HandlerTimeout.String())
				return
			}
			statusCode = plugin.HTTPStatus(err)
			logger.Error().
				Err(err).
				Str("error_code", plugin.ErrorCode(err)).
				Msg("install failed")
			api.WriteError(w, r, err)
			return
		}

		// Build response
		resp := InstallPluginResponse{
			InstalledCount: result.InstalledCount,
			SkippedCount:   result.SkippedCount,
			FailedCount:    result.FailedCount,
			Plugins:        make([]PluginInfoDTO, 0, len(result.Plugins)),
			Errors:         make([]PluginErrorDTO, 0, len(result.Errors)),
			PartialFailure: result.FailedCount > 0 && result.InstalledCount > 0,
		}

		// Convert plugins to DTO
		for _, p := range result.Plugins {
			resp.Plugins = append(resp.Plugins, PluginInfoDTO{
				ID:       p.ID,
				Name:     p.Name,
				Version:  p.Version,
				Type:     p.Type,
				Author:   p.Author,
				Severity: p.Severity,
				Tags:     p.Tags,
			})
		}

		// Convert errors to DTO
		for _, err := range result.Errors {
			resp.Errors = append(resp.Errors, PluginErrorDTO{
				PluginID:   err.PluginID,
				Error:      err.Error,
				Code:       err.Code,
				Suggestion: err.Suggestion,
			})
		}

		// Log success with result metrics
		statusCode = http.StatusOK
		logger.Info().
			Int("installed_count", result.InstalledCount).
			Int("skipped_count", result.SkippedCount).
			Int("failed_count", result.FailedCount).
			Bool("partial_failure", resp.PartialFailure).
			Msg("install succeeded")

		api.WriteJSON(w, statusCode, resp)
	}
}

// ListPluginsHandler handles GET /api/v1/plugins
//
// Returns a list of all installed plugins with their metadata.
//
// Response format:
//
//	{
//	  "plugins": [
//	    {
//	      "id": "ssh-weak-cipher",
//	      "name": "SSH Weak Cipher Detection",
//	      "version": "1.0.0",
//	      "author": "vulntor-security",
//	      "severity": "high",
//	      "tags": ["ssh", "crypto"]
//	    }
//	  ],
//	  "count": 1
//	}
func ListPluginsHandler(pluginService PluginService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Setup structured logger
		logger := log.With().
			Str("component", "api.plugins").
			Str("op", "list").
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Logger()

		start := time.Now()
		var statusCode int
		defer func() {
			logger.Info().
				Int("status", statusCode).
				Dur("duration_ms", time.Since(start)).
				Msg("request completed")
		}()

		// Validate optional query params (e.g., category) if provided
		if verr := ParseListPlugins(r); verr != nil {
			api.WriteJSONError(w, http.StatusBadRequest, "Bad Request", "INVALID_QUERY", verr.Error())
			return
		}

		// Log operation start
		logger.Info().Msg("list started")

		plugins, err := pluginService.List(r.Context())
		if err != nil {
			statusCode = plugin.HTTPStatus(err)
			logger.Error().
				Err(err).
				Str("error_code", plugin.ErrorCode(err)).
				Msg("list failed")
			api.WriteError(w, r, err)
			return
		}

		// Convert to DTO
		dtos := make([]PluginInfoDTO, 0, len(plugins))
		for _, p := range plugins {
			dtos = append(dtos, PluginInfoDTO{
				ID:       p.ID,
				Name:     p.Name,
				Version:  p.Version,
				Type:     p.Type,
				Author:   p.Author,
				Severity: p.Severity,
				Tags:     p.Tags,
			})
		}

		resp := PluginListResponse{
			Plugins: dtos,
			Count:   len(dtos),
		}

		// Log success with metrics
		statusCode = http.StatusOK
		logger.Info().
			Int("count", len(dtos)).
			Msg("list succeeded")

		api.WriteJSON(w, statusCode, resp)
	}
}

// GetPluginHandler handles GET /api/v1/plugins/{id}
//
// Returns detailed information about a specific plugin.
//
// Path parameter:
//   - id: Plugin identifier
//
// Response format:
//
//	{
//	  "id": "ssh-weak-cipher",
//	  "name": "SSH Weak Cipher Detection",
//	  "version": "1.0.0",
//	  "author": "vulntor-security",
//	  "severity": "high",
//	  "tags": ["ssh", "crypto"]
//	}
//
// Returns 404 if plugin not found.
func GetPluginHandler(pluginService PluginService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Setup structured logger
		logger := log.With().
			Str("component", "api.plugins").
			Str("op", "get").
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Logger()

		start := time.Now()
		var statusCode int
		defer func() {
			logger.Info().
				Int("status", statusCode).
				Dur("duration_ms", time.Since(start)).
				Msg("request completed")
		}()

		id := r.PathValue("id")
		if err := ValidatePluginID(id); err != nil {
			statusCode = http.StatusBadRequest
			code := "INVALID_PLUGIN_ID"
			if strings.Contains(err.Error(), "required") {
				code = "PLUGIN_ID_REQUIRED"
			}
			logger.Error().
				Str("error_code", code).
				Msg("validation failed: invalid plugin id")
			api.WriteJSONError(w, statusCode, "Bad Request", code, err.Error())
			return
		}

		// Log operation start with request snapshot
		logger.Info().
			Str("plugin_id", id).
			Msg("get started")

		info, err := pluginService.GetInfo(r.Context(), id)
		if err != nil {
			statusCode = plugin.HTTPStatus(err)
			logger.Error().
				Err(err).
				Str("error_code", plugin.ErrorCode(err)).
				Str("plugin_id", id).
				Msg("get failed")
			// Use WriteError which will automatically map plugin errors to correct HTTP status
			api.WriteError(w, r, err)
			return
		}

		// Convert to DTO
		dto := PluginInfoDTO{
			ID:       info.ID,
			Name:     info.Name,
			Version:  info.Version,
			Type:     info.Type,
			Author:   info.Author,
			Severity: info.Severity,
			Tags:     info.Tags,
		}

		// Log success
		statusCode = http.StatusOK
		logger.Info().
			Str("plugin_id", info.ID).
			Str("plugin_name", info.Name).
			Str("version", info.Version).
			Msg("get succeeded")

		api.WriteJSON(w, statusCode, dto)
	}
}

// UninstallPluginHandler handles DELETE /api/v1/plugins/{id}
//
// Uninstalls a plugin by ID.
//
// Path parameter:
//   - id: Plugin identifier
//
// Response format:
//
//	{
//	  "message": "plugin uninstalled successfully",
//	  "removed_count": 1
//	}
//
// Returns 404 if plugin not found, 500 for server errors, 504 for timeout.
func UninstallPluginHandler(pluginService PluginService, config api.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Setup structured logger
		logger := log.With().
			Str("component", "api.plugins").
			Str("op", "uninstall").
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Logger()

		start := time.Now()
		var statusCode int
		defer func() {
			logger.Info().
				Int("status", statusCode).
				Dur("duration_ms", time.Since(start)).
				Msg("request completed")
		}()

		// Apply handler-level timeout (only if request context doesn't have deadline)
		ctx := r.Context()
		if _, hasDeadline := ctx.Deadline(); !hasDeadline && config.HandlerTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, config.HandlerTimeout)
			defer cancel()
		}

		id := r.PathValue("id")
		if err := ValidatePluginID(id); err != nil {
			statusCode = http.StatusBadRequest
			code := "INVALID_PLUGIN_ID"
			if strings.Contains(err.Error(), "required") {
				code = "PLUGIN_ID_REQUIRED"
			}
			logger.Error().
				Str("error_code", code).
				Str("plugin_id", id).
				Msg("validation failed: invalid plugin id")
			api.WriteJSONError(w, statusCode, "Bad Request", code, err.Error())
			return
		}

		// Log operation start with request snapshot
		logger.Info().
			Str("plugin_id", id).
			Msg("uninstall started")

		// Build uninstall options (single plugin)
		opts := plugin.UninstallOptions{
			All: false,
		}

		result, err := pluginService.Uninstall(ctx, id, opts)
		if err != nil {
			// Check if timeout occurred
			if ctx.Err() == context.DeadlineExceeded {
				statusCode = http.StatusGatewayTimeout
				logger.Error().
					Err(err).
					Str("error_code", "TIMEOUT").
					Str("plugin_id", id).
					Msg("uninstall failed: timeout")
				api.WriteJSONError(w, statusCode, "Gateway Timeout", "TIMEOUT",
					"operation timed out after "+config.HandlerTimeout.String())
				return
			}
			statusCode = plugin.HTTPStatus(err)
			logger.Error().
				Err(err).
				Str("error_code", plugin.ErrorCode(err)).
				Str("plugin_id", id).
				Msg("uninstall failed")
			// Use WriteError which will automatically map plugin errors to correct HTTP status
			api.WriteError(w, r, err)
			return
		}

		// Log success with metrics
		statusCode = http.StatusOK
		logger.Info().
			Str("plugin_id", id).
			Int("removed_count", result.RemovedCount).
			Int("remaining_count", result.RemainingCount).
			Msg("uninstall succeeded")

		api.WriteJSON(w, statusCode, map[string]any{
			"message":       "plugin uninstalled successfully",
			"removed_count": result.RemovedCount,
		})
	}
}

// UpdatePluginsHandler handles POST /api/v1/plugins/update
//
// Updates plugins from remote sources, optionally filtered by category or source.
//
// Request body:
//
//	{
//	  "category": "ssh",      // Optional: filter by category
//	  "source": "official",    // Optional: filter by source
//	  "force": false,          // Optional: force re-download
//	  "dry_run": false         // Optional: simulate without downloading
//	}
//
// Response format:
//
//	{
//	  "updated_count": 5,
//	  "skipped_count": 3,
//	  "failed_count": 0,
//	  "plugins": [{"id": "ssh-weak-cipher", "name": "...", ...}],
//	  "errors": []
//	}
func UpdatePluginsHandler(pluginService PluginService, config api.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Setup structured logger
		logger := log.With().
			Str("component", "api.plugins").
			Str("op", "update").
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Logger()

		start := time.Now()
		var statusCode int
		defer func() {
			logger.Info().
				Int("status", statusCode).
				Dur("duration_ms", time.Since(start)).
				Msg("request completed")
		}()

		// Apply handler-level timeout (only if request context doesn't have deadline)
		ctx := r.Context()
		if _, hasDeadline := ctx.Deadline(); !hasDeadline && config.HandlerTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, config.HandlerTimeout)
			defer cancel()
		}

		// Defense-in-depth: Limit request body size (2MB)
		r.Body = http.MaxBytesReader(w, r.Body, plugin.MaxRequestBodySize)

		var req UpdatePluginsRequest
		// Empty body is OK for update (updates all plugins)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
			statusCode = http.StatusBadRequest
			logger.Error().
				Err(err).
				Str("error_code", "INVALID_REQUEST_BODY").
				Msg("failed to decode request")
			api.WriteJSONError(w, statusCode, "Bad Request", "INVALID_REQUEST_BODY", "invalid request body: "+err.Error())
			return
		}

		// Log request snapshot
		logger.Info().
			Str("source", req.Source).
			Str("category", req.Category).
			Bool("dry_run", req.DryRun).
			Bool("force", req.Force).
			Msg("update started")

		// Validate update request fields (category/source)
		if err := ParseUpdatePlugins(req); err != nil {
			statusCode = http.StatusBadRequest
			code := "INVALID_INPUT"
			if strings.Contains(err.Error(), "category") {
				code = "INVALID_CATEGORY"
				validCategories := plugin.GetValidCategories()
				logger.Error().Str("error_code", code).Msg("validation failed: invalid category")
				api.WriteJSONError(w, statusCode, "Bad Request", code,
					"invalid category '"+req.Category+"' (valid: "+formatSourceList(validCategories)+")")
				return
			}
			if strings.Contains(err.Error(), "source") {
				code = "INVALID_SOURCE"
				logger.Error().Str("error_code", code).Msg("validation failed: invalid source")
				api.WriteJSONError(w, statusCode, "Bad Request", code,
					"invalid source '"+req.Source+"' (valid: "+formatSourceList(plugin.ValidSources)+")")
				return
			}
			logger.Error().Str("error_code", code).Msg("validation failed: update request")
			api.WriteJSONError(w, statusCode, "Bad Request", code, err.Error())
			return
		}

		// Build update options
		opts := plugin.UpdateOptions{
			Source: req.Source,
			Force:  req.Force,
			DryRun: req.DryRun,
		}

		// Convert category string to Category type
		if req.Category != "" {
			opts.Category = plugin.Category(req.Category)
		}

		// Call service with timeout context
		result, err := pluginService.Update(ctx, opts)
		if err != nil {
			// Check if timeout occurred
			if ctx.Err() == context.DeadlineExceeded {
				statusCode = http.StatusGatewayTimeout
				logger.Error().
					Err(err).
					Str("error_code", "TIMEOUT").
					Msg("update failed: timeout")
				api.WriteJSONError(w, statusCode, "Gateway Timeout", "TIMEOUT",
					"operation timed out after "+config.HandlerTimeout.String())
				return
			}
			statusCode = plugin.HTTPStatus(err)
			logger.Error().
				Err(err).
				Str("error_code", plugin.ErrorCode(err)).
				Msg("update failed")
			api.WriteError(w, r, err)
			return
		}

		// Build response
		resp := UpdatePluginsResponse{
			UpdatedCount:   result.UpdatedCount,
			SkippedCount:   result.SkippedCount,
			FailedCount:    result.FailedCount,
			Plugins:        make([]PluginInfoDTO, 0, len(result.Plugins)),
			Errors:         make([]PluginErrorDTO, 0, len(result.Errors)),
			PartialFailure: result.FailedCount > 0 && result.UpdatedCount > 0,
		}

		// Convert plugins to DTO
		for _, p := range result.Plugins {
			resp.Plugins = append(resp.Plugins, PluginInfoDTO{
				ID:       p.ID,
				Name:     p.Name,
				Version:  p.Version,
				Type:     p.Type,
				Author:   p.Author,
				Severity: p.Severity,
				Tags:     p.Tags,
			})
		}

		// Convert errors to DTO
		for _, err := range result.Errors {
			resp.Errors = append(resp.Errors, PluginErrorDTO{
				PluginID:   err.PluginID,
				Error:      err.Error,
				Code:       err.Code,
				Suggestion: err.Suggestion,
			})
		}

		// Log success with metrics
		statusCode = http.StatusOK
		logger.Info().
			Int("updated_count", result.UpdatedCount).
			Int("skipped_count", result.SkippedCount).
			Int("failed_count", result.FailedCount).
			Bool("partial_failure", resp.PartialFailure).
			Msg("update succeeded")

		api.WriteJSON(w, statusCode, resp)
	}
}
