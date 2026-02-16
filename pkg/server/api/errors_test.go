package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/plugin"
	"github.com/cyprob/cyprob/pkg/storage"
)

func TestWriteError_NotFound(t *testing.T) {
	notFoundErr := &storage.NotFoundError{
		ResourceType: "scan",
		ResourceID:   "scan-123",
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/scan-123", nil)
	w := httptest.NewRecorder()

	WriteError(w, req, notFoundErr)

	require.Equal(t, http.StatusNotFound, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	require.Equal(t, "Not Found", response.Error)
	require.Equal(t, "RESOURCE_NOT_FOUND", response.Code)
	require.Contains(t, response.Message, "scan-123")
}

func TestWriteError_InternalServerError(t *testing.T) {
	genericErr := errors.New("database connection failed")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	w := httptest.NewRecorder()

	WriteError(w, req, genericErr)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	require.Equal(t, "Internal Server Error", response.Error)
	require.Equal(t, "INTERNAL_ERROR", response.Code)
	require.Equal(t, "database connection failed", response.Message)
}

func TestWriteError_PluginNotFound(t *testing.T) {
	pluginErr := plugin.ErrPluginNotFound

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins/ssh-weak-cipher", nil)
	w := httptest.NewRecorder()

	WriteError(w, req, pluginErr)

	require.Equal(t, http.StatusNotFound, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	require.Equal(t, "Not Found", response.Error)
	require.Equal(t, "PLUGIN_NOT_FOUND", response.Code)
	require.Equal(t, "plugin not found", response.Message)
}

func TestWriteError_PluginInvalidInput(t *testing.T) {
	pluginErr := fmt.Errorf("invalid category 'invalid': %w", plugin.ErrInvalidCategory)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/install", nil)
	w := httptest.NewRecorder()

	WriteError(w, req, pluginErr)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	require.Equal(t, "Bad Request", response.Error)
	require.Equal(t, "INVALID_CATEGORY", response.Code)
	require.Contains(t, response.Message, "invalid category")
}

func TestWriteError_PluginUnavailable(t *testing.T) {
	pluginErr := fmt.Errorf("remote repository unreachable: %w", plugin.ErrSourceNotAvailable)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/update", nil)
	w := httptest.NewRecorder()

	WriteError(w, req, pluginErr)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	require.Equal(t, "Service Unavailable", response.Error)
	require.Equal(t, "SOURCE_NOT_AVAILABLE", response.Code)
	require.Contains(t, response.Message, "remote repository")
}

func TestWriteError_PluginConflict(t *testing.T) {
	pluginErr := fmt.Errorf("plugin already installed with version 1.0.0: %w", plugin.ErrPluginAlreadyInstalled)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/install", nil)
	w := httptest.NewRecorder()

	WriteError(w, req, pluginErr)

	require.Equal(t, http.StatusConflict, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	require.Equal(t, "Conflict", response.Error)
	require.Equal(t, "PLUGIN_ALREADY_INSTALLED", response.Code)
	require.Contains(t, response.Message, "already installed")
}

func TestWriteError_PluginPartialFailure(t *testing.T) {
	pluginErr := fmt.Errorf("some plugins failed to update: %w", plugin.ErrPartialFailure)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/update", nil)
	w := httptest.NewRecorder()

	WriteError(w, req, pluginErr)

	require.Equal(t, http.StatusOK, w.Code) // Partial failure returns 200
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	require.Equal(t, "OK", response.Error)
	require.Equal(t, "PARTIAL_FAILURE", response.Code)
	require.Contains(t, response.Message, "failed to update")
}

func TestWriteJSONError(t *testing.T) {
	w := httptest.NewRecorder()

	WriteJSONError(w, http.StatusBadRequest, "Invalid Input", "INVALID_TARGET", "Target parameter is required")

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	require.Equal(t, "Invalid Input", response.Error)
	require.Equal(t, "INVALID_TARGET", response.Code)
	require.Equal(t, "Target parameter is required", response.Message)
}

func TestWriteJSON_Success(t *testing.T) {
	w := httptest.NewRecorder()

	data := map[string]any{
		"id":     "scan-1",
		"status": "completed",
	}

	WriteJSON(w, http.StatusOK, data)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response map[string]any
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	require.Equal(t, "scan-1", response["id"])
	require.Equal(t, "completed", response["status"])
}

func TestWriteJSON_Array(t *testing.T) {
	w := httptest.NewRecorder()

	data := []ScanMetadata{
		{ID: "scan-1", Status: "completed", StartTime: "2024-01-01T00:00:00Z", Targets: 10},
		{ID: "scan-2", Status: "running", StartTime: "2024-01-02T00:00:00Z", Targets: 5},
	}

	WriteJSON(w, http.StatusOK, data)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response []ScanMetadata
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	require.Len(t, response, 2)
	require.Equal(t, "scan-1", response[0].ID)
	require.Equal(t, "scan-2", response[1].ID)
}

// Test JSON encoding error path (unencodable data)
func TestWriteJSON_EncodingError(t *testing.T) {
	w := httptest.NewRecorder()

	// Channels are not JSON-encodable
	data := map[string]any{
		"channel": make(chan int),
	}

	// Should not panic, should log error instead
	WriteJSON(w, http.StatusOK, data)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))
	// Body will be empty or partial due to encoding failure
}

func TestWriteJSONError_EncodingError(t *testing.T) {
	// Create a broken ResponseWriter that fails on Write
	w := &brokenResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		failOnWrite:      true,
	}

	// This should handle the encoding error gracefully
	WriteJSONError(w, http.StatusBadRequest, "Test Error", "TEST_ERROR", "Test message")

	// Should set status code before attempting to write body
	require.Equal(t, http.StatusBadRequest, w.statusCode)
}

func TestWriteError_EncodingError(t *testing.T) {
	// Create a broken ResponseWriter that fails on Write
	w := &brokenResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		failOnWrite:      true,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	err := errors.New("test error")

	// This should handle the encoding error gracefully
	WriteError(w, req, err)

	// Should set status code before attempting to write body
	require.Equal(t, http.StatusInternalServerError, w.statusCode)
}

// brokenResponseWriter is a ResponseWriter that can simulate write failures
type brokenResponseWriter struct {
	*httptest.ResponseRecorder
	failOnWrite bool
	statusCode  int
}

func (b *brokenResponseWriter) Write(p []byte) (int, error) {
	if b.failOnWrite {
		return 0, errors.New("simulated write failure")
	}
	return b.ResponseRecorder.Write(p)
}

func (b *brokenResponseWriter) WriteHeader(statusCode int) {
	b.statusCode = statusCode
	b.ResponseRecorder.WriteHeader(statusCode)
}

func TestHttpStatusText_Default(t *testing.T) {
	require.Equal(t, http.StatusText(http.StatusTeapot), httpStatusText(http.StatusTeapot))
}

func TestIsPluginError(t *testing.T) {
	require.True(t, isPluginError(plugin.ErrPluginNotFound))
	require.False(t, isPluginError(errors.New("other error")))
}

func TestWriteError_InvalidInputError(t *testing.T) {
	invalidErr := &storage.InvalidInputError{}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", nil)
	w := httptest.NewRecorder()

	WriteError(w, req, invalidErr)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response ErrorResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	require.Equal(t, "Bad Request", response.Error)
	require.Equal(t, "INVALID_INPUT", response.Code)
	require.Contains(t, response.Message, "invalid")
}

func TestHttpStatusText_InternalServerError(t *testing.T) {
	require.Equal(t, "Internal Server Error", httpStatusText(http.StatusInternalServerError))
}
