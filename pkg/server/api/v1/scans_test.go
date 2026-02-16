package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/server/api"
	"github.com/cyprob/cyprob/pkg/storage"
)

// Mock workspace for testing
type mockWorkspace struct {
	scans      []api.ScanMetadata
	scanDetail map[string]*api.ScanDetail
	listError  error
	getError   error
}

func (m *mockWorkspace) ListScans() ([]api.ScanMetadata, error) {
	if m.listError != nil {
		return nil, m.listError
	}
	return m.scans, nil
}

func (m *mockWorkspace) GetScan(id string) (*api.ScanDetail, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	if detail, ok := m.scanDetail[id]; ok {
		return detail, nil
	}
	// Return storage.NotFoundError so handler correctly returns 404
	return nil, &storage.NotFoundError{
		ResourceType: "scan",
		ResourceID:   id,
	}
}

func TestListScansHandler_Success(t *testing.T) {
	mockWs := &mockWorkspace{
		scans: []api.ScanMetadata{
			{ID: "scan-1", Status: "completed", StartTime: "2024-01-01T00:00:00Z", Targets: 10},
			{ID: "scan-2", Status: "running", StartTime: "2024-01-02T00:00:00Z", Targets: 5},
		},
	}

	deps := &api.Deps{
		Workspace: mockWs,
	}

	handler := ListScansHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var scans []api.ScanMetadata
	err := json.NewDecoder(w.Body).Decode(&scans)
	require.NoError(t, err)
	require.Len(t, scans, 2)
	require.Equal(t, "scan-1", scans[0].ID)
	require.Equal(t, "completed", scans[0].Status)
	require.Equal(t, 10, scans[0].Targets)
}

func TestListScansHandler_InvalidLimit(t *testing.T) {
	deps := &api.Deps{}
	handler := ListScansHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans?limit=1000", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListScansHandler_InvalidOffset removed - cursor-based pagination doesn't use offset

func TestListScansHandler_DefaultLimitApplied(t *testing.T) {
	// With storage backend; ensure pagination does not panic when list is empty
	mockBackend := &mockStorageBackend{scans: []*storage.ScanMetadata{}}
	deps := &api.Deps{Storage: mockBackend}
	handler := ListScansHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}

func TestGetScanHandler_EmptyID_ReturnsBadRequest(t *testing.T) {
	deps := &api.Deps{}
	handler := GetScanHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListScansHandler_EmptyList(t *testing.T) {
	mockWs := &mockWorkspace{
		scans: []api.ScanMetadata{},
	}

	deps := &api.Deps{
		Workspace: mockWs,
	}

	handler := ListScansHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var scans []api.ScanMetadata
	err := json.NewDecoder(w.Body).Decode(&scans)
	require.NoError(t, err)
	require.Len(t, scans, 0)
}

func TestListScansHandler_WorkspaceError(t *testing.T) {
	mockWs := &mockWorkspace{
		listError: fmt.Errorf("workspace error"),
	}

	deps := &api.Deps{
		Workspace: mockWs,
	}

	handler := ListScansHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Contains(t, w.Body.String(), "Internal Server Error")
}

func TestGetScanHandler_Success(t *testing.T) {
	mockWs := &mockWorkspace{
		scanDetail: map[string]*api.ScanDetail{
			"scan-1": {
				ID:        "scan-1",
				Status:    "completed",
				StartTime: "2024-01-01T00:00:00Z",
				EndTime:   "2024-01-01T00:05:00Z",
				Results: map[string]any{
					"hosts_found": 10,
				},
			},
		},
	}

	deps := &api.Deps{
		Workspace: mockWs,
	}

	handler := GetScanHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/scan-1", nil)
	req.SetPathValue("id", "scan-1")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var scan api.ScanDetail
	err := json.NewDecoder(w.Body).Decode(&scan)
	require.NoError(t, err)
	require.Equal(t, "scan-1", scan.ID)
	require.Equal(t, "completed", scan.Status)
	require.Equal(t, "2024-01-01T00:05:00Z", scan.EndTime)
	require.Equal(t, float64(10), scan.Results["hosts_found"])
}

func TestGetScanHandler_NotFound(t *testing.T) {
	mockWs := &mockWorkspace{
		scanDetail: map[string]*api.ScanDetail{},
	}

	deps := &api.Deps{
		Workspace: mockWs,
	}

	handler := GetScanHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "Not Found")
}

func TestGetScanHandler_WorkspaceError(t *testing.T) {
	mockWs := &mockWorkspace{
		getError: fmt.Errorf("workspace error"),
	}

	deps := &api.Deps{
		Workspace: mockWs,
	}

	handler := GetScanHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/scan-1", nil)
	req.SetPathValue("id", "scan-1")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Generic workspace errors should return 500, not 404
	// Only storage.NotFoundError returns 404
	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetScanHandler_DifferentIDs(t *testing.T) {
	mockWs := &mockWorkspace{
		scanDetail: map[string]*api.ScanDetail{
			"scan-1": {ID: "scan-1", Status: "completed"},
			"scan-2": {ID: "scan-2", Status: "running"},
		},
	}

	deps := &api.Deps{
		Workspace: mockWs,
	}

	handler := GetScanHandler(deps)

	// Test scan-1
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/scans/scan-1", nil)
	req1.SetPathValue("id", "scan-1")
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	require.Equal(t, http.StatusOK, w1.Code)
	var scan1 api.ScanDetail
	err := json.NewDecoder(w1.Body).Decode(&scan1)
	require.NoError(t, err)
	require.Equal(t, "scan-1", scan1.ID)

	// Test scan-2
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/scans/scan-2", nil)
	req2.SetPathValue("id", "scan-2")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	require.Equal(t, http.StatusOK, w2.Code)
	var scan2 api.ScanDetail
	err = json.NewDecoder(w2.Body).Decode(&scan2)
	require.NoError(t, err)
	require.Equal(t, "scan-2", scan2.ID)
}

// Mock storage backend for testing storage path
type mockStorageBackend struct {
	scans     []*storage.ScanMetadata
	scanByID  map[string]*storage.ScanMetadata
	listError error
	getError  error
}

type mockScanStore struct {
	backend *mockStorageBackend
}

func (m *mockStorageBackend) Scans() storage.ScanStore {
	return &mockScanStore{backend: m}
}

func (m *mockScanStore) List(ctx context.Context, orgID string, filter storage.ScanFilter) ([]*storage.ScanMetadata, error) {
	if m.backend.listError != nil {
		return nil, m.backend.listError
	}
	scans := m.backend.scans
	if filter.Status != "" {
		filtered := make([]*storage.ScanMetadata, 0, len(scans))
		for _, s := range scans {
			if s.Status == filter.Status {
				filtered = append(filtered, s)
			}
		}
		scans = filtered
	}
	return scans, nil
}

func (m *mockScanStore) Get(ctx context.Context, orgID, scanID string) (*storage.ScanMetadata, error) {
	if m.backend.getError != nil {
		return nil, m.backend.getError
	}
	if scan, ok := m.backend.scanByID[scanID]; ok {
		return scan, nil
	}
	return nil, &storage.NotFoundError{
		ResourceType: "scan",
		ResourceID:   scanID,
	}
}

func (m *mockScanStore) Create(ctx context.Context, orgID string, metadata *storage.ScanMetadata) error {
	return nil
}

func (m *mockScanStore) Update(ctx context.Context, orgID, scanID string, updates storage.ScanUpdates) error {
	return nil
}

func (m *mockScanStore) Delete(ctx context.Context, orgID, scanID string) error {
	return nil
}

func (m *mockScanStore) ReadData(ctx context.Context, orgID, scanID string, dataType storage.DataType) (io.ReadCloser, error) {
	return nil, storage.ErrNotSupported
}

func (m *mockScanStore) WriteData(ctx context.Context, orgID, scanID string, dataType storage.DataType, data io.Reader) error {
	return nil
}

func (m *mockScanStore) AppendData(ctx context.Context, orgID, scanID string, dataType storage.DataType, data []byte) error {
	return nil
}

func (m *mockScanStore) GetAnalytics(ctx context.Context, orgID string, period storage.TimePeriod) (*storage.Analytics, error) {
	return nil, storage.ErrNotSupported
}

func (m *mockScanStore) ListPaginated(ctx context.Context, orgID string, filter storage.ScanFilter, cursor string, limit int) ([]*storage.ScanMetadata, string, int, error) {
	if m.backend.listError != nil {
		return nil, "", 0, m.backend.listError
	}

	// Validate cursor (mimics real storage behavior)
	if cursor != "" {
		_, err := storage.DecodeCursor(cursor)
		if err != nil {
			return nil, "", 0, storage.NewInvalidInputError("cursor", err.Error())
		}
	}

	scans := m.backend.scans
	if filter.Status != "" {
		filtered := make([]*storage.ScanMetadata, 0, len(scans))
		for _, s := range scans {
			if s.Status == filter.Status {
				filtered = append(filtered, s)
			}
		}
		scans = filtered
	}
	// Simple mock: return all matching scans, no actual pagination
	return scans, "", len(scans), nil
}

func (m *mockStorageBackend) Initialize(ctx context.Context) error {
	return nil
}

func (m *mockStorageBackend) Close() error {
	return nil
}

func (m *mockStorageBackend) GarbageCollect(ctx context.Context, opts storage.GCOptions) (*storage.GCResult, error) {
	return &storage.GCResult{}, nil
}

func TestListScansHandler_WithStorage(t *testing.T) {
	now := time.Now()
	mockStorage := &mockStorageBackend{
		scans: []*storage.ScanMetadata{
			{
				ID:        "storage-scan-1",
				Status:    "completed",
				StartedAt: now.Add(-1 * time.Hour),
			},
			{
				ID:        "storage-scan-2",
				Status:    "running",
				StartedAt: now,
			},
		},
	}

	deps := &api.Deps{
		Storage: mockStorage,
	}

	handler := ListScansHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response struct {
		Scans      []api.ScanMetadata `json:"scans"`
		NextCursor string             `json:"next_cursor"`
		Total      int                `json:"total"`
	}
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	require.Len(t, response.Scans, 2)
	require.Equal(t, "storage-scan-1", response.Scans[0].ID)
	require.Equal(t, "completed", response.Scans[0].Status)
	require.Equal(t, "", response.NextCursor) // No cursor for small result set
	require.Equal(t, 2, response.Total)
}

func TestListScansHandler_StatusFilter(t *testing.T) {
	now := time.Now()
	mockStorage := &mockStorageBackend{
		scans: []*storage.ScanMetadata{
			{ID: "s1", Status: "running", StartedAt: now},
			{ID: "s2", Status: "completed", StartedAt: now},
			{ID: "s3", Status: "running", StartedAt: now},
		},
	}
	deps := &api.Deps{Storage: mockStorage}
	handler := ListScansHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans?status=running", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var response struct {
		Scans      []api.ScanMetadata `json:"scans"`
		NextCursor string             `json:"next_cursor"`
		Total      int                `json:"total"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
	require.Len(t, response.Scans, 2)
	require.Equal(t, "running", response.Scans[0].Status)
	require.Equal(t, 2, response.Total)
}

func TestListScansHandler_InvalidStatus(t *testing.T) {
	deps := &api.Deps{}
	handler := ListScansHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans?status=bogus", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListScansHandler_NonIntegerLimit(t *testing.T) {
	deps := &api.Deps{}
	handler := ListScansHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans?limit=abc", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)

	// Cursor is opaque string, no integer validation needed
}

func TestListScansHandler_OffsetBoundary(t *testing.T) {
	now := time.Now()
	mockStorage := &mockStorageBackend{
		scans: []*storage.ScanMetadata{
			{ID: "s1", Status: "completed", StartedAt: now},
			{ID: "s2", Status: "completed", StartedAt: now},
		},
	}
	deps := &api.Deps{Storage: mockStorage}
	handler := ListScansHandler(deps)

	// First page with cursor pagination
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans?limit=50", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	var response struct {
		Scans      []api.ScanMetadata `json:"scans"`
		NextCursor string             `json:"next_cursor"`
		Total      int                `json:"total"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
	require.Len(t, response.Scans, 2)
	require.Equal(t, 2, response.Total)

	// Invalid cursor returns 400 from storage layer
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/scans?cursor=invalid&limit=50", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	require.Equal(t, http.StatusBadRequest, w2.Code) // Invalid cursor validation
}

func TestListScansHandler_StorageError(t *testing.T) {
	mockStorage := &mockStorageBackend{
		listError: fmt.Errorf("storage backend error"),
	}

	deps := &api.Deps{
		Storage: mockStorage,
	}

	handler := ListScansHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Contains(t, w.Body.String(), "Internal Server Error")
}

func TestGetScanHandler_WithStorage(t *testing.T) {
	now := time.Now()
	completedAt := now.Add(5 * time.Minute)

	mockStorage := &mockStorageBackend{
		scanByID: map[string]*storage.ScanMetadata{
			"storage-scan-1": {
				ID:              "storage-scan-1",
				Status:          "completed",
				StartedAt:       now,
				CompletedAt:     completedAt,
				HostCount:       15,
				ServiceCount:    42,
				Duration:        300,
				StorageLocation: "/path/to/scan",
				VulnCount: storage.VulnCounts{
					Critical: 2,
					High:     5,
					Medium:   8,
					Low:      12,
					Info:     20,
				},
			},
		},
	}

	deps := &api.Deps{
		Storage: mockStorage,
	}

	handler := GetScanHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/storage-scan-1", nil)
	req.SetPathValue("id", "storage-scan-1")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var scan api.ScanDetail
	err := json.NewDecoder(w.Body).Decode(&scan)
	require.NoError(t, err)
	require.Equal(t, "storage-scan-1", scan.ID)
	require.Equal(t, "completed", scan.Status)
	require.NotEmpty(t, scan.EndTime)
	require.Equal(t, float64(15), scan.Results["hosts_found"])
	require.Equal(t, float64(42), scan.Results["services_found"])
	require.Equal(t, float64(47), scan.Results["vulnerabilities"]) // 2+5+8+12+20
	require.Equal(t, float64(2), scan.Results["vuln_critical"])
	require.Equal(t, float64(5), scan.Results["vuln_high"])
	require.Equal(t, float64(300), scan.Results["duration_seconds"])
}

func TestGetScanHandler_StorageNotFound(t *testing.T) {
	mockStorage := &mockStorageBackend{
		scanByID: map[string]*storage.ScanMetadata{},
	}

	deps := &api.Deps{
		Storage: mockStorage,
	}

	handler := GetScanHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "Not Found")
}

func TestGetScanHandler_StorageError(t *testing.T) {
	mockStorage := &mockStorageBackend{
		getError: fmt.Errorf("storage backend error"),
	}

	deps := &api.Deps{
		Storage: mockStorage,
	}

	handler := GetScanHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/scan-1", nil)
	req.SetPathValue("id", "scan-1")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetScanHandler_WithErrorMessage(t *testing.T) {
	now := time.Now()

	mockStorage := &mockStorageBackend{
		scanByID: map[string]*storage.ScanMetadata{
			"failed-scan": {
				ID:           "failed-scan",
				Status:       "failed",
				StartedAt:    now,
				CompletedAt:  now.Add(1 * time.Minute),
				ErrorMessage: "Connection timeout",
			},
		},
	}

	deps := &api.Deps{
		Storage: mockStorage,
	}

	handler := GetScanHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/failed-scan", nil)
	req.SetPathValue("id", "failed-scan")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var scan api.ScanDetail
	err := json.NewDecoder(w.Body).Decode(&scan)
	require.NoError(t, err)
	require.Equal(t, "failed", scan.Status)
	require.Equal(t, "Connection timeout", scan.Results["error"])
}

func TestListScansHandler_NoBackend(t *testing.T) {
	deps := &api.Deps{
		Storage:   nil,
		Workspace: nil,
	}

	handler := ListScansHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Contains(t, w.Body.String(), "no storage backend configured")
}

func TestGetScanHandler_NoBackend(t *testing.T) {
	deps := &api.Deps{
		Storage:   nil,
		Workspace: nil,
	}

	handler := GetScanHandler(deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/scan-1", nil)
	req.SetPathValue("id", "scan-1")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Contains(t, w.Body.String(), "no storage backend configured")
}
