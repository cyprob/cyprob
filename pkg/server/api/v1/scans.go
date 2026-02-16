package v1

import (
	"context"
	"errors"
	"net/http"

	"github.com/cyprob/cyprob/pkg/server/api"
	"github.com/cyprob/cyprob/pkg/storage"
)

// DTO Evolution Policy
// The request/response payloads handled in this file are part of the public API
// contract. To evolve them safely without breaking existing clients:
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

// ListScansHandler handles GET /api/v1/scans
//
// Returns paginated scan metadata with cursor-based pagination for scalability.
// This is a lightweight endpoint for listing scans without full details.
//
// Query parameters:
//   - status: Filter by status (pending, running, completed, failed)
//   - limit: Number of results per page (1-100, default 50)
//   - cursor: Pagination cursor (empty for first page)
//
// Response format:
//
//	{
//	  "scans": [
//	    {"id": "scan-1", "status": "completed", "start_time": "2024-01-01T00:00:00Z", "targets": 10},
//	    {"id": "scan-2", "status": "running", "start_time": "2024-01-02T00:00:00Z", "targets": 5}
//	  ],
//	  "next_cursor": "eyJpZCI6InNjYW4tMiIsInRzIjoxNzA0MTU4NDAwMDAwMDAwMDAwfQ==",
//	  "total": 100
//	}
func ListScansHandler(deps *api.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse and validate query params (status, limit, cursor)
		query, qerr := ParseListScansQuery(r)
		if qerr != nil {
			api.WriteJSONError(w, http.StatusBadRequest, "Bad Request", "INVALID_QUERY", qerr.Error())
			return
		}

		// Build storage filter (push down status when possible)
		storageFilter := storage.ScanFilter{}
		if query.Status != "" {
			storageFilter.Status = query.Status
		}

		// Use cursor-based pagination from storage layer
		if deps.Storage != nil {
			scans, nextCursor, total, err := listScansFromStoragePaginated(
				r.Context(), deps.Storage, storageFilter, query.Cursor, query.Limit,
			)
			if err != nil {
				api.WriteError(w, r, err)
				return
			}

			// Return paginated response with cursor and total
			response := map[string]any{
				"scans":       scans,
				"next_cursor": nextCursor,
				"total":       total,
			}
			api.WriteJSON(w, http.StatusOK, response)
			return
		}

		// Fall back to workspace (legacy, offset-based pagination)
		if deps.Workspace != nil {
			scans, err := deps.Workspace.ListScans()
			if err != nil {
				api.WriteError(w, r, err)
				return
			}

			// Legacy response format (array only, no pagination metadata)
			api.WriteJSON(w, http.StatusOK, scans)
			return
		}

		// No storage backend configured
		err := errors.New("no storage backend configured")
		api.WriteError(w, r, err)
	}
}

// GetScanHandler handles GET /api/v1/scans/{id}
//
// Returns full scan details including results for a specific scan ID.
//
// Path parameter:
//   - id: Scan identifier
//
// Response format:
//
//	{
//	  "id": "scan-1",
//	  "status": "completed",
//	  "start_time": "2024-01-01T00:00:00Z",
//	  "end_time": "2024-01-01T00:05:00Z",
//	  "results": {
//	    "hosts_found": 10,
//	    "ports_open": 25,
//	    "vulnerabilities": []
//	  }
//	}
//
// Returns 404 if scan not found.
func GetScanHandler(deps *api.Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			api.WriteJSONError(w, http.StatusBadRequest, "Bad Request", "SCAN_ID_REQUIRED", "scan id is required")
			return
		}

		var scan *api.ScanDetail
		var err error

		// Try new storage backend first, fall back to workspace
		if deps.Storage != nil {
			scan, err = getScanFromStorage(r.Context(), deps.Storage, id)
		} else if deps.Workspace != nil {
			scan, err = deps.Workspace.GetScan(id)
		} else {
			err = errors.New("no storage backend configured")
			api.WriteError(w, r, err)
			return
		}

		if err != nil {
			api.WriteError(w, r, err)
			return
		}

		api.WriteJSON(w, http.StatusOK, scan)
	}
}

// listScansFromStoragePaginated uses cursor-based pagination from storage layer
func listScansFromStoragePaginated(ctx context.Context, backend storage.Backend, filter storage.ScanFilter, cursor string, limit int) ([]api.ScanMetadata, string, int, error) {
	// Get paginated scans from storage (orgID="default" for OSS)
	storageScans, nextCursor, total, err := backend.Scans().ListPaginated(ctx, "default", filter, cursor, limit)
	if err != nil {
		return nil, "", 0, err
	}

	// Convert to API format
	apiScans := make([]api.ScanMetadata, 0, len(storageScans))
	for _, s := range storageScans {
		apiScans = append(apiScans, api.ScanMetadata{
			ID:        s.ID,
			StartTime: s.StartedAt.Format("2006-01-02T15:04:05Z"),
			Status:    s.Status,
			Targets:   1, // TODO: Calculate from target string (e.g., CIDR range)
		})
	}

	return apiScans, nextCursor, total, nil
}

// getScanFromStorage retrieves scan details from storage and converts to API format
func getScanFromStorage(ctx context.Context, backend storage.Backend, scanID string) (*api.ScanDetail, error) {
	// Get scan metadata
	metadata, err := backend.Scans().Get(ctx, "default", scanID)
	if err != nil {
		return nil, err
	}

	// Build results map
	results := map[string]any{
		"hosts_found":      metadata.HostCount,
		"services_found":   metadata.ServiceCount,
		"vulnerabilities":  metadata.VulnCount.Total(),
		"vuln_critical":    metadata.VulnCount.Critical,
		"vuln_high":        metadata.VulnCount.High,
		"vuln_medium":      metadata.VulnCount.Medium,
		"vuln_low":         metadata.VulnCount.Low,
		"vuln_info":        metadata.VulnCount.Info,
		"duration_seconds": metadata.Duration,
		"storage_location": metadata.StorageLocation,
	}

	// Add error message if scan failed
	if metadata.ErrorMessage != "" {
		results["error"] = metadata.ErrorMessage
	}

	// Convert to API format
	detail := &api.ScanDetail{
		ID:        metadata.ID,
		StartTime: metadata.StartedAt.Format("2006-01-02T15:04:05Z"),
		Status:    metadata.Status,
		Results:   results,
	}

	// Add end time if scan completed
	if !metadata.CompletedAt.IsZero() {
		detail.EndTime = metadata.CompletedAt.Format("2006-01-02T15:04:05Z")
	}

	return detail, nil
}
