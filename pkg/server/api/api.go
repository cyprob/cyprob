package api

import (
	"sync/atomic"

	"github.com/cyprob/cyprob/pkg/storage"
)

// Deps holds dependencies for API handlers.
// This pattern enables dependency injection and easier testing.
type Deps struct {
	// Storage backend for scan data (NEW - preferred)
	Storage storage.Backend

	// Workspace provides access to scan data (DEPRECATED - use Storage instead)
	// Kept for backward compatibility during migration
	Workspace WorkspaceInterface

	// PluginService provides plugin management operations
	// Actual type: *plugin.Service (must implement v1.PluginService interface)
	// Type asserted in router to v1.PluginService
	PluginService any

	// Config holds API-level configuration (timeouts, limits, etc.)
	Config Config

	// Ready flag for readiness check
	Ready *atomic.Bool
}

// WorkspaceInterface is the subset of workspace methods needed by the API.
// Defined here to avoid circular dependencies and ease mocking.
type WorkspaceInterface interface {
	ListScans() ([]ScanMetadata, error)
	GetScan(id string) (*ScanDetail, error)
}

// ScanMetadata represents scan list item
type ScanMetadata struct {
	ID        string `json:"id"`
	StartTime string `json:"start_time"`
	Status    string `json:"status"`
	Targets   int    `json:"targets"`
}

// ScanDetail represents full scan details
type ScanDetail struct {
	ID        string         `json:"id"`
	StartTime string         `json:"start_time"`
	EndTime   string         `json:"end_time,omitempty"`
	Status    string         `json:"status"`
	Results   map[string]any `json:"results"`
}
