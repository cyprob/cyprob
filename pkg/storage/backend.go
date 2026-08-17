// Package storage provides a unified storage abstraction layer for Cyprob.
//
// The storage package defines the Backend interface that abstracts storage
// operations for both OSS (file-based) and Enterprise (PostgreSQL + S3) editions.
//
// OSS Edition uses LocalBackend (file-based storage + in-memory index).
// Enterprise Edition uses PostgresBackend (PostgreSQL metadata + S3 data).
//
// Both implementations use the same JSONL format for scan data, enabling
// easy migration from OSS to Enterprise.
package storage

import (
	"context"
	"io"
)

// Backend is the main storage abstraction interface.
//
// Backend provides access to domain-specific stores (ScanStore, etc.).
// This design keeps the interface focused and allows Enterprise edition
// to add additional stores (UserStore, OrgStore) without modifying OSS code.
//
// Thread-safety: All methods must be safe for concurrent use.
//
// Enterprise Extension:
// Enterprise edition can extend this interface with additional stores:
//   - Users() UserStore       // User management
//   - Organizations() OrgStore // Organization management
//   - Templates() TemplateStore // Scan templates
//   - Integrations() IntegrationStore // Third-party integrations
//
// These Enterprise stores are not defined in OSS to keep the OSS implementation simple.
type Backend interface {
	// Initialize prepares the backend for use.
	// This may involve creating directories (OSS) or running migrations (Enterprise).
	//
	// Returns error if initialization fails.
	Initialize(ctx context.Context) error

	// Close releases resources held by the backend.
	// This should be called when the backend is no longer needed.
	//
	// Returns error if cleanup fails.
	Close() error

	// Scans returns the scan storage interface.
	//
	// All scan-related operations (CRUD, data files, metadata) go through
	// the returned ScanStore interface.
	Scans() ScanStore

	// GarbageCollect performs garbage collection based on retention policies.
	//
	// This removes scans that violate configured retention policies:
	//   - Scans older than MaxAgeDays
	//   - Scans exceeding MaxScans count (oldest deleted first)
	//
	// Returns statistics about deleted scans and any errors encountered.
	GarbageCollect(ctx context.Context, opts GCOptions) (*GCResult, error)
}

// ScanStore manages scan metadata and data files.
//
// This interface handles all scan-related storage operations:
// - Metadata CRUD (List, Get, Create, Update, Delete)
// - Data file I/O (Read, Write, Append for JSONL files)
// - Analytics (Enterprise-only)
//
// Thread-safety: All methods must be safe for concurrent use.
type ScanStore interface {
	// Metadata operations (fast queries for web UI)

	// List returns a list of scans matching the given filter.
	//
	// The orgID parameter identifies the organization (OSS uses "default").
	// Results are filtered and sorted according to the filter parameters.
	//
	// Returns empty slice if no scans match the filter.
	// Returns error if the operation fails.
	//
	// Deprecated: Use ListPaginated for better scalability with large datasets.
	List(ctx context.Context, orgID string, filter ScanFilter) ([]*ScanMetadata, error)

	// ListPaginated returns a paginated list of scans matching the given filter.
	//
	// Parameters:
	//   - ctx: Request context
	//   - orgID: Organization identifier (OSS uses "default")
	//   - filter: Filtering criteria (status, etc.)
	//   - cursor: Pagination cursor (empty string for first page)
	//   - limit: Maximum number of results (1-100, default 50)
	//
	// Returns:
	//   - scans: List of scan metadata (up to limit items)
	//   - nextCursor: Cursor for next page (empty if no more results)
	//   - total: Total count of scans matching filter
	//   - error: Error if operation fails
	//
	// The cursor is an opaque string that should be passed as-is to get the next page.
	// Cursors are base64-encoded and URL-safe.
	ListPaginated(ctx context.Context, orgID string, filter ScanFilter, cursor string, limit int) (scans []*ScanMetadata, nextCursor string, total int, err error)

	// Get retrieves metadata for a specific scan.
	//
	// Returns ErrNotFound if the scan does not exist.
	// Returns error if the operation fails.
	Get(ctx context.Context, orgID, scanID string) (*ScanMetadata, error)

	// Create creates a new scan with the given metadata.
	//
	// The scan metadata should have at minimum: ID, Target, Status.
	// Returns ErrAlreadyExists if a scan with the same ID already exists.
	// Returns error if the operation fails.
	Create(ctx context.Context, orgID string, scan *ScanMetadata) error

	// Update updates metadata for an existing scan.
	//
	// Only non-zero fields in updates are applied (partial update).
	// Returns ErrNotFound if the scan does not exist.
	// Returns error if the operation fails.
	Update(ctx context.Context, orgID, scanID string, updates ScanUpdates) error

	// Delete removes a scan and all its associated data.
	//
	// This is a destructive operation and cannot be undone.
	// Returns ErrNotFound if the scan does not exist.
	// Returns error if the operation fails.
	Delete(ctx context.Context, orgID, scanID string) error

	// Data operations (JSONL files containing scan results)

	// ReadData opens a data file for reading.
	//
	// The dataType parameter specifies which file to read (hosts, services, etc.).
	// The caller is responsible for closing the returned ReadCloser.
	//
	// Returns ErrNotFound if the data file does not exist.
	// Returns error if the operation fails.
	ReadData(ctx context.Context, orgID, scanID string, dataType DataType) (io.ReadCloser, error)

	// WriteData writes data to a file, replacing any existing content.
	//
	// The dataType parameter specifies which file to write.
	// The data is expected to be in JSONL format (one JSON object per line).
	//
	// Returns error if the operation fails.
	WriteData(ctx context.Context, orgID, scanID string, dataType DataType, data io.Reader) error

	// AppendData appends data to an existing file.
	//
	// This is used for streaming scan results as they are discovered.
	// The data should be complete JSONL lines (including newlines).
	//
	// Thread-safe: Multiple goroutines can append to the same file concurrently.
	// Returns error if the operation fails.
	AppendData(ctx context.Context, orgID, scanID string, dataType DataType, data []byte) error

	// Analytics operations (Enterprise-only)

	// GetAnalytics returns analytics for an organization over a time period.
	//
	// OSS Edition: Returns ErrNotSupported.
	// Enterprise Edition: Returns aggregated statistics from the database.
	//
	// Returns error if the operation fails.
	GetAnalytics(ctx context.Context, orgID string, period TimePeriod) (*Analytics, error)
}

// AuditLogger manages audit log entries.
//
// This interface is separate from ScanStore because audit logging is
// a cross-cutting concern that applies to all operations (scans, users, orgs, etc.).
//
// OSS Edition: May implement simple file-based logging or return ErrNotSupported.
// Enterprise Edition: Writes to audit_logs table in database.
type AuditLogger interface {
	// Log records an audit event.
	//
	// Returns error if the operation fails.
	Log(ctx context.Context, entry AuditEntry) error
}

// TimePeriod represents a time range for analytics queries.
type TimePeriod struct {
	Start any // time.Time or duration string
	End   any // time.Time or duration string
}

// Analytics contains aggregated statistics for an organization.
type Analytics struct {
	TotalScans     int     `json:"total_scans"`
	CompletedScans int     `json:"completed_scans"`
	FailedScans    int     `json:"failed_scans"`
	TotalCritical  int     `json:"total_critical"`
	TotalHigh      int     `json:"total_high"`
	TotalMedium    int     `json:"total_medium"`
	TotalLow       int     `json:"total_low"`
	AvgDuration    float64 `json:"avg_duration_seconds"`
	LastScanTime   string  `json:"last_scan_time,omitempty"`
	TotalHosts     int     `json:"total_hosts"`
	TotalServices  int     `json:"total_services"`
	TotalVulns     int     `json:"total_vulnerabilities"`
}

// AuditEntry represents an audit log entry.
type AuditEntry struct {
	OrgID        string         `json:"org_id"`
	UserID       string         `json:"user_id"`
	Action       string         `json:"action"`        // create_scan, delete_scan, etc.
	ResourceType string         `json:"resource_type"` // scan, user, org, etc.
	ResourceID   string         `json:"resource_id"`
	IPAddress    string         `json:"ip_address,omitempty"`
	UserAgent    string         `json:"user_agent,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}
