package v1

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-playground/validator/v10"

	"github.com/cyprob/cyprob/pkg/plugin"
)

var validate = validator.New()

// ListScansQuery represents supported query params for GET /api/v1/scans
type ListScansQuery struct {
	Status string
	Limit  int
	Cursor string // Opaque cursor for pagination (empty for first page)
}

// ParseListScansQuery parses and validates query params.
// Returns validated query with sane defaults (Limit=50) when omitted.
func ParseListScansQuery(r *http.Request) (*ListScansQuery, error) {
	q := r.URL.Query()
	var res ListScansQuery

	if v := strings.TrimSpace(q.Get("status")); v != "" {
		// Validate only if provided
		if err := validate.Var(v, "oneof=pending running completed failed"); err != nil {
			return nil, &ValidationError{Field: "status", Reason: "must be one of: pending,running,completed,failed"}
		}
		res.Status = v
	}

	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, &ValidationError{Field: "limit", Reason: "must be an integer"}
		}
		if err := validate.Var(n, "min=1,max=100"); err != nil {
			return nil, &ValidationError{Field: "limit", Reason: "must be between 1 and 100"}
		}
		res.Limit = n
	}

	// Cursor parameter (opaque string, no validation needed beyond trimming)
	if v := strings.TrimSpace(q.Get("cursor")); v != "" {
		res.Cursor = v
	}

	// Defaults
	if res.Limit == 0 {
		res.Limit = 50
	}

	return &res, nil
}

// ValidationError is a lightweight error used for 400 responses.
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	if e == nil {
		return ""
	}
	if e.Field == "" {
		return "validation failed"
	}
	if e.Reason == "" {
		return e.Field + ": invalid"
	}
	return e.Field + ": " + e.Reason
}

// ---- Plugin API validation helpers ----

var pluginIDRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,62}$`)

// ValidatePluginID validates a plugin ID slug.
func ValidatePluginID(id string) error {
	if strings.TrimSpace(id) == "" {
		return &ValidationError{Field: "id", Reason: "required"}
	}
	if !pluginIDRe.MatchString(id) {
		return &ValidationError{Field: "id", Reason: "invalid format (lowercase alnum, hyphen/underscore, 3-63)"}
	}
	return nil
}

// ValidateSource validates a plugin source against whitelist.
func ValidateSource(src string) error {
	if src == "" {
		return nil
	}
	if !plugin.IsValidSource(src) {
		return &ValidationError{Field: "source", Reason: "invalid"}
	}
	return nil
}

// ValidateCategory validates plugin category against whitelist.
func ValidateCategory(cat string) error {
	if cat == "" {
		return nil
	}
	if !plugin.IsValidCategory(cat) {
		return &ValidationError{Field: "category", Reason: "invalid"}
	}
	return nil
}

// ParseInstallPlugin validates install request fields.
func ParseInstallPlugin(req InstallPluginRequest) error {
	if strings.TrimSpace(req.Target) == "" {
		return &ValidationError{Field: "target", Reason: "required"}
	}
	// If not a known category, validate as plugin ID
	if !plugin.IsValidCategory(req.Target) {
		if err := ValidatePluginID(req.Target); err != nil {
			return err
		}
	}
	if err := ValidateSource(req.Source); err != nil {
		return err
	}
	return nil
}

// ParseUpdatePlugins validates update request fields.
func ParseUpdatePlugins(req UpdatePluginsRequest) error {
	if err := ValidateCategory(req.Category); err != nil {
		return err
	}
	if err := ValidateSource(req.Source); err != nil {
		return err
	}
	return nil
}

// ParseListPlugins validates optional category filter in query (if present).
func ParseListPlugins(r *http.Request) error {
	cat := strings.TrimSpace(r.URL.Query().Get("category"))
	if cat == "" {
		return nil
	}
	return ValidateCategory(cat)
}
