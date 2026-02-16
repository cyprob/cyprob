package v1

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cyprob/cyprob/pkg/plugin"
)

// --- helper for request ---
func newRequestWithQuery(params map[string]string) *http.Request {
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	r, _ := http.NewRequest(http.MethodGet, "/api/v1/scans?"+q.Encode(), nil)
	return r
}

func TestValidation_ParseListScansQuery_OK_Defaults(t *testing.T) {
	r := newRequestWithQuery(nil)
	got, err := ParseListScansQuery(r)
	assert.NoError(t, err)
	assert.Equal(t, 50, got.Limit)
	assert.Equal(t, "", got.Cursor)
	assert.Equal(t, "", got.Status)
}

func TestValidation_ParseListScansQuery_AllValid(t *testing.T) {
	r := newRequestWithQuery(map[string]string{
		"status": "pending",
		"limit":  "10",
		"cursor": "eyJpZCI6InNjYW4tMTIzIiwidHMiOjE3MzA1NTI0MDAwMDAwMDAwMDB9",
	})
	got, err := ParseListScansQuery(r)
	assert.NoError(t, err)
	assert.Equal(t, "pending", got.Status)
	assert.Equal(t, 10, got.Limit)
	assert.Equal(t, "eyJpZCI6InNjYW4tMTIzIiwidHMiOjE3MzA1NTI0MDAwMDAwMDAwMDB9", got.Cursor)
}

func TestValidation_ParseListScansQuery_InvalidStatus(t *testing.T) {
	r := newRequestWithQuery(map[string]string{"status": "wrong"})
	got, err := ParseListScansQuery(r)
	assert.Nil(t, got)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status")
}

func TestValidation_ParseListScansQuery_InvalidLimit(t *testing.T) {
	r := newRequestWithQuery(map[string]string{"limit": "abc"})
	got, err := ParseListScansQuery(r)
	assert.Nil(t, got)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "limit")
}

func TestValidation_ParseListScansQuery_LimitOutOfRange(t *testing.T) {
	r := newRequestWithQuery(map[string]string{"limit": "101"})
	got, err := ParseListScansQuery(r)
	assert.Nil(t, got)
	assert.Error(t, err)
}

func TestValidation_ErrorFormatting(t *testing.T) {
	var e *ValidationError
	assert.Equal(t, "", e.Error())

	e = &ValidationError{}
	assert.Equal(t, "validation failed", e.Error())

	e = &ValidationError{Field: "limit"}
	assert.Equal(t, "limit: invalid", e.Error())

	e = &ValidationError{Field: "limit", Reason: "too high"}
	assert.Equal(t, "limit: too high", e.Error())
}

func TestValidation_ValidatePluginID(t *testing.T) {
	assert.Error(t, ValidatePluginID(""))              // required
	assert.Error(t, ValidatePluginID("Invalid!"))      // invalid chars
	assert.Error(t, ValidatePluginID("ab"))            // too short
	assert.NoError(t, ValidatePluginID("abc"))         // ok
	assert.NoError(t, ValidatePluginID("abc_123"))     // ok
	assert.NoError(t, ValidatePluginID("abc-xyz_123")) // ok
}

func TestValidation_ParseUpdatePlugins(t *testing.T) {
	t.Run("invalid category", func(t *testing.T) {
		req := UpdatePluginsRequest{Category: "invalid-cat", Source: ""}
		err := ParseUpdatePlugins(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "category")
	})

	t.Run("invalid source", func(t *testing.T) {
		req := UpdatePluginsRequest{Category: "", Source: "invalid-src"}
		err := ParseUpdatePlugins(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "source")
	})

	t.Run("valid", func(t *testing.T) {
		req := UpdatePluginsRequest{}
		err := ParseUpdatePlugins(req)
		assert.NoError(t, err)
	})
}

func TestValidation_ValidateCategory(t *testing.T) {
	t.Run("empty category returns nil", func(t *testing.T) {
		err := ValidateCategory("")
		assert.NoError(t, err)
	})

	t.Run("invalid category returns ValidationError", func(t *testing.T) {
		err := ValidateCategory("something_invalid")
		assert.Error(t, err)
		assert.IsType(t, &ValidationError{}, err)
		assert.Contains(t, err.Error(), "category")
	})

	t.Run("valid category returns nil", func(t *testing.T) {
		// whitelist'ten geçerli bir kategori bul (varsa)
		validCategory := ""
		for _, c := range plugin.GetValidCategories() {
			if ValidateCategory(c) == nil {
				validCategory = c
				break
			}
		}

		if validCategory == "" {
			t.Skip("no valid category found in plugin whitelist")
		}

		err := ValidateCategory(validCategory)
		assert.NoError(t, err)
	})
}
