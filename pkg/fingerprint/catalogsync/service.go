package catalogsync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cyprob/cyprob/pkg/fingerprint"
)

// Source loads the raw probe catalog bytes (YAML/JSON) from a backing store.
type Source interface {
	Load(ctx context.Context) ([]byte, error)
}

// Store persists the catalog bytes to a destination (e.g., workspace cache).
type Store interface {
	Save(ctx context.Context, data []byte) error
}

// Service orchestrates catalog synchronization.
type Service struct {
	Source   Source
	Store    Store
	CacheDir string
}

// Sync fetches the catalog from Source, validates it, writes it using Store,
// and refreshes the in-memory catalog via WarmProbeCatalogWithExternal.
func (s Service) Sync(ctx context.Context) (*fingerprint.ProbeCatalog, error) {
	if s.Source == nil {
		return nil, errors.New("catalog source is not configured")
	}
	if s.Store == nil {
		return nil, errors.New("catalog store is not configured")
	}
	if s.CacheDir == "" {
		return nil, errors.New("cache directory is not configured")
	}

	data, err := s.Source.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}

	catalog, err := fingerprint.ParseProbeCatalog(data)
	if err != nil {
		return nil, fmt.Errorf("validate catalog: %w", err)
	}

	if err := s.Store.Save(ctx, data); err != nil {
		return nil, fmt.Errorf("save catalog: %w", err)
	}

	if err := fingerprint.WarmProbeCatalogWithExternal(s.CacheDir); err != nil {
		return nil, fmt.Errorf("reload catalog: %w", err)
	}

	return catalog, nil
}

// FileSource loads the catalog from a local file path.
type FileSource struct {
	Path string
}

func (f FileSource) Load(_ context.Context) ([]byte, error) {
	if f.Path == "" {
		return nil, errors.New("file path is empty")
	}
	return os.ReadFile(f.Path)
}

// HTTPSource downloads the catalog from a URL using the provided http.Client (or default).
type HTTPSource struct {
	URL    string
	Client *http.Client
}

func (h HTTPSource) Load(ctx context.Context) ([]byte, error) {
	if h.URL == "" {
		return nil, errors.New("url is empty")
	}
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch catalog: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("unexpected status from catalog source: %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read catalog body: %w", err)
	}
	return data, nil
}

// FileStore writes the catalog bytes to a path on disk.
type FileStore struct {
	Path string
}

func (f FileStore) Save(_ context.Context, data []byte) error {
	if f.Path == "" {
		return errors.New("file store path is empty")
	}
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create catalog directory: %w", err)
	}
	return os.WriteFile(f.Path, data, 0o644)
}
