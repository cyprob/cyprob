package storage

import (
	"context"
	"fmt"
)

// Factory is a function that creates a Backend instance.
//
// The factory pattern allows different editions (OSS vs Enterprise) to
// provide different implementations of the Backend interface.
//
// OSS Edition uses LocalBackend (file-based storage).
// Enterprise Edition uses PostgresBackend (database + S3 storage).
type Factory func(ctx context.Context, cfg *Config) (Backend, error)

// DefaultFactory is the backend factory used by NewBackend().
//
// This variable can be overridden by Enterprise edition to inject a different
// backend implementation.
//
// OSS Edition: Points to NewLocalBackend (defined in local.go)
// Enterprise Edition: Overridden to point to NewPostgresBackend
//
// Example (Enterprise):
//
//	import (
//	    "github.com/cyprob/cyprob/pkg/storage"
//	    enterpriseStorage "github.com/cyprob/cyprob-enterprise/pkg/storage"
//	)
//
//	func init() {
//	    // Override OSS factory with Enterprise implementation
//	    storage.DefaultFactory = enterpriseStorage.NewPostgresBackend
//	}
var DefaultFactory Factory

// NewBackend creates a storage backend using the current DefaultFactory.
//
// This is the main entry point for creating storage backends in the application.
// The actual backend implementation is determined by which factory is installed
// in DefaultFactory.
//
// Configuration is validated before the backend is created.
//
// Example (OSS):
//
//	cfg := &storage.Config{
//	    WorkspaceRoot: "~/.local/share/vulntor",
//	}
//	backend, err := storage.NewBackend(ctx, cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer backend.Close()
//
// Example (Enterprise):
//
//	cfg := &storage.Config{
//	    DatabaseURL: "postgresql://vulntor:password@localhost:5432/vulntor",
//	    S3Bucket:    "vulntor-scans",
//	    S3Region:    "us-west-2",
//	}
//	backend, err := storage.NewBackend(ctx, cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer backend.Close()
func NewBackend(ctx context.Context, cfg *Config) (Backend, error) {
	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid storage configuration: %w", err)
	}

	// Use the current factory
	if DefaultFactory == nil {
		return nil, fmt.Errorf("no storage backend factory registered")
	}

	// Create backend
	backend, err := DefaultFactory(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage backend: %w", err)
	}

	return backend, nil
}

func setupDefaultFactory() {
	// OSS edition: Use LocalBackend by default
	// This is set here as a placeholder; local.go will override it
	// when it's included in the build.
	DefaultFactory = func(ctx context.Context, cfg *Config) (Backend, error) {
		return nil, fmt.Errorf("no backend implementation available (import pkg/storage/local)")
	}
}

// init sets the default factory.
// This will be called when the package is imported.
func init() {
	setupDefaultFactory()
}
