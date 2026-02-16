// Package deps provides dependency injection for the Vulntor server.
//
// The Deps struct holds all dependencies required by server components
// (HTTP handlers, API endpoints, job managers, etc.) and enables easy
// mocking in tests.
package deps

import (
	"sync/atomic"

	"github.com/rs/zerolog"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/storage"
)

// Deps holds all dependencies required by server components.
// This struct is passed to HTTP handlers, API endpoints, job managers, etc.
// It enables dependency injection and makes testing easier by allowing
// mock implementations to be substituted.
type Deps struct {
	// Storage is the storage backend for persisting scan data, user data, etc.
	// This abstracts the underlying storage implementation (LocalBackend for OSS,
	// PostgreSQL/S3 for Enterprise).
	Storage storage.Backend

	// Engine is the application manager that provides access to config, events,
	// hooks, and application lifecycle management.
	Engine engine.Manager

	// Logger is the structured logger used throughout the server.
	// All server components should log through this logger with appropriate
	// component fields.
	Logger *zerolog.Logger

	// Ready is an atomic boolean flag indicating whether the server is ready
	// to serve traffic. It's set to true after HTTP server and background
	// workers have started successfully.
	//
	// The /readyz endpoint checks this flag to determine readiness.
	Ready *atomic.Bool
}

// New creates a new Deps instance with the provided dependencies.
// All parameters are required and must not be nil.
func New(storage storage.Backend, engine engine.Manager, logger *zerolog.Logger) *Deps {
	ready := &atomic.Bool{}
	ready.Store(false) // Start as not ready

	return &Deps{
		Storage: storage,
		Engine:  engine,
		Logger:  logger,
		Ready:   ready,
	}
}

// SetReady marks the server as ready to serve traffic.
// This should be called after all components (HTTP, workers) have started successfully.
func (d *Deps) SetReady() {
	d.Ready.Store(true)
}

// SetNotReady marks the server as not ready (e.g., during shutdown).
func (d *Deps) SetNotReady() {
	d.Ready.Store(false)
}

// IsReady returns true if the server is ready to serve traffic.
func (d *Deps) IsReady() bool {
	return d.Ready.Load()
}
