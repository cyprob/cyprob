// AppManager manages the application lifecycle, providing access to the application's context and version information.
// It is constructed by the Factory and holds a cancellable context for controlling application execution.
// pkg/engine/manager.go
package engine

import (
	"context"

	"github.com/cyprob/cyprob/pkg/config"
	"github.com/cyprob/cyprob/pkg/event"
	"github.com/cyprob/cyprob/pkg/hook"
)

// Manager exposes core application services and lifecycle control.
type Manager interface {
	Context() context.Context
	Config() *config.Manager
	Events() *event.Manager
	Hooks() *hook.Manager
	Shutdown()
}

// AppManagerKeyType is an unexported type for the context key.
// This prevents collisions with context keys defined in other packages.
type appManagerKeyType struct{}

// AppManagerKey is the key used to store and retrieve the AppManager
// from a context.Context. It is exported for use in other packages.
var AppManagerKey = appManagerKeyType{}

// AppManager represents the application manager constructed by Factory.
type AppManager struct {
	// ctx is the context for managing request-scoped values, cancellation signals, and deadlines across API boundaries.
	ctx context.Context
	// cancel is the function to cancel the associated context, used to signal termination or cleanup.
	cancel context.CancelFunc

	ConfigManager *config.Manager // Configuration manager for loading and managing application settings.

	EventManager *event.Manager // Event manager for handling events and notifications within the application.

	HookManager *hook.Manager // Hook manager for managing lifecycle hooks and custom event triggers.
}

// Context returns the context associated with the AppManager instance.
// This context can be used for managing deadlines, cancellation signals,
// and other request-scoped values across API boundaries and between processes.
func (a *AppManager) Context() context.Context {
	return a.ctx
}

// Config returns the shared configuration manager.
func (a *AppManager) Config() *config.Manager {
	return a.ConfigManager
}

// Events returns the event manager.
func (a *AppManager) Events() *event.Manager {
	return a.EventManager
}

// Hooks returns the hook manager.
func (a *AppManager) Hooks() *hook.Manager {
	return a.HookManager
}

// Shutdown gracefully shuts down the AppManager by invoking its cancellation function.
// This will signal any running operations to terminate and release associated resources.
func (a *AppManager) Shutdown() {
	a.cancel()
}
