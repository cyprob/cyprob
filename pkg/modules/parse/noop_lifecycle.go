// pkg/modules/parse/noop_lifecycle.go
package parse

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/cyprob/cyprob/pkg/engine"
)

// noopLifecycleModule is a minimal example module that implements ModuleLifecycle.
// It does not produce or consume any data; it only logs lifecycle transitions.
type noopLifecycleModule struct {
	instanceID string
}

func (m *noopLifecycleModule) Metadata() engine.ModuleMetadata {
	return engine.ModuleMetadata{
		ID:          "noop-lifecycle",
		Name:        "noop-lifecycle",
		Description: "Example module demonstrating LifecycleInit/Start/Stop",
		Version:     "0.1.0",
		Type:        engine.ParseModuleType,
	}
}

func (m *noopLifecycleModule) Init(instanceID string, _ map[string]any) error {
	m.instanceID = instanceID
	return nil
}

func (m *noopLifecycleModule) Execute(ctx context.Context, _ map[string]any, _ chan<- engine.ModuleOutput) error {
	// No-op
	_ = ctx
	return nil
}

// Implement ModuleLifecycle
func (m *noopLifecycleModule) LifecycleInit(ctx context.Context) error {
	log.Info().Str("component", "noop-lifecycle").Str("instance", m.instanceID).Msg("LifecycleInit")
	_ = ctx
	return nil
}

func (m *noopLifecycleModule) LifecycleStart(ctx context.Context) error {
	log.Info().Str("component", "noop-lifecycle").Str("instance", m.instanceID).Msg("LifecycleStart")
	_ = ctx
	return nil
}

func (m *noopLifecycleModule) LifecycleStop(ctx context.Context) error {
	log.Info().Str("component", "noop-lifecycle").Str("instance", m.instanceID).Msg("LifecycleStop")
	_ = ctx
	return nil
}

// Register the module factory at init time.
func init() { //nolint:gochecknoinits // simple registration
	engine.RegisterModuleFactory("noop-lifecycle", func() engine.Module { return &noopLifecycleModule{} })
}
