package parse

import (
	"context"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
)

func TestNoopLifecycle_FullCoverage(t *testing.T) {
	factory := func() engine.Module { return &noopLifecycleModule{} }
	modIface := factory()
	mod, ok := modIface.(*noopLifecycleModule)
	if !ok {
		t.Fatalf("expected *noopLifecycleModule, got %T", modIface)
	}

	// ---- Metadata ----
	meta := mod.Metadata()
	if meta.ID != "noop-lifecycle" {
		t.Errorf("expected ID noop-lifecycle, got %s", meta.ID)
	}
	if meta.Name != "noop-lifecycle" {
		t.Errorf("expected Name noop-lifecycle, got %s", meta.Name)
	}
	if meta.Description == "" {
		t.Errorf("expected non-empty Description")
	}
	if meta.Version != "0.1.0" {
		t.Errorf("expected Version 0.1.0, got %s", meta.Version)
	}
	if meta.Type != engine.ParseModuleType {
		t.Errorf("unexpected Type: %v", meta.Type)
	}

	// ---- Init ----
	err := mod.Init("abc123", nil)
	if err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	if mod.instanceID != "abc123" {
		t.Errorf("expected instanceID abc123, got %s", mod.instanceID)
	}

	// ---- Execute ----
	ctx := context.Background()
	if err := mod.Execute(ctx, nil, nil); err != nil {
		t.Errorf("Execute returned error: %v", err)
	}

	// ---- Lifecycle ----
	if err := mod.LifecycleInit(ctx); err != nil {
		t.Errorf("LifecycleInit returned error: %v", err)
	}
	if err := mod.LifecycleStart(ctx); err != nil {
		t.Errorf("LifecycleStart returned error: %v", err)
	}
	if err := mod.LifecycleStop(ctx); err != nil {
		t.Errorf("LifecycleStop returned error: %v", err)
	}
}

// TestNoopLifecycle_FactoryRegistration simply ensures RegisterModuleFactory can be called without panic.
func TestNoopLifecycle_FactoryRegistration(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RegisterModuleFactory should not panic: %v", r)
		}
	}()

	engine.RegisterModuleFactory("noop-lifecycle", func() engine.Module { return &noopLifecycleModule{} })
}
