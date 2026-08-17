package storage

import (
	"context"
	"fmt"
	"testing"
)

func TestNewBackend_InvalidConfig(t *testing.T) {
	cfg := &Config{
		WorkspaceRoot: "", // Invalid: empty
	}
	_, err := NewBackend(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !containsString(err.Error(), "invalid storage configuration") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewBackend_NoDefaultFactory(t *testing.T) {
	orig := DefaultFactory
	t.Cleanup(func() { DefaultFactory = orig })

	// Ensure no factory is registered
	DefaultFactory = nil

	cfg := &Config{
		WorkspaceRoot: "~/.local/share/cyprob",
	}
	_, err := NewBackend(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if err.Error() != "no storage backend factory registered" && !containsString(err.Error(), "no storage backend factory registered") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewBackend_FactoryReturnsError(t *testing.T) {
	orig := DefaultFactory
	t.Cleanup(func() { DefaultFactory = orig })

	DefaultFactory = func(ctx context.Context, cfg *Config) (Backend, error) {
		return nil, fmt.Errorf("boom")
	}

	cfg := &Config{
		WorkspaceRoot: "~/.local/share/cyprob",
	}
	_, err := NewBackend(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	// Should wrap the inner error
	if !containsString(err.Error(), "failed to create storage backend") || !containsString(err.Error(), "boom") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewBackend_PropagatesFactoryResult(t *testing.T) {
	orig := DefaultFactory
	t.Cleanup(func() { DefaultFactory = orig })

	// Factory that returns (nil, nil). NewBackend should return the same.
	DefaultFactory = func(ctx context.Context, cfg *Config) (Backend, error) {
		return nil, nil
	}

	cfg := &Config{
		WorkspaceRoot: "~/.local/share/cyprob",
	}
	b, err := NewBackend(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b != nil {
		t.Fatalf("expected nil backend, got %#v", b)
	}
}

func TestSetupDefaultFactory_DefaultFactoryErr(t *testing.T) {
	DefaultFactory = func(ctx context.Context, cfg *Config) (Backend, error) {
		return nil, fmt.Errorf("old backend")
	}

	setupDefaultFactory()

	_, err := DefaultFactory(context.Background(), &Config{})
	if !containsString(err.Error(), "no backend implementation available") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// containsString reports whether substr is within s; helper to keep error checks simple.
func containsString(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) && (stringIndex(s, substr) >= 0))
}

// stringIndex returns the index of substr in s or -1 if not present.
func stringIndex(s, substr string) int {
	n := len(s)
	m := len(substr)
	if m == 0 {
		return 0
	}
	if m > n {
		return -1
	}
	for i := 0; i <= n-m; i++ {
		if s[i:i+m] == substr {
			return i
		}
	}
	return -1
}
