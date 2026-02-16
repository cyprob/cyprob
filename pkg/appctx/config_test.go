package appctx

import (
	"context"
	"testing"

	"github.com/cyprob/cyprob/pkg/config"
)

func TestWithConfig(t *testing.T) {
	t.Run("stores config manager in context", func(t *testing.T) {
		manager := &config.Manager{}
		ctx := WithConfig(context.Background(), manager)

		retrieved, ok := Config(ctx)
		if !ok {
			t.Fatal("expected to retrieve config manager")
		}
		if retrieved != manager {
			t.Error("retrieved manager does not match stored manager")
		}
	})

	t.Run("handles nil context", func(t *testing.T) {
		manager := &config.Manager{}
		//nolint:staticcheck
		ctx := WithConfig(nil, manager)

		retrieved, ok := Config(ctx)
		if !ok {
			t.Fatal("expected to retrieve config manager")
		}
		if retrieved != manager {
			t.Error("retrieved manager does not match stored manager")
		}
	})
}

func TestConfig(t *testing.T) {
	t.Run("retrieves config manager from context", func(t *testing.T) {
		manager := &config.Manager{}
		ctx := context.WithValue(context.Background(), configKey, manager)

		retrieved, ok := Config(ctx)
		if !ok {
			t.Fatal("expected to retrieve config manager")
		}
		if retrieved != manager {
			t.Error("retrieved manager does not match stored manager")
		}
	})

	t.Run("returns false for nil context", func(t *testing.T) {
		//nolint:staticcheck
		_, ok := Config(nil)
		if ok {
			t.Error("expected false for nil context")
		}
	})

	t.Run("returns false when config not in context", func(t *testing.T) {
		ctx := context.Background()
		_, ok := Config(ctx)
		if ok {
			t.Error("expected false when config not in context")
		}
	})

	t.Run("returns false for nil config manager", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), configKey, (*config.Manager)(nil))
		_, ok := Config(ctx)
		if ok {
			t.Error("expected false for nil config manager")
		}
	})

	t.Run("returns false for wrong type in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), configKey, "not a manager")
		_, ok := Config(ctx)
		if ok {
			t.Error("expected false for wrong type")
		}
	})
}
