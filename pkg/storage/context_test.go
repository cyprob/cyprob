// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"context"
	"testing"
)

func TestWithConfig(t *testing.T) {
	t.Run("stores config in context", func(t *testing.T) {
		cfg := &Config{
			WorkspaceRoot: "/test/path",
		}

		ctx := WithConfig(context.Background(), cfg)

		retrieved, ok := ConfigFromContext(ctx)
		if !ok {
			t.Fatal("expected config to be in context")
		}

		if retrieved.WorkspaceRoot != "/test/path" {
			t.Errorf("expected WorkspaceRoot '/test/path', got %q", retrieved.WorkspaceRoot)
		}
	})

	t.Run("handles nil context", func(t *testing.T) {
		cfg := &Config{
			WorkspaceRoot: "/test/path",
		}

		// WithConfig handles nil by creating background context
		//nolint:staticcheck // Testing nil context handling
		ctx := WithConfig(nil, cfg)

		if ctx == nil {
			t.Fatal("expected non-nil context")
		}

		retrieved, ok := ConfigFromContext(ctx)
		if !ok {
			t.Fatal("expected config to be in context")
		}

		if retrieved.WorkspaceRoot != "/test/path" {
			t.Errorf("expected WorkspaceRoot '/test/path', got %q", retrieved.WorkspaceRoot)
		}
	})
}

func TestConfigFromContext(t *testing.T) {
	t.Run("retrieves config from context", func(t *testing.T) {
		cfg := &Config{
			WorkspaceRoot: "/test/path",
			Retention: RetentionConfig{
				MaxScans:   100,
				MaxAgeDays: 30,
			},
		}

		ctx := WithConfig(context.Background(), cfg)
		retrieved, ok := ConfigFromContext(ctx)

		if !ok {
			t.Fatal("expected config to be found")
		}

		if retrieved.WorkspaceRoot != cfg.WorkspaceRoot {
			t.Errorf("expected WorkspaceRoot %q, got %q", cfg.WorkspaceRoot, retrieved.WorkspaceRoot)
		}

		if retrieved.Retention.MaxScans != cfg.Retention.MaxScans {
			t.Errorf("expected MaxScans %d, got %d", cfg.Retention.MaxScans, retrieved.Retention.MaxScans)
		}
	})

	t.Run("returns false for nil context", func(t *testing.T) {
		//nolint:staticcheck // Testing nil context handling
		_, ok := ConfigFromContext(nil)
		if ok {
			t.Error("expected false for nil context")
		}
	})

	t.Run("returns false when config not in context", func(t *testing.T) {
		ctx := context.Background()
		_, ok := ConfigFromContext(ctx)
		if ok {
			t.Error("expected false when config not in context")
		}
	})

	t.Run("returns false for nil config", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), configKey, (*Config)(nil))
		_, ok := ConfigFromContext(ctx)
		if ok {
			t.Error("expected false for nil config")
		}
	})

	t.Run("returns false for wrong type in context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), configKey, "not a config")
		_, ok := ConfigFromContext(ctx)
		if ok {
			t.Error("expected false for wrong type")
		}
	})
}
