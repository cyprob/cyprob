package engine

import (
	"context"

	"github.com/cyprob/cyprob/pkg/config"
	"github.com/cyprob/cyprob/pkg/event"
	"github.com/cyprob/cyprob/pkg/hook"
)

// NewTestAppManager creates a minimal AppManager for tests without loading config files.
func NewTestAppManager() *AppManager {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := config.NewManager()
	return &AppManager{
		ctx:           ctx,
		cancel:        cancel,
		ConfigManager: cfg,
		EventManager:  event.NewManager(),
		HookManager:   hook.NewManager(),
	}
}
