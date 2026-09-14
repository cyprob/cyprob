// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
)

// ManifestWatcher watches the plugin manifest file for changes and
// automatically reloads it when modifications are detected.
//
// This solves the issue where CLI plugin changes don't appear in the
// server API until restart (#27).
//
// Testing:
//   - Unit tests: watcher_test.go (18 test cases)
//   - Integration tests: watcher_integration_test.go (4 test cases, Issue #103)
//
// Run integration tests: go test -tags=integration -v ./pkg/plugin -run TestManifestWatcher
type ManifestWatcher struct {
	// manifest is the ManifestManager to reload on changes
	manifest *ManifestManager

	// watcher is the fsnotify file watcher
	watcher *fsnotify.Watcher

	// debounceDelay is the time to wait before reloading after a change
	// (prevents multiple reloads for rapid successive writes)
	debounceDelay time.Duration

	// logger for structured logging
	logger zerolog.Logger

	// mu protects the debounce timer
	mu sync.Mutex

	// debounceTimer is the active debounce timer (if any)
	debounceTimer *time.Timer
}

// NewManifestWatcher creates a new manifest file watcher.
//
// The watcher monitors the manifest file for changes and automatically
// calls Reload() when modifications are detected. Changes are debounced
// to avoid multiple reloads during rapid successive writes.
//
// Default debounce delay is 100ms, which provides near-instant sync
// while avoiding redundant reloads.
func NewManifestWatcher(manifest *ManifestManager, logger zerolog.Logger) (*ManifestWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &ManifestWatcher{
		manifest:      manifest,
		watcher:       watcher,
		debounceDelay: 100 * time.Millisecond,
		logger:        logger.With().Str("component", "plugin.watcher").Logger(),
	}, nil
}

// Start begins watching the manifest file for changes.
//
// This method blocks until the context is canceled. It should be run
// in a separate goroutine:
//
//	go watcher.Start(ctx)
//
// When a file change is detected, the manifest is reloaded after the
// debounce delay. Multiple rapid changes are coalesced into a single reload.
func (w *ManifestWatcher) Start(ctx context.Context) error {
	// Add the manifest file's parent directory to the watcher
	// (fsnotify requires watching directories, not files directly)
	manifestDir := filepath.Dir(w.manifest.manifestPath)
	manifestFile := filepath.Base(w.manifest.manifestPath)

	if err := w.watcher.Add(manifestDir); err != nil {
		w.logger.Error().
			Err(err).
			Str("dir", manifestDir).
			Msg("Failed to watch manifest directory")
		return err
	}

	w.logger.Info().
		Str("file", w.manifest.manifestPath).
		Dur("debounce", w.debounceDelay).
		Msg("Started watching manifest file")

	defer func() {
		if err := w.watcher.Close(); err != nil {
			w.logger.Warn().Err(err).Msg("Error closing watcher")
		}
		w.logger.Info().Msg("Stopped watching manifest file")
	}()

	for {
		select {
		case <-ctx.Done():
			// Context canceled, stop watching
			return ctx.Err()

		case event, ok := <-w.watcher.Events:
			if !ok {
				// Watcher closed
				return nil
			}

			// Only react to changes to the manifest file itself
			// (ignore other files in the same directory)
			if filepath.Base(event.Name) != manifestFile {
				continue
			}

			// Only react to write/create events
			// (ignore chmod, remove events - remove is handled by create on next write)
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				w.logger.Debug().
					Str("op", event.Op.String()).
					Str("file", event.Name).
					Msg("Detected manifest file change")

				// Schedule reload with debouncing
				w.scheduleReload()
			}

		case err, ok := <-w.watcher.Errors:
			if !ok {
				// Watcher closed
				return nil
			}

			w.logger.Warn().
				Err(err).
				Msg("File watcher error")
		}
	}
}

// scheduleReload schedules a manifest reload after the debounce delay.
// If a reload is already scheduled, the timer is reset.
func (w *ManifestWatcher) scheduleReload() {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Cancel existing timer if any
	if w.debounceTimer != nil {
		w.debounceTimer.Stop()
	}

	// Schedule new reload
	w.debounceTimer = time.AfterFunc(w.debounceDelay, func() {
		if err := w.manifest.Reload(); err != nil {
			w.logger.Error().
				Err(err).
				Msg("Failed to reload manifest")
		} else {
			w.logger.Info().
				Msg("Manifest reloaded successfully")
		}
	})
}

// Close stops the watcher and releases resources.
func (w *ManifestWatcher) Close() error {
	return w.watcher.Close()
}
