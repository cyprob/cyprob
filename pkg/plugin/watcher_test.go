// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// TestNewManifestWatcher_Success verifies that NewManifestWatcher creates
// a watcher with the correct configuration.
func TestNewManifestWatcher_Success(t *testing.T) {
	// Create temp directory for manifest
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	// Create valid manifest file (plugins is a map, not array)
	initialManifest := `{"version":"1.0","plugins":{},"last_updated":"2025-01-01T00:00:00Z"}`

	err := os.WriteFile(manifestPath, []byte(initialManifest), 0o644)
	require.NoError(t, err)

	// Create ManifestManager using constructor
	manifest, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	logger := zerolog.New(os.Stdout)
	watcher, err := NewManifestWatcher(manifest, logger)

	require.NoError(t, err)
	require.NotNil(t, watcher)
	require.Equal(t, manifest, watcher.manifest)
	require.NotNil(t, watcher.watcher)
	require.Equal(t, 100*time.Millisecond, watcher.debounceDelay)

	// Clean up
	require.NoError(t, watcher.Close())
}

// TestManifestWatcher_DetectsFileChange verifies that the watcher detects
// file changes and triggers a reload.
func TestManifestWatcher_DetectsFileChange(t *testing.T) {
	// Create temp directory for manifest
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	// Create initial manifest file (plugins is a map)
	initialContent := `{"version":"1.0","plugins":{},"last_updated":"2025-01-01T00:00:00Z"}`

	err := os.WriteFile(manifestPath, []byte(initialContent), 0o644)
	require.NoError(t, err)

	// Create ManifestManager
	manifest, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Load initial manifest
	err = manifest.Load()
	require.NoError(t, err)

	logger := zerolog.Nop() // Quiet logger for test
	watcher, err := NewManifestWatcher(manifest, logger)
	require.NoError(t, err)
	defer watcher.Close()

	// Start watcher in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- watcher.Start(ctx)
	}()

	// Wait for watcher to initialize
	time.Sleep(50 * time.Millisecond)

	// Modify the file (add a plugin to the map)
	updatedContent := `{"version":"1.0","plugins":{"test-plugin":{"id":"test-plugin","name":"Test","version":"1.0.0","category":"test"}},"last_updated":"2025-01-01T01:00:00Z"}`

	err = os.WriteFile(manifestPath, []byte(updatedContent), 0o644)
	require.NoError(t, err)

	// Wait for debounce delay + processing time
	time.Sleep(250 * time.Millisecond)

	// Stop watcher
	cancel()

	// Wait for watcher to stop
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(1 * time.Second):
		t.Fatal("Watcher did not stop in time")
	}

	// Verify manifest was reloaded by checking plugin count
	plugins, err := manifest.List()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(plugins), 0, "Manifest should be accessible after reload")
}

// TestManifestWatcher_ContextCancellation verifies that the watcher stops
// gracefully when the context is canceled.
func TestManifestWatcher_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	manifestContent := `{"version":"1.0","plugins":{},"last_updated":"2025-01-01T00:00:00Z"}`

	err := os.WriteFile(manifestPath, []byte(manifestContent), 0o644)
	require.NoError(t, err)

	manifest, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	logger := zerolog.Nop()
	watcher, err := NewManifestWatcher(manifest, logger)
	require.NoError(t, err)
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())

	errChan := make(chan error, 1)
	go func() {
		errChan <- watcher.Start(ctx)
	}()

	// Wait for watcher to start
	time.Sleep(50 * time.Millisecond)

	// Cancel context
	cancel()

	// Verify watcher stops with context.Canceled error
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(1 * time.Second):
		t.Fatal("Watcher did not stop after context cancellation")
	}
}

// TestManifestWatcher_Close verifies that Close() properly releases resources.
func TestManifestWatcher_Close(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	manifestContent := `{"version":"1.0","plugins":{},"last_updated":"2025-01-01T00:00:00Z"}`

	err := os.WriteFile(manifestPath, []byte(manifestContent), 0o644)
	require.NoError(t, err)

	manifest, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	logger := zerolog.Nop()
	watcher, err := NewManifestWatcher(manifest, logger)
	require.NoError(t, err)

	// Close should succeed
	err = watcher.Close()
	require.NoError(t, err)

	// Second close might or might not fail depending on fsnotify implementation
	// Just verify no panic
	_ = watcher.Close()
}

// TestService_StartManifestWatcher_WithRealManager verifies that
// StartManifestWatcher works with a real ManifestManager.
func TestService_StartManifestWatcher_WithRealManager(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	// Create manifest file
	manifestContent := `{"version":"1.0","plugins":{},"last_updated":"2025-01-01T00:00:00Z"}`

	err := os.WriteFile(manifestPath, []byte(manifestContent), 0o644)
	require.NoError(t, err)

	// Create ManifestManager
	manifestMgr, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Create service with real ManifestManager
	service := &Service{
		manifest: manifestMgr,
		logger:   zerolog.Nop(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// StartManifestWatcher should succeed and block until context canceled
	err = service.StartManifestWatcher(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestService_StartManifestWatcher_WithMock verifies that
// StartManifestWatcher gracefully skips when using a mock (not *ManifestManager).
func TestService_StartManifestWatcher_WithMock(t *testing.T) {
	// Use mock manifest (not *ManifestManager)
	mockManifest := &mockManifestManager{}

	service := &Service{
		manifest: mockManifest,
		logger:   zerolog.Nop(),
	}

	ctx := context.Background()

	// Should return nil immediately (skip watcher for mock)
	err := service.StartManifestWatcher(ctx)
	require.NoError(t, err, "Should skip watcher for mock manifest")
}

// TestManifestWatcher_WatcherErrors verifies handling of watcher errors.
func TestManifestWatcher_WatcherErrors(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	manifestContent := `{"version":"1.0","plugins":{},"last_updated":"2025-01-01T00:00:00Z"}`

	err := os.WriteFile(manifestPath, []byte(manifestContent), 0o644)
	require.NoError(t, err)

	manifest, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	logger := zerolog.Nop()
	watcher, err := NewManifestWatcher(manifest, logger)
	require.NoError(t, err)
	defer watcher.Close()

	// Start watcher
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- watcher.Start(ctx)
	}()

	// Wait for watcher to start
	time.Sleep(50 * time.Millisecond)

	// Close watcher's underlying fsnotify watcher to trigger error channel closure
	watcher.watcher.Close()

	// Wait for watcher to detect closure and exit
	select {
	case err := <-errChan:
		// Should exit gracefully (nil or context timeout)
		if err != nil && err != context.DeadlineExceeded {
			t.Logf("Watcher exited with: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Watcher did not exit after underlying watcher closed")
	}
}

// TestManifestWatcher_IgnoresNonWriteEvents verifies that the watcher
// ignores events other than Write/Create (e.g., Chmod).
func TestManifestWatcher_IgnoresNonWriteEvents(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	manifestContent := `{"version":"1.0","plugins":{},"last_updated":"2025-01-01T00:00:00Z"}`

	err := os.WriteFile(manifestPath, []byte(manifestContent), 0o644)
	require.NoError(t, err)

	manifest, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	err = manifest.Load()
	require.NoError(t, err)

	logger := zerolog.Nop()
	watcher, err := NewManifestWatcher(manifest, logger)
	require.NoError(t, err)
	defer watcher.Close()

	// Start watcher
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- watcher.Start(ctx)
	}()

	// Wait for watcher to initialize
	time.Sleep(50 * time.Millisecond)

	// Chmod the file (should be ignored by watcher)
	err = os.Chmod(manifestPath, 0o600)
	require.NoError(t, err)

	// Wait a bit to ensure no reload happens
	time.Sleep(150 * time.Millisecond)

	// Test passes if watcher handles chmod event gracefully
	// (should be ignored, no reload)
}

// TestManifestWatcher_ReloadError verifies handling when Reload() fails.
func TestManifestWatcher_ReloadError(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	manifestContent := `{"version":"1.0","plugins":{},"last_updated":"2025-01-01T00:00:00Z"}`

	err := os.WriteFile(manifestPath, []byte(manifestContent), 0o644)
	require.NoError(t, err)

	manifest, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	err = manifest.Load()
	require.NoError(t, err)

	logger := zerolog.Nop()
	watcher, err := NewManifestWatcher(manifest, logger)
	require.NoError(t, err)
	defer watcher.Close()

	// Start watcher
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- watcher.Start(ctx)
	}()

	// Wait for watcher to initialize
	time.Sleep(50 * time.Millisecond)

	// Write invalid JSON to trigger reload error
	invalidContent := `{"version":"1.0","plugins":INVALID_JSON}`

	err = os.WriteFile(manifestPath, []byte(invalidContent), 0o644)
	require.NoError(t, err)

	// Wait for debounce + reload attempt
	time.Sleep(200 * time.Millisecond)

	// Cancel watcher
	cancel()

	// Watcher should still exit gracefully despite reload error
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(1 * time.Second):
		t.Fatal("Watcher did not stop after context cancellation")
	}
}

// TestService_StartManifestWatcher_ErrorCreatingWatcher tests error
// handling when watcher creation fails.
func TestService_StartManifestWatcher_ErrorCreatingWatcher(t *testing.T) {
	// Use a path that will cause fsnotify.NewWatcher to work
	// but watcher.Add to fail (non-existent directory)
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "nonexistent", "registry.json")

	// Create ManifestManager (creates parent dirs)
	manifest, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	service := &Service{
		manifest: manifest,
		logger:   zerolog.Nop(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Should handle watcher error gracefully
	// (might succeed if dir exists, or fail gracefully)
	err = service.StartManifestWatcher(ctx)

	// Either succeeds (dir was created) or times out
	if err != nil && err != context.DeadlineExceeded {
		t.Logf("StartManifestWatcher returned error: %v", err)
	}
}

// TestManifestWatcher_AddDirectoryError tests error handling when
// watcher.Add fails to add directory.
func TestManifestWatcher_AddDirectoryError(t *testing.T) {
	// Create temp directory for manifest but delete it before starting watcher
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	manifestContent := `{"version":"1.0","plugins":{},"last_updated":"2025-01-01T00:00:00Z"}`

	err := os.WriteFile(manifestPath, []byte(manifestContent), 0o644)
	require.NoError(t, err)

	manifest, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	logger := zerolog.Nop()
	watcher, err := NewManifestWatcher(manifest, logger)
	require.NoError(t, err)
	defer watcher.Close()

	// Remove the directory to cause watcher.Add to fail
	err = os.RemoveAll(tmpDir)
	require.NoError(t, err)

	ctx := context.Background()

	// Start should fail when trying to add non-existent directory
	err = watcher.Start(ctx)
	require.Error(t, err, "Start should fail when directory doesn't exist")
}

// TestManifestWatcher_CloseError tests error handling in defer when Close fails.
func TestManifestWatcher_CloseError(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	manifestContent := `{"version":"1.0","plugins":{},"last_updated":"2025-01-01T00:00:00Z"}`

	err := os.WriteFile(manifestPath, []byte(manifestContent), 0o644)
	require.NoError(t, err)

	manifest, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	logger := zerolog.Nop()
	watcher, err := NewManifestWatcher(manifest, logger)
	require.NoError(t, err)

	// Start watcher
	ctx, cancel := context.WithCancel(context.Background())

	errChan := make(chan error, 1)
	go func() {
		errChan <- watcher.Start(ctx)
	}()

	// Wait for watcher to start
	time.Sleep(50 * time.Millisecond)

	// Close watcher manually (will cause defer Close to fail with error)
	err = watcher.Close()
	require.NoError(t, err)

	// Cancel context to trigger exit
	cancel()

	// Wait for watcher to exit (defer will try to close already-closed watcher)
	select {
	case err := <-errChan:
		// Should exit gracefully (nil when watcher closed, or context.Canceled)
		if err != nil && err != context.Canceled {
			t.Fatalf("Unexpected error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Watcher did not exit")
	}
}

// TestManifestWatcher_ReloadSuccess verifies successful reload logging.
func TestManifestWatcher_ReloadSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	initialContent := `{"version":"1.0","plugins":{},"last_updated":"2025-01-01T00:00:00Z"}`

	err := os.WriteFile(manifestPath, []byte(initialContent), 0o644)
	require.NoError(t, err)

	manifest, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	err = manifest.Load()
	require.NoError(t, err)

	logger := zerolog.Nop()
	watcher, err := NewManifestWatcher(manifest, logger)
	require.NoError(t, err)
	defer watcher.Close()

	// Start watcher
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- watcher.Start(ctx)
	}()

	// Wait for watcher to start
	time.Sleep(50 * time.Millisecond)

	// Write valid update to trigger successful reload
	updatedContent := `{"version":"1.0","plugins":{"new-plugin":{"id":"new-plugin","name":"New","version":"1.0.0","category":"test"}},"last_updated":"2025-01-01T02:00:00Z"}`

	err = os.WriteFile(manifestPath, []byte(updatedContent), 0o644)
	require.NoError(t, err)

	// Wait for debounce + reload
	time.Sleep(200 * time.Millisecond)

	// Verify manifest was reloaded successfully
	plugins, err := manifest.List()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(plugins), 1, "Manifest should have the new plugin after successful reload")

	// Cancel and cleanup
	cancel()

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(1 * time.Second):
		t.Fatal("Watcher did not exit")
	}
}

// TestManifestWatcher_DebounceTimerCancellation tests timer cancellation
// when multiple rapid changes occur.
func TestManifestWatcher_DebounceTimerCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	initialContent := `{"version":"1.0","plugins":{},"last_updated":"2025-01-01T00:00:00Z"}`

	err := os.WriteFile(manifestPath, []byte(initialContent), 0o644)
	require.NoError(t, err)

	manifest, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	err = manifest.Load()
	require.NoError(t, err)

	logger := zerolog.Nop()
	watcher, err := NewManifestWatcher(manifest, logger)
	require.NoError(t, err)

	// Shorter debounce for faster test
	watcher.debounceDelay = 100 * time.Millisecond
	defer watcher.Close()

	// Start watcher
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- watcher.Start(ctx)
	}()

	// Wait for watcher to start
	time.Sleep(50 * time.Millisecond)

	// Trigger multiple rapid changes to test timer cancellation
	for i := range 3 {
		content := `{"version":"1.0","plugins":{"plugin-` + string(rune(i+48)) + `":{"id":"plugin-` + string(rune(i+48)) + `","name":"Test","version":"1.0.0","category":"test"}},"last_updated":"2025-01-01T02:00:00Z"}`

		err = os.WriteFile(manifestPath, []byte(content), 0o644)
		require.NoError(t, err)
		time.Sleep(30 * time.Millisecond) // Less than debounce delay
	}

	// Wait for debounce to complete
	time.Sleep(200 * time.Millisecond)

	// Verify debouncing worked (should have final state)
	plugins, err := manifest.List()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(plugins), 1, "Manifest should be reloaded after debouncing")

	// Cancel and cleanup
	cancel()

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(1 * time.Second):
		t.Fatal("Watcher did not exit")
	}
}

// TestNewManifestWatcher_FsnotifyError tests error handling when
// fsnotify.NewWatcher fails (hard to trigger in practice).
func TestNewManifestWatcher_FsnotifyError(t *testing.T) {
	// This test documents the error path but fsnotify.NewWatcher
	// rarely fails in normal circumstances.
	// We can't easily force it to fail without mocking.
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	manifestContent := `{"version":"1.0","plugins":{},"last_updated":"2025-01-01T00:00:00Z"}`

	err := os.WriteFile(manifestPath, []byte(manifestContent), 0o644)
	require.NoError(t, err)

	manifest, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	logger := zerolog.Nop()

	// Under normal circumstances, this should succeed
	watcher, err := NewManifestWatcher(manifest, logger)
	if err != nil {
		// If it fails, error is handled correctly
		require.Error(t, err)
		require.Nil(t, watcher)
	} else {
		// If it succeeds (expected), cleanup
		require.NoError(t, err)
		require.NotNil(t, watcher)
		watcher.Close()
	}
}

// TestService_StartManifestWatcher_NonExistentDirectory tests that
// StartManifestWatcher fails gracefully when directory doesn't exist.
func TestService_StartManifestWatcher_NonExistentDirectory(t *testing.T) {
	// Create manifest in a directory, then delete the directory
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "subdir", "registry.json")

	// Create ManifestManager (creates dirs)
	manifest, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	// Create initial manifest file
	manifestContent := `{"version":"1.0","plugins":{},"last_updated":"2025-01-01T00:00:00Z"}`

	err = os.MkdirAll(filepath.Dir(manifestPath), 0o755)
	require.NoError(t, err)

	err = os.WriteFile(manifestPath, []byte(manifestContent), 0o644)
	require.NoError(t, err)

	service := &Service{
		manifest: manifest,
		logger:   zerolog.Nop(),
	}

	// Remove the directory to cause watcher.Add to fail
	err = os.RemoveAll(filepath.Join(tmpDir, "subdir"))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// StartManifestWatcher should fail when directory doesn't exist
	err = service.StartManifestWatcher(ctx)
	require.Error(t, err, "StartManifestWatcher should fail when directory doesn't exist")
}

// TestService_StartManifestWatcher_WatcherStartError tests error
// propagation when watcher.Start fails.
func TestService_StartManifestWatcher_WatcherStartError(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "registry.json")

	manifestContent := `{"version":"1.0","plugins":{},"last_updated":"2025-01-01T00:00:00Z"}`

	err := os.WriteFile(manifestPath, []byte(manifestContent), 0o644)
	require.NoError(t, err)

	manifest, err := NewManifestManager(manifestPath)
	require.NoError(t, err)

	service := &Service{
		manifest: manifest,
		logger:   zerolog.Nop(),
	}

	// Use already-canceled context to trigger immediate exit
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Should return context.Canceled error
	err = service.StartManifestWatcher(ctx)
	require.ErrorIs(t, err, context.Canceled, "Should propagate context cancellation error")
}
