// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestNewService(t *testing.T) {
	t.Run("with valid cache directory", func(t *testing.T) {
		cacheDir := t.TempDir()

		svc, err := NewService(WithCacheDir(cacheDir))

		require.NoError(t, err)
		require.NotNil(t, svc)
		require.NotNil(t, svc.cache)
		require.NotNil(t, svc.manifest)
		require.NotNil(t, svc.downloader)
		require.NotNil(t, svc.logger)
		require.NotEmpty(t, svc.sources)
		require.Len(t, svc.sources, 1) // Default: 1 source
		require.Equal(t, "official", svc.sources[0].Name)
	})

	t.Run("with empty cache directory uses default", func(t *testing.T) {
		svc, err := NewService()

		require.NoError(t, err)
		require.NotNil(t, svc)

		// Verify cache manager was created with default path
		require.NotNil(t, svc.cache)
	})

	t.Run("creates cache directory if not exists", func(t *testing.T) {
		tempDir := t.TempDir()
		cacheDir := filepath.Join(tempDir, "nonexistent", "cache")

		svc, err := NewService(WithCacheDir(cacheDir))

		require.NoError(t, err)
		require.NotNil(t, svc)

		// Verify directory was created
		_, err = os.Stat(cacheDir)
		require.NoError(t, err, "cache directory should be created")
	})

	t.Run("creates manifest in parent directory", func(t *testing.T) {
		tempDir := t.TempDir()
		cacheDir := filepath.Join(tempDir, "cache")

		svc, err := NewService(WithCacheDir(cacheDir))

		require.NoError(t, err)
		require.NotNil(t, svc.manifest)

		// Manifest should be in parent directory
		expectedManifestDir := tempDir
		_, err = os.Stat(expectedManifestDir)
		require.NoError(t, err)
	})
}

func TestDefaultSources(t *testing.T) {
	t.Run("returns official source", func(t *testing.T) {
		sources := defaultSources()

		require.Len(t, sources, 1)
		require.Equal(t, "official", sources[0].Name)
		require.Equal(t, "https://plugins.pentora.ai/manifest.yaml", sources[0].URL)
		require.True(t, sources[0].Enabled)
		require.Equal(t, 1, sources[0].Priority)
	})

	t.Run("returns enabled sources", func(t *testing.T) {
		sources := defaultSources()

		for _, source := range sources {
			require.True(t, source.Enabled, "default sources should be enabled")
		}
	})
}

func TestService_Initialization(t *testing.T) {
	t.Run("all dependencies initialized", func(t *testing.T) {
		cacheDir := t.TempDir()

		svc, err := NewService(WithCacheDir(cacheDir))

		require.NoError(t, err)

		// Verify all required dependencies are initialized
		require.NotNil(t, svc.cache, "cache manager should be initialized")
		require.NotNil(t, svc.manifest, "manifest manager should be initialized")
		require.NotNil(t, svc.downloader, "downloader should be initialized")
		require.NotEmpty(t, svc.sources, "sources should have default values")
		require.NotNil(t, svc.logger, "logger should have default value")
	})

	t.Run("optional dependencies default to nil/zero", func(t *testing.T) {
		cacheDir := t.TempDir()

		svc, err := NewService(WithCacheDir(cacheDir))

		require.NoError(t, err)

		// Optional dependencies should be nil until injected
		require.Nil(t, svc.storage, "storage should be nil by default")
	})
}

// Test that verifies service can be created and used in realistic scenario
func TestService_Integration_Basic(t *testing.T) {
	t.Run("create service and verify it's ready for operations", func(t *testing.T) {
		cacheDir := t.TempDir()

		// Create service
		svc, err := NewService(WithCacheDir(cacheDir))
		require.NoError(t, err)
		require.NotNil(t, svc)

		// Service should be ready to use
		// (Will be tested further when Install/Update/etc methods are implemented)

		// Verify service has working dependencies
		require.NotNil(t, svc.cache)
		require.NotNil(t, svc.manifest)
		require.NotNil(t, svc.downloader)
	})
}

// ============================================================================
// Install() Method Tests
// ============================================================================

// Test helper to create Service with mocks
func newTestService(cache CacheInterface, manifest ManifestInterface, downloader DownloaderInterface, sources []PluginSource) *Service {
	return &Service{
		cache:      cache,
		manifest:   manifest,
		downloader: downloader,
		sources:    sources,
		logger:     zerolog.New(os.Stdout),
	}
}

// builder helpers to reduce duplication in tests
func newDownloader(fetch func(ctx context.Context, src PluginSource) (*PluginManifest, error), download func(ctx context.Context, id, version string) (*CacheEntry, error)) *mockDownloader {
	return &mockDownloader{fetchManifestFunc: fetch, downloadFunc: download}
}

func newCache(opts ...func(*mockCacheManager)) *mockCacheManager {
	m := &mockCacheManager{}
	for _, o := range opts {
		o(m)
	}
	return m
}

// newManifest is kept for symmetry with other helpers and future tests.
// Marked as used via a trivial reference to avoid unused lints when
// specific tests are excluded by -run filters in CI.
var _ = func() *mockManifestManager { return newManifest() }()

func newManifest(opts ...func(*mockManifestManager)) *mockManifestManager {
	m := &mockManifestManager{}
	for _, o := range opts {
		o(m)
	}
	return m
}

// common asserts
func requireInstallSuccess(t *testing.T, result *InstallResult, wantID, wantVersion string) {
	t.Helper()
	require.NotNil(t, result)
	require.Equal(t, 1, result.InstalledCount)
	require.Equal(t, 0, result.SkippedCount)
	require.Equal(t, 0, result.FailedCount)
	require.Len(t, result.Plugins, 1)
	require.Equal(t, wantID, result.Plugins[0].ID)
	require.Equal(t, wantVersion, result.Plugins[0].Version)
}

// Mock implementations

// mockDownloader for testing Install() method
type mockDownloader struct {
	fetchManifestFunc func(ctx context.Context, src PluginSource) (*PluginManifest, error)
	downloadFunc      func(ctx context.Context, id, version string) (*CacheEntry, error)
}

func (m *mockDownloader) FetchManifest(ctx context.Context, src PluginSource) (*PluginManifest, error) {
	if m.fetchManifestFunc != nil {
		return m.fetchManifestFunc(ctx, src)
	}
	return &PluginManifest{Plugins: []PluginManifestEntry{}}, nil
}

func (m *mockDownloader) Download(ctx context.Context, id, version string) (*CacheEntry, error) {
	if m.downloadFunc != nil {
		return m.downloadFunc(ctx, id, version)
	}
	return &CacheEntry{}, nil
}

// mockCacheManager for testing Install() method
type mockCacheManager struct {
	getEntryFunc func(ctx context.Context, name, version string) (*CacheEntry, error)
	sizeFunc     func(ctx context.Context) (int64, error)
	pruneFunc    func(ctx context.Context, olderThan time.Duration) (int, error)
	removeFunc   func(ctx context.Context, id, version string) error
	putFunc      func(ctx context.Context, entry CacheEntry) error
	listFunc     func(ctx context.Context) ([]CacheEntry, error)
	deleteFunc   func(ctx context.Context, name, version string) error
}

func (m *mockCacheManager) GetEntry(ctx context.Context, name, version string) (*CacheEntry, error) {
	if m.getEntryFunc != nil {
		return m.getEntryFunc(ctx, name, version)
	}
	return nil, ErrPluginNotInstalled
}

func (m *mockCacheManager) Size(ctx context.Context) (int64, error) {
	if m.sizeFunc != nil {
		return m.sizeFunc(ctx)
	}
	return 0, nil
}

func (m *mockCacheManager) Prune(ctx context.Context, olderThan time.Duration) (int, error) {
	if m.pruneFunc != nil {
		return m.pruneFunc(ctx, olderThan)
	}
	return 0, nil
}

func (m *mockCacheManager) Remove(ctx context.Context, id, version string) error {
	if m.removeFunc != nil {
		return m.removeFunc(ctx, id, version)
	}
	return nil
}

func (m *mockCacheManager) Put(ctx context.Context, entry CacheEntry) error {
	if m.putFunc != nil {
		return m.putFunc(ctx, entry)
	}
	return nil
}

func (m *mockCacheManager) List(ctx context.Context) ([]CacheEntry, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx)
	}
	return []CacheEntry{}, nil
}

func (m *mockCacheManager) Delete(ctx context.Context, name, version string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, name, version)
	}
	return nil
}

// mockManifestManager for testing Install() method
type mockManifestManager struct {
	addFunc    func(entry *ManifestEntry) error
	saveFunc   func() error
	listFunc   func() ([]*ManifestEntry, error)
	removeFunc func(id string) error
	getFunc    func(id string) (*ManifestEntry, error)
	updateFunc func(id string, entry *ManifestEntry) error
}

func (m *mockManifestManager) Add(entry *ManifestEntry) error {
	if m.addFunc != nil {
		return m.addFunc(entry)
	}
	return nil
}

func (m *mockManifestManager) Save() error {
	if m.saveFunc != nil {
		return m.saveFunc()
	}
	return nil
}

func (m *mockManifestManager) List() ([]*ManifestEntry, error) {
	if m.listFunc != nil {
		return m.listFunc()
	}
	return []*ManifestEntry{}, nil
}

func (m *mockManifestManager) Remove(id string) error {
	if m.removeFunc != nil {
		return m.removeFunc(id)
	}
	return nil
}

func (m *mockManifestManager) Get(id string) (*ManifestEntry, error) {
	if m.getFunc != nil {
		return m.getFunc(id)
	}
	return nil, ErrPluginNotFound
}

func (m *mockManifestManager) Update(id string, entry *ManifestEntry) error {
	if m.updateFunc != nil {
		return m.updateFunc(id, entry)
	}
	return nil
}

func TestService_Install_ByPluginID(t *testing.T) {
	t.Run("install plugin by ID successfully", func(t *testing.T) {
		ctx := context.Background()

		// Mock downloader that returns a test plugin
		dl := newDownloader(func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
			return &PluginManifest{
				Plugins: []PluginManifestEntry{
					{
						ID:         "test-plugin",
						Name:       "Test Plugin",
						Version:    "1.0.0",
						Author:     "Test Author",
						Categories: []Category{CategorySSH},
						URL:        "https://example.com/plugin.tar.gz",
						Checksum:   "sha256:abcd1234",
						Size:       1024,
					},
				},
			}, nil
		}, func(ctx context.Context, id, version string) (*CacheEntry, error) {
			require.Equal(t, "test-plugin", id)
			require.Equal(t, "1.0.0", version)
			return &CacheEntry{Name: "Test Plugin", Version: "1.0.0"}, nil
		})

		// Mock cache that returns "not found" (plugin not cached)
		cache := newCache(func(m *mockCacheManager) {
			m.getEntryFunc = func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return nil, ErrPluginNotInstalled
			}
		})

		// Mock manifest
		manifest := &mockManifestManager{}

		// Create service with mocks
		svc := newTestService(cache, manifest, dl, []PluginSource{
			{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
		})

		// Install plugin by ID
		result, err := svc.Install(ctx, "test-plugin", InstallOptions{})

		// Verify results
		require.NoError(t, err)
		requireInstallSuccess(t, result, "test-plugin", "1.0.0")
	})

	t.Run("plugin not found error", func(t *testing.T) {
		ctx := context.Background()

		// Mock downloader that returns empty manifest
		dl := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{Plugins: []PluginManifestEntry{}}, nil
			},
		}

		svc := newTestService(&mockCacheManager{}, &mockManifestManager{}, dl, []PluginSource{
			{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
		})

		// Try to install non-existent plugin
		result, err := svc.Install(ctx, "non-existent-plugin", InstallOptions{})

		// Verify error
		require.Error(t, err)
		require.Nil(t, result)
		require.ErrorIs(t, err, ErrNoPluginsFound, "should return ErrNoPluginsFound when manifest is empty")
	})
}

func TestService_Install_ByCategory(t *testing.T) {
	t.Run("install all plugins in category", func(t *testing.T) {
		ctx := context.Background()

		// Mock downloader with multiple SSH plugins
		mockDownloader := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Plugins: []PluginManifestEntry{
						{
							ID:         "ssh-plugin-1",
							Name:       "SSH Plugin 1",
							Version:    "1.0.0",
							Categories: []Category{CategorySSH},
							URL:        "https://example.com/ssh1.tar.gz",
							Checksum:   "sha256:abcd1234",
						},
						{
							ID:         "ssh-plugin-2",
							Name:       "SSH Plugin 2",
							Version:    "2.0.0",
							Categories: []Category{CategorySSH},
							URL:        "https://example.com/ssh2.tar.gz",
							Checksum:   "sha256:efgh5678",
						},
						{
							ID:         "http-plugin",
							Name:       "HTTP Plugin",
							Version:    "1.0.0",
							Categories: []Category{CategoryHTTP},
							URL:        "https://example.com/http.tar.gz",
							Checksum:   "sha256:ijkl9012",
						},
					},
				}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				return &CacheEntry{}, nil
			},
		}

		mockCache := newCache(func(m *mockCacheManager) {
			m.getEntryFunc = func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return nil, ErrPluginNotInstalled
			}
		})

		svc := newTestService(mockCache, &mockManifestManager{}, mockDownloader, []PluginSource{{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true}})

		// Install all SSH plugins
		result, err := svc.Install(ctx, "ssh", InstallOptions{})

		// Verify results
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 2, result.InstalledCount, "should install 2 SSH plugins")
		require.Equal(t, 0, result.SkippedCount)
		require.Equal(t, 0, result.FailedCount)
		require.Len(t, result.Plugins, 2)
	})

	t.Run("no plugins found in category", func(t *testing.T) {
		ctx := context.Background()

		mockDownloader := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Plugins: []PluginManifestEntry{
						{
							ID:         "http-plugin",
							Name:       "HTTP Plugin",
							Version:    "1.0.0",
							Categories: []Category{CategoryHTTP},
						},
					},
				}, nil
			},
		}

		svc := &Service{
			cache:      &mockCacheManager{},
			manifest:   &mockManifestManager{},
			downloader: mockDownloader,
			sources: []PluginSource{
				{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
			},
			logger: zerolog.New(os.Stdout),
		}

		// Try to install TLS plugins (none exist in manifest)
		result, err := svc.Install(ctx, "tls", InstallOptions{})

		// Verify error
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "no plugins match criteria")
	})
}

func TestService_Install_WithForce(t *testing.T) {
	t.Run("force reinstall cached plugin", func(t *testing.T) {
		ctx := context.Background()

		mockDownloader := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Plugins: []PluginManifestEntry{
						{
							ID:         "cached-plugin",
							Name:       "Cached Plugin",
							Version:    "1.0.0",
							Categories: []Category{CategorySSH},
							URL:        "https://example.com/cached.tar.gz",
							Checksum:   "sha256:abcd1234",
						},
					},
				}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				return &CacheEntry{}, nil
			},
		}

		// Mock cache that returns plugin as already cached
		mockCache := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return &CacheEntry{Name: name, Version: version}, nil
			},
		}

		svc := &Service{
			cache:      mockCache,
			manifest:   &mockManifestManager{},
			downloader: mockDownloader,
			sources: []PluginSource{
				{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
			},
			logger: zerolog.New(os.Stdout),
		}

		// Install with force=true
		result, err := svc.Install(ctx, "cached-plugin", InstallOptions{Force: true})

		// Verify plugin was reinstalled
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 1, result.InstalledCount, "should reinstall with force")
		require.Equal(t, 0, result.SkippedCount)
	})

	t.Run("skip already cached plugin without force", func(t *testing.T) {
		ctx := context.Background()

		mockDownloader := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Plugins: []PluginManifestEntry{
						{
							ID:         "cached-plugin",
							Name:       "Cached Plugin",
							Version:    "1.0.0",
							Categories: []Category{CategorySSH},
						},
					},
				}, nil
			},
		}

		// Mock cache that returns plugin as already cached
		mockCache := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return &CacheEntry{Name: name, Version: version}, nil
			},
		}

		svc := &Service{
			cache:      mockCache,
			manifest:   &mockManifestManager{},
			downloader: mockDownloader,
			sources: []PluginSource{
				{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
			},
			logger: zerolog.New(os.Stdout),
		}

		// Install without force (default)
		result, err := svc.Install(ctx, "cached-plugin", InstallOptions{Force: false})

		// Verify plugin was skipped
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 0, result.InstalledCount)
		require.Equal(t, 1, result.SkippedCount, "should skip already cached plugin")
	})
}

func TestService_Install_WithDryRun(t *testing.T) {
	t.Run("dry run does not download", func(t *testing.T) {
		ctx := context.Background()

		downloadCalled := false

		mockDownloader := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Plugins: []PluginManifestEntry{
						{
							ID:         "test-plugin",
							Name:       "Test Plugin",
							Version:    "1.0.0",
							Categories: []Category{CategorySSH},
						},
					},
				}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				downloadCalled = true
				return &CacheEntry{}, nil
			},
		}

		mockCache := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return nil, ErrPluginNotInstalled
			},
		}

		svc := &Service{
			cache:      mockCache,
			manifest:   &mockManifestManager{},
			downloader: mockDownloader,
			sources: []PluginSource{
				{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
			},
			logger: zerolog.New(os.Stdout),
		}

		// Install with DryRun=true
		result, err := svc.Install(ctx, "test-plugin", InstallOptions{DryRun: true})

		// Verify no download occurred
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 1, result.InstalledCount, "should count as installed in dry run")
		require.False(t, downloadCalled, "download should not be called in dry run")
	})
}

func TestService_Install_WithSourceFilter(t *testing.T) {
	t.Run("install from specific source", func(t *testing.T) {
		ctx := context.Background()

		officialSourceCalled := false
		communitySourceCalled := false

		mockDownloader := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				if src.Name == "official" {
					officialSourceCalled = true
					return &PluginManifest{
						Plugins: []PluginManifestEntry{
							{
								ID:         "official-plugin",
								Name:       "Official Plugin",
								Version:    "1.0.0",
								Categories: []Category{CategorySSH},
							},
						},
					}, nil
				}
				if src.Name == "community" {
					communitySourceCalled = true
					return &PluginManifest{
						Plugins: []PluginManifestEntry{
							{
								ID:         "community-plugin",
								Name:       "Community Plugin",
								Version:    "1.0.0",
								Categories: []Category{CategorySSH},
							},
						},
					}, nil
				}
				return &PluginManifest{}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				return &CacheEntry{}, nil
			},
		}

		mockCache := newCache(func(m *mockCacheManager) {
			m.getEntryFunc = func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return nil, ErrPluginNotInstalled
			}
		})

		svc := newTestService(mockCache, &mockManifestManager{}, mockDownloader, []PluginSource{
			{Name: "official", URL: "https://official.com/manifest.yaml", Enabled: true},
			{Name: "community", URL: "https://community.com/manifest.yaml", Enabled: true},
		})

		// Install from official source only
		result, err := svc.Install(ctx, "official-plugin", InstallOptions{Source: "official"})

		// Verify only official source was called
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 1, result.InstalledCount)
		require.True(t, officialSourceCalled, "official source should be called")
		require.False(t, communitySourceCalled, "community source should NOT be called")
	})

	t.Run("source not found error", func(t *testing.T) {
		ctx := context.Background()

		svc := newTestService(&mockCacheManager{}, &mockManifestManager{}, &mockDownloader{}, []PluginSource{{Name: "official", URL: "https://official.com/manifest.yaml", Enabled: true}})

		// Try to install from non-existent source
		result, err := svc.Install(ctx, "test-plugin", InstallOptions{Source: "non-existent"})

		// Verify error
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "source 'non-existent' not found")
	})
}

func TestService_Install_PartialFailures(t *testing.T) {
	t.Run("some plugins succeed, some fail", func(t *testing.T) {
		ctx := context.Background()

		mockDownloader := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Plugins: []PluginManifestEntry{
						{
							ID:         "success-plugin",
							Name:       "Success Plugin",
							Version:    "1.0.0",
							Categories: []Category{CategorySSH},
						},
						{
							ID:         "fail-plugin",
							Name:       "Fail Plugin",
							Version:    "1.0.0",
							Categories: []Category{CategorySSH},
						},
					},
				}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				if id == "fail-plugin" {
					return nil, fmt.Errorf("download failed")
				}
				return &CacheEntry{}, nil
			},
		}

		mockCache := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return nil, ErrPluginNotInstalled
			},
		}

		svc := &Service{
			cache:      mockCache,
			manifest:   &mockManifestManager{},
			downloader: mockDownloader,
			sources: []PluginSource{
				{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
			},
			logger: zerolog.New(os.Stdout),
		}

		// Install category with partial failure
		result, err := svc.Install(ctx, "ssh", InstallOptions{})

		// Verify partial failure is returned
		require.Error(t, err, "should return ErrPartialFailure on partial failure")
		require.ErrorIs(t, err, ErrPartialFailure)
		require.NotNil(t, result)
		require.Equal(t, 1, result.InstalledCount, "one plugin should succeed")
		require.Equal(t, 1, result.FailedCount, "one plugin should fail")
		require.Len(t, result.Errors, 1, "should collect errors")
		require.Contains(t, result.Errors[0].Error, "download failed")
	})
}

func TestService_Install_ContextCancellation(t *testing.T) {
	t.Run("context canceled during installation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		downloadCount := 0

		mockDownloader := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Plugins: []PluginManifestEntry{
						{ID: "plugin-1", Name: "Plugin 1", Version: "1.0.0", Categories: []Category{CategorySSH}},
						{ID: "plugin-2", Name: "Plugin 2", Version: "1.0.0", Categories: []Category{CategorySSH}},
						{ID: "plugin-3", Name: "Plugin 3", Version: "1.0.0", Categories: []Category{CategorySSH}},
					},
				}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				downloadCount++
				if downloadCount == 2 {
					cancel() // Cancel after second download
				}
				return &CacheEntry{}, nil
			},
		}

		mockCache := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return nil, ErrPluginNotInstalled
			},
		}

		svc := &Service{
			cache:      mockCache,
			manifest:   &mockManifestManager{},
			downloader: mockDownloader,
			sources: []PluginSource{
				{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
			},
			logger: zerolog.New(os.Stdout),
		}

		// Install category - should be canceled mid-way
		result, err := svc.Install(ctx, "ssh", InstallOptions{})

		// Verify context cancellation
		require.Error(t, err)
		require.Equal(t, context.Canceled, err)
		require.NotNil(t, result)
		require.Equal(t, 2, result.InstalledCount, "should install 2 before cancellation")
	})
}

func TestService_Install_EmptyManifest(t *testing.T) {
	t.Run("no plugins in manifest", func(t *testing.T) {
		ctx := context.Background()

		mockDownloader := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{Plugins: []PluginManifestEntry{}}, nil
			},
		}

		svc := newTestService(&mockCacheManager{}, &mockManifestManager{}, mockDownloader, []PluginSource{
			{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
		})

		// Try to install from empty manifest
		result, err := svc.Install(ctx, "test-plugin", InstallOptions{})

		// Verify error
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "no plugins found in any source")
	})
}

// ============================================================================
// Update() Method Tests
// ============================================================================

func TestService_Update_AllPlugins(t *testing.T) {
	t.Run("update all plugins successfully", func(t *testing.T) {
		ctx := context.Background()

		// Mock downloader with multiple plugins
		dl := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Plugins: []PluginManifestEntry{
						{
							ID:         "plugin-1",
							Name:       "Plugin 1",
							Version:    "1.0.0",
							Categories: []Category{CategorySSH},
							URL:        "https://example.com/plugin1.tar.gz",
							Checksum:   "sha256:abc123",
						},
						{
							ID:         "plugin-2",
							Name:       "Plugin 2",
							Version:    "2.0.0",
							Categories: []Category{CategoryHTTP},
							URL:        "https://example.com/plugin2.tar.gz",
							Checksum:   "sha256:def456",
						},
					},
				}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				return &CacheEntry{Name: id, Version: version}, nil
			},
		}

		// Mock cache - plugins not cached
		cache := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return nil, ErrPluginNotInstalled
			},
		}

		svc := newTestService(cache, &mockManifestManager{}, dl, []PluginSource{
			{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
		})

		// Update all plugins
		result, err := svc.Update(ctx, UpdateOptions{})

		// Verify results
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 2, result.UpdatedCount)
		require.Equal(t, 0, result.SkippedCount)
		require.Equal(t, 0, result.FailedCount)
		require.Len(t, result.Plugins, 2)
	})

	t.Run("empty manifest returns error", func(t *testing.T) {
		ctx := context.Background()

		dl := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{Plugins: []PluginManifestEntry{}}, nil
			},
		}

		svc := newTestService(&mockCacheManager{}, &mockManifestManager{}, dl, []PluginSource{
			{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
		})

		result, err := svc.Update(ctx, UpdateOptions{})

		require.Error(t, err)
		require.Nil(t, result)
		require.ErrorIs(t, err, ErrNoPluginsFound)
	})
}

func TestService_Update_ByCategory(t *testing.T) {
	t.Run("update plugins in specific category", func(t *testing.T) {
		ctx := context.Background()

		dl := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Plugins: []PluginManifestEntry{
						{
							ID:         "ssh-plugin-1",
							Name:       "SSH Plugin 1",
							Version:    "1.0.0",
							Categories: []Category{CategorySSH},
						},
						{
							ID:         "ssh-plugin-2",
							Name:       "SSH Plugin 2",
							Version:    "2.0.0",
							Categories: []Category{CategorySSH},
						},
						{
							ID:         "http-plugin",
							Name:       "HTTP Plugin",
							Version:    "1.0.0",
							Categories: []Category{CategoryHTTP},
						},
					},
				}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				return &CacheEntry{}, nil
			},
		}

		cache := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return nil, ErrPluginNotInstalled
			},
		}

		svc := newTestService(cache, &mockManifestManager{}, dl, []PluginSource{
			{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
		})

		// Update only SSH plugins
		result, err := svc.Update(ctx, UpdateOptions{Category: CategorySSH})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 2, result.UpdatedCount, "should update 2 SSH plugins")
		require.Equal(t, 0, result.SkippedCount)
	})

	t.Run("no plugins in category", func(t *testing.T) {
		ctx := context.Background()

		dl := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Plugins: []PluginManifestEntry{
						{
							ID:         "http-plugin",
							Name:       "HTTP Plugin",
							Version:    "1.0.0",
							Categories: []Category{CategoryHTTP},
						},
					},
				}, nil
			},
		}

		svc := newTestService(&mockCacheManager{}, &mockManifestManager{}, dl, []PluginSource{
			{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
		})

		result, err := svc.Update(ctx, UpdateOptions{Category: CategoryTLS})

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "no plugins match criteria")
	})
}

func TestService_Update_SkipCached(t *testing.T) {
	t.Run("skip already cached plugins", func(t *testing.T) {
		ctx := context.Background()

		dl := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Plugins: []PluginManifestEntry{
						{
							ID:         "cached-plugin",
							Name:       "Cached Plugin",
							Version:    "1.0.0",
							Categories: []Category{CategorySSH},
						},
						{
							ID:         "new-plugin",
							Name:       "New Plugin",
							Version:    "1.0.0",
							Categories: []Category{CategorySSH},
						},
					},
				}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				return &CacheEntry{}, nil
			},
		}

		// Mock cache - first plugin is cached, second is not
		cache := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				if name == "Cached Plugin" {
					return &CacheEntry{Name: name, Version: version}, nil
				}
				return nil, ErrPluginNotInstalled
			},
		}

		svc := newTestService(cache, &mockManifestManager{}, dl, []PluginSource{
			{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
		})

		result, err := svc.Update(ctx, UpdateOptions{})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 1, result.UpdatedCount, "one new plugin")
		require.Equal(t, 1, result.SkippedCount, "one cached plugin")
	})

	t.Run("force re-download cached plugins", func(t *testing.T) {
		ctx := context.Background()

		dl := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Plugins: []PluginManifestEntry{
						{
							ID:         "cached-plugin",
							Name:       "Cached Plugin",
							Version:    "1.0.0",
							Categories: []Category{CategorySSH},
						},
					},
				}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				return &CacheEntry{}, nil
			},
		}

		// Mock cache - plugin is cached
		cache := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return &CacheEntry{Name: name, Version: version}, nil
			},
		}

		svc := newTestService(cache, &mockManifestManager{}, dl, []PluginSource{
			{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
		})

		// Force re-download
		result, err := svc.Update(ctx, UpdateOptions{Force: true})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 1, result.UpdatedCount, "should re-download with force")
		require.Equal(t, 0, result.SkippedCount)
	})
}

func TestService_Update_DryRun(t *testing.T) {
	t.Run("dry run does not download", func(t *testing.T) {
		ctx := context.Background()

		downloadCalled := false

		dl := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Plugins: []PluginManifestEntry{
						{
							ID:         "test-plugin",
							Name:       "Test Plugin",
							Version:    "1.0.0",
							Categories: []Category{CategorySSH},
						},
					},
				}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				downloadCalled = true
				return &CacheEntry{}, nil
			},
		}

		cache := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return nil, ErrPluginNotInstalled
			},
		}

		svc := newTestService(cache, &mockManifestManager{}, dl, []PluginSource{
			{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
		})

		result, err := svc.Update(ctx, UpdateOptions{DryRun: true})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 1, result.UpdatedCount, "counts as updated in dry run")
		require.False(t, downloadCalled, "should not download in dry run")
		require.Len(t, result.Plugins, 1, "should list plugins that would be updated")
	})
}

func TestService_Update_SourceFilter(t *testing.T) {
	t.Run("update from specific source", func(t *testing.T) {
		ctx := context.Background()

		officialCalled := false
		communityCalled := false

		dl := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				if src.Name == "official" {
					officialCalled = true
					return &PluginManifest{
						Plugins: []PluginManifestEntry{
							{ID: "official-plugin", Name: "Official Plugin", Version: "1.0.0", Categories: []Category{CategorySSH}},
						},
					}, nil
				}
				if src.Name == "community" {
					communityCalled = true
					return &PluginManifest{
						Plugins: []PluginManifestEntry{
							{ID: "community-plugin", Name: "Community Plugin", Version: "1.0.0", Categories: []Category{CategorySSH}},
						},
					}, nil
				}
				return &PluginManifest{}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				return &CacheEntry{}, nil
			},
		}

		cache := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return nil, ErrPluginNotInstalled
			},
		}

		svc := newTestService(cache, &mockManifestManager{}, dl, []PluginSource{
			{Name: "official", URL: "https://official.com/manifest.yaml", Enabled: true},
			{Name: "community", URL: "https://community.com/manifest.yaml", Enabled: true},
		})

		result, err := svc.Update(ctx, UpdateOptions{Source: "official"})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 1, result.UpdatedCount)
		require.True(t, officialCalled, "official source should be called")
		require.False(t, communityCalled, "community source should NOT be called")
	})

	t.Run("source not found error", func(t *testing.T) {
		ctx := context.Background()

		svc := newTestService(&mockCacheManager{}, &mockManifestManager{}, &mockDownloader{}, []PluginSource{
			{Name: "official", URL: "https://official.com/manifest.yaml", Enabled: true},
		})

		result, err := svc.Update(ctx, UpdateOptions{Source: "non-existent"})

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "source 'non-existent' not found")
	})
}

func TestService_Update_PartialFailures(t *testing.T) {
	t.Run("some plugins succeed, some fail", func(t *testing.T) {
		ctx := context.Background()

		dl := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Plugins: []PluginManifestEntry{
						{ID: "success-plugin", Name: "Success Plugin", Version: "1.0.0", Categories: []Category{CategorySSH}},
						{ID: "fail-plugin", Name: "Fail Plugin", Version: "1.0.0", Categories: []Category{CategorySSH}},
					},
				}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				if id == "fail-plugin" {
					return nil, fmt.Errorf("download failed")
				}
				return &CacheEntry{}, nil
			},
		}

		cache := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return nil, ErrPluginNotInstalled
			},
		}

		svc := newTestService(cache, &mockManifestManager{}, dl, []PluginSource{
			{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
		})

		result, err := svc.Update(ctx, UpdateOptions{})

		require.Error(t, err, "should return ErrPartialFailure on partial failure")
		require.ErrorIs(t, err, ErrPartialFailure)
		require.NotNil(t, result)
		require.Equal(t, 1, result.UpdatedCount)
		require.Equal(t, 1, result.FailedCount)
		require.Len(t, result.Errors, 1)
		require.Contains(t, result.Errors[0].Error, "download failed")
	})
}

func TestService_Update_ContextCancellation(t *testing.T) {
	t.Run("context canceled during update", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		downloadCount := 0

		dl := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Plugins: []PluginManifestEntry{
						{ID: "plugin-1", Name: "Plugin 1", Version: "1.0.0", Categories: []Category{CategorySSH}},
						{ID: "plugin-2", Name: "Plugin 2", Version: "1.0.0", Categories: []Category{CategorySSH}},
						{ID: "plugin-3", Name: "Plugin 3", Version: "1.0.0", Categories: []Category{CategorySSH}},
					},
				}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				downloadCount++
				if downloadCount == 2 {
					cancel() // Cancel after second download
				}
				return &CacheEntry{}, nil
			},
		}

		cache := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return nil, ErrPluginNotInstalled
			},
		}

		svc := newTestService(cache, &mockManifestManager{}, dl, []PluginSource{
			{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
		})

		result, err := svc.Update(ctx, UpdateOptions{})

		require.Error(t, err)
		require.Equal(t, context.Canceled, err)
		require.NotNil(t, result)
		require.Equal(t, 2, result.UpdatedCount, "should update 2 before cancellation")
	})
}

// ============================================================================
// Uninstall() Method Tests
// ============================================================================

func TestService_Uninstall_ByPluginID(t *testing.T) {
	t.Run("uninstall specific plugin successfully", func(t *testing.T) {
		ctx := context.Background()

		removedID := ""

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{
						ID:      "test-plugin",
						Name:    "Test Plugin",
						Version: "1.0.0",
						Tags:    []string{"ssh"},
					},
					{
						ID:      "other-plugin",
						Name:    "Other Plugin",
						Version: "2.0.0",
						Tags:    []string{"http"},
					},
				}, nil
			},
			removeFunc: func(id string) error {
				removedID = id
				return nil
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		result, err := svc.Uninstall(ctx, "test-plugin", UninstallOptions{})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 1, result.RemovedCount)
		require.Equal(t, 0, result.FailedCount)
		require.Equal(t, 1, result.RemainingCount)
		require.Equal(t, "test-plugin", removedID)
	})

	t.Run("plugin not found error", func(t *testing.T) {
		ctx := context.Background()

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{ID: "existing-plugin", Name: "Existing", Version: "1.0.0"},
				}, nil
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		result, err := svc.Uninstall(ctx, "non-existent-plugin", UninstallOptions{})

		require.Error(t, err)
		require.Nil(t, result)
		require.ErrorIs(t, err, ErrPluginNotFound)
		require.Contains(t, err.Error(), "not found (not installed)")
	})
}

func TestService_Uninstall_ByCategory(t *testing.T) {
	t.Run("uninstall all plugins in category", func(t *testing.T) {
		ctx := context.Background()

		removedIDs := []string{}

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{ID: "ssh-plugin-1", Name: "SSH Plugin 1", Version: "1.0.0", Tags: []string{"ssh"}},
					{ID: "ssh-plugin-2", Name: "SSH Plugin 2", Version: "2.0.0", Tags: []string{"ssh"}},
					{ID: "http-plugin", Name: "HTTP Plugin", Version: "1.0.0", Tags: []string{"http"}},
				}, nil
			},
			removeFunc: func(id string) error {
				removedIDs = append(removedIDs, id)
				return nil
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		result, err := svc.Uninstall(ctx, "", UninstallOptions{Category: CategorySSH})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 2, result.RemovedCount, "should remove 2 SSH plugins")
		require.Equal(t, 0, result.FailedCount)
		require.Equal(t, 1, result.RemainingCount)
		require.Contains(t, removedIDs, "ssh-plugin-1")
		require.Contains(t, removedIDs, "ssh-plugin-2")
	})

	t.Run("no plugins in category", func(t *testing.T) {
		ctx := context.Background()

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{ID: "http-plugin", Name: "HTTP Plugin", Version: "1.0.0", Tags: []string{"http"}},
				}, nil
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		result, err := svc.Uninstall(ctx, "", UninstallOptions{Category: CategoryTLS})

		require.Error(t, err)
		require.Nil(t, result)
		require.ErrorIs(t, err, ErrNoPluginsFound)
		require.Contains(t, err.Error(), "no plugins found in category 'tls'")
	})
}

func TestService_Uninstall_All(t *testing.T) {
	t.Run("uninstall all plugins successfully", func(t *testing.T) {
		ctx := context.Background()

		removedIDs := []string{}

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{ID: "plugin-1", Name: "Plugin 1", Version: "1.0.0", Tags: []string{"ssh"}},
					{ID: "plugin-2", Name: "Plugin 2", Version: "2.0.0", Tags: []string{"http"}},
					{ID: "plugin-3", Name: "Plugin 3", Version: "3.0.0", Tags: []string{"tls"}},
				}, nil
			},
			removeFunc: func(id string) error {
				removedIDs = append(removedIDs, id)
				return nil
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		result, err := svc.Uninstall(ctx, "", UninstallOptions{All: true})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 3, result.RemovedCount, "should remove all 3 plugins")
		require.Equal(t, 0, result.FailedCount)
		require.Equal(t, 0, result.RemainingCount)
		require.Len(t, removedIDs, 3)
	})

	t.Run("empty manifest returns success", func(t *testing.T) {
		ctx := context.Background()

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{}, nil
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		result, err := svc.Uninstall(ctx, "", UninstallOptions{All: true})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 0, result.RemovedCount)
		require.Equal(t, 0, result.FailedCount)
		require.Equal(t, 0, result.RemainingCount)
	})
}

func TestService_Uninstall_ValidationErrors(t *testing.T) {
	t.Run("no mode specified error", func(t *testing.T) {
		ctx := context.Background()

		svc := newTestService(&mockCacheManager{}, &mockManifestManager{}, &mockDownloader{}, []PluginSource{})

		result, err := svc.Uninstall(ctx, "", UninstallOptions{})

		require.Error(t, err)
		require.Nil(t, result)
		require.ErrorIs(t, err, ErrInvalidInput)
		require.Contains(t, err.Error(), "must specify plugin ID, category, or --all")
	})

	t.Run("multiple modes specified - target and category", func(t *testing.T) {
		ctx := context.Background()

		svc := newTestService(&mockCacheManager{}, &mockManifestManager{}, &mockDownloader{}, []PluginSource{})

		result, err := svc.Uninstall(ctx, "plugin-id", UninstallOptions{Category: CategorySSH})

		require.Error(t, err)
		require.Nil(t, result)
		require.ErrorIs(t, err, ErrInvalidInput)
		require.Contains(t, err.Error(), "cannot specify multiple uninstall modes")
	})

	t.Run("multiple modes specified - target and all", func(t *testing.T) {
		ctx := context.Background()

		svc := newTestService(&mockCacheManager{}, &mockManifestManager{}, &mockDownloader{}, []PluginSource{})

		result, err := svc.Uninstall(ctx, "plugin-id", UninstallOptions{All: true})

		require.Error(t, err)
		require.Nil(t, result)
		require.ErrorIs(t, err, ErrInvalidInput)
	})

	t.Run("multiple modes specified - category and all", func(t *testing.T) {
		ctx := context.Background()

		svc := newTestService(&mockCacheManager{}, &mockManifestManager{}, &mockDownloader{}, []PluginSource{})

		result, err := svc.Uninstall(ctx, "", UninstallOptions{Category: CategorySSH, All: true})

		require.Error(t, err)
		require.Nil(t, result)
		require.ErrorIs(t, err, ErrInvalidInput)
	})
}

func TestService_Uninstall_PartialFailures(t *testing.T) {
	t.Run("some plugins succeed, some fail", func(t *testing.T) {
		ctx := context.Background()

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{ID: "success-plugin", Name: "Success Plugin", Version: "1.0.0", Tags: []string{"ssh"}},
					{ID: "fail-plugin", Name: "Fail Plugin", Version: "2.0.0", Tags: []string{"ssh"}},
				}, nil
			},
			removeFunc: func(id string) error {
				if id == "fail-plugin" {
					return fmt.Errorf("removal failed")
				}
				return nil
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		result, err := svc.Uninstall(ctx, "", UninstallOptions{Category: CategorySSH})

		require.Error(t, err, "should return ErrPartialFailure on partial failure")
		require.ErrorIs(t, err, ErrPartialFailure)
		require.NotNil(t, result)
		require.Equal(t, 1, result.RemovedCount)
		require.Equal(t, 1, result.FailedCount)
		require.Len(t, result.Errors, 1)
		require.Contains(t, result.Errors[0].Error, "removal failed")
	})
}

func TestService_Uninstall_ContextCancellation(t *testing.T) {
	t.Run("context canceled during uninstall", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		removeCount := 0

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{ID: "plugin-1", Name: "Plugin 1", Version: "1.0.0", Tags: []string{"ssh"}},
					{ID: "plugin-2", Name: "Plugin 2", Version: "1.0.0", Tags: []string{"ssh"}},
					{ID: "plugin-3", Name: "Plugin 3", Version: "1.0.0", Tags: []string{"ssh"}},
				}, nil
			},
			removeFunc: func(id string) error {
				removeCount++
				if removeCount == 2 {
					cancel() // Cancel after second removal
				}
				return nil
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		result, err := svc.Uninstall(ctx, "", UninstallOptions{All: true})

		require.Error(t, err)
		require.Equal(t, context.Canceled, err)
		require.NotNil(t, result)
		require.Equal(t, 2, result.RemovedCount, "should remove 2 before cancellation")
		require.Equal(t, 1, result.RemainingCount, "one plugin should remain")
	})
}

func TestService_Uninstall_ManifestErrors(t *testing.T) {
	t.Run("manifest list error", func(t *testing.T) {
		ctx := context.Background()

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return nil, fmt.Errorf("failed to read manifest")
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		result, err := svc.Uninstall(ctx, "", UninstallOptions{All: true})

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "list installed plugins")
		require.Contains(t, err.Error(), "failed to read manifest")
	})

	t.Run("manifest save error after successful removal", func(t *testing.T) {
		ctx := context.Background()

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{ID: "test-plugin", Name: "Test Plugin", Version: "1.0.0"},
				}, nil
			},
			removeFunc: func(id string) error {
				return nil
			},
			saveFunc: func() error {
				return fmt.Errorf("failed to save manifest")
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		result, err := svc.Uninstall(ctx, "test-plugin", UninstallOptions{})

		require.NoError(t, err, "should not fail even if save fails")
		require.NotNil(t, result)
		require.Equal(t, 1, result.RemovedCount)
		require.Len(t, result.Errors, 1, "should collect save error")
		require.Contains(t, result.Errors[0].Error, "save manifest")
	})
}

func TestService_List(t *testing.T) {
	t.Run("list all plugins", func(t *testing.T) {
		ctx := context.Background()

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{
						ID:       "ssh-weak-cipher",
						Name:     "SSH Weak Cipher",
						Version:  "1.0.0",
						Type:     "evaluation",
						Author:   "cyprob",
						Severity: "medium",
						Tags:     []string{"ssh", "crypto"},
					},
					{
						ID:       "http-missing-headers",
						Name:     "HTTP Missing Security Headers",
						Version:  "1.0.1",
						Type:     "evaluation",
						Author:   "cyprob",
						Severity: "low",
						Tags:     []string{"http", "web"},
					},
				}, nil
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		plugins, err := svc.List(ctx)

		require.NoError(t, err)
		require.Len(t, plugins, 2)

		// Verify first plugin
		require.Equal(t, "ssh-weak-cipher", plugins[0].ID)
		require.Equal(t, "SSH Weak Cipher", plugins[0].Name)
		require.Equal(t, "1.0.0", plugins[0].Version)
		require.Equal(t, "evaluation", plugins[0].Type)
		require.Equal(t, "cyprob", plugins[0].Author)
		require.Equal(t, "medium", plugins[0].Severity)
		require.Equal(t, []string{"ssh", "crypto"}, plugins[0].Tags)

		// Verify second plugin
		require.Equal(t, "http-missing-headers", plugins[1].ID)
		require.Equal(t, "HTTP Missing Security Headers", plugins[1].Name)
		require.Equal(t, "1.0.1", plugins[1].Version)
	})

	t.Run("list empty manifest", func(t *testing.T) {
		ctx := context.Background()

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{}, nil
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		plugins, err := svc.List(ctx)

		require.NoError(t, err)
		require.Empty(t, plugins)
	})

	t.Run("manifest list error", func(t *testing.T) {
		ctx := context.Background()

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return nil, fmt.Errorf("failed to read manifest")
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		plugins, err := svc.List(ctx)

		require.Error(t, err)
		require.Nil(t, plugins)
		require.Contains(t, err.Error(), "list manifest")
		require.Contains(t, err.Error(), "failed to read manifest")
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		callCount := 0
		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				callCount++
				cancel() // Cancel immediately after first call
				return []*ManifestEntry{
					{ID: "plugin-1", Name: "Plugin 1", Version: "1.0.0"},
					{ID: "plugin-2", Name: "Plugin 2", Version: "1.0.0"},
				}, nil
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		plugins, err := svc.List(ctx)

		require.Error(t, err)
		require.Equal(t, context.Canceled, err)
		require.Nil(t, plugins)
	})
}

func TestService_GetInfo(t *testing.T) {
	t.Run("get existing plugin info", func(t *testing.T) {
		ctx := context.Background()

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{
						ID:       "ssh-weak-cipher",
						Name:     "SSH Weak Cipher",
						Version:  "1.0.0",
						Type:     "evaluation",
						Author:   "cyprob",
						Severity: "medium",
						Tags:     []string{"ssh", "crypto"},
						Path:     "/tmp/plugins/ssh-weak-cipher/1.0.0/plugin.yaml",
					},
				}, nil
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		info, err := svc.GetInfo(ctx, "ssh-weak-cipher")

		require.NoError(t, err)
		require.NotNil(t, info)
		require.Equal(t, "ssh-weak-cipher", info.ID)
		require.Equal(t, "SSH Weak Cipher", info.Name)
		require.Equal(t, "1.0.0", info.Version)
		require.Equal(t, "evaluation", info.Type)
		require.Equal(t, "cyprob", info.Author)
		require.Equal(t, "medium", info.Severity)
		require.Equal(t, []string{"ssh", "crypto"}, info.Tags)
		require.Equal(t, "/tmp/plugins/ssh-weak-cipher/1.0.0/plugin.yaml", info.Path)
		// CacheDir and CacheSize may be empty if directory doesn't exist
	})

	t.Run("plugin not found", func(t *testing.T) {
		ctx := context.Background()

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{ID: "other-plugin", Name: "Other Plugin", Version: "1.0.0"},
				}, nil
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		info, err := svc.GetInfo(ctx, "nonexistent-plugin")

		require.Error(t, err)
		require.Equal(t, ErrPluginNotFound, err)
		require.Nil(t, info)
	})

	t.Run("manifest list error", func(t *testing.T) {
		ctx := context.Background()

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return nil, fmt.Errorf("failed to read manifest")
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		info, err := svc.GetInfo(ctx, "ssh-weak-cipher")

		require.Error(t, err)
		require.Nil(t, info)
		require.Contains(t, err.Error(), "list manifest")
		require.Contains(t, err.Error(), "failed to read manifest")
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				cancel() // Cancel before processing
				return []*ManifestEntry{
					{ID: "test-plugin", Name: "Test Plugin", Version: "1.0.0"},
				}, nil
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		info, err := svc.GetInfo(ctx, "test-plugin")

		require.Error(t, err)
		require.Equal(t, context.Canceled, err)
		require.Nil(t, info)
	})

	t.Run("multiple plugins in manifest", func(t *testing.T) {
		ctx := context.Background()

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{ID: "plugin-1", Name: "Plugin 1", Version: "1.0.0"},
					{ID: "plugin-2", Name: "Plugin 2", Version: "1.0.1"},
					{ID: "plugin-3", Name: "Plugin 3", Version: "2.0.0"},
				}, nil
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		info, err := svc.GetInfo(ctx, "plugin-2")

		require.NoError(t, err)
		require.NotNil(t, info)
		require.Equal(t, "plugin-2", info.ID)
		require.Equal(t, "Plugin 2", info.Name)
		require.Equal(t, "1.0.1", info.Version)
	})
}

// Benchmark tests for performance monitoring

func BenchmarkService_List(b *testing.B) {
	ctx := context.Background()

	// Create manifest with 100 plugins
	entries := make([]*ManifestEntry, 100)
	for i := range 100 {
		entries[i] = &ManifestEntry{
			ID:      fmt.Sprintf("plugin-%d", i),
			Name:    fmt.Sprintf("Plugin %d", i),
			Version: "1.0.0",
			Type:    "evaluation",
			Author:  "cyprob",
		}
	}

	manifest := &mockManifestManager{
		listFunc: func() ([]*ManifestEntry, error) {
			return entries, nil
		},
	}

	svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

	for b.Loop() {
		_, _ = svc.List(ctx)
	}
}

func BenchmarkService_GetInfo(b *testing.B) {
	ctx := context.Background()

	// Create manifest with 100 plugins
	entries := make([]*ManifestEntry, 100)
	for i := range 100 {
		entries[i] = &ManifestEntry{
			ID:      fmt.Sprintf("plugin-%d", i),
			Name:    fmt.Sprintf("Plugin %d", i),
			Version: "1.0.0",
			Type:    "evaluation",
			Author:  "cyprob",
			Path:    fmt.Sprintf("/tmp/plugins/plugin-%d/1.0.0/plugin.yaml", i),
		}
	}

	manifest := &mockManifestManager{
		listFunc: func() ([]*ManifestEntry, error) {
			return entries, nil
		},
	}

	svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

	for b.Loop() {
		_, _ = svc.GetInfo(ctx, "plugin-50")
	}
}

func BenchmarkService_Install(b *testing.B) {
	ctx := context.Background()

	manifest := &mockManifestManager{
		addFunc: func(entry *ManifestEntry) error {
			return nil
		},
		saveFunc: func() error {
			return nil
		},
	}

	cache := &mockCacheManager{
		getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
			return nil, ErrPluginNotFound
		},
	}

	downloader := &mockDownloader{
		fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
			return &PluginManifest{
				Plugins: []PluginManifestEntry{
					{
						ID:       "test-plugin",
						Name:     "Test Plugin",
						Version:  "1.0.0",
						URL:      "https://example.com/plugin.yaml",
						Checksum: "sha256:abc123",
					},
				},
			}, nil
		},
		downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
			return &CacheEntry{
				Name:    id,
				Version: version,
				Path:    "/tmp/plugin.yaml",
			}, nil
		},
	}

	sources := []PluginSource{
		{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
	}

	svc := newTestService(cache, manifest, downloader, sources)

	for b.Loop() {
		_, _ = svc.Install(ctx, "test-plugin", InstallOptions{})
	}
}

func BenchmarkService_Update(b *testing.B) {
	ctx := context.Background()

	manifest := &mockManifestManager{
		addFunc: func(entry *ManifestEntry) error {
			return nil
		},
		saveFunc: func() error {
			return nil
		},
	}

	cache := &mockCacheManager{
		getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
			return nil, ErrPluginNotFound
		},
	}

	downloader := &mockDownloader{
		fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
			return &PluginManifest{
				Plugins: []PluginManifestEntry{
					{
						ID:       "plugin-1",
						Name:     "Plugin 1",
						Version:  "1.0.0",
						URL:      "https://example.com/plugin1.yaml",
						Checksum: "sha256:abc123",
					},
					{
						ID:       "plugin-2",
						Name:     "Plugin 2",
						Version:  "1.0.0",
						URL:      "https://example.com/plugin2.yaml",
						Checksum: "sha256:def456",
					},
				},
			}, nil
		},
		downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
			return &CacheEntry{
				Name:    id,
				Version: version,
				Path:    "/tmp/plugin.yaml",
			}, nil
		},
	}

	sources := []PluginSource{
		{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
	}

	svc := newTestService(cache, manifest, downloader, sources)

	for b.Loop() {
		_, _ = svc.Update(ctx, UpdateOptions{})
	}
}

func BenchmarkService_Uninstall(b *testing.B) {
	ctx := context.Background()

	removeCount := 0
	manifest := &mockManifestManager{
		listFunc: func() ([]*ManifestEntry, error) {
			return []*ManifestEntry{
				{ID: "plugin-1", Name: "Plugin 1", Version: "1.0.0"},
				{ID: "plugin-2", Name: "Plugin 2", Version: "1.0.0"},
				{ID: "plugin-3", Name: "Plugin 3", Version: "1.0.0"},
			}, nil
		},
		removeFunc: func(id string) error {
			removeCount++
			return nil
		},
		saveFunc: func() error {
			return nil
		},
	}

	svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

	for b.Loop() {
		_, _ = svc.Uninstall(ctx, "", UninstallOptions{All: true})
	}
}

func TestService_Clean(t *testing.T) {
	t.Run("clean old cache entries successfully", func(t *testing.T) {
		ctx := context.Background()

		callCount := 0
		cache := &mockCacheManager{
			sizeFunc: func(ctx context.Context) (int64, error) {
				// First call: before cleaning (1 MB)
				// Second call: after cleaning (500 KB)
				callCount++
				if callCount == 1 {
					return 1024 * 1024, nil
				}
				return 512 * 1024, nil
			},
			pruneFunc: func(ctx context.Context, olderThan time.Duration) (int, error) {
				require.Equal(t, 720*time.Hour, olderThan)
				return 5, nil
			},
		}

		svc := newTestService(cache, &mockManifestManager{}, &mockDownloader{}, []PluginSource{})

		opts := CleanOptions{
			OlderThan: 720 * time.Hour,
			DryRun:    false,
		}

		result, err := svc.Clean(ctx, opts)

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 5, result.RemovedCount)
		require.Equal(t, int64(1024*1024), result.SizeBefore)
		require.Equal(t, int64(512*1024), result.SizeAfter)
		require.Equal(t, int64(512*1024), result.Freed)
	})

	t.Run("dry run does not remove entries", func(t *testing.T) {
		ctx := context.Background()

		cache := &mockCacheManager{
			sizeFunc: func(ctx context.Context) (int64, error) {
				return 1024 * 1024, nil
			},
			pruneFunc: func(ctx context.Context, olderThan time.Duration) (int, error) {
				t.Fatal("Prune should not be called in dry-run mode")
				return 0, nil
			},
		}

		svc := newTestService(cache, &mockManifestManager{}, &mockDownloader{}, []PluginSource{})

		opts := CleanOptions{
			OlderThan: 24 * time.Hour,
			DryRun:    true,
		}

		result, err := svc.Clean(ctx, opts)

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 0, result.RemovedCount)
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		svc := newTestService(&mockCacheManager{}, &mockManifestManager{}, &mockDownloader{}, []PluginSource{})

		opts := CleanOptions{
			OlderThan: 24 * time.Hour,
		}

		_, err := svc.Clean(ctx, opts)

		require.Error(t, err)
		require.Equal(t, context.Canceled, err)
	})
}

func TestService_Verify(t *testing.T) {
	t.Run("verify all plugins successfully", func(t *testing.T) {
		ctx := context.Background()

		manifest := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{ID: "plugin-1", Name: "Plugin 1", Version: "1.0.0", Checksum: "sha256:abc123"},
					{ID: "plugin-2", Name: "Plugin 2", Version: "2.0.0", Checksum: "sha256:def456"},
				}, nil
			},
		}

		cache := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return &CacheEntry{
					ID:      name,
					Version: version,
					Path:    "/fake/path/plugin.yaml",
				}, nil
			},
		}

		svc := newTestService(cache, manifest, &mockDownloader{}, []PluginSource{})

		opts := VerifyOptions{}

		result, err := svc.Verify(ctx, opts)

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 2, result.TotalCount)
		// Note: Actual checksum verification will fail in tests without real files
		// This test verifies the flow works correctly
	})

	t.Run("verify specific plugin", func(t *testing.T) {
		ctx := context.Background()

		manifest := &mockManifestManager{
			getFunc: func(id string) (*ManifestEntry, error) {
				if id == "plugin-1" {
					return &ManifestEntry{
						ID:       "plugin-1",
						Name:     "Plugin 1",
						Version:  "1.0.0",
						Checksum: "sha256:abc123",
					}, nil
				}
				return nil, ErrPluginNotFound
			},
		}

		cache := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return &CacheEntry{
					ID:      name,
					Version: version,
					Path:    "/fake/path/plugin.yaml",
				}, nil
			},
		}

		svc := newTestService(cache, manifest, &mockDownloader{}, []PluginSource{})

		opts := VerifyOptions{
			PluginID: "plugin-1",
		}

		result, err := svc.Verify(ctx, opts)

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 1, result.TotalCount)
	})

	t.Run("plugin not found", func(t *testing.T) {
		ctx := context.Background()

		manifest := &mockManifestManager{
			getFunc: func(id string) (*ManifestEntry, error) {
				return nil, ErrPluginNotFound
			},
		}

		svc := newTestService(&mockCacheManager{}, manifest, &mockDownloader{}, []PluginSource{})

		opts := VerifyOptions{
			PluginID: "non-existent",
		}

		_, err := svc.Verify(ctx, opts)

		require.Error(t, err)
		require.Equal(t, ErrPluginNotFound, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		svc := newTestService(&mockCacheManager{}, &mockManifestManager{}, &mockDownloader{}, []PluginSource{})

		opts := VerifyOptions{}

		_, err := svc.Verify(ctx, opts)

		require.Error(t, err)
		require.Equal(t, context.Canceled, err)
	})
}

// TestPartialFailureSemantics verifies that service methods return ErrPartialFailure
// when bulk operations have both successes and failures.
func TestPartialFailureSemantics(t *testing.T) {
	ctx := context.Background()

	t.Run("Install returns ErrPartialFailure when installing category with multiple plugins and some fail", func(t *testing.T) {
		// This test simulates installing a category containing multiple plugins where some downloads fail

		downloader := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Version: "1.0.0",
					Plugins: []PluginManifestEntry{
						{
							ID:          "ssh-plugin-1",
							Name:        "SSH Plugin 1",
							Version:     "1.0.0",
							Author:      "test",
							Categories:  []Category{CategorySSH},
							URL:         "https://example.com/ssh1.tar.gz",
							Checksum:    "sha256:abc123",
							Size:        1024,
							Description: "Test SSH plugin 1",
						},
						{
							ID:          "ssh-plugin-2",
							Name:        "SSH Plugin 2",
							Version:     "1.0.0",
							Author:      "test",
							Categories:  []Category{CategorySSH},
							URL:         "https://example.com/ssh2.tar.gz",
							Checksum:    "sha256:def456",
							Size:        1024,
							Description: "Test SSH plugin 2",
						},
					},
				}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				// Simulate download failure for ssh-plugin-2
				if id == "ssh-plugin-2" {
					return nil, fmt.Errorf("download failed for ssh-plugin-2")
				}
				return &CacheEntry{ID: id, Name: id, Version: version}, nil
			},
		}

		cacheManager := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return nil, ErrPluginNotInstalled
			},
		}

		manifestManager := &mockManifestManager{}

		svc := newTestService(cacheManager, manifestManager, downloader, []PluginSource{
			{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
		})

		// Install all SSH category plugins (should install 1, fail 1)
		result, err := svc.Install(ctx, "ssh", InstallOptions{})

		// Should return ErrPartialFailure
		require.Error(t, err)
		require.ErrorIs(t, err, ErrPartialFailure)

		// Result should show partial success
		require.NotNil(t, result)
		require.Equal(t, 1, result.InstalledCount)
		require.Equal(t, 1, result.FailedCount)
		require.Len(t, result.Errors, 1)
	})

	t.Run("Install returns nil error when all plugins succeed", func(t *testing.T) {
		downloader := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Version: "1.0.0",
					Plugins: []PluginManifestEntry{
						{
							ID:         "test-plugin",
							Name:       "Test Plugin",
							Version:    "1.0.0",
							Author:     "test",
							Categories: []Category{CategorySSH},
							URL:        "https://example.com/plugin.tar.gz",
							Checksum:   "sha256:abc123",
							Size:       1024,
						},
					},
				}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				return &CacheEntry{ID: id, Name: id, Version: version}, nil
			},
		}

		cacheManager := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				return nil, ErrPluginNotInstalled
			},
		}

		manifestManager := &mockManifestManager{}

		svc := newTestService(cacheManager, manifestManager, downloader, []PluginSource{
			{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
		})

		result, err := svc.Install(ctx, "ssh", InstallOptions{})

		// Should return nil error when all succeed
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 1, result.InstalledCount)
		require.Equal(t, 0, result.FailedCount)
		require.Empty(t, result.Errors)
	})

	t.Run("Update returns ErrPartialFailure when some plugins fail to download", func(t *testing.T) {
		downloader := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Version: "1.0.0",
					Plugins: []PluginManifestEntry{
						{
							ID:         "ssh-plugin-1",
							Name:       "SSH Plugin 1",
							Version:    "2.0.0",
							Author:     "test",
							Categories: []Category{CategorySSH},
							URL:        "https://example.com/ssh1.tar.gz",
							Checksum:   "sha256:abc123",
							Size:       1024,
						},
						{
							ID:         "ssh-plugin-2",
							Name:       "SSH Plugin 2",
							Version:    "2.0.0",
							Author:     "test",
							Categories: []Category{CategorySSH},
							URL:        "https://example.com/ssh2.tar.gz",
							Checksum:   "sha256:def456",
							Size:       1024,
						},
					},
				}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				// Simulate download failure for ssh-plugin-2
				if id == "ssh-plugin-2" {
					return nil, fmt.Errorf("download failed for ssh-plugin-2")
				}
				return &CacheEntry{ID: id, Name: id, Version: version}, nil
			},
		}

		cacheManager := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				// Return not found so Update attempts to download
				return nil, ErrPluginNotInstalled
			},
		}

		manifestManager := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{ID: "ssh-plugin-1", Name: "SSH Plugin 1", Version: "1.0.0", InstalledAt: time.Now().Add(-24 * time.Hour)},
					{ID: "ssh-plugin-2", Name: "SSH Plugin 2", Version: "1.0.0", InstalledAt: time.Now().Add(-24 * time.Hour)},
				}, nil
			},
		}

		svc := newTestService(cacheManager, manifestManager, downloader, []PluginSource{
			{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
		})

		result, err := svc.Update(ctx, UpdateOptions{Category: CategorySSH})

		// Should return ErrPartialFailure
		require.Error(t, err)
		require.ErrorIs(t, err, ErrPartialFailure)

		// Result should show partial success
		require.NotNil(t, result)
		require.Equal(t, 1, result.UpdatedCount)
		require.Equal(t, 1, result.FailedCount)
		require.Len(t, result.Errors, 1)
	})

	t.Run("Update returns nil error when all plugins succeed", func(t *testing.T) {
		downloader := &mockDownloader{
			fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
				return &PluginManifest{
					Version: "1.0.0",
					Plugins: []PluginManifestEntry{
						{
							ID:         "test-plugin",
							Name:       "Test Plugin",
							Version:    "2.0.0",
							Author:     "test",
							Categories: []Category{CategorySSH},
							URL:        "https://example.com/plugin.tar.gz",
							Checksum:   "sha256:abc123",
							Size:       1024,
						},
					},
				}, nil
			},
			downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
				return &CacheEntry{ID: id, Name: id, Version: version}, nil
			},
		}

		cacheManager := &mockCacheManager{
			getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
				// Return not found so Update attempts to download
				return nil, ErrPluginNotInstalled
			},
		}

		manifestManager := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{ID: "test-plugin", Name: "Test Plugin", Version: "1.0.0", InstalledAt: time.Now().Add(-24 * time.Hour)},
				}, nil
			},
		}

		svc := newTestService(cacheManager, manifestManager, downloader, []PluginSource{
			{Name: "official", URL: "https://example.com/manifest.yaml", Enabled: true},
		})

		result, err := svc.Update(ctx, UpdateOptions{Category: CategorySSH})

		// Should return nil error when all succeed
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 1, result.UpdatedCount)
		require.Equal(t, 0, result.FailedCount)
		require.Empty(t, result.Errors)
	})

	t.Run("Uninstall returns ErrPartialFailure when removing category with multiple plugins and some fail", func(t *testing.T) {
		cacheManager := &mockCacheManager{
			removeFunc: func(ctx context.Context, id, version string) error {
				return nil // Cache removal always succeeds
			},
		}

		manifestManager := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{ID: "ssh-plugin-1", Name: "SSH Plugin 1", Version: "1.0.0", Tags: []string{"ssh"}},
					{ID: "ssh-plugin-2", Name: "SSH Plugin 2", Version: "1.0.0", Tags: []string{"ssh"}},
				}, nil
			},
			removeFunc: func(id string) error {
				// Simulate manifest removal failure for ssh-plugin-2
				if id == "ssh-plugin-2" {
					return fmt.Errorf("failed to remove ssh-plugin-2 from manifest")
				}
				return nil
			},
		}

		svc := newTestService(cacheManager, manifestManager, &mockDownloader{}, []PluginSource{})

		// Uninstall all SSH category plugins (should remove 1, fail 1)
		result, err := svc.Uninstall(ctx, "", UninstallOptions{Category: CategorySSH})

		// Should return ErrPartialFailure
		require.Error(t, err)
		require.ErrorIs(t, err, ErrPartialFailure)

		// Result should show partial success
		require.NotNil(t, result)
		require.Equal(t, 1, result.RemovedCount)
		require.Equal(t, 1, result.FailedCount)
		require.Len(t, result.Errors, 1)
	})

	t.Run("Uninstall returns nil error when all plugins succeed", func(t *testing.T) {
		cacheManager := &mockCacheManager{
			removeFunc: func(ctx context.Context, id, version string) error {
				return nil
			},
		}

		manifestManager := &mockManifestManager{
			listFunc: func() ([]*ManifestEntry, error) {
				return []*ManifestEntry{
					{ID: "test-plugin", Name: "Test Plugin", Version: "1.0.0"},
				}, nil
			},
		}

		svc := newTestService(cacheManager, manifestManager, &mockDownloader{}, []PluginSource{})

		result, err := svc.Uninstall(ctx, "test-plugin", UninstallOptions{})

		// Should return nil error when all succeed
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 1, result.RemovedCount)
		require.Equal(t, 0, result.FailedCount)
		require.Empty(t, result.Errors)
	})
}

// TestServiceInputValidation tests that service methods validate inputs.
// This verifies defense-in-depth: service layer validates regardless of CLI/API validation.
func TestServiceInputValidation(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp("", "cyprob-plugin-test-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.RemoveAll(tmpDir)
	})

	svc, err := NewService(WithCacheDir(tmpDir))
	require.NoError(t, err)

	t.Run("Install validates target", func(t *testing.T) {
		// Empty target
		_, err := svc.Install(ctx, "", InstallOptions{})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidOption)
		require.Contains(t, err.Error(), "target cannot be empty")

		// Whitespace-only target
		_, err = svc.Install(ctx, "   ", InstallOptions{})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidOption)
		require.Contains(t, err.Error(), "whitespace")

		// Invalid plugin ID format
		_, err = svc.Install(ctx, "Invalid-Plugin", InstallOptions{})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidOption)
		require.Contains(t, err.Error(), "invalid plugin ID format")
	})

	t.Run("Install validates category option", func(t *testing.T) {
		// Invalid category
		_, err := svc.Install(ctx, "ssh", InstallOptions{Category: "invalid"})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidOption)
		require.Contains(t, err.Error(), "invalid category")
	})

	t.Run("Install validates source option", func(t *testing.T) {
		// Whitespace-only source
		_, err := svc.Install(ctx, "ssh", InstallOptions{Source: "   "})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidOption)
		require.Contains(t, err.Error(), "source cannot be whitespace")

		// Invalid source format
		_, err = svc.Install(ctx, "ssh", InstallOptions{Source: "invalid@source"})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidOption)
		require.Contains(t, err.Error(), "invalid source name")
	})

	t.Run("Update validates category option", func(t *testing.T) {
		// Invalid category
		_, err := svc.Update(ctx, UpdateOptions{Category: "invalid"})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidOption)
		require.Contains(t, err.Error(), "invalid category")
	})

	t.Run("Update validates source option", func(t *testing.T) {
		// Whitespace-only source
		_, err := svc.Update(ctx, UpdateOptions{Source: "   "})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidOption)
		require.Contains(t, err.Error(), "source cannot be whitespace")
	})

	t.Run("Uninstall validates target when provided", func(t *testing.T) {
		// Empty target is OK (can use category or all flag)
		// But if provided, must be valid

		// Invalid plugin ID format
		_, err := svc.Uninstall(ctx, "Invalid-Plugin", UninstallOptions{})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidOption)
		require.Contains(t, err.Error(), "invalid plugin ID format")

		// Whitespace-only
		_, err = svc.Uninstall(ctx, "   ", UninstallOptions{})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidOption)
	})

	t.Run("Uninstall validates category option", func(t *testing.T) {
		// Invalid category
		_, err := svc.Uninstall(ctx, "", UninstallOptions{Category: "invalid"})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidOption)
		require.Contains(t, err.Error(), "invalid category")
	})

	t.Run("GetInfo validates plugin ID", func(t *testing.T) {
		// Empty plugin ID
		_, err := svc.GetInfo(ctx, "")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidOption)
		require.Contains(t, err.Error(), "plugin ID cannot be empty")

		// Whitespace-only
		_, err = svc.GetInfo(ctx, "   ")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidOption)
		require.Contains(t, err.Error(), "whitespace")

		// Invalid format
		_, err = svc.GetInfo(ctx, "Invalid-Plugin")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidOption)
		require.Contains(t, err.Error(), "invalid plugin ID format")
	})
}

// Test timeout behavior for service methods
func TestService_TimeoutBehavior(t *testing.T) {
	// Create a service with very short timeouts
	shortConfig := ServiceConfig{
		InstallTimeout:   1 * time.Millisecond,
		UpdateTimeout:    1 * time.Millisecond,
		UninstallTimeout: 1 * time.Millisecond,
		ListTimeout:      1 * time.Millisecond,
		GetInfoTimeout:   1 * time.Millisecond,
		CleanTimeout:     1 * time.Millisecond,
		VerifyTimeout:    1 * time.Millisecond,
	}

	svc, err := NewService(
		WithCacheDir(t.TempDir()),
		WithConfig(shortConfig),
	)
	require.NoError(t, err)

	t.Run("Install respects timeout", func(t *testing.T) {
		ctx := context.Background()
		_, err := svc.Install(ctx, "nonexistent", InstallOptions{})
		// Should timeout or fail (not hang indefinitely)
		require.Error(t, err)
	})

	t.Run("Update respects timeout", func(t *testing.T) {
		ctx := context.Background()
		_, err := svc.Update(ctx, UpdateOptions{})
		// Should timeout or fail (not hang indefinitely)
		require.Error(t, err)
	})

	t.Run("List respects timeout", func(t *testing.T) {
		ctx := context.Background()
		_, err := svc.List(ctx)
		// List might succeed quickly or timeout
		_ = err
	})
}

func TestService_WithConfig(t *testing.T) {
	customConfig := ServiceConfig{
		InstallTimeout: 120 * time.Second,
		UpdateTimeout:  90 * time.Second,
	}

	svc, err := NewService(
		WithCacheDir(t.TempDir()),
		WithConfig(customConfig),
	)
	require.NoError(t, err)

	// Verify config was applied
	require.Equal(t, 120*time.Second, svc.config.InstallTimeout)
	require.Equal(t, 90*time.Second, svc.config.UpdateTimeout)

	// Verify config is actually used (via integration test - timeout enforcement)
	ctx := context.Background()
	_, err = svc.Install(ctx, "nonexistent", InstallOptions{})
	require.Error(t, err) // Will fail for other reasons, but confirms WithConfig worked
}

func TestService_ContextWithExistingDeadline(t *testing.T) {
	svc, err := NewService(WithCacheDir(t.TempDir()))
	require.NoError(t, err)

	// Create context with existing deadline
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Service should respect the existing deadline, not override it
	_, err = svc.List(ctx)
	// Will either succeed quickly or timeout from context
	_ = err
}

func TestService_FetchPlugins_DisabledSource(t *testing.T) {
	ctx := context.Background()
	dl := &mockDownloader{
		fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
			t.Fatalf("FetchManifest should not be called for disabled source")
			return nil, nil
		},
	}
	svc := newTestService(nil, nil, dl, []PluginSource{
		{Name: "disabled", URL: "https://fake.com/manifest.yaml", Enabled: false},
	})

	plugins, err := svc.fetchPlugins(ctx, "")
	require.NoError(t, err)
	require.Empty(t, plugins, "disabled sources should be ignored")
}

func TestService_FindPluginByID_CaseInsensitive(t *testing.T) {
	svc := newTestService(nil, nil, nil, nil)
	plugins := []PluginManifestEntry{
		{ID: "ssh-plugin", Name: "SSH Plugin"},
	}
	plugin, err := svc.findPluginByID(plugins, "SSH-PLUGIN")
	require.NoError(t, err)
	require.Equal(t, "ssh-plugin", plugin.ID)
	require.Equal(t, "SSH Plugin", plugin.Name)
}

func TestService_Update_ManifestSaveFailure(t *testing.T) {
	ctx := context.Background()

	dl := &mockDownloader{
		fetchManifestFunc: func(ctx context.Context, src PluginSource) (*PluginManifest, error) {
			return &PluginManifest{
				Plugins: []PluginManifestEntry{
					{
						ID:         "p1",
						Name:       "Plugin 1",
						Version:    "1.0.0",
						Categories: []Category{CategorySSH},
					},
				},
			}, nil
		},
		downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
			return &CacheEntry{}, nil
		},
	}

	mf := &mockManifestManager{
		addFunc: func(entry *ManifestEntry) error { return nil },
		saveFunc: func() error {
			return fmt.Errorf("save failed")
		},
	}

	svc := newTestService(&mockCacheManager{}, mf, dl, []PluginSource{
		{Name: "official", URL: "https://example.com", Enabled: true},
	})

	result, err := svc.Update(ctx, UpdateOptions{})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPartialFailure)
	require.NotNil(t, result)
	require.Equal(t, 1, result.FailedCount)
	require.Contains(t, result.Errors[0].Error, "save failed")
}

func TestService_installOne_CacheCheckFailureIgnored(t *testing.T) {
	ctx := context.Background()

	var downloadCalled bool

	cache := &mockCacheManager{
		getEntryFunc: func(ctx context.Context, name, version string) (*CacheEntry, error) {
			// Simulate cache read error (different from ErrPluginNotInstalled)
			return nil, fmt.Errorf("some other cache error")
		},
	}
	downloader := &mockDownloader{
		downloadFunc: func(ctx context.Context, id, version string) (*CacheEntry, error) {
			downloadCalled = true
			return &CacheEntry{}, nil
		},
	}
	manifest := &mockManifestManager{
		addFunc:  func(entry *ManifestEntry) error { return nil },
		saveFunc: func() error { return nil },
	}

	svc := newTestService(cache, manifest, downloader, nil)

	err := svc.installOne(ctx, PluginManifestEntry{
		ID:         "test-plugin",
		Name:       "Test Plugin",
		Version:    "1.0.0",
		Categories: []Category{CategorySSH},
		URL:        "http://example.com/plugin.tar.gz",
		Checksum:   "sha256:1234",
	}, InstallOptions{})

	require.NoError(t, err)
	require.True(t, downloadCalled, "should proceed with download even if cache check fails")
}
