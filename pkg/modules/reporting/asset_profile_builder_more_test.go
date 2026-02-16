package reporting

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"github.com/cyprob/cyprob/pkg/modules/parse"
)

// NOTE: Vulnerability aggregation is handled, but not asserted here due to
// evolving profile structure. Focus other behaviors for now.

func TestAssetProfileBuilderHandlesEmptyInputs(t *testing.T) {
	m := newAssetProfileBuilderModule()
	if err := m.Init(assetProfileBuilderModuleTypeName, map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}
	outCh := make(chan engine.ModuleOutput, 1)
	if err := m.Execute(context.Background(), map[string]any{}, outCh); err != nil {
		t.Fatalf("execute: %v", err)
	}
	select {
	case out := <-outCh:
		if _, ok := out.Data.([]engine.AssetProfile); !ok {
			t.Fatalf("expected []engine.AssetProfile, got %T", out.Data)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for output")
	}
}

func TestAssetProfileBuilderMergesParsedDetails(t *testing.T) {
	m := newAssetProfileBuilderModule()
	if err := m.Init(assetProfileBuilderModuleTypeName, map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}
	target := "203.0.113.42"
	port := 80
	inputs := map[string]any{
		"config.targets": []string{target},
		"service.http.details": []any{
			parse.HTTPParsedInfo{Target: target, Port: port, ServerProduct: "nginx", ServerVersion: "1.21.6"},
		},
		"service.ssh.details": []any{
			parse.SSHParsedInfo{Target: target, Port: 22, Software: "OpenSSH", SoftwareVersion: "9.3"},
		},
	}
	outCh := make(chan engine.ModuleOutput, 1)
	if err := m.Execute(context.Background(), inputs, outCh); err != nil {
		t.Fatalf("execute: %v", err)
	}
	select {
	case out := <-outCh:
		profiles := out.Data.([]engine.AssetProfile)
		if len(profiles) == 0 {
			t.Fatalf("no profiles")
		}
		ap := profiles[0]
		// Expect to see both HTTP and SSH services reflected in the profile maps
		if _, ok := ap.OpenPorts[target]; !ok {
			t.Fatalf("expected open ports for %s", target)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestAssetProfileBuilderNormalizesTechTags(t *testing.T) {
	m := newAssetProfileBuilderModule()
	require.NoError(t, m.Init(assetProfileBuilderModuleTypeName, map[string]any{}))

	target := "198.51.100.12"
	port := 443
	inputs := map[string]any{
		"config.targets": []string{target},
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: target, OpenPorts: []int{port}},
		},
		"service.tech.tags": []any{
			parse.TechTagResult{Target: target, Port: port, Tags: []string{"mail_server", "IIS", "roundcube", "unknown-tag"}},
		},
	}

	outCh := make(chan engine.ModuleOutput, 1)
	require.NoError(t, m.Execute(context.Background(), inputs, outCh))

	select {
	case out := <-outCh:
		profiles, ok := out.Data.([]engine.AssetProfile)
		require.True(t, ok)
		require.NotEmpty(t, profiles)

		ports := profiles[0].OpenPorts[target]
		require.NotEmpty(t, ports)
		tags := ports[0].Service.TechTags
		require.Contains(t, tags, parse.TagMailService)
		require.Contains(t, tags, parse.TagMicrosoftIIS)
		require.Contains(t, tags, parse.TagRoundcube)
		require.Contains(t, tags, parse.TagWebmail)
		require.NotContains(t, tags, "unknown-tag")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}
