package parse

import (
	"context"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
)

func TestServiceIdentityNormalizer_PostgresIdentity(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-postgres", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.postgres.details": []any{
			scanpkg.PostgresServiceInfo{
				Target:        "198.51.100.30",
				Port:          5432,
				PostgresProbe: true,
				GreetingKind:  "auth_ok",
				ServerVersion: "9.6.24",
				ProductHint:   "PostgreSQL",
				VendorHint:    "PostgreSQL Global Development Group",
				VersionHint:   "9.6.24",
			},
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	var identity ServiceIdentityInfo
	found := false
	for item := range out {
		candidate, ok := item.Data.(ServiceIdentityInfo)
		if !ok {
			continue
		}
		if candidate.Target == "198.51.100.30" && candidate.Port == 5432 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected postgres identity output")
	}
	if identity.ServiceName != "postgresql" {
		t.Fatalf("service_name: got %q", identity.ServiceName)
	}
	if identity.Product != "PostgreSQL" || identity.Version != "9.6.24" {
		t.Fatalf("fields: product=%q version=%q", identity.Product, identity.Version)
	}
	if identity.FieldSources["product"] != sourcePostgresNative {
		t.Fatalf("source: %+v", identity.FieldSources)
	}
	if !hasTag(identity.TechTags, "postgresql") {
		t.Fatalf("tech tags: %+v", identity.TechTags)
	}
}

// A postgres probe that only confirmed presence (auth required, no version)
// should still yield the service identity, without a version.
func TestServiceIdentityNormalizer_PostgresAuthRequiredNoVersion(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-postgres-auth", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.postgres.details": []any{
			scanpkg.PostgresServiceInfo{
				Target:        "198.51.100.31",
				Port:          5432,
				PostgresProbe: true,
				GreetingKind:  "auth_required",
				AuthRequired:  true,
				ProductHint:   "PostgreSQL",
				VendorHint:    "PostgreSQL Global Development Group",
			},
		},
	}

	out := make(chan engine.ModuleOutput, 8)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	found := false
	for item := range out {
		candidate, ok := item.Data.(ServiceIdentityInfo)
		if !ok {
			continue
		}
		if candidate.Target == "198.51.100.31" && candidate.Port == 5432 {
			if candidate.ServiceName != "postgresql" || candidate.Product != "PostgreSQL" {
				t.Fatalf("expected postgres identity without version, got %+v", candidate)
			}
			if candidate.Version != "" {
				t.Fatalf("expected no version, got %q", candidate.Version)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("expected postgres identity output")
	}
}
