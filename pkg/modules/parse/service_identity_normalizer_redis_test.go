package parse

import (
	"context"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
)

func TestServiceIdentityNormalizer_RedisIdentity(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-redis", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.redis.details": []any{
			scanpkg.RedisServiceInfo{
				Target:        "198.51.100.20",
				Port:          6379,
				RedisProbe:    true,
				GreetingKind:  "info",
				ServerVersion: "5.0.5",
				Mode:          "standalone",
				ProductHint:   "Redis",
				VendorHint:    "Redis",
				VersionHint:   "5.0.5",
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
		if candidate.Target == "198.51.100.20" && candidate.Port == 6379 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected redis identity output")
	}
	if identity.ServiceName != "redis" {
		t.Fatalf("service_name: got %q", identity.ServiceName)
	}
	if identity.Product != "Redis" || identity.Vendor != "Redis" || identity.Version != "5.0.5" {
		t.Fatalf("fields: product=%q vendor=%q version=%q", identity.Product, identity.Vendor, identity.Version)
	}
	if identity.FieldSources["product"] != sourceRedisNative {
		t.Fatalf("source: %+v", identity.FieldSources)
	}
	if identity.FieldConfidence["product"] != 0.74 || identity.FieldConfidence["version"] != 0.66 {
		t.Fatalf("confidence: %+v", identity.FieldConfidence)
	}
	if !hasTag(identity.TechTags, "redis") {
		t.Fatalf("tech tags: %+v", identity.TechTags)
	}
}
