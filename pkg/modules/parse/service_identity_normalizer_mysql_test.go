package parse

import (
	"context"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
)

func TestServiceIdentityNormalizer_MySQLFallbackIdentity(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-mysql", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.mysql.details": []any{
			scanpkg.MySQLServiceInfo{
				Target:        "198.51.100.160",
				Port:          3306,
				MySQLProbe:    true,
				GreetingKind:  "handshake",
				ServerVersion: "8.0.36-MySQL Community Server",
				ProductHint:   "MySQL",
				VendorHint:    "Oracle",
				VersionHint:   "8.0.36-MySQL",
				TLSEnabled:    true,
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
		if candidate.Target == "198.51.100.160" && candidate.Port == 3306 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected mysql identity output")
	}
	if identity.ServiceName != "mysql" {
		t.Fatalf("expected service_name=mysql, got %q", identity.ServiceName)
	}
	if identity.Product != "MySQL" || identity.Vendor != "Oracle" || identity.Version != "8.0.36-MySQL" {
		t.Fatalf("unexpected mysql identity fields: product=%q vendor=%q version=%q", identity.Product, identity.Vendor, identity.Version)
	}
	if identity.FieldSources["product"] != sourceMySQLNative || identity.FieldSources["vendor"] != sourceMySQLNative {
		t.Fatalf("expected mysql native field sources, got %+v", identity.FieldSources)
	}
	if identity.FieldConfidence["product"] != 0.74 || identity.FieldConfidence["vendor"] != 0.72 || identity.FieldConfidence["version"] != 0.66 {
		t.Fatalf("unexpected mysql confidence values: %+v", identity.FieldConfidence)
	}
	if !hasTag(identity.TechTags, "mysql") {
		t.Fatalf("expected mysql tech tag, got %+v", identity.TechTags)
	}
}

func TestServiceIdentityNormalizer_MySQLDoesNotOverwriteFingerprint(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-mysql-no-overwrite", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.fingerprint.details": []any{
			FingerprintParsedInfo{
				Target:     "198.51.100.161",
				Port:       3306,
				Protocol:   "mysql",
				Product:    "MariaDB",
				Vendor:     "MariaDB Foundation",
				Version:    "10.11.5",
				Confidence: 0.92,
			},
		},
		"service.mysql.details": []any{
			scanpkg.MySQLServiceInfo{
				Target:      "198.51.100.161",
				Port:        3306,
				MySQLProbe:  true,
				ProductHint: "MySQL",
				VendorHint:  "Oracle",
				VersionHint: "8.0.36-MySQL",
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
		if candidate.Target == "198.51.100.161" && candidate.Port == 3306 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected mysql identity output")
	}
	if identity.Product != "MariaDB" || identity.Vendor != "MariaDB Foundation" || identity.Version != "10.11.5" {
		t.Fatalf("expected fingerprint identity preserved, got product=%q vendor=%q version=%q", identity.Product, identity.Vendor, identity.Version)
	}
	if identity.FieldSources["product"] != sourceFingerprint || identity.FieldSources["version"] != sourceFingerprint {
		t.Fatalf("expected fingerprint sources preserved, got %+v", identity.FieldSources)
	}
	if !hasTag(identity.TechTags, "mysql") {
		t.Fatalf("expected mysql tag, got %+v", identity.TechTags)
	}
}
