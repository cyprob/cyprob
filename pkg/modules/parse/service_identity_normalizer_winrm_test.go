package parse

import (
	"context"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
)

func TestServiceIdentityNormalizer_WinRMFallbackIdentity(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-winrm", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.winrm.details": []any{
			scanpkg.WINRMServiceInfo{
				Target:               "198.51.100.180",
				Port:                 5986,
				WINRMProbe:           true,
				WINRMTransport:       "https",
				AuthRequired:         true,
				IdentifySupported:    false,
				ServiceHint:          "WinRM",
				ProductVersion:       "OS: 10.0.20348 SP: 0.0 Stack: 3.0",
				TLSEnabled:           true,
				HTTPStatusCode:       401,
				ServerHeader:         "Microsoft-HTTPAPI/2.0",
				ContentType:          "application/soap+xml; charset=UTF-8",
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
		if candidate.Target == "198.51.100.180" && candidate.Port == 5986 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected winrm identity output")
	}
	if identity.ServiceName != "winrm" {
		t.Fatalf("expected service_name=winrm, got %q", identity.ServiceName)
	}
	if identity.Product != "WinRM" || identity.Vendor != "Microsoft" || identity.Version != "OS: 10.0.20348 SP: 0.0 Stack: 3.0" {
		t.Fatalf("unexpected winrm identity fields: product=%q vendor=%q version=%q", identity.Product, identity.Vendor, identity.Version)
	}
	if identity.FieldSources["product"] != sourceWinRMNative || identity.FieldSources["vendor"] != sourceWinRMNative {
		t.Fatalf("expected winrm native field sources, got %+v", identity.FieldSources)
	}
	if identity.FieldConfidence["product"] != 0.74 || identity.FieldConfidence["vendor"] != 0.72 || identity.FieldConfidence["version"] != 0.65 {
		t.Fatalf("unexpected winrm confidence values: %+v", identity.FieldConfidence)
	}
	if !hasTag(identity.TechTags, TagWinRM) || !hasTag(identity.TechTags, TagWSMAN) || !hasTag(identity.TechTags, TagTLS) {
		t.Fatalf("expected winrm/wsman/tls tags, got %+v", identity.TechTags)
	}
}

func TestServiceIdentityNormalizer_WinRMDoesNotOverwriteFingerprint(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-winrm-no-overwrite", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.fingerprint.details": []any{
			FingerprintParsedInfo{
				Target:     "198.51.100.181",
				Port:       5985,
				Protocol:   "http",
				Product:    "WinRM",
				Vendor:     "Microsoft",
				Version:    "Stack: 2.0",
				Confidence: 0.92,
			},
		},
		"service.winrm.details": []any{
			scanpkg.WINRMServiceInfo{
				Target:            "198.51.100.181",
				Port:              5985,
				WINRMProbe:        true,
				WINRMTransport:    "http",
				IdentifySupported: true,
				ServiceHint:       "WinRM",
				ProductVersion:    "OS: 10.0.17763 SP: 0.0 Stack: 3.0",
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
		if candidate.Target == "198.51.100.181" && candidate.Port == 5985 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected winrm identity output")
	}
	if identity.Product != "WinRM" || identity.Vendor != "Microsoft" || identity.Version != "Stack: 2.0" {
		t.Fatalf("expected fingerprint identity preserved, got product=%q vendor=%q version=%q", identity.Product, identity.Vendor, identity.Version)
	}
	if identity.FieldSources["version"] != sourceFingerprint {
		t.Fatalf("expected fingerprint version source preserved, got %+v", identity.FieldSources)
	}
	if !hasTag(identity.TechTags, TagWinRM) || !hasTag(identity.TechTags, TagWSMAN) {
		t.Fatalf("expected winrm/wsman tags, got %+v", identity.TechTags)
	}
}
