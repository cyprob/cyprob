package parse

import (
	"context"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
)

func TestServiceIdentityNormalizer_DNSFallbackIdentityPrefersSupportedUDP(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-dns", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.dns.details": []any{
			scanpkg.DNSServiceInfo{
				Target:       "198.51.100.53",
				Port:         53,
				Transport:    "tcp",
				DNSProbe:     true,
				ProductHint:  "",
				ResponseCode: "NOERROR",
			},
			scanpkg.DNSServiceInfo{
				Target:               "198.51.100.53",
				Port:                 53,
				Transport:            "udp",
				DNSProbe:             true,
				VersionBindSupported: true,
				VersionBind:          "BIND 9.16.23",
				ProductHint:          "BIND",
				VendorHint:           "ISC",
				VersionHint:          "9.16.23",
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
		if candidate.Target == "198.51.100.53" && candidate.Port == 53 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected dns identity output")
	}
	if identity.ServiceName != "dns" || identity.Product != "BIND" || identity.Vendor != "ISC" || identity.Version != "9.16.23" {
		t.Fatalf("unexpected dns identity: %+v", identity)
	}
	if identity.Protocol != "udp" {
		t.Fatalf("expected selected transport udp, got %q", identity.Protocol)
	}
	if identity.FieldSources["product"] != sourceDNSNative || identity.FieldSources["protocol"] != sourceDNSNative {
		t.Fatalf("unexpected field sources: %+v", identity.FieldSources)
	}
	if !hasTag(identity.TechTags, TagDNS) {
		t.Fatalf("expected dns tech tag, got %+v", identity.TechTags)
	}
}

func TestServiceIdentityNormalizer_DNSDoesNotOverwriteFingerprint(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-dns-no-overwrite", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.fingerprint.details": []any{
			FingerprintParsedInfo{
				Target:     "198.51.100.54",
				Port:       53,
				Protocol:   "dns",
				Product:    "Microsoft DNS",
				Vendor:     "Microsoft",
				Version:    "10.0",
				Confidence: 0.90,
			},
		},
		"service.dns.details": []any{
			scanpkg.DNSServiceInfo{
				Target:               "198.51.100.54",
				Port:                 53,
				Transport:            "udp",
				DNSProbe:             true,
				VersionBindSupported: true,
				ProductHint:          "BIND",
				VendorHint:           "ISC",
				VersionHint:          "9.16.23",
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
		if candidate.Target == "198.51.100.54" && candidate.Port == 53 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected dns identity output")
	}
	if identity.Product != "Microsoft DNS" || identity.Vendor != "Microsoft" || identity.Version != "10.0" {
		t.Fatalf("expected fingerprint identity preserved, got %+v", identity)
	}
	if identity.FieldSources["product"] != sourceFingerprint || identity.FieldSources["version"] != sourceFingerprint {
		t.Fatalf("expected fingerprint sources preserved, got %+v", identity.FieldSources)
	}
	if !hasTag(identity.TechTags, TagDNS) {
		t.Fatalf("expected dns tech tag, got %+v", identity.TechTags)
	}
}
