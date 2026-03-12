package parse

import (
	"context"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
)

func TestServiceIdentityNormalizer_SNMPFallbackIdentity(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-snmp", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.snmp.details": []any{
			scanpkg.SNMPServiceInfo{
				Target:      "198.51.100.140",
				Port:        161,
				SNMPProbe:   true,
				SNMPVersion: "SNMPv2c",
				Community:   "public",
				SysDescr:    "Net-SNMP 5.9",
				SysObjectID: ".1.3.6.1.4.1.8072.3.2.10",
				ProductHint: "Net-SNMP",
				VendorHint:  "Net-SNMP Project",
				VersionHint: "5.9",
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
		if candidate.Target == "198.51.100.140" && candidate.Port == 161 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected snmp identity output")
	}
	if identity.ServiceName != "snmp" {
		t.Fatalf("expected service_name=snmp, got %q", identity.ServiceName)
	}
	if identity.Product != "Net-SNMP" || identity.Vendor != "Net-SNMP Project" || identity.Version != "5.9" {
		t.Fatalf("unexpected snmp identity fields: product=%q vendor=%q version=%q", identity.Product, identity.Vendor, identity.Version)
	}
	if identity.FieldSources["product"] != sourceSNMPNative || identity.FieldSources["vendor"] != sourceSNMPNative {
		t.Fatalf("expected snmp native field sources, got %+v", identity.FieldSources)
	}
	if identity.FieldConfidence["product"] != 0.75 || identity.FieldConfidence["vendor"] != 0.75 || identity.FieldConfidence["version"] != 0.65 {
		t.Fatalf("unexpected snmp confidence values: %+v", identity.FieldConfidence)
	}
	if !hasTag(identity.TechTags, TagSNMP) {
		t.Fatalf("expected snmp tech tag, got %+v", identity.TechTags)
	}
}

func TestServiceIdentityNormalizer_SNMPDoesNotOverwriteFingerprint(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-snmp-no-overwrite", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.fingerprint.details": []any{
			FingerprintParsedInfo{
				Target:     "198.51.100.141",
				Port:       161,
				Protocol:   "snmp",
				Product:    "Net-SNMP",
				Vendor:     "Net-SNMP Project",
				Version:    "5.8",
				Confidence: 0.90,
			},
		},
		"service.snmp.details": []any{
			scanpkg.SNMPServiceInfo{
				Target:      "198.51.100.141",
				Port:        161,
				SNMPProbe:   true,
				SNMPVersion: "SNMPv2c",
				Community:   "public",
				ProductHint: "Cisco IOS",
				VendorHint:  "Cisco",
				VersionHint: "15.7",
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
		if candidate.Target == "198.51.100.141" && candidate.Port == 161 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected snmp identity output")
	}
	if identity.Product != "Net-SNMP" || identity.Vendor != "Net-SNMP Project" || identity.Version != "5.8" {
		t.Fatalf("expected fingerprint identity preserved, got product=%q vendor=%q version=%q", identity.Product, identity.Vendor, identity.Version)
	}
	if identity.FieldSources["product"] != sourceFingerprint || identity.FieldSources["version"] != sourceFingerprint {
		t.Fatalf("expected fingerprint sources preserved, got %+v", identity.FieldSources)
	}
	if !hasTag(identity.TechTags, TagSNMP) {
		t.Fatalf("expected snmp tech tag, got %+v", identity.TechTags)
	}
}
