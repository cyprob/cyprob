package parse

import (
	"context"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
)

func TestServiceIdentityNormalizer_FTPFallbackIdentity(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-ftp", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.ftp.details": []any{
			scanpkg.FTPServiceInfo{
				Target:       "198.51.100.150",
				Port:         21,
				FTPProbe:     true,
				FTPProtocol:  "ftp",
				Banner:       "220 FileZilla Server 1.9.4 ready",
				SystemHint:   "UNIX Type: L8",
				SoftwareHint: "FileZilla Server",
				VendorHint:   "FileZilla Project",
				VersionHint:  "1.9.4",
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
		if candidate.Target == "198.51.100.150" && candidate.Port == 21 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ftp identity output")
	}
	if identity.ServiceName != "ftp" {
		t.Fatalf("expected service_name=ftp, got %q", identity.ServiceName)
	}
	if identity.Product != "FileZilla Server" || identity.Vendor != "FileZilla Project" || identity.Version != "1.9.4" {
		t.Fatalf("unexpected ftp identity fields: product=%q vendor=%q version=%q", identity.Product, identity.Vendor, identity.Version)
	}
	if identity.FieldSources["product"] != sourceFTPNative || identity.FieldSources["vendor"] != sourceFTPNative {
		t.Fatalf("expected ftp native field sources, got %+v", identity.FieldSources)
	}
	if identity.FieldConfidence["product"] != 0.72 || identity.FieldConfidence["vendor"] != 0.70 || identity.FieldConfidence["version"] != 0.66 {
		t.Fatalf("unexpected ftp confidence values: %+v", identity.FieldConfidence)
	}
	if !hasTag(identity.TechTags, TagFTP) {
		t.Fatalf("expected ftp tech tag, got %+v", identity.TechTags)
	}
}

func TestServiceIdentityNormalizer_FTPDoesNotOverwriteFingerprint(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-ftp-no-overwrite", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.fingerprint.details": []any{
			FingerprintParsedInfo{
				Target:     "198.51.100.151",
				Port:       990,
				Protocol:   "ftp",
				Product:    "CrushFTP",
				Vendor:     "CrushFTP, LLC",
				Version:    "11",
				Confidence: 0.92,
			},
		},
		"service.ftp.details": []any{
			scanpkg.FTPServiceInfo{
				Target:       "198.51.100.151",
				Port:         990,
				FTPProbe:     true,
				FTPProtocol:  "ftps",
				TLSEnabled:   true,
				SoftwareHint: "FileZilla Server",
				VendorHint:   "FileZilla Project",
				VersionHint:  "1.9.4",
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
		if candidate.Target == "198.51.100.151" && candidate.Port == 990 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ftp identity output")
	}
	if identity.Product != "CrushFTP" || identity.Vendor != "CrushFTP, LLC" || identity.Version != "11" {
		t.Fatalf("expected fingerprint identity preserved, got product=%q vendor=%q version=%q", identity.Product, identity.Vendor, identity.Version)
	}
	if identity.FieldSources["product"] != sourceFingerprint || identity.FieldSources["version"] != sourceFingerprint {
		t.Fatalf("expected fingerprint sources preserved, got %+v", identity.FieldSources)
	}
	if !hasTag(identity.TechTags, TagFTP) || !hasTag(identity.TechTags, TagTLS) {
		t.Fatalf("expected ftp/tls tags, got %+v", identity.TechTags)
	}
}
