package parse

import (
	"context"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
)

func normalizeOne(t *testing.T, inputs map[string]any, target string, port int) ServiceIdentityInfo {
	t.Helper()
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-bmc", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}
	out := make(chan engine.ModuleOutput, 8)
	if err := module.Execute(context.Background(), inputs, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)
	for item := range out {
		candidate, ok := item.Data.(ServiceIdentityInfo)
		if ok && candidate.Target == target && candidate.Port == port {
			return candidate
		}
	}
	t.Fatalf("no identity emitted for %s:%d", target, port)
	return ServiceIdentityInfo{}
}

// The whole point of the bridge: the certificate on an iLO already names the
// product, and before this the service went out tagged tls/ssl/https only —
// nine such services on the measured estate, and the shipped bmc/ilo plugins
// could not intersect any of them.
func TestServiceIdentityNormalizer_ControllerProductBecomesRoutingTag(t *testing.T) {
	identity := normalizeOne(t, map[string]any{
		"service.tls.details": []any{
			scanpkg.TLSServiceInfo{
				Target:      "198.51.100.31",
				Port:        443,
				TLSProbe:    true,
				TLSVersion:  "TLS 1.2",
				VendorHint:  "HPE",
				ProductHint: "iLO",
			},
		},
	}, "198.51.100.31", 443)

	if identity.Product != "iLO" {
		t.Fatalf("product = %q, want iLO", identity.Product)
	}
	for _, want := range []string{TagBMC, TagILO} {
		if !hasTag(identity.TechTags, want) {
			t.Fatalf("tech tags %v missing %q", identity.TechTags, want)
		}
	}
	// The transport tags the TLS pass already wrote must survive: the bridge
	// appends, it does not replace.
	for _, want := range []string{TagTLS, TagHTTPS} {
		if !hasTag(identity.TechTags, want) {
			t.Fatalf("tech tags %v lost %q", identity.TechTags, want)
		}
	}
}

// A storage array answering TLS on 443 is the case that makes a keyword search
// wrong. Seven services on the measured estate carry this product string, and
// tagging them bmc would route controller content at an asset class that is not
// one.
func TestServiceIdentityNormalizer_StorageArrayIsNotTaggedAsAController(t *testing.T) {
	identity := normalizeOne(t, map[string]any{
		"service.tls.details": []any{
			scanpkg.TLSServiceInfo{
				Target:      "198.51.100.60",
				Port:        443,
				TLSProbe:    true,
				TLSVersion:  "TLS 1.2",
				ProductHint: "SAN Volume Controller",
			},
		},
	}, "198.51.100.60", 443)

	if hasTag(identity.TechTags, TagBMC) {
		t.Fatalf("tech tags %v tagged a storage array as a controller", identity.TechTags)
	}
}
