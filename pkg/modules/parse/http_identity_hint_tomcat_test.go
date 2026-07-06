package parse

import (
	"context"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
)

const tomcat404Banner = "HTTP/1.1 404 \r\nContent-Type: text/html;charset=utf-8\r\n\r\n" +
	"<!doctype html><html lang=\"en\"><head><title>HTTP Status 404 – Not Found</title></head>" +
	"<body><h1>HTTP Status 404 – Not Found</h1><hr class=\"line\" />" +
	"<h3>Apache Tomcat/9.0.30</h3></body></html>"

func TestDetectHTTPIdentitySignals_TomcatBodyVersion(t *testing.T) {
	t.Parallel()

	signals, reason := detectHTTPIdentitySignals(scanpkg.BannerGrabResult{
		IP:            "203.0.113.9",
		Port:          8080,
		ResponseClass: bannerResponseClassOrigin,
		Banner:        tomcat404Banner,
	})
	if reason != "" {
		t.Fatalf("unexpected skip reason %q", reason)
	}
	if !hasHTTPIdentitySignal(signals, httpIdentitySignalTomcatBody) {
		t.Fatalf("expected tomcat signal, got %+v", signals)
	}
	if v := httpIdentitySignalValue(signals, httpIdentitySignalTomcatBody); v != "9.0.30" {
		t.Fatalf("expected extracted version 9.0.30, got %q", v)
	}
}

func TestServiceIdentityNormalizer_TomcatBodyIdentity(t *testing.T) {
	module := newServiceIdentityNormalizerModule()
	if err := module.Init("test-service-identity-tomcat", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	inputs := map[string]any{
		"service.banner.tcp": []any{
			scanpkg.BannerGrabResult{
				IP:            "203.0.113.10",
				Port:          8080,
				ResponseClass: bannerResponseClassOrigin,
				Banner:        tomcat404Banner,
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
		if candidate.Target == "203.0.113.10" && candidate.Port == 8080 {
			identity = candidate
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected tomcat identity output")
	}
	if identity.Product != "Apache Tomcat" || identity.Version != "9.0.30" {
		t.Fatalf("fields: product=%q version=%q", identity.Product, identity.Version)
	}
	if identity.Vendor != "Apache" {
		t.Fatalf("vendor: got %q", identity.Vendor)
	}
	if !hasTag(identity.TechTags, "tomcat") {
		t.Fatalf("tech tags: %+v", identity.TechTags)
	}
}
