package scan

import "testing"

func TestApplyRedisInfo_ParsesServerSection(t *testing.T) {
	payload := "# Server\r\nredis_version:5.0.5\r\nredis_mode:standalone\r\nos:Linux 5.15.0 x86_64\r\narch_bits:64\r\n"
	var info RedisServiceInfo
	info.RedisProbe = true
	applyRedisInfo(&info, payload)

	if info.ServerVersion != "5.0.5" {
		t.Fatalf("version: got %q", info.ServerVersion)
	}
	if info.Mode != "standalone" {
		t.Fatalf("mode: got %q", info.Mode)
	}
	if info.ArchBits != "64" {
		t.Fatalf("arch_bits: got %q", info.ArchBits)
	}
	if info.ProductHint != "Redis" || info.VendorHint != "Redis" || info.VersionHint != "5.0.5" {
		t.Fatalf("hints: %+v", info)
	}
	if info.GreetingKind != "info" {
		t.Fatalf("greeting: got %q", info.GreetingKind)
	}
}

func TestApplyRedisInfo_AuthRequired(t *testing.T) {
	var info RedisServiceInfo
	info.RedisProbe = true
	applyRedisInfo(&info, "-NOAUTH Authentication required.\r\n")

	if !info.AuthRequired {
		t.Fatal("expected auth_required")
	}
	if info.GreetingKind != "auth_required" {
		t.Fatalf("greeting: got %q", info.GreetingKind)
	}
	if info.ProductHint != "Redis" {
		t.Fatalf("product: got %q", info.ProductHint)
	}
	if info.ServerVersion != "" {
		t.Fatalf("no version expected, got %q", info.ServerVersion)
	}
}

func TestRedisCandidatesFromOpenPorts_NativePortOnly(t *testing.T) {
	item := map[string]any{"target": "203.0.113.5", "open_ports": []int{80, 6379, 8080}}
	candidates := redisCandidatesFromOpenPorts(item, map[int]struct{}{})
	if len(candidates) != 1 || candidates[0].port != 6379 {
		t.Fatalf("expected only 6379, got %+v", candidates)
	}
}

func TestRedisNativePort(t *testing.T) {
	if !isRedisNativePort(6379) || isRedisNativePort(6380) {
		t.Fatal("native port check wrong")
	}
}
