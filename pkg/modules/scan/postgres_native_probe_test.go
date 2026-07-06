package scan

import (
	"encoding/binary"
	"testing"
)

func TestBuildPostgresStartupMessage(t *testing.T) {
	msg := buildPostgresStartupMessage("postgres")
	if len(msg) < 8 {
		t.Fatalf("message too short: %d", len(msg))
	}
	declaredLen := binary.BigEndian.Uint32(msg[0:4])
	if int(declaredLen) != len(msg) {
		t.Fatalf("length prefix %d != actual %d", declaredLen, len(msg))
	}
	proto := binary.BigEndian.Uint32(msg[4:8])
	if proto != postgresProtocolVersion3 {
		t.Fatalf("protocol: got %d", proto)
	}
	if msg[len(msg)-1] != 0 {
		t.Fatal("message must be null-terminated")
	}
}

func TestParsePostgresParameterStatus(t *testing.T) {
	payload := append([]byte("server_version"), 0)
	payload = append(payload, []byte("9.6.24")...)
	payload = append(payload, 0)
	name, value := parsePostgresParameterStatus(payload)
	if name != "server_version" || value != "9.6.24" {
		t.Fatalf("got name=%q value=%q", name, value)
	}
}

func TestExtractPostgresCoreVersion(t *testing.T) {
	cases := map[string]string{
		"9.6.24":                        "9.6.24",
		"14.2 (Debian 14.2-1.pgdg110+1)": "14.2",
		"16.1":                          "16.1",
	}
	for in, want := range cases {
		if got := extractPostgresCoreVersion(in); got != want {
			t.Fatalf("%q -> got %q want %q", in, got, want)
		}
	}
}

func TestApplyPostgresHints(t *testing.T) {
	info := PostgresServiceInfo{PostgresProbe: true, ServerVersion: "9.6.24"}
	applyPostgresHints(&info)
	if info.ProductHint != "PostgreSQL" || info.VendorHint == "" || info.VersionHint != "9.6.24" {
		t.Fatalf("hints: %+v", info)
	}
}

func TestPostgresAuthMethodName(t *testing.T) {
	if postgresAuthMethodName(5) != "md5_password" || postgresAuthMethodName(10) != "sasl" {
		t.Fatal("auth method name mapping wrong")
	}
}

func TestPostgresNativePort(t *testing.T) {
	if !isPostgresNativePort(5432) || isPostgresNativePort(5433) {
		t.Fatal("native port check wrong")
	}
}
