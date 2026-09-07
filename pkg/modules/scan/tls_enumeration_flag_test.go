package scan

import (
	"context"
	"crypto/tls"
	"testing"
	"time"
)

// The walk asks a service the same question once per suite it supports, and it
// is paid on every port that completes a handshake -- so it is off unless asked
// for. These tests exist because nothing else in the suite proves the probe
// runs the walk at all: the wiring assertions were dropped when the enumeration
// tests were rewritten for the raw ClientHello, and their absence is why adding
// this flag broke no test.

func TestProbeTLSDetails_DoesNotEnumerateByDefault(t *testing.T) {
	t.Parallel()

	// A real TLS server, because the probe's own strategies have to succeed
	// before enumeration is even considered.
	host, port, handshakes, stop := startPinnedTLSServer(t, 0, nil)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result := probeTLSDetails(ctx, host, "", port, TLSProbeOptions{})

	if !result.TLSProbe {
		t.Fatalf("the probe did not read the service: %s", result.ProbeError)
	}
	if result.Enumeration != nil {
		t.Fatalf("enumeration must be off unless asked for, got %+v", result.Enumeration)
	}
	// Asserted on the server's own connection count, not only on the absent
	// field: a walk that ran and then discarded its result would still have
	// cost the target every one of its dials.
	if got, want := int(handshakes.Load()), len(result.Attempts); got != want {
		t.Fatalf("server saw %d connections for %d recorded attempts — the walk ran anyway", got, want)
	}
}

func TestProbeTLSDetails_EnumeratesWhenAsked(t *testing.T) {
	t.Parallel()

	host, port, handshakes, stop := startPinnedTLSServer(t, tls.VersionTLS12, []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result := probeTLSDetails(ctx, host, "", port, TLSProbeOptions{EnumerateCipherSuites: true})

	if result.Enumeration == nil {
		t.Fatal("the flag is what turns the walk on; nothing else does")
	}
	if len(result.Enumeration.CipherSuites) == 0 {
		t.Fatalf("the walk found nothing: %+v", result.Enumeration)
	}
	if result.Enumeration.Dials == 0 {
		t.Fatal("an enumeration that cost nothing did not happen")
	}
	// Every connection the server saw is one the probe accounts for: its
	// recorded attempts plus the enumeration dials it declares.
	accounted := len(result.Attempts) + result.Enumeration.Dials
	if got := int(handshakes.Load()); got != accounted {
		t.Fatalf("server saw %d connections, probe accounts for %d (%d attempts + %d enumeration dials)",
			got, accounted, len(result.Attempts), result.Enumeration.Dials)
	}
}

// A service only the observation channel could reach is the one most worth
// enumerating, so the flag must reach that path too rather than only the
// ordinary one.
func TestProbeTLSDetails_EnumeratesAServiceOnlyTheChannelCouldReach(t *testing.T) {
	t.Parallel()

	host, port, _, stop := startPinnedTLSServer(t, tls.VersionTLS10, nil)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result := probeTLSDetails(ctx, host, "", port, TLSProbeOptions{EnumerateCipherSuites: true})

	if !result.TLSProbe {
		t.Fatalf("the channel did not reach a TLS 1.0-only server: %s", result.ProbeError)
	}
	if result.Enumeration == nil {
		t.Fatal("a service the channel reached must still be enumerated when asked")
	}
	if len(result.Enumeration.TLSVersions) != 1 || result.Enumeration.TLSVersions[0] != "TLS1.0" {
		t.Fatalf("expected exactly TLS1.0, got %v", result.Enumeration.TLSVersions)
	}
}

func TestTLSNativeProbeModule_InitReadsTheEnumerationFlag(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		config map[string]any
		want   bool
	}{
		{"absent", map[string]any{}, false},
		{"false", map[string]any{"enumerate_cipher_suites": false}, false},
		{"true", map[string]any{"enumerate_cipher_suites": true}, true},
		// The DAG carries node config through JSON, so a bool can arrive as a
		// string. Reading it as anything but true would silently leave the walk
		// off in the profile that asked for it.
		{"string true", map[string]any{"enumerate_cipher_suites": "true"}, true},
		{"string false", map[string]any{"enumerate_cipher_suites": "false"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			module := newTLSNativeProbeModule()
			if err := module.Init("tls-native-probe-test", tc.config); err != nil {
				t.Fatalf("init: %v", err)
			}
			if module.options.EnumerateCipherSuites != tc.want {
				t.Fatalf("want %v, got %v", tc.want, module.options.EnumerateCipherSuites)
			}
		})
	}
}

// The default has to be visible to whoever wires the module, not only to
// whoever reads the struct.
func TestTLSNativeProbeModule_EnumerationIsDeclaredOffByDefault(t *testing.T) {
	t.Parallel()

	if defaultTLSProbeOptions().EnumerateCipherSuites {
		t.Fatal("the default must be off")
	}
	module := newTLSNativeProbeModule()
	parameter, ok := module.Metadata().ConfigSchema["enumerate_cipher_suites"]
	if !ok {
		t.Fatal("the flag must be declared, or nothing can turn it on through node config")
	}
	if parameter.Type != "bool" {
		t.Fatalf("declared type %q", parameter.Type)
	}
	if enabled, isBool := parameter.Default.(bool); !isBool || enabled {
		t.Fatalf("the declared default must be false, got %#v", parameter.Default)
	}
}
