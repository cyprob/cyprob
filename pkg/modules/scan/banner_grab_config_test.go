package scan

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
)

// cyprob#316, the same class as #315: banner-grab reads
// tls_insecure_skip_verify in Init and drives a real tls.Config field with it,
// and the module's schema declared six options and not this one. A caller could
// set it; anything reading the schema to find out what exists could not — and
// of the seven, this is the one with a security meaning.
//
// Declaration and behavior are checked together, because either alone can be
// right while the pair is wrong: a declared option nothing honors is a lie, and
// an honored option nothing declares is what this fixes.

func TestBannerGrabModule_DeclaresTheTLSVerificationOptionItHonors(t *testing.T) {
	t.Parallel()

	module := newBannerGrabModule()
	schema := module.Metadata().ConfigSchema

	parameter, declared := schema["tls_insecure_skip_verify"]
	if !declared {
		t.Fatal("tls_insecure_skip_verify is read by Init but not declared, so nothing reading the schema knows it exists")
	}
	if parameter.Type != "bool" {
		t.Fatalf("declared as %q, want bool", parameter.Type)
	}
	if parameter.Description == "" {
		t.Fatal("no description")
	}
	// A declaration that lies about the default is worse than none: this one
	// defaults to skipping verification, and a schema claiming otherwise would
	// tell an operator the opposite of what the scan does.
	declaredDefault, isBool := parameter.Default.(bool)
	if !isBool || !declaredDefault {
		t.Fatalf("declares default %#v, the module defaults to true", parameter.Default)
	}
}

// The value has to survive Init in every form node configuration delivers it.
// A bool type assertion accepted only the first of these and dropped the rest
// on the floor, leaving verification off while the operator had turned it on.
func TestBannerGrabModule_TLSVerificationOptionSurvivesEveryConfigForm(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		value any
		want  bool
	}{
		{"bool false", false, false},
		{"bool true", true, true},
		{"string false, as YAML and env deliver it", "false", false},
		{"string true", "true", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			module := newBannerGrabModule()
			if err := module.Init("banner-grab-test", map[string]any{"tls_insecure_skip_verify": tc.value}); err != nil {
				t.Fatalf("init: %v", err)
			}
			if module.config.TLSInsecureSkipVerify != tc.want {
				t.Fatalf("tls_insecure_skip_verify=%#v: module holds %v, want %v",
					tc.value, module.config.TLSInsecureSkipVerify, tc.want)
			}
		})
	}
}

// What a scan gets when nothing sets it: verification skipped, because a
// scanner that refused a certificate no client would accept would hide the
// service rather than the defect.
func TestBannerGrabModule_TLSVerificationDefaultsToSkipping(t *testing.T) {
	t.Parallel()

	module := newBannerGrabModule()
	if err := module.Init("banner-grab-test", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if !module.config.TLSInsecureSkipVerify {
		t.Fatal("tls_insecure_skip_verify must default to true")
	}
}

// Declared and read is still not the same as used. The three tests above stay
// green with the dial hardcoding InsecureSkipVerify: true, because none of them
// reaches a dial -- a suite that does not fail when a behavior is removed may
// simply have no test for it.
//
// This one runs the real probe against a real server whose certificate no root
// store trusts, both ways round, so the option is proven to reach tls.Config
// rather than merely to arrive in the struct.
func TestRunCommandProbe_TLSVerificationOptionReachesTheDial(t *testing.T) {
	t.Parallel()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "secure")
	}))
	defer secure.Close()
	host, port := hostPortOf(t, secure.URL)

	probe := func(skipVerify bool) engine.ProbeObservation {
		module := newBannerGrabModule()
		module.config.SendProbes = true
		module.config.TLSInsecureSkipVerify = skipVerify
		module.config.ConnectTimeout = 500 * time.Millisecond
		module.config.ReadTimeout = 500 * time.Millisecond
		return module.runCommandProbe(context.Background(), host, host, port, commandProbeSpec{
			ProbeID: "https-get", Protocol: "https", UseTLS: true,
			Commands: []string{buildCanonicalGETRequest(host)},
		})
	}

	skipping := probe(true)
	if !skipping.IsTLS || skipping.TLS == nil {
		t.Fatalf("with verification skipped the handshake must complete: isTLS=%v err=%q", skipping.IsTLS, skipping.Error)
	}

	verifying := probe(false)
	if verifying.IsTLS || verifying.TLS != nil {
		t.Fatal("with verification on, an untrusted certificate must not produce a completed handshake")
	}
	if verifying.Error == "" {
		t.Fatal("the refused handshake must be recorded as an error")
	}
}

// The CONNECT-tunnel path builds its own tls.Config and reads the same option,
// and it is reached by a different function, so the dial test above does not
// cover it. Same experiment through a proxy.
func TestRunConnectTunnelOriginRetry_TLSVerificationOptionReachesTheDial(t *testing.T) {
	t.Parallel()

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "<html><title>origin</title></html>")
	}))
	defer origin.Close()
	originHost, originPort := hostPortOf(t, origin.URL)
	proxyHost, proxyPort := startCONNECTTunnelForConfigTest(t, originHost, originPort)

	probe := func(skipVerify bool) engine.ProbeObservation {
		module := newBannerGrabModule()
		module.config.SendProbes = true
		module.config.TLSInsecureSkipVerify = skipVerify
		module.config.ConnectTimeout = 2 * time.Second
		module.config.ReadTimeout = 2 * time.Second
		return module.runConnectTunnelOriginRetry(context.Background(), proxyHost, originHost, proxyPort)
	}

	skipping := probe(true)
	if skipping.TLS == nil || !skipping.IsTLS {
		t.Fatalf("with verification skipped the tunnel must be wrapped: isTLS=%v err=%q", skipping.IsTLS, skipping.Error)
	}

	verifying := probe(false)
	if verifying.TLS != nil || verifying.IsTLS {
		t.Fatal("with verification on, the untrusted origin certificate must not produce a completed handshake")
	}
}

func startCONNECTTunnelForConfigTest(t *testing.T, originHost string, originPort int) (string, int) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(conn)
				for {
					line, readErr := reader.ReadString('\n')
					if readErr != nil {
						return
					}
					if strings.TrimSpace(line) == "" {
						break
					}
				}
				upstream, dialErr := net.Dial("tcp", net.JoinHostPort(originHost, fmt.Sprintf("%d", originPort)))
				if dialErr != nil {
					return
				}
				defer func() { _ = upstream.Close() }()
				if _, writeErr := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); writeErr != nil {
					return
				}
				done := make(chan struct{})
				go func() { _, _ = copyUntilClosed(upstream, reader); close(done) }()
				_, _ = copyUntilClosed(conn, bufio.NewReader(upstream))
				<-done
			}()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}
