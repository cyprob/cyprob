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

// cyprob#310. is_tls became "some connection in this scan was TLS" rather than
// "this port speaks TLS", and on an appliance that redirects port 80 to HTTPS
// the difference is twenty services recorded as TLS with no certificate, no
// version and no suite -- a flag EE cannot lower once it is set.

func isTLSTestModule() *BannerGrabModule {
	module := newBannerGrabModule()
	module.config.SendProbes = true
	module.config.TLSInsecureSkipVerify = true
	module.config.ConnectTimeout = 500 * time.Millisecond
	module.config.ReadTimeout = 500 * time.Millisecond
	return module
}

func hostPortOf(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	trimmed := strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
	host, portText, err := net.SplitHostPort(trimmed)
	if err != nil {
		t.Fatalf("split %q: %v", rawURL, err)
	}
	port := 0
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		t.Fatalf("port %q: %v", portText, err)
	}
	return host, port
}

// The field case, reconstructed: port 80 answers a redirect to HTTPS, the hop is
// followed, and the hop's handshake is real -- about the other port.
func TestFollowHTTPRedirects_TLSHopDoesNotMakeTheScannedPortTLS(t *testing.T) {
	t.Parallel()

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "VMware/ESXi")
		_, _ = fmt.Fprint(w, "<html><title>ID_EESX_Welcome</title></html>")
	}))
	defer origin.Close()
	originHost, originPort := hostPortOf(t, origin.URL)

	initial := engine.ProbeObservation{
		ProbeID:      "http-get",
		Protocol:     "http",
		ObservedPort: 80,
		Response: fmt.Sprintf("HTTP/1.1 302 Found\r\nLocation: https://%s:%d/\r\nContent-Length: 0\r\n\r\n",
			originHost, originPort),
	}
	classifyHTTPProbeObservation(&initial)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	followed := isTLSTestModule().followHTTPRedirects(ctx, originHost, originHost, 80, initial)
	if len(followed) == 0 {
		t.Fatal("no redirect was followed, so this test proves nothing")
	}

	var sawTLSHop bool
	for _, obs := range followed {
		if obs.TLS != nil && obs.ObservedPort == originPort {
			sawTLSHop = true
		}
	}
	if !sawTLSHop {
		t.Fatalf("the hop did not complete a handshake on the other port: %+v", followed)
	}

	selection := selectPrimaryBannerObservation(80, append([]engine.ProbeObservation{initial}, followed...))
	if selection.IsTLS {
		t.Fatalf("port 80 was reported as TLS because a redirect to %d was followed (banner %.40q)",
			originPort, selection.Banner)
	}
	// The banner still travels: identifying the service behind the redirect is
	// the reason for following it. Only the TLS claim is withheld.
	if !strings.Contains(selection.Banner, "VMware/ESXi") {
		t.Fatalf("the followed banner must still be selected, got %.60q", selection.Banner)
	}
}

// The regression for the fix above: a handshake on the port being scanned must
// still count, or the defense would be free to be right by always saying false.
func TestSelectPrimaryBannerObservation_HandshakeOnTheScannedPortStillCounts(t *testing.T) {
	t.Parallel()

	selection := selectPrimaryBannerObservation(443, []engine.ProbeObservation{{
		ProbeID:      "https-get",
		ObservedPort: 443,
		IsTLS:        true,
		TLS:          &engine.TLSObservation{Version: "TLS1.3"},
		Response:     "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
	}})
	if !selection.IsTLS {
		t.Fatal("a handshake on the scanned port is exactly what is_tls is for")
	}
}

// An observation with no recorded port predates this field or comes from a path
// that does not dial; it must not be silently dropped from consideration.
func TestSelectPrimaryBannerObservation_UnrecordedPortIsNotDiscarded(t *testing.T) {
	t.Parallel()

	selection := selectPrimaryBannerObservation(443, []engine.ProbeObservation{{
		ProbeID:  "https-get",
		IsTLS:    true,
		Response: "HTTP/1.1 200 OK\r\n\r\n",
	}})
	if !selection.IsTLS {
		t.Fatal("an observation with no ObservedPort must still be able to speak for the port")
	}
}

// A proxy that refuses CONNECT answers in plaintext, and that answer is
// selectable. The observation used to arrive claiming TLS from a literal set
// before the dial.
func TestRunConnectTunnelOriginRetry_PlaintextRefusalIsNotTLS(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
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
				_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
			}()
		}
	}()
	addr := listener.Addr().(*net.TCPAddr)

	obs := isTLSTestModule().runConnectTunnelOriginRetry(context.Background(), addr.IP.String(), "origin.test", addr.Port)
	if strings.TrimSpace(obs.Response) == "" {
		t.Fatal("the proxy's plaintext refusal must be kept as the response, or this test proves nothing")
	}
	if obs.TLS != nil {
		t.Fatal("no handshake happened")
	}
	if obs.IsTLS {
		t.Fatalf("a plaintext proxy refusal was reported as TLS: %.60q", obs.Response)
	}

	classifyHTTPProbeObservation(&obs)
	if selection := selectPrimaryBannerObservation(addr.Port, []engine.ProbeObservation{obs}); selection.IsTLS {
		t.Fatalf("the plaintext refusal reached selection as TLS: %.60q", selection.Banner)
	}
}

// The other half: when the tunnel is wrapped and the handshake completes, the
// observation must say so.
func TestRunConnectTunnelOriginRetry_WrappedTunnelIsTLS(t *testing.T) {
	t.Parallel()

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "<html><title>origin</title></html>")
	}))
	defer origin.Close()
	originHost, originPort := hostPortOf(t, origin.URL)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

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

	obs := isTLSTestModule().runConnectTunnelOriginRetry(context.Background(), addr.IP.String(), originHost, addr.Port)
	if obs.TLS == nil {
		t.Fatalf("the tunnel should have been wrapped: err=%q resp=%.60q", obs.Error, obs.Response)
	}
	if !obs.IsTLS {
		t.Fatal("a completed handshake through the tunnel must set is_tls")
	}
}

func copyUntilClosed(dst net.Conn, src *bufio.Reader) (int64, error) {
	buf := make([]byte, 4096)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			written, writeErr := dst.Write(buf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
		}
		if err != nil {
			return total, err
		}
	}
}

// is_tls comes from the handshake, not from what the probe was configured to
// attempt. The two agree today only because a failed TLS dial produces no
// response and is never selected.
func TestRunCommandProbe_IsTLSComesFromTheHandshake(t *testing.T) {
	t.Parallel()

	t.Run("a TLS probe against a plaintext service claims nothing", func(t *testing.T) {
		t.Parallel()
		plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprint(w, "plain")
		}))
		defer plain.Close()
		host, port := hostPortOf(t, plain.URL)

		obs := isTLSTestModule().runCommandProbe(context.Background(), host, host, port, commandProbeSpec{
			ProbeID: "https-get", Protocol: "https", UseTLS: true,
			Commands: []string{buildCanonicalGETRequest(host)},
		})
		if obs.IsTLS {
			t.Fatalf("the handshake failed, so nothing may claim TLS: err=%q", obs.Error)
		}
		if obs.ObservedPort != port {
			t.Fatalf("the observation must record where it connected, got %d", obs.ObservedPort)
		}
	})

	t.Run("a TLS probe against a TLS service says so", func(t *testing.T) {
		t.Parallel()
		secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprint(w, "secure")
		}))
		defer secure.Close()
		host, port := hostPortOf(t, secure.URL)

		obs := isTLSTestModule().runCommandProbe(context.Background(), host, host, port, commandProbeSpec{
			ProbeID: "https-get", Protocol: "https", UseTLS: true,
			Commands: []string{buildCanonicalGETRequest(host)},
		})
		if !obs.IsTLS || obs.TLS == nil {
			t.Fatalf("a completed handshake must be recorded: isTLS=%v tls=%v err=%q", obs.IsTLS, obs.TLS != nil, obs.Error)
		}
	})
}

// The top score bucket is earned by a handshake, not by a probe id that happens
// to start with "https".
func TestBannerObservationScore_HTTPSBucketRequiresAHandshake(t *testing.T) {
	t.Parallel()

	named := engine.ProbeObservation{ProbeID: "https-connect-origin", ObservedPort: 443, Response: "HTTP/1.1 403 Forbidden\r\n\r\n"}
	plain := engine.ProbeObservation{ProbeID: "http-get", ObservedPort: 443, Response: "HTTP/1.1 200 OK\r\n\r\n"}
	// It lands in the http bucket, which is what it is: the name no longer buys
	// the top bucket, so it can no longer outrank the probe that actually
	// described the service.
	if bannerObservationScore(named, 443) > bannerObservationScore(plain, 443) {
		t.Fatalf("an https-named probe with no handshake must not outrank a plain one: %d vs %d",
			bannerObservationScore(named, 443), bannerObservationScore(plain, 443))
	}

	handshook := named
	handshook.IsTLS = true
	handshook.TLS = &engine.TLSObservation{Version: "TLS1.2"}
	if bannerObservationScore(handshook, 443) <= bannerObservationScore(plain, 443) {
		t.Fatal("a real TLS observation must still win its bucket")
	}
	// And a handshake on some other port buys nothing here.
	elsewhere := handshook
	elsewhere.ObservedPort = 8443
	if bannerObservationScore(elsewhere, 443) >= bannerObservationScore(handshook, 443) {
		t.Fatal("a handshake on another port must not score as this port's TLS")
	}
}
