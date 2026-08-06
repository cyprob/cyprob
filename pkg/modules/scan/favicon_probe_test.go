package scan

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

func TestFaviconCandidatesFromOpenPorts(t *testing.T) {
	candidates := faviconCandidatesFromOpenPorts(discovery.TCPPortDiscoveryResult{
		Target:    "192.0.2.10",
		OpenPorts: []int{22, 80, 443, 8443, 3306},
	})
	schemes := map[int]string{}
	for _, c := range candidates {
		schemes[c.port] = c.scheme
	}
	require.Equal(t, "http", schemes[80])
	require.Equal(t, "https", schemes[443])
	require.Equal(t, "https", schemes[8443])
	require.NotContains(t, schemes, 22, "non-HTTP ports must not be probed")
	require.NotContains(t, schemes, 3306)
}

func TestProbeFavicon_HashesServedIcon(t *testing.T) {
	icon := []byte("\x00\x00\x01\x00pretend-icon-bytes")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != faviconPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(icon)
	}))
	defer server.Close()

	host, portStr, _ := strings.Cut(strings.TrimPrefix(server.URL, "http://"), ":")
	port, _ := strconv.Atoi(portStr)

	result := probeFavicon(context.Background(),
		faviconCandidate{target: host, port: port, scheme: "http"},
		FaviconProbeOptions{TotalTimeout: 3 * time.Second, RequestTimeout: time.Second})

	require.Empty(t, result.ProbeError)
	require.Equal(t, len(icon), result.SizeBytes)
	require.Equal(t, FaviconHash(icon), result.FaviconHash)
	require.NotZero(t, result.FaviconHash)
}

func TestProbeFavicon_MissingIconIsNotAnIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	host, portStr, _ := strings.Cut(strings.TrimPrefix(server.URL, "http://"), ":")
	port, _ := strconv.Atoi(portStr)

	result := probeFavicon(context.Background(),
		faviconCandidate{target: host, port: port, scheme: "http"},
		FaviconProbeOptions{TotalTimeout: 3 * time.Second, RequestTimeout: time.Second})

	require.Equal(t, "status_404", result.ProbeError)
	require.Zero(t, result.FaviconHash)
	require.Empty(t, result.VendorHint)
}

// An empty body must not hash to a value that could collide in the corpus.
func TestProbeFavicon_EmptyBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	host, portStr, _ := strings.Cut(strings.TrimPrefix(server.URL, "http://"), ":")
	port, _ := strconv.Atoi(portStr)

	result := probeFavicon(context.Background(),
		faviconCandidate{target: host, port: port, scheme: "http"},
		FaviconProbeOptions{TotalTimeout: 3 * time.Second, RequestTimeout: time.Second})
	require.Equal(t, "empty_body", result.ProbeError)
	require.Zero(t, result.FaviconHash)
}

func TestLookupFaviconIdentity(t *testing.T) {
	t.Run("a verified hash resolves", func(t *testing.T) {
		// Verified against a live device that reported this identity itself.
		vendor, product := LookupFaviconIdentity(1684467926)
		require.Equal(t, "Huawei", vendor)
		require.Equal(t, "HUAWEI WiFi BE3", product)
	})

	t.Run("an unknown hash asserts nothing", func(t *testing.T) {
		// The hash still fingerprints the device; only the name is missing.
		vendor, product := LookupFaviconIdentity(123456789)
		require.Empty(t, vendor)
		require.Empty(t, product)
	})

	t.Run("a zero hash is not an identity", func(t *testing.T) {
		vendor, product := LookupFaviconIdentity(0)
		require.Empty(t, vendor)
		require.Empty(t, product)
	})
}

// TestProbeFavicon_Live exercises a real device. Skipped unless FAVICON_LIVE_URL
// is set, e.g. FAVICON_LIVE_URL=http://192.168.1.1 go test -run Favicon_Live
func TestProbeFavicon_Live(t *testing.T) {
	raw := os.Getenv("FAVICON_LIVE_URL")
	if raw == "" {
		t.Skip("set FAVICON_LIVE_URL to run the live favicon probe test")
	}
	scheme, rest, _ := strings.Cut(raw, "://")
	host, portStr, hasPort := strings.Cut(rest, ":")
	port := 80
	if scheme == "https" {
		port = 443
	}
	if hasPort {
		port, _ = strconv.Atoi(portStr)
	}

	result := probeFavicon(context.Background(),
		faviconCandidate{target: host, port: port, scheme: scheme},
		FaviconProbeOptions{TotalTimeout: 8 * time.Second, RequestTimeout: 4 * time.Second})

	require.Empty(t, result.ProbeError, "expected a favicon from %s", raw)
	require.NotZero(t, result.FaviconHash)
	t.Logf("%s -> hash=%d size=%d vendor=%q product=%q",
		raw, result.FaviconHash, result.SizeBytes, result.VendorHint, result.ProductHint)
}

// A device that drops one request but answers the next must still be
// identified: without a retry the corpus entry exists, matches, and never fires.
func TestProbeFavicon_RetriesOnceOnTransportFailure(t *testing.T) {
	icon := []byte("\x00\x00\x01\x00pretend-icon-bytes")
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			// Hijack and drop the connection so the client sees a transport error.
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		_, _ = w.Write(icon)
	}))
	defer server.Close()

	host, portStr, _ := strings.Cut(strings.TrimPrefix(server.URL, "http://"), ":")
	port, _ := strconv.Atoi(portStr)

	result := probeFavicon(context.Background(),
		faviconCandidate{target: host, port: port, scheme: "http"},
		FaviconProbeOptions{TotalTimeout: 5 * time.Second, RequestTimeout: 2 * time.Second})

	require.Empty(t, result.ProbeError, "the second attempt succeeded")
	require.Equal(t, FaviconHash(icon), result.FaviconHash)
	require.Equal(t, 2, result.Attempts)
	require.Equal(t, int32(2), atomic.LoadInt32(&attempts))
}

// A single "no_response" for every failure is untraceable; the reason an
// operator needs is which failure it was.
func TestClassifyFaviconError(t *testing.T) {
	require.Empty(t, classifyFaviconError(nil))
	require.Equal(t, "timeout", classifyFaviconError(context.DeadlineExceeded))
	require.Equal(t, "canceled", classifyFaviconError(context.Canceled))
	require.Equal(t, "connection_refused", classifyFaviconError(errors.New("dial tcp 192.0.2.1:80: connect: connection refused")))
	require.Equal(t, "connection_reset", classifyFaviconError(errors.New("read tcp: connection reset by peer")))
	require.Equal(t, "no_route", classifyFaviconError(errors.New("dial tcp: no route to host")))
	require.Equal(t, "tls_error", classifyFaviconError(errors.New("remote error: tls: handshake failure")))
	require.Equal(t, "no_response", classifyFaviconError(errors.New("something else entirely")))
}

// A successful first attempt must not pay the retry delay.
func TestProbeFavicon_RecordsASingleAttemptOnSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("\x00\x00\x01\x00icon"))
	}))
	defer server.Close()
	host, portStr, _ := strings.Cut(strings.TrimPrefix(server.URL, "http://"), ":")
	port, _ := strconv.Atoi(portStr)

	result := probeFavicon(context.Background(),
		faviconCandidate{target: host, port: port, scheme: "http"},
		FaviconProbeOptions{TotalTimeout: 3 * time.Second, RequestTimeout: time.Second})
	require.Empty(t, result.ProbeError)
	require.Equal(t, 1, result.Attempts)
}

// A vendor-only entry is legitimate: an appliance can be attributable to its
// maker while stating no model anywhere reachable without credentials, and the
// vendor is the half that generalises across a product line anyway.
func TestLookupFaviconIdentity_VendorWithoutProduct(t *testing.T) {
	vendor, product := LookupFaviconIdentity(-1548649046)
	require.Equal(t, "Sophos", vendor)
	require.Empty(t, product, "no model was verifiable, and guessing one would mislabel every matching device")
}
