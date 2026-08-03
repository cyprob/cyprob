package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
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

// The corpus starts empty on purpose; an unknown hash must yield no name rather
// than a wrong one, while the hash itself still identifies the device uniquely.
func TestLookupFaviconIdentity_UnknownHashAssertsNothing(t *testing.T) {
	vendor, product := LookupFaviconIdentity(1684467926)
	if FaviconCorpusSize() == 0 {
		require.Empty(t, vendor)
		require.Empty(t, product)
	}
	v, p := LookupFaviconIdentity(0)
	require.Empty(t, v)
	require.Empty(t, p)
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
