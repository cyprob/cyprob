package scan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/fingerprint"
)

func hintAccumulatorPtr() *hintAccumulator {
	acc := newHintAccumulator()
	return &acc
}

func tlsTestTarget(t *testing.T, handler http.HandlerFunc) (string, int, func()) {
	t.Helper()

	ts := httptest.NewTLSServer(handler)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "https://"))
	if err != nil {
		ts.Close()
		t.Fatalf("split host/port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		ts.Close()
		t.Fatalf("atoi: %v", err)
	}
	return host, port, ts.Close
}

// The 9080 case: a service that speaks only TLS on a port the catalog does not
// list, so the plain-text pass records nothing at all.
func TestRunTLSFallbackPass_RecoversASilentTLSPort(t *testing.T) {
	host, port, closeServer := tlsTestTarget(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
	})
	defer closeServer()

	catalog, err := fingerprint.GetProbeCatalog()
	if err != nil {
		t.Fatalf("probe catalog: %v", err)
	}

	m := newBannerGrabModule()
	observations := make([]engine.ProbeObservation, 0, 2)
	var lastError string
	hints := newHintAccumulator()

	m.runTLSFallbackPass(context.Background(), host, host, port, catalog,
		&observations, &lastError, &hints, map[string]struct{}{})

	banner := selectPrimaryBannerObservation(observations).Banner
	if banner == "" {
		t.Fatal("expected the TLS fallback to produce a banner where the plain pass had none")
	}
	if !strings.Contains(banner, "200") {
		t.Fatalf("expected the server's response, got %q", banner)
	}
}

// A port that already answered has told us what it is. Re-probing it would spend
// a handshake to overwrite an answer we hold, so silence is the only trigger.
func TestRunTLSFallbackPass_LeavesAnExistingBannerAlone(t *testing.T) {
	host, port, closeServer := tlsTestTarget(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer closeServer()

	catalog, err := fingerprint.GetProbeCatalog()
	if err != nil {
		t.Fatalf("probe catalog: %v", err)
	}

	existing := engine.ProbeObservation{
		ProbeID:  "http-get",
		Response: "HTTP/1.1 401 Unauthorized\r\nServer: something\r\n\r\n",
	}
	observations := []engine.ProbeObservation{existing}
	var lastError string

	m := newBannerGrabModule()
	m.runTLSFallbackPass(context.Background(), host, host, port, catalog,
		&observations, &lastError, hintAccumulatorPtr(), map[string]struct{}{})

	if len(observations) != 1 {
		t.Fatalf("expected no additional probe, got %d observations", len(observations))
	}
}

// The pass must not repeat a probe the main loop already ran, whatever the
// reason that probe produced nothing.
func TestRunTLSFallbackPass_SkipsProbesAlreadyAttempted(t *testing.T) {
	host, port, closeServer := tlsTestTarget(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer closeServer()

	catalog, err := fingerprint.GetProbeCatalog()
	if err != nil {
		t.Fatalf("probe catalog: %v", err)
	}

	attempted := map[string]struct{}{}
	for _, spec := range catalog.FallbackProbesFor(port, nil) {
		if spec.UseTLS {
			attempted[spec.ID] = struct{}{}
		}
	}
	if len(attempted) == 0 {
		t.Skip("catalog has no TLS fallback probe to exercise")
	}

	observations := make([]engine.ProbeObservation, 0, 1)
	var lastError string

	m := newBannerGrabModule()
	m.runTLSFallbackPass(context.Background(), host, host, port, catalog,
		&observations, &lastError, hintAccumulatorPtr(), attempted)

	if len(observations) != 0 {
		t.Fatalf("expected every TLS probe to be skipped as already attempted, got %d", len(observations))
	}
}

// A cancelled context must stop the pass before it dials.
func TestRunTLSFallbackPass_HonoursContextCancellation(t *testing.T) {
	host, port, closeServer := tlsTestTarget(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer closeServer()

	catalog, err := fingerprint.GetProbeCatalog()
	if err != nil {
		t.Fatalf("probe catalog: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	observations := make([]engine.ProbeObservation, 0, 1)
	var lastError string

	m := newBannerGrabModule()
	m.runTLSFallbackPass(ctx, host, host, port, catalog,
		&observations, &lastError, hintAccumulatorPtr(), map[string]struct{}{})

	if len(observations) != 0 {
		t.Fatalf("expected no probe after cancellation, got %d", len(observations))
	}
}
