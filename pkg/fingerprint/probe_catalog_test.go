package fingerprint

import (
	"testing"
)

func TestGetProbeCatalog(t *testing.T) {
	catalog, err := GetProbeCatalog()
	if err != nil {
		t.Fatalf("GetProbeCatalog error: %v", err)
	}
	if catalog == nil {
		t.Fatal("expected catalog, got nil")
	}

	probes := catalog.ProbesFor(80, []string{"http"})
	if len(probes) == 0 {
		t.Fatalf("expected probes for port 80 http hint")
	}

	seen := map[string]struct{}{}
	for _, p := range probes {
		seen[p.ID] = struct{}{}
	}
	if _, ok := seen["http-get"]; !ok {
		t.Fatalf("expected http-get probe in result: %v", probes)
	}
}

func TestProbeCatalogValidate(t *testing.T) {
	catalog := ProbeCatalog{
		Groups: []ProbeGroup{
			{
				ID:     "test",
				Probes: []ProbeSpec{{ID: "p", Protocol: "test", Payload: "PING"}},
			},
		},
	}
	if err := catalog.Validate(); err != nil {
		t.Fatalf("unexpected validate error: %v", err)
	}
}

func TestProbeCatalog_ProbesFor_Combinations(t *testing.T) {
	catalog := ProbeCatalog{Groups: []ProbeGroup{
		{ // requires port 80, any protocol
			ID: "g1", PortHints: []int{80}, Probes: []ProbeSpec{{ID: "p1", Protocol: "tcp", Payload: "X"}},
		},
		{ // requires http hint, no port hint
			ID: "g2", ProtocolHints: []string{"HTTP"}, Probes: []ProbeSpec{{ID: "p2", Protocol: "tcp", Payload: "Y"}},
		},
		{ // both hints and includes/excludes
			ID: "g3", PortHints: []int{443}, ProtocolHints: []string{"https"}, Probes: []ProbeSpec{{ID: "p3", Protocol: "tcp", Payload: "Z", PortInclude: []int{443}, PortExclude: []int{8443}}},
		},
	}}

	// nil catalog safety
	var nilCat *ProbeCatalog
	if out := nilCat.ProbesFor(80, nil); out != nil {
		t.Fatalf("expected nil for nil catalog")
	}

	// port 80, no hints -> g1 matches (port hint present), g2 does not (needs http hint)
	out := catalog.ProbesFor(80, nil)
	if len(out) != 1 || out[0].ID != "p1" {
		t.Fatalf("unexpected for port80 no hints: %#v", out)
	}

	// port 25, http hint -> g2 matches via protocol hint even without port hints
	out = catalog.ProbesFor(25, []string{"http"})
	if len(out) != 1 || out[0].ID != "p2" {
		t.Fatalf("unexpected for port25 http hint: %#v", out)
	}

	// port 443 with https hint -> g3 matches; include/exclude allow 443
	out = catalog.ProbesFor(443, []string{"HTTPS"})
	if len(out) != 1 || out[0].ID != "p3" {
		t.Fatalf("unexpected for port443 https: %#v", out)
	}

	// port 8443 with https hint -> group matches but probe excludes this port
	out = catalog.ProbesFor(8443, []string{"https"})
	if len(out) != 0 {
		t.Fatalf("expected exclude to filter out, got %#v", out)
	}
}

func TestProbeCatalog_NormalizeHints_And_ContainsInt(t *testing.T) {
	// normalize lowercases and skips empties
	m := normalizeHints([]string{"HTTP", "", "Ssh"})
	if _, ok := m["http"]; !ok {
		t.Fatalf("expected http present")
	}
	if _, ok := m["ssh"]; !ok {
		t.Fatalf("expected ssh present")
	}
	if len(m) != 2 {
		t.Fatalf("unexpected len: %d", len(m))
	}

	// containsInt true/false
	if !containsInt([]int{1, 2, 3}, 2) {
		t.Fatalf("containsInt should be true")
	}
	if containsInt([]int{1, 2, 3}, 4) {
		t.Fatalf("containsInt should be false")
	}
}

func TestProbeCatalog_FallbackProbesFor_FiltersStatefulProtocolsWithoutHints(t *testing.T) {
	catalog := ProbeCatalog{
		FallbackProbeIDs: []string{"http-get", "https-get", "redis-ping", "ftp-feat"},
		Groups: []ProbeGroup{
			{ID: "http", Probes: []ProbeSpec{{ID: "http-get", Protocol: "http", Payload: "GET /"}}},
			{ID: "https", Probes: []ProbeSpec{{ID: "https-get", Protocol: "https", Payload: "GET /"}}},
			{ID: "redis", Probes: []ProbeSpec{{ID: "redis-ping", Protocol: "redis", Payload: "PING"}}},
			{ID: "ftp", Probes: []ProbeSpec{{ID: "ftp-feat", Protocol: "ftp", Payload: "FEAT"}}},
		},
	}

	out := catalog.FallbackProbesFor(3389, nil)
	if len(out) != 2 || out[0].ID != "http-get" || out[1].ID != "https-get" {
		t.Fatalf("unexpected fallback probes without hints: %#v", out)
	}

	out = catalog.FallbackProbesFor(2121, []string{"ftp"})
	if len(out) != 3 {
		t.Fatalf("expected ftp fallback to be included with ftp hint, got %#v", out)
	}
	if out[2].ID != "ftp-feat" {
		t.Fatalf("expected ftp-feat in fallback set, got %#v", out)
	}
}

func TestProbeCatalog_Validate_Errors(t *testing.T) {
	var nilCat *ProbeCatalog
	if err := nilCat.Validate(); err == nil {
		t.Fatalf("expected error for nil catalog")
	}

	// missing group id
	c := ProbeCatalog{Groups: []ProbeGroup{{ID: "", Probes: []ProbeSpec{{ID: "p", Protocol: "x", Payload: "y"}}}}}
	if err := c.Validate(); err == nil {
		t.Fatalf("expected missing group id error")
	}

	// group with no probes
	c = ProbeCatalog{Groups: []ProbeGroup{{ID: "g", Probes: nil}}}
	if err := c.Validate(); err == nil {
		t.Fatalf("expected no probes error")
	}

	// probe missing id
	c = ProbeCatalog{Groups: []ProbeGroup{{ID: "g", Probes: []ProbeSpec{{ID: "", Protocol: "x", Payload: "y"}}}}}
	if err := c.Validate(); err == nil {
		t.Fatalf("expected probe missing id error")
	}

	// probe missing protocol
	c = ProbeCatalog{Groups: []ProbeGroup{{ID: "g", Probes: []ProbeSpec{{ID: "p", Protocol: "", Payload: "y"}}}}}
	if err := c.Validate(); err == nil {
		t.Fatalf("expected probe missing protocol error")
	}

	// probe missing payload
	c = ProbeCatalog{Groups: []ProbeGroup{{ID: "g", Probes: []ProbeSpec{{ID: "p", Protocol: "x", Payload: ""}}}}}
	if err := c.Validate(); err == nil {
		t.Fatalf("expected probe missing payload error")
	}
}

// A print port answers a payload with paper, so no probe may be selected for
// one — not by port hint, not by protocol hint, not through the fallback set
// (cyprob#268).
func TestProbeCatalog_PrintPortsSelectNoProbe(t *testing.T) {
	catalog := ProbeCatalog{
		Groups: []ProbeGroup{{
			ID:            "g1",
			PortHints:     []int{9100},
			ProtocolHints: []string{"http"},
			Probes:        []ProbeSpec{{ID: "p1", Protocol: "tcp", Payload: "X"}},
		}},
		FallbackProbeIDs: []string{"p1"},
	}

	for _, port := range []int{515, 9100, 9101, 9102} {
		if out := catalog.ProbesFor(port, []string{"http"}); len(out) != 0 {
			t.Fatalf("port %d selected %d probes; a payload here prints", port, len(out))
		}
		if out := catalog.FallbackProbesFor(port, []string{"http"}); len(out) != 0 {
			t.Fatalf("port %d selected %d fallback probes; a payload here prints", port, len(out))
		}
	}

	// A neighboring port is untouched: the guard is about these ports, not
	// about the probes.
	if out := catalog.ProbesFor(9103, []string{"http"}); len(out) != 0 {
		t.Fatalf("9103 is not a print port and has no group; got %#v", out)
	}
	if out := catalog.FallbackProbesFor(9103, []string{"http"}); len(out) != 1 {
		t.Fatalf("expected the fallback set on a non-print port, got %#v", out)
	}
}

// The floor is not data: a catalog loaded from outside the binary may add
// ports and may not drop one.
func TestProbeCatalog_NeverProbePortsExtendsButCannotShrink(t *testing.T) {
	catalog := ProbeCatalog{
		Groups: []ProbeGroup{{
			ID:        "g1",
			PortHints: []int{9100, 9200},
			Probes:    []ProbeSpec{{ID: "p1", Protocol: "tcp", Payload: "X"}},
		}},
		FallbackProbeIDs: []string{"p1"},
		NeverProbePorts:  []int{9200},
	}

	if out := catalog.ProbesFor(9200, nil); len(out) != 0 {
		t.Fatalf("never_probe_ports did not take effect: %#v", out)
	}
	if out := catalog.ProbesFor(9100, nil); len(out) != 0 {
		t.Fatalf("a catalog that omits 9100 must not re-enable it: %#v", out)
	}
}

// FallbackProbes() asks with no port at all; it predates this guard and must
// keep returning the legacy set rather than nothing.
func TestProbeCatalog_UnportedFallbackIsUnaffected(t *testing.T) {
	catalog := ProbeCatalog{
		Groups:           []ProbeGroup{{ID: "g1", Probes: []ProbeSpec{{ID: "p1", Protocol: "tcp", Payload: "X"}}}},
		FallbackProbeIDs: []string{"p1"},
	}

	if out := catalog.FallbackProbes(); len(out) != 1 {
		t.Fatalf("expected the legacy unfiltered set, got %#v", out)
	}
}

// The shipped catalog, not a hand-built one.
func TestProbeCatalog_EmbeddedCatalogRefusesPrintPorts(t *testing.T) {
	catalog, err := GetProbeCatalog()
	if err != nil {
		t.Fatalf("probe catalog: %v", err)
	}

	for _, port := range []int{515, 9100, 9101, 9102} {
		if out := catalog.ProbesFor(port, []string{"http", "web"}); len(out) != 0 {
			t.Fatalf("shipped catalog selects %d probes on %d", len(out), port)
		}
		if out := catalog.FallbackProbesFor(port, []string{"http", "web"}); len(out) != 0 {
			t.Fatalf("shipped catalog selects %d fallback probes on %d", len(out), port)
		}
	}

	// Control: the fallback set is still reachable on an unlisted, harmless port.
	if out := catalog.FallbackProbesFor(2096, nil); len(out) == 0 {
		t.Fatal("fallback probes disappeared on a non-print port")
	}
}
