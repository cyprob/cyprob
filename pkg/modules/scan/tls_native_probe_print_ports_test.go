package scan

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// The floor is tested by what reaches the wire, not by what the module reports.
// A printer that discards a malformed job looks identical to one that was never
// written to, which is how the field measurement on cyprob-ee#590 nearly read as
// a pass. These tests count connections.

func printPortTestOptions() TLSProbeOptions {
	return TLSProbeOptions{
		TotalTimeout:   time.Second,
		ConnectTimeout: 200 * time.Millisecond,
		IOTimeout:      200 * time.Millisecond,
	}
}

// countingListener accepts and counts, and answers nothing — the behaviour of a
// raw print port, which consumes bytes and never replies.
func countingListener(t *testing.T, port int) (*net.TCPAddr, *atomic.Int64) {
	t.Helper()

	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:%d on this host: %v", port, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var conns atomic.Int64
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			conns.Add(1)
			_ = conn.Close()
		}
	}()

	return ln.Addr().(*net.TCPAddr), &conns
}

func TestProbeTLSDetailsNeverDialsAPrintPort(t *testing.T) {
	addr, conns := countingListener(t, 9101)

	info := probeTLSDetails(context.Background(), "127.0.0.1", "", addr.Port, printPortTestOptions())

	if got := conns.Load(); got != 0 {
		t.Fatalf("print port %d was dialled %d time(s); the payload must not reach it", addr.Port, got)
	}
	if info.ProbeError != "print_port_write_blocked" {
		t.Fatalf("probe_error = %q, want %q", info.ProbeError, "print_port_write_blocked")
	}
	if len(info.Attempts) != 0 {
		t.Fatalf("attempts = %d, want 0: a refused write is not an attempt", len(info.Attempts))
	}
}

// Positive control. Without it a zero-connection result would prove only that
// the listener, the probe or the test harness was broken.
func TestProbeTLSDetailsStillDialsAnOrdinaryPort(t *testing.T) {
	addr, conns := countingListener(t, 0)

	_ = probeTLSDetails(context.Background(), "127.0.0.1", "", addr.Port, printPortTestOptions())

	if conns.Load() == 0 {
		t.Fatalf("ordinary port %d was never dialled; the test proves nothing about the print-port case", addr.Port)
	}
}

// The ports arrive from EE as extra_ports, which is the scan's whole port spec.
// A floor that a caller can widen is not a floor, so the check belongs where the
// set is built rather than in whoever fills it.
func TestCandidatePortSetRefusesPrintPortsFromConfig(t *testing.T) {
	set := buildTLSCandidatePortSet([]int{515, 9100, 9101, 9102, 9443, 8080})

	for _, port := range []int{515, 9100, 9101, 9102} {
		if _, present := set[port]; present {
			t.Errorf("port %d is a candidate even though extra_ports naming it must not re-enable it", port)
		}
	}
	for _, port := range []int{443, 8443, 9443, 8080} {
		if _, present := set[port]; !present {
			t.Errorf("port %d went missing; the floor must drop print ports only", port)
		}
	}
}

func TestCandidatesFromOpenPortsSkipPrintPorts(t *testing.T) {
	set := buildTLSCandidatePortSet([]int{9100, 8080})
	item := map[string]any{
		"target":     "192.0.2.10",
		"open_ports": []int{9100, 8080},
	}

	candidates := tlsCandidatesFromOpenPorts(item, set)

	if len(candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(candidates))
	}
	if candidates[0].port != 8080 {
		t.Fatalf("candidate port = %d, want 8080", candidates[0].port)
	}
}
