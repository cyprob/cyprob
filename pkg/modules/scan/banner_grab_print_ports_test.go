package scan

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/fingerprint"
)

// listenCountingBytes accepts one connection on the given port and records how
// many bytes the client sent. A print port cannot be simulated any other way:
// the defect is not what comes back, it is what goes out.
func listenCountingBytes(t *testing.T, port int) (*net.TCPListener, *int64) {
	t.Helper()

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:%d here: %v", port, err)
	}

	var received int64
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				atomic.AddInt64(&received, int64(n))
			}(conn)
		}
	}()

	return ln, &received
}

// The cyprob#268 report, as a test: an office sweep put our probe payload on
// paper. Nothing may be written to a JetDirect port, by either probe path.
func TestRunActiveProbes_SendsNothingToAPrintPort(t *testing.T) {
	const printPort = 9100

	ln, received := listenCountingBytes(t, printPort)
	defer func() { _ = ln.Close() }()

	catalog, err := fingerprint.GetProbeCatalog()
	if err != nil {
		t.Fatalf("probe catalog: %v", err)
	}

	m := newBannerGrabModule()
	observations := make([]engine.ProbeObservation, 0, 2)
	var lastError string
	hints := newHintAccumulator()
	hints.add("http") // the hint that used to pull http-get onto any port

	host := "127.0.0.1"
	m.runActiveProbes(context.Background(), net.JoinHostPort(host, strconv.Itoa(printPort)),
		host, host, printPort, catalog, &observations, &lastError, &hints)

	m.runTLSFallbackPass(context.Background(), host, host, printPort, catalog,
		&observations, &lastError, &hints, map[string]struct{}{})

	// Give any connection the listener did accept time to be read.
	time.Sleep(200 * time.Millisecond)

	if n := atomic.LoadInt64(received); n != 0 {
		t.Fatalf("%d bytes reached the print port; on a real device that is a printed page", n)
	}
	if len(observations) != 0 {
		t.Fatalf("expected no probe observations on a print port, got %d", len(observations))
	}
}
