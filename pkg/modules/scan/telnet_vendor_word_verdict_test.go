package scan

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// mikrotikFTPGreeting is the greeting recorded on 192.168.0.41:21, the service
// that was stored as telnet because this string contains "MikroTik".
const mikrotikFTPGreeting = "220 Habib FTP server (MikroTik 6.49.10) ready\r\n"

func TestTelnetVerdict_VendorWordIsNotProtocolProof(t *testing.T) {
	outcome := parseTelnetTranscript([]byte(mikrotikFTPGreeting))

	if outcome.iacDetected {
		t.Fatalf("fixture is wrong: an FTP greeting must carry no IAC byte")
	}
	if !bannerLooksLikeTelnet(outcome.banner) {
		t.Fatalf("fixture is wrong: this banner must still pass the candidate filter, " +
			"otherwise the test would pass for the wrong reason")
	}

	if bannerShowsTelnetDialog(outcome.banner) {
		t.Errorf("an FTP greeting naming a vendor must not count as telnet dialog: %q", outcome.banner)
	}
}

func TestTelnetVerdict_RealDialogStillCounts(t *testing.T) {
	cases := map[string]string{
		"login prompt":    "\r\nWelcome to the router\r\nlogin: ",
		"username prompt": "Username: ",
		"password prompt": "\r\nPassword: ",
	}
	for name, banner := range cases {
		t.Run(name, func(t *testing.T) {
			if !bannerShowsTelnetDialog(banner) {
				t.Errorf("a login/password prompt is telnet evidence and must still be accepted: %q", banner)
			}
		})
	}
}

func TestTelnetVerdict_IACStillCounts(t *testing.T) {
	// IAC DO ECHO, IAC WILL SUPPRESS-GO-AHEAD -- a real telnet negotiation.
	outcome := parseTelnetTranscript([]byte{255, 253, 1, 255, 251, 3})
	if !outcome.iacDetected {
		t.Fatalf("IAC negotiation must still be detected; the verdict's first branch depends on it")
	}
}

func TestFTPHints_ReadsRouterOSVersionFromTheGreeting(t *testing.T) {
	product, vendor, version := inferFTPSoftwareHints(mikrotikFTPGreeting)

	if product != "RouterOS" {
		t.Errorf("product = %q, want RouterOS", product)
	}
	if vendor != "MikroTik" {
		t.Errorf("vendor = %q, want MikroTik", vendor)
	}
	if version != "6.49.10" {
		t.Errorf("version = %q, want 6.49.10 -- this is the only unauthenticated "+
			"source of a RouterOS version on these devices", version)
	}
}

func TestFTPHints_DoesNotInventAVersion(t *testing.T) {
	product, vendor, version := inferFTPSoftwareHints("220 MikroTik FTP server ready")
	if product != "RouterOS" || vendor != "MikroTik" {
		t.Fatalf("product/vendor = %q/%q, want RouterOS/MikroTik", product, vendor)
	}
	if version != "" {
		t.Errorf("version = %q, want empty: the greeting names no version", version)
	}
}

func TestFTPHints_LeavesOtherServersAlone(t *testing.T) {
	product, _, version := inferFTPSoftwareHints("220 ProFTPD 1.3.5 Server ready")
	if product != "ProFTPD" || version != "1.3.5" {
		t.Errorf("product/version = %q/%q, want ProFTPD/1.3.5", product, version)
	}
}

// TestProbeTelnetAttempt_RefusesAnFTPGreeting drives the verdict branch itself
// against a local listener, because asserting the predicate alone would not
// notice the call site reverting to the candidate filter.
func TestProbeTelnetAttempt_RefusesAnFTPGreeting(t *testing.T) {
	host, port, stop := serveOnce(t, mikrotikFTPGreeting)
	defer stop()

	attempt, outcome, errCode := probeTelnetAttempt(context.Background(), host, port, TelnetProbeOptions{
		ConnectTimeout: 2 * time.Second,
		IOTimeout:      2 * time.Second,
	})

	if outcome == nil {
		t.Fatalf("no transcript was read; the fixture never spoke")
	}
	if outcome.banner == "" {
		t.Fatalf("fixture is wrong: the probe must actually have read the greeting")
	}
	if attempt.Success {
		t.Errorf("probe reported success on an FTP greeting; error code %q", errCode)
	}
	if errCode != "protocol_mismatch" {
		t.Errorf("error = %q, want protocol_mismatch", errCode)
	}
}

// serveOnce accepts one connection, writes payload and closes.
func serveOnce(t *testing.T, payload string) (string, int, func()) {
	t.Helper()
	ln := mustListenTCP(t, "127.0.0.1:0")

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(payload))
	}()

	host, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse listener port: %v", err)
	}
	return host, port, func() { _ = ln.Close() }
}
