package scan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// cyprob#294. Everything here reads bytes an untrusted peer chose, so the tests
// are mostly about what the parser refuses. Where a test asserts an error, it
// also asserts that nothing plausible-but-wrong came back with it: an error
// alone does not prove the parser did not first read across a boundary.

// --- ClientHello ---------------------------------------------------------

func TestBuildRawClientHello_Shape(t *testing.T) {
	t.Parallel()

	suites := []uint16{0xC02F, 0x009C, 0x0035}
	record, err := buildRawClientHello(rawClientHello{hostname: "enum.test", version: 0x0303, suites: suites})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if record[0] != tlsRecordTypeHandshake {
		t.Fatalf("record type: got 0x%02X", record[0])
	}
	if v := binary.BigEndian.Uint16(record[1:3]); v != tlsLegacyRecordVersion {
		t.Fatalf("record version must be TLS 1.0 for compatibility, got 0x%04X", v)
	}
	if n := int(binary.BigEndian.Uint16(record[3:5])); n != len(record)-5 {
		t.Fatalf("record length %d does not match the %d bytes that follow", n, len(record)-5)
	}
	if record[5] != tlsHandshakeTypeClient {
		t.Fatalf("handshake type: got 0x%02X", record[5])
	}
	if n := int(record[6])<<16 | int(record[7])<<8 | int(record[8]); n != len(record)-9 {
		t.Fatalf("handshake length %d does not match the %d bytes that follow", n, len(record)-9)
	}
	// legacy_version is always 0x0303 whatever we pin in extension 43: a 1.3
	// server answers illegal_parameter to anything else.
	if v := binary.BigEndian.Uint16(record[9:11]); v != tlsLegacyClientVersion {
		t.Fatalf("legacy_version must be 0x0303, got 0x%04X", v)
	}

	parsed, err := parseTestClientHello(record)
	if err != nil {
		t.Fatalf("parse own hello: %v", err)
	}
	if len(parsed.suites) != len(suites) {
		t.Fatalf("expected %d suites, got %v", len(suites), parsed.suites)
	}
	for i, id := range suites {
		if parsed.suites[i] != id {
			t.Fatalf("suite %d: expected 0x%04X, got 0x%04X", i, id, parsed.suites[i])
		}
	}
	if parsed.sni != "enum.test" {
		t.Fatalf("SNI: got %q", parsed.sni)
	}
	if parsed.version != 0x0303 {
		t.Fatalf("supported_versions: got 0x%04X", parsed.version)
	}
	if parsed.compressionCount != 1 {
		t.Fatalf("exactly one compression method is required, got %d", parsed.compressionCount)
	}
	for _, required := range []uint16{tlsExtSupportedGroups, tlsExtSignatureAlgorithms, tlsExtRenegotiationInfo} {
		if _, ok := parsed.extensions[required]; !ok {
			t.Fatalf("extension 0x%04X is missing; its absence changes the meaning of alert 40", required)
		}
	}
	if _, ok := parsed.extensions[tlsExtKeyShare]; ok {
		t.Fatal("key_share must not be sent below TLS 1.3")
	}
}

func TestBuildRawClientHello_TLS13SendsAnEmptyKeyShare(t *testing.T) {
	t.Parallel()

	record, err := buildRawClientHello(rawClientHello{version: 0x0304, suites: []uint16{0x1301}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	parsed, err := parseTestClientHello(record)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	share, ok := parsed.extensions[tlsExtKeyShare]
	if !ok {
		t.Fatal("a TLS 1.3 hello without key_share draws missing_extension and no ServerHello")
	}
	// Empty client_shares: asks for the server's choice without generating key
	// material we would have no use for.
	if !bytes.Equal(share, []byte{0x00, 0x00}) {
		t.Fatalf("client_shares must be empty, got %x", share)
	}
}

// The walk's whole conclusion rests on this: alert 40 is attributable to the
// suite list only if the suite list is the only thing that changed.
func TestBuildRawClientHello_OnlyTheSuiteVectorVaries(t *testing.T) {
	t.Parallel()

	offers := [][]uint16{
		{0xC02F, 0x009C, 0x0035, 0x000A},
		{0x009C, 0x0035, 0x000A},
		{0x0035},
	}
	var reference []byte
	for i, offer := range offers {
		record, err := buildRawClientHello(rawClientHello{hostname: "enum.test", version: 0x0303, suites: offer})
		if err != nil {
			t.Fatalf("build %d: %v", i, err)
		}
		stripped, err := stripTestClientHelloVariables(record)
		if err != nil {
			t.Fatalf("strip %d: %v", i, err)
		}
		if reference == nil {
			reference = stripped
			continue
		}
		if !bytes.Equal(reference, stripped) {
			t.Fatalf("hello %d differs outside the cipher suite vector, so a refusal cannot be attributed to the suites", i)
		}
	}
}

func TestBuildRawClientHello_RefusesContaminatedOffers(t *testing.T) {
	t.Parallel()

	for _, id := range []uint16{0x0000, 0x00FF, 0x5600, 0x0A0A, 0xFAFA} {
		if _, err := buildRawClientHello(rawClientHello{version: 0x0303, suites: []uint16{id}}); !errors.Is(err, errRawHelloBadSuite) {
			t.Fatalf("0x%04X must never be offered, got err=%v", id, err)
		}
	}
	if _, err := buildRawClientHello(rawClientHello{version: 0x0303}); !errors.Is(err, errRawHelloNoSuites) {
		t.Fatalf("an empty offer must be refused, got %v", err)
	}
	if _, err := buildRawClientHello(rawClientHello{version: 0x0300, suites: []uint16{0x0035}}); !errors.Is(err, errRawHelloBadVersion) {
		t.Fatalf("SSL 3.0 needs a different message format entirely, got %v", err)
	}
	// The whole registry must still fit in one record.
	if _, err := buildRawClientHello(rawClientHello{version: 0x0303, suites: tlsRegistryLegacySuiteIDs}); err != nil {
		t.Fatalf("the full legacy offer must fit in one record: %v", err)
	}
}

func TestRawHelloSNIName(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"enum.test":              "enum.test",
		"enum.test.":             "enum.test",
		"":                       "",
		"10.20.30.1":             "",
		"::1":                    "",
		"a b":                    "",
		strings.Repeat("a", 256): "",
	}
	for in, want := range cases {
		if got := rawHelloSNIName(in); got != want {
			t.Fatalf("rawHelloSNIName(%q): want %q, got %q", in, want, got)
		}
	}
}

// --- ServerHello: the happy paths, so the refusals below cannot be satisfied
// by refusing everything ---------------------------------------------------

func TestReadRawServerFlight_ParsesAServerHello(t *testing.T) {
	t.Parallel()

	flight, err := readRawServerFlight(bytes.NewReader(testServerHelloRecord(t, testServerHello{
		legacyVersion: 0x0303,
		suite:         0xC02F,
	})))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if flight.Kind != rawFlightServerHello {
		t.Fatalf("kind: %s", flight.Kind)
	}
	if flight.CipherSuite != 0xC02F || flight.Version != 0x0303 {
		t.Fatalf("suite 0x%04X version 0x%04X", flight.CipherSuite, flight.Version)
	}
	if flight.ViaHelloRetry {
		t.Fatal("an ordinary ServerHello is not a HelloRetryRequest")
	}
}

// legacy_version is 0x0303 even for TLS 1.3. Reading it and stopping labels
// every 1.3 server as 1.2 and files its 0x13xx suite in the wrong namespace.
func TestReadRawServerFlight_DerivesTLS13FromSupportedVersions(t *testing.T) {
	t.Parallel()

	flight, err := readRawServerFlight(bytes.NewReader(testServerHelloRecord(t, testServerHello{
		legacyVersion:    0x0303,
		suite:            0x1301,
		supportedVersion: 0x0304,
	})))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if flight.Version != 0x0304 {
		t.Fatalf("version must come from extension 43, got 0x%04X", flight.Version)
	}
	if flight.LegacyVersion != 0x0303 {
		t.Fatalf("the legacy field must still be reported, got 0x%04X", flight.LegacyVersion)
	}
}

func TestReadRawServerFlight_FlagsHelloRetryRequest(t *testing.T) {
	t.Parallel()

	flight, err := readRawServerFlight(bytes.NewReader(testServerHelloRecord(t, testServerHello{
		legacyVersion:    0x0303,
		suite:            0x1302,
		supportedVersion: 0x0304,
		random:           helloRetryRequestRandom,
		keyShare:         []byte{0x00, 0x1d}, // the two-byte selected_group form
	})))
	if err != nil {
		t.Fatalf("a HelloRetryRequest is a valid answer, not a malformed one: %v", err)
	}
	if !flight.ViaHelloRetry {
		t.Fatal("the fixed random must be recognized")
	}
	if flight.CipherSuite != 0x1302 {
		t.Fatalf("the HRR's suite is a real selection, got 0x%04X", flight.CipherSuite)
	}
}

func TestReadRawServerFlight_DetectsDowngradeCanary(t *testing.T) {
	t.Parallel()

	random := append([]byte(nil), bytes.Repeat([]byte{0x11}, 24)...)
	random = append(random, []byte("DOWNGRD\x01")...)
	flight, err := readRawServerFlight(bytes.NewReader(testServerHelloRecord(t, testServerHello{
		legacyVersion: 0x0303, suite: 0xC02F, random: random,
	})))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if flight.DowngradeCanary != "tls12" {
		t.Fatalf("expected the canary to be surfaced, got %q", flight.DowngradeCanary)
	}
}

func TestReadRawServerFlight_ServerHelloWithNoExtensionsIsValid(t *testing.T) {
	t.Parallel()

	flight, err := readRawServerFlight(bytes.NewReader(testServerHelloRecord(t, testServerHello{
		legacyVersion: 0x0301, suite: 0x000A, omitExtensions: true,
	})))
	if err != nil {
		t.Fatalf("a ServerHello may end after the compression method: %v", err)
	}
	if flight.Version != 0x0301 || flight.CipherSuite != 0x000A {
		t.Fatalf("suite 0x%04X version 0x%04X", flight.CipherSuite, flight.Version)
	}
}

// --- ServerHello: what it must refuse ------------------------------------

func TestReadRawServerFlight_TruncatedAtEveryBoundary(t *testing.T) {
	t.Parallel()

	full := testServerHelloRecord(t, testServerHello{legacyVersion: 0x0303, suite: 0xC02F})
	for n := 0; n < len(full); n++ {
		flight, err := readRawServerFlight(bytes.NewReader(full[:n]))
		if err == nil {
			t.Fatalf("a %d-byte prefix of a %d-byte flight must not parse", n, len(full))
		}
		if flight.CipherSuite != 0 {
			t.Fatalf("prefix of %d bytes produced suite 0x%04X — a partial parse leaked a value", n, flight.CipherSuite)
		}
	}
}

// The bug that fabricates a finding rather than crashing: a vector bounds-checked
// against the buffer instead of the message reads forward into the next message.
// cyprob#312. This test used to corrupt the session-id length to 0xFF, which
// overruns not only its own message but the whole buffer, so vector8() failed
// for want of bytes whether the cursor was scoped or not — proven by mutation
// in review: the cursor was changed to buf[4:] and the test still passed.
//
// Isolating the bound needs an overrun that is small enough to pass the
// separate len(sessionID) > 32 check, which means the bytes worth stealing have
// to be within 32 of the cursor. Two well-formed ServerHellos can never do
// that: the second one's suite sits at least 42 bytes away, behind its own
// header, version and 32-byte random. So the message that follows is not a
// ServerHello — nothing parses it, and it only has to be there.
func TestReadRawServerFlight_VectorsAreScopedToTheMessage(t *testing.T) {
	t.Parallel()

	t.Run("a length reaching into what follows, small enough to pass the 32-byte check", func(t *testing.T) {
		t.Parallel()

		// 38 bytes exactly: 2 version + 32 random + 1 session-id length + 0
		// session id + 2 suite + 1 compression, and no extensions block.
		first := testServerHelloBody(t, testServerHello{
			legacyVersion:  0x0303,
			suite:          0x0035,
			sessionID:      []byte{},
			omitExtensions: true,
		})
		if len(first) != tlsMinServerHelloBody {
			t.Fatalf("the fixture must be the minimum body for the arithmetic below, got %d bytes", len(first))
		}

		// What an unscoped cursor would find 7 bytes past the session-id
		// length: a suite value that was never negotiated, followed by a zero
		// compression byte, and then nothing — so the parse would succeed and
		// return 0xC030 rather than fail.
		stolen := []byte{0xC0, 0x30, 0x00}
		following := append([]byte{tlsHandshakeTypeServer, 0x00, 0x00, byte(len(stolen))}, stolen...)

		// 3 bytes left in this message, then the 4-byte header of what follows.
		const overrun = 3 + 4
		if overrun > 32 {
			t.Fatal("the overrun must stay under the session-id cap, or the > 32 check is what refuses it")
		}
		first[2+32] = byte(overrun)

		payload := append(testHandshakeHeader(first), first...)
		payload = append(payload, following...)

		flight, err := readRawServerFlight(bytes.NewReader(testRecord(tlsRecordTypeHandshake, payload)))
		if flight.CipherSuite == 0xC030 {
			t.Fatal("the parser read past its own message and returned a suite from what followed")
		}
		if err == nil {
			t.Fatal("a session id length overrunning its message must be refused")
		}
		if !errors.Is(err, errRawMalformed) {
			t.Fatalf("want malformed, got %v", err)
		}
	})

	// The original case, kept because it is still worth refusing — but named
	// for what it actually proves, which is not the scoping.
	t.Run("a length overrunning the whole buffer is refused for want of bytes", func(t *testing.T) {
		t.Parallel()

		first := testServerHelloBody(t, testServerHello{legacyVersion: 0x0303, suite: 0x0035})
		first[2+32] = 0xFF
		second := testServerHelloBody(t, testServerHello{legacyVersion: 0x0303, suite: 0xC030})

		payload := append(testHandshakeHeader(first), first...)
		payload = append(payload, testHandshakeHeader(second)...)
		payload = append(payload, second...)

		flight, err := readRawServerFlight(bytes.NewReader(testRecord(tlsRecordTypeHandshake, payload)))
		if err == nil {
			t.Fatal("a session id length overrunning its message must be refused")
		}
		if flight.CipherSuite == 0xC030 {
			t.Fatal("the parser read into the following message and returned its suite")
		}
	})
}

func TestReadRawServerFlight_RejectsDeclaredLengths(t *testing.T) {
	t.Parallel()

	t.Run("record longer than a plaintext record", func(t *testing.T) {
		t.Parallel()
		header := []byte{tlsRecordTypeHandshake, 0x03, 0x03, 0xFF, 0xFF}
		if _, err := readRawServerFlight(bytes.NewReader(header)); !errors.Is(err, errRawMalformed) {
			t.Fatalf("want malformed, got %v", err)
		}
	})

	t.Run("handshake longer than a ServerHello can be", func(t *testing.T) {
		t.Parallel()
		payload := []byte{tlsHandshakeTypeServer, 0xFF, 0xFF, 0xFF}
		if _, err := readRawServerFlight(bytes.NewReader(testRecord(tlsRecordTypeHandshake, payload))); !errors.Is(err, errRawMalformed) {
			t.Fatalf("want malformed, got %v", err)
		}
	})

	t.Run("handshake shorter than the fixed body", func(t *testing.T) {
		t.Parallel()
		payload := []byte{tlsHandshakeTypeServer, 0x00, 0x00, 0x20}
		payload = append(payload, bytes.Repeat([]byte{0x00}, 32)...)
		if _, err := readRawServerFlight(bytes.NewReader(testRecord(tlsRecordTypeHandshake, payload))); !errors.Is(err, errRawMalformed) {
			t.Fatalf("want malformed, got %v", err)
		}
	})

	t.Run("extensions block overruns the message", func(t *testing.T) {
		t.Parallel()
		body := testServerHelloBody(t, testServerHello{legacyVersion: 0x0303, suite: 0xC02F, supportedVersion: 0x0304})
		binary.BigEndian.PutUint16(body[len(body)-2-4-2:], 0xFF00)
		payload := append(testHandshakeHeader(body), body...)
		if _, err := readRawServerFlight(bytes.NewReader(testRecord(tlsRecordTypeHandshake, payload))); err == nil {
			t.Fatal("an extensions block longer than the message must be refused")
		}
	})
}

func TestReadRawServerFlight_RejectsWrongHandshakeType(t *testing.T) {
	t.Parallel()

	// The body is a well-formed ServerHello and only the type byte is wrong, so
	// a parser without the type check parses it happily and returns a perfectly
	// plausible suite. That is the point: a Certificate or a ClientHello read
	// positionally fabricates a finding rather than crashing, and a test that
	// merely asserted "some error" would pass with the check removed.
	body := testServerHelloBody(t, testServerHello{legacyVersion: 0x0303, suite: 0xC030})
	for _, msgType := range []byte{0x01 /* ClientHello */, 0x0B /* Certificate */, 0x04 /* NewSessionTicket */} {
		header := testHandshakeHeader(body)
		header[0] = msgType
		payload := append(append([]byte(nil), header...), body...)
		flight, err := readRawServerFlight(bytes.NewReader(testRecord(tlsRecordTypeHandshake, payload)))
		if !errors.Is(err, errRawMalformed) {
			t.Fatalf("handshake type 0x%02X must be refused, got %v", msgType, err)
		}
		if flight.CipherSuite != 0 {
			t.Fatalf("handshake type 0x%02X yielded suite 0x%04X — it was parsed positionally", msgType, flight.CipherSuite)
		}
	}

	// And a real ClientHello on the wire, which is what a misconfigured proxy
	// in front of the service sends back.
	hello, err := buildRawClientHello(rawClientHello{version: 0x0303, suites: []uint16{0xC02F, 0x0035}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := readRawServerFlight(bytes.NewReader(hello)); !errors.Is(err, errRawMalformed) {
		t.Fatalf("want malformed, got %v", err)
	}
}

func TestReadRawServerFlight_RejectsNonNullCompression(t *testing.T) {
	t.Parallel()

	if _, err := readRawServerFlight(bytes.NewReader(testServerHelloRecord(t, testServerHello{
		legacyVersion: 0x0303, suite: 0xC02F, compression: 0x01,
	}))); !errors.Is(err, errRawMalformed) {
		t.Fatalf("want malformed, got %v", err)
	}
}

func TestReadRawServerFlight_RejectsOversizedSessionIDEcho(t *testing.T) {
	t.Parallel()

	// Deliberately stricter than crypto/tls, which caps nothing here: RFC 8446
	// declares the echo as opaque<0..32>.
	if _, err := readRawServerFlight(bytes.NewReader(testServerHelloRecord(t, testServerHello{
		legacyVersion: 0x0303, suite: 0xC02F, sessionID: bytes.Repeat([]byte{0x01}, 33),
	}))); !errors.Is(err, errRawMalformed) {
		t.Fatalf("want malformed, got %v", err)
	}
}

func TestReadRawServerFlight_RejectsTrailingBytes(t *testing.T) {
	t.Parallel()

	body := testServerHelloBody(t, testServerHello{legacyVersion: 0x0303, suite: 0xC02F, supportedVersion: 0x0304})
	body = append(body, bytes.Repeat([]byte{0xAB}, 32)...)
	payload := append(testHandshakeHeader(body), body...)
	if _, err := readRawServerFlight(bytes.NewReader(testRecord(tlsRecordTypeHandshake, payload))); !errors.Is(err, errRawMalformed) {
		t.Fatalf("bytes after a well-formed extensions block must be refused, got %v", err)
	}
}

func TestReadRawServerFlight_RejectsDuplicateExtensions(t *testing.T) {
	t.Parallel()

	// The unknown type is the interesting one: a parser that skips unknown
	// bodies before checking for a repeat lets it past.
	for _, extType := range []uint16{tlsExtSupportedVersions, 0xFAFA} {
		body := testServerHelloBody(t, testServerHello{
			legacyVersion: 0x0303, suite: 0xC02F,
			extraExtensions: []testExtension{{extType, []byte{0x03, 0x04}}, {extType, []byte{0x03, 0x04}}},
		})
		payload := append(testHandshakeHeader(body), body...)
		if _, err := readRawServerFlight(bytes.NewReader(testRecord(tlsRecordTypeHandshake, payload))); !errors.Is(err, errRawDuplicateExtension) {
			t.Fatalf("duplicate 0x%04X must be refused, got %v", extType, err)
		}
	}
}

func TestReadRawServerFlight_BoundsExtensionCount(t *testing.T) {
	t.Parallel()

	extras := make([]testExtension, 0, 2000)
	for i := 0; i < 2000; i++ {
		extras = append(extras, testExtension{uint16(0x8000 + i), nil})
	}
	body := testServerHelloBody(t, testServerHello{legacyVersion: 0x0303, suite: 0xC02F, extraExtensions: extras})
	payload := append(testHandshakeHeader(body), body...)
	if _, err := readRawServerFlight(bytes.NewReader(testRecord(tlsRecordTypeHandshake, payload))); !errors.Is(err, errRawTooManyExtensions) {
		t.Fatalf("the block length alone does not bound the work; got %v", err)
	}
}

func TestReadRawServerFlight_SupportedVersionsMustBeExactlyTwoBytes(t *testing.T) {
	t.Parallel()

	for _, body := range [][]byte{{}, {0x03}, {0x03, 0x04, 0x00}, {0x02, 0x03, 0x04}} {
		hello := testServerHelloBody(t, testServerHello{
			legacyVersion: 0x0303, suite: 0xC02F,
			extraExtensions: []testExtension{{tlsExtSupportedVersions, body}},
		})
		payload := append(testHandshakeHeader(hello), hello...)
		if _, err := readRawServerFlight(bytes.NewReader(testRecord(tlsRecordTypeHandshake, payload))); !errors.Is(err, errRawMalformed) {
			t.Fatalf("supported_versions of %d bytes must be refused, got %v", len(body), err)
		}
	}
}

// A record boundary is invisible at the message layer, and the split that
// catches a naive reassembler is the one inside a two-byte field — so every
// split point is tried rather than a chosen few.
func TestReadRawServerFlight_SplitAcrossRecordsAtEveryOffset(t *testing.T) {
	t.Parallel()

	body := testServerHelloBody(t, testServerHello{legacyVersion: 0x0303, suite: 0xC030, supportedVersion: 0x0304})
	message := append(testHandshakeHeader(body), body...)

	for split := 1; split < len(message); split++ {
		stream := append(testRecord(tlsRecordTypeHandshake, message[:split]), testRecord(tlsRecordTypeHandshake, message[split:])...)
		flight, err := readRawServerFlight(bytes.NewReader(stream))
		if err != nil {
			t.Fatalf("split at %d: %v", split, err)
		}
		if flight.CipherSuite != 0xC030 || flight.Version != 0x0304 {
			t.Fatalf("split at %d: suite 0x%04X version 0x%04X", split, flight.CipherSuite, flight.Version)
		}
	}
}

func TestReadRawServerFlight_BoundsNonAdvancingRecords(t *testing.T) {
	t.Parallel()

	// Interleaved with a handshake byte so a counter that resets on progress
	// never trips, which is exactly how crypto/tls's own bound is defeated.
	stream := make([]byte, 0, 4096)
	for i := 0; i < 64; i++ {
		stream = append(stream, testRecord(tlsRecordTypeCCS, []byte{0x01})...)
	}
	done := make(chan error, 1)
	go func() { _, err := readRawServerFlight(bytes.NewReader(stream)); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, errRawNonAdvancingPeer) && !errors.Is(err, errRawTooManyRecords) {
			t.Fatalf("want a peer-budget error, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stream of useless records must be bounded")
	}
}

func TestReadRawServerFlight_ClassifiesNonTLSServices(t *testing.T) {
	t.Parallel()

	cases := map[string][]byte{
		// The first five bytes parse as a record declaring 11570 bytes; without
		// the first-byte gate the parser blocks for them from a peer that is
		// itself waiting for our banner.
		"ssh banner":     []byte("SSH-2.0-OpenSSH_9.6\r\n"),
		"plaintext http": []byte("HTTP/1.1 400 Bad Request\r\n\r\n"),
		"sslv2 header":   {0x80, 0x2e, 0x01, 0x03, 0x01},
		"garbage":        bytes.Repeat([]byte{0xFF}, 64),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			done := make(chan rawServerFlight, 1)
			go func() {
				flight, _ := readRawServerFlight(bytes.NewReader(input))
				done <- flight
			}()
			select {
			case flight := <-done:
				if flight.Kind != rawFlightNotTLS {
					t.Fatalf("want not_tls, got %q", flight.Kind)
				}
				if flight.CipherSuite != 0 {
					t.Fatalf("a non-TLS service must yield no suite, got 0x%04X", flight.CipherSuite)
				}
				if len(flight.FirstBytes) != 5 {
					t.Fatalf("the first five bytes must be kept for diagnosis, got %d", len(flight.FirstBytes))
				}
			case <-time.After(5 * time.Second):
				t.Fatal("classification must not block on a peer that is waiting for us")
			}
		})
	}
}

func TestReadRawServerFlight_ClassifiesAlerts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		description uint8
		want        rawFlightKind
	}{
		{40, rawFlightRefused},      // handshake_failure -- no shared suite
		{71, rawFlightRefused},      // insufficient_security
		{70, rawFlightVersionRefus}, // protocol_version
		{47, rawFlightProbeReject},  // illegal_parameter -- our hello was wrong
		{109, rawFlightProbeReject}, // missing_extension
		{112, rawFlightProbeReject}, // unrecognized_name -- wrong SNI, not a refusal
		{86, rawFlightProbeReject},  // inappropriate_fallback
		{80, rawFlightProbeReject},  // internal_error
	}
	for _, tc := range cases {
		flight, err := readRawServerFlight(bytes.NewReader(testRecord(tlsRecordTypeAlert, []byte{tlsAlertLevelFatal, tc.description})))
		if err != nil {
			t.Fatalf("alert %d: %v", tc.description, err)
		}
		if flight.Kind != tc.want {
			t.Fatalf("alert %d: want %q, got %q", tc.description, tc.want, flight.Kind)
		}
		if flight.CipherSuite != 0 {
			t.Fatalf("alert %d produced a suite", tc.description)
		}
	}

	if _, err := readRawServerFlight(bytes.NewReader(testRecord(tlsRecordTypeAlert, []byte{0x02}))); !errors.Is(err, errRawMalformed) {
		t.Fatalf("an alert body must be exactly two bytes, got %v", err)
	}
}

// Nothing retained may alias the read buffer: reusing it would corrupt results
// already returned, and holding one field would pin the whole buffer per host.
func TestReadRawServerFlight_DoesNotAliasTheReadBuffer(t *testing.T) {
	t.Parallel()

	record := testServerHelloRecord(t, testServerHello{legacyVersion: 0x0303, suite: 0xC02F})
	flight, err := readRawServerFlight(bytes.NewReader(record))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	first := append([]byte(nil), flight.FirstBytes...)
	for i := range record {
		record[i] = 0xAA
	}
	if !bytes.Equal(first, flight.FirstBytes) {
		t.Fatal("FirstBytes aliases the source buffer")
	}
}

// A reader that never delivers must not hang the parser forever; the caller's
// deadline is what stops it, and the parser must propagate rather than spin.
func TestReadRawServerFlight_PropagatesReadErrors(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("read failed")
	if _, err := readRawServerFlight(errReader{sentinel}); !errors.Is(err, sentinel) {
		t.Fatalf("want the reader's error, got %v", err)
	}
	if _, err := readRawServerFlight(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF on an empty stream, got %v", err)
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }
