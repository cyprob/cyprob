package scan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Reading the server's first flight, by hand
//
// The parser reads exactly one handshake message from an untrusted peer and
// performs no cryptography. Every length in a TLS record is attacker-controlled,
// so the shape of this file is: never index before the read is confirmed
// complete, never allocate on a declared length before bounding it, and never
// bounds-check a vector against the read buffer when the message is what
// contains it. That last one is the mistake that produces a plausible wrong
// answer rather than a crash -- a session-id length that overruns its message
// reads forward into the next one and returns a cipher suite from the wrong
// offset, which is a fabricated finding with nothing to notice.
//
// The other half of this file is classification. "No shared cipher suite" and
// "you have been rate-limited" arrive as the same alert or as no bytes at all,
// and conflating them is precisely the failure cyprob#294 exists to prevent, so
// the verdict, the alert and the transport outcome are three separate fields
// and a transport failure can never write "refused".

const (
	tlsMaxRecordsPerFlight   = 32
	tlsMaxBytesPerFlight     = 32 << 10
	tlsMaxNonAdvancingRecord = 8
	tlsMaxExtensionsInHello  = 24
	tlsMinServerHelloBody    = 38 // 2 version + 32 random + 1 sid len + 2 suite + 1 compression
	tlsMaxServerHelloMessage = 16384
	tlsAlertLevelWarning     = 1
	tlsAlertLevelFatal       = 2
)

// helloRetryRequestRandom is the fixed value RFC 8446 puts in a
// HelloRetryRequest's random field. It is the only way to tell one from an
// ordinary ServerHello.
var helloRetryRequestRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

var (
	downgradeCanaryTLS12 = []byte("DOWNGRD\x01")
	downgradeCanaryTLS11 = []byte("DOWNGRD\x00")
)

var (
	errRawNotTLS             = errors.New("not_tls")
	errRawMalformed          = errors.New("malformed")
	errRawTooManyRecords     = errors.New("too_many_records")
	errRawTooManyBytes       = errors.New("too_many_bytes")
	errRawNonAdvancingPeer   = errors.New("too_many_useless_records")
	errRawTooManyExtensions  = errors.New("too_many_extensions")
	errRawDuplicateExtension = errors.New("duplicate_extension")
)

// rawFlightKind is what the server's first flight turned out to be. It is
// deliberately not a boolean: "refused" and "we never got a usable answer" are
// different results and only one of them may end a walk cleanly.
type rawFlightKind string

const (
	rawFlightServerHello  rawFlightKind = "server_hello"
	rawFlightRefused      rawFlightKind = "refused"
	rawFlightVersionRefus rawFlightKind = "version_refused"
	rawFlightProbeReject  rawFlightKind = "probe_rejected"
	rawFlightNotTLS       rawFlightKind = "not_tls"
)

// rawServerFlight is everything one dial learned. FirstBytes is kept for every
// outcome because a peer nobody can classify is diagnosable from its first five
// bytes and from nothing else.
type rawServerFlight struct {
	Kind             rawFlightKind
	CipherSuite      uint16
	Version          uint16
	LegacyVersion    uint16
	ViaHelloRetry    bool
	DowngradeCanary  string
	AlertLevel       uint8
	AlertDescription uint8
	FirstBytes       []byte
}

// readRawServerFlight reads records until it has one handshake message, an
// alert, or a reason to stop.
func readRawServerFlight(r io.Reader) (rawServerFlight, error) {
	flight := rawServerFlight{}
	handshake := make([]byte, 0, 512)

	records, totalBytes, nonAdvancing := 0, 0, 0
	header := make([]byte, 5)

	for {
		if records >= tlsMaxRecordsPerFlight {
			return flight, errRawTooManyRecords
		}
		if _, err := io.ReadFull(r, header); err != nil {
			return flight, err
		}
		records++
		totalBytes += len(header)

		if records == 1 {
			flight.FirstBytes = append([]byte(nil), header...)
			if kind, ok := classifyFirstRecordByte(header); !ok {
				flight.Kind = kind
				return flight, errRawNotTLS
			}
		}

		length := int(binary.BigEndian.Uint16(header[3:5]))
		// Nothing on this connection is ever encrypted, so a plaintext record
		// larger than the plaintext maximum is malformed. crypto/tls allows
		// more to leave room for expansion it will never see here.
		if length > tlsMaxPlaintextRecord {
			return flight, fmt.Errorf("%w: record length %d", errRawMalformed, length)
		}
		if totalBytes+length > tlsMaxBytesPerFlight {
			return flight, errRawTooManyBytes
		}

		payload := make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return flight, err
		}
		totalBytes += length

		advanced := false
		switch header[0] {
		case tlsRecordTypeHandshake:
			if length == 0 {
				return flight, fmt.Errorf("%w: empty handshake record", errRawMalformed)
			}
			handshake = append(handshake, payload...)
			advanced = true

		case tlsRecordTypeAlert:
			return parseRawAlert(flight, payload)

		case tlsRecordTypeCCS:
			// Legal TLS 1.3 middlebox compatibility, and legal nowhere else in
			// a first flight. It carries no information either way.
			if length != 1 || payload[0] != 0x01 {
				return flight, fmt.Errorf("%w: change_cipher_spec body", errRawMalformed)
			}

		case tlsRecordTypeAppData:
			return flight, fmt.Errorf("%w: application data before ServerHello", errRawMalformed)

		default:
			return flight, fmt.Errorf("%w: record type %d", errRawMalformed, header[0])
		}

		if !advanced {
			nonAdvancing++
			// Never reset on an advancing record. crypto/tls resets its own
			// counter, which lets a peer alternate useless records with one
			// useful byte and spin inside the bound forever.
			if nonAdvancing >= tlsMaxNonAdvancingRecord {
				return flight, errRawNonAdvancingPeer
			}
			continue
		}

		done, err := rawHandshakeComplete(handshake)
		if err != nil {
			return flight, err
		}
		if done {
			return parseRawServerHello(flight, handshake)
		}
	}
}

// classifyFirstRecordByte decides, before anything else is read, whether this
// is TLS at all. An SSH banner's first bytes parse as a record header declaring
// 11570 bytes, and a parser without this gate blocks waiting for them from a
// peer that is itself waiting for our banner.
func classifyFirstRecordByte(header []byte) (rawFlightKind, bool) {
	if header[0] == 0x80 {
		return rawFlightNotTLS, false // SSLv2 record header
	}
	switch header[0] {
	case tlsRecordTypeHandshake, tlsRecordTypeAlert, tlsRecordTypeCCS, tlsRecordTypeAppData:
		// A TLS content type. Whether it is a *sensible* first record is the
		// record loop's business; this gate only separates TLS from a service
		// that is not speaking TLS at all.
	default:
		return rawFlightNotTLS, false
	}
	if binary.BigEndian.Uint16(header[1:3]) >= 0x1000 {
		return rawFlightNotTLS, false
	}
	return rawFlightServerHello, true
}

func parseRawAlert(flight rawServerFlight, payload []byte) (rawServerFlight, error) {
	if len(payload) != 2 {
		return flight, fmt.Errorf("%w: alert body of %d bytes", errRawMalformed, len(payload))
	}
	flight.AlertLevel, flight.AlertDescription = payload[0], payload[1]
	flight.Kind = classifyRawAlert(payload[1])
	return flight, nil
}

// classifyRawAlert is the load-bearing table. Alert 40 is what a server sends
// when it shares no cipher suite with us -- and also when it shares no group,
// and when it dislikes our renegotiation extension, and at several certificate
// dead ends. Reading it as a suite refusal is sound only because every byte of
// the hello except the suite vector is held constant across a walk.
func classifyRawAlert(description uint8) rawFlightKind {
	switch description {
	case 40, 71: // handshake_failure, insufficient_security
		return rawFlightRefused
	case 70: // protocol_version
		return rawFlightVersionRefus
	default:
		// 47 illegal_parameter, 50 decode_error, 80 internal_error, 109
		// missing_extension, 112 unrecognized_name, 86 inappropriate_fallback:
		// all of these say our hello was wrong, not that the suite is
		// unsupported. Recording one as a refusal would delete a supported
		// suite from the answer.
		return rawFlightProbeReject
	}
}

// rawHandshakeComplete reports whether the buffer holds a whole message, and
// rejects the message before it is whole when its declared shape is impossible.
func rawHandshakeComplete(buf []byte) (bool, error) {
	if len(buf) < 4 {
		return false, nil
	}
	// Checked before a single body byte is parsed. A ClientHello read
	// positionally as a ServerHello puts the client's suite-list length where
	// the negotiated suite belongs: a fabricated finding, no crash.
	if buf[0] != tlsHandshakeTypeServer {
		return false, fmt.Errorf("%w: handshake type %d", errRawMalformed, buf[0])
	}
	length := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	if length > tlsMaxServerHelloMessage {
		return false, fmt.Errorf("%w: ServerHello of %d bytes", errRawMalformed, length)
	}
	if length < tlsMinServerHelloBody {
		return false, fmt.Errorf("%w: ServerHello body of %d bytes", errRawMalformed, length)
	}
	return len(buf) >= 4+length, nil
}

func parseRawServerHello(flight rawServerFlight, buf []byte) (rawServerFlight, error) {
	length := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	// Scoped to this message and nothing beyond it, so a lying vector length
	// cannot read into whatever followed.
	body := newRawCursor(buf[4 : 4+length])

	legacyVersion, ok := body.uint16()
	if !ok {
		return flight, fmt.Errorf("%w: legacy_version", errRawMalformed)
	}
	random, ok := body.bytes(32)
	if !ok {
		return flight, fmt.Errorf("%w: random", errRawMalformed)
	}
	sessionID, ok := body.vector8()
	if !ok {
		return flight, fmt.Errorf("%w: legacy_session_id_echo", errRawMalformed)
	}
	// Stricter than crypto/tls, which caps nothing here. RFC 8446 declares the
	// echo as opaque<0..32>, and a server that exceeds it is telling us
	// something worth recording rather than something worth accommodating.
	if len(sessionID) > 32 {
		return flight, fmt.Errorf("%w: session id echo of %d bytes", errRawMalformed, len(sessionID))
	}
	cipherSuite, ok := body.uint16()
	if !ok {
		return flight, fmt.Errorf("%w: cipher_suite", errRawMalformed)
	}
	compression, ok := body.uint8()
	if !ok {
		return flight, fmt.Errorf("%w: legacy_compression_method", errRawMalformed)
	}
	if compression != 0x00 {
		return flight, fmt.Errorf("%w: compression method %d", errRawMalformed, compression)
	}

	flight.Kind = rawFlightServerHello
	flight.LegacyVersion = legacyVersion
	flight.Version = legacyVersion
	flight.CipherSuite = cipherSuite
	flight.ViaHelloRetry = bytes.Equal(random, helloRetryRequestRandom)

	supportedVersion, err := parseRawServerHelloExtensions(&body)
	if err != nil {
		return flight, err
	}
	// The TLS 1.3 trap: legacy_version is 0x0303 even for TLS 1.3, and the real
	// version is a bare uint16 inside extension 43. Reading the field and
	// stopping labels every TLS 1.3 server as TLS 1.2 and files its 0x13xx
	// suite in the wrong namespace.
	if supportedVersion != 0 {
		flight.Version = supportedVersion
	}

	if !flight.ViaHelloRetry && flight.Version <= 0x0303 {
		// Free, crypto-free signal: a server that supports a higher version
		// than it just negotiated says so in the last eight bytes of its
		// random. Skipped for a HelloRetryRequest, whose random is the fixed
		// marker, and at 1.3, where those bytes mean something else.
		switch {
		case bytes.Equal(random[24:32], downgradeCanaryTLS12):
			flight.DowngradeCanary = "tls12"
		case bytes.Equal(random[24:32], downgradeCanaryTLS11):
			flight.DowngradeCanary = "tls11"
		}
	}
	return flight, nil
}

// parseRawServerHelloExtensions returns the version from extension 43, or zero
// when the block is absent. A ServerHello with no extensions at all is legal.
func parseRawServerHelloExtensions(body *rawCursor) (uint16, error) {
	if body.empty() {
		return 0, nil
	}
	block, ok := body.vector16()
	if !ok {
		return 0, fmt.Errorf("%w: extensions block", errRawMalformed)
	}
	// Trailing bytes after a well-formed block are a parse failure, not
	// something to ignore -- crypto/tls requires the message to be exactly
	// consumed and so do we.
	if !body.empty() {
		return 0, fmt.Errorf("%w: %d bytes after the extensions block", errRawMalformed, body.remaining())
	}

	cursor := newRawCursor(block)
	seen := make(map[uint16]struct{}, 8)
	supportedVersion := uint16(0)

	for !cursor.empty() {
		if len(seen) >= tlsMaxExtensionsInHello {
			// The block length alone does not bound the work: 16383 legal
			// four-byte empty extensions fit inside one message.
			return 0, errRawTooManyExtensions
		}
		extType, ok := cursor.uint16()
		if !ok {
			return 0, fmt.Errorf("%w: extension type", errRawMalformed)
		}
		extBody, ok := cursor.vector16()
		if !ok {
			return 0, fmt.Errorf("%w: extension 0x%04X body", errRawMalformed, extType)
		}
		// Checked for unknown types too: skipping the body first would let a
		// repeat slip past.
		if _, duplicate := seen[extType]; duplicate {
			return 0, fmt.Errorf("%w: 0x%04X", errRawDuplicateExtension, extType)
		}
		seen[extType] = struct{}{}

		switch extType {
		case tlsExtSupportedVersions:
			// Exactly two bytes: the list form belongs to the ClientHello. A
			// four-byte body is a malformed ServerHello, not an invitation to
			// read the first two.
			if len(extBody) != 2 {
				return 0, fmt.Errorf("%w: supported_versions of %d bytes", errRawMalformed, len(extBody))
			}
			supportedVersion = binary.BigEndian.Uint16(extBody)
		case tlsExtKeyShare:
			// Two shapes, told apart by length and not by context: a bare
			// two-byte selected_group is the HelloRetryRequest form, and
			// rejecting it would turn every real TLS 1.3 server into a false
			// malformed finding.
			if len(extBody) != 2 {
				inner := newRawCursor(extBody)
				if _, ok := inner.uint16(); !ok {
					return 0, fmt.Errorf("%w: key_share group", errRawMalformed)
				}
				if _, ok := inner.vector16(); !ok {
					return 0, fmt.Errorf("%w: key_share exchange", errRawMalformed)
				}
				if !inner.empty() {
					return 0, fmt.Errorf("%w: key_share trailing bytes", errRawMalformed)
				}
			}
		}
	}
	return supportedVersion, nil
}

// rawCursor reads length-prefixed structures without ever slicing past the
// buffer it was given. Every read returns a copy, so a retained field neither
// aliases the socket buffer nor pins it.
type rawCursor struct {
	buf []byte
}

func newRawCursor(b []byte) rawCursor { return rawCursor{buf: b} }

func (c *rawCursor) empty() bool    { return len(c.buf) == 0 }
func (c *rawCursor) remaining() int { return len(c.buf) }

func (c *rawCursor) uint8() (uint8, bool) {
	if len(c.buf) < 1 {
		return 0, false
	}
	v := c.buf[0]
	c.buf = c.buf[1:]
	return v, true
}

func (c *rawCursor) uint16() (uint16, bool) {
	if len(c.buf) < 2 {
		return 0, false
	}
	v := binary.BigEndian.Uint16(c.buf)
	c.buf = c.buf[2:]
	return v, true
}

func (c *rawCursor) bytes(n int) ([]byte, bool) {
	if n < 0 || len(c.buf) < n {
		return nil, false
	}
	out := append([]byte(nil), c.buf[:n]...)
	c.buf = c.buf[n:]
	return out, true
}

func (c *rawCursor) vector8() ([]byte, bool) {
	n, ok := c.uint8()
	if !ok {
		return nil, false
	}
	return c.bytes(int(n))
}

func (c *rawCursor) vector16() ([]byte, bool) {
	n, ok := c.uint16()
	if !ok {
		return nil, false
	}
	return c.bytes(int(n))
}
