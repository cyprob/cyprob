package scan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// Byte-level fixtures. The enumerator reads an untrusted peer, so its tests
// have to be able to write anything a peer could -- which means building the
// records here rather than borrowing a real TLS server that can only produce
// well-formed ones.

type testExtension struct {
	extType uint16
	body    []byte
}

type testServerHello struct {
	legacyVersion    uint16
	suite            uint16
	compression      uint8
	random           []byte
	sessionID        []byte
	supportedVersion uint16
	keyShare         []byte
	extraExtensions  []testExtension
	omitExtensions   bool
}

func testRecord(contentType byte, payload []byte) []byte {
	record := make([]byte, 0, 5+len(payload))
	record = append(record, contentType)
	record = binary.BigEndian.AppendUint16(record, 0x0303)
	record = binary.BigEndian.AppendUint16(record, uint16(len(payload)))
	return append(record, payload...)
}

func testHandshakeHeader(body []byte) []byte {
	return []byte{tlsHandshakeTypeServer, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
}

func testServerHelloBody(t *testing.T, spec testServerHello) []byte {
	t.Helper()

	random := spec.random
	if random == nil {
		random = bytes.Repeat([]byte{0x5A}, 32)
	}
	if len(random) != 32 {
		t.Fatalf("a ServerHello random is 32 bytes, fixture gave %d", len(random))
	}
	sessionID := spec.sessionID
	if sessionID == nil {
		sessionID = bytes.Repeat([]byte{0x7B}, 32)
	}

	body := make([]byte, 0, 128)
	body = binary.BigEndian.AppendUint16(body, spec.legacyVersion)
	body = append(body, random...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	body = binary.BigEndian.AppendUint16(body, spec.suite)
	body = append(body, spec.compression)

	if spec.omitExtensions {
		return body
	}

	extensions := make([]byte, 0, 32)
	if spec.supportedVersion != 0 {
		extensions = appendRawExtension(extensions, tlsExtSupportedVersions,
			[]byte{byte(spec.supportedVersion >> 8), byte(spec.supportedVersion)})
	}
	if spec.keyShare != nil {
		extensions = appendRawExtension(extensions, tlsExtKeyShare, spec.keyShare)
	}
	for _, extra := range spec.extraExtensions {
		extensions = appendRawExtension(extensions, extra.extType, extra.body)
	}

	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	return append(body, extensions...)
}

func testServerHelloRecord(t *testing.T, spec testServerHello) []byte {
	t.Helper()
	body := testServerHelloBody(t, spec)
	return testRecord(tlsRecordTypeHandshake, append(testHandshakeHeader(body), body...))
}

func testAlertRecord(description uint8) []byte {
	return testRecord(tlsRecordTypeAlert, []byte{tlsAlertLevelFatal, description})
}

// parsedTestClientHello is what a fake server needs from our hello: which
// suites were offered, which version was pinned, and what else we sent.
type parsedTestClientHello struct {
	suites           []uint16
	version          uint16
	sni              string
	compressionCount int
	extensions       map[uint16][]byte
}

var errTestHelloMalformed = errors.New("test_client_hello_malformed")

func parseTestClientHello(record []byte) (parsedTestClientHello, error) {
	out := parsedTestClientHello{extensions: map[uint16][]byte{}}
	if len(record) < 9 || record[0] != tlsRecordTypeHandshake || record[5] != tlsHandshakeTypeClient {
		return out, errTestHelloMalformed
	}
	bodyLen := int(record[6])<<16 | int(record[7])<<8 | int(record[8])
	if len(record) < 9+bodyLen {
		return out, errTestHelloMalformed
	}
	cursor := newRawCursor(record[9 : 9+bodyLen])

	if _, ok := cursor.uint16(); !ok { // legacy_version
		return out, errTestHelloMalformed
	}
	if _, ok := cursor.bytes(32); !ok { // random
		return out, errTestHelloMalformed
	}
	if _, ok := cursor.vector8(); !ok { // legacy_session_id
		return out, errTestHelloMalformed
	}
	suiteBytes, ok := cursor.vector16()
	if !ok || len(suiteBytes)%2 != 0 {
		return out, errTestHelloMalformed
	}
	for i := 0; i+1 < len(suiteBytes); i += 2 {
		out.suites = append(out.suites, binary.BigEndian.Uint16(suiteBytes[i:i+2]))
	}
	compression, ok := cursor.vector8()
	if !ok {
		return out, errTestHelloMalformed
	}
	out.compressionCount = len(compression)

	block, ok := cursor.vector16()
	if !ok {
		return out, errTestHelloMalformed
	}
	extCursor := newRawCursor(block)
	for !extCursor.empty() {
		extType, ok := extCursor.uint16()
		if !ok {
			return out, errTestHelloMalformed
		}
		extBody, ok := extCursor.vector16()
		if !ok {
			return out, errTestHelloMalformed
		}
		out.extensions[extType] = extBody
		switch extType {
		case tlsExtSupportedVersions:
			if len(extBody) >= 3 {
				out.version = binary.BigEndian.Uint16(extBody[1:3])
			}
		case tlsExtServerName:
			if len(extBody) >= 5 {
				out.sni = string(extBody[5:])
			}
		}
	}
	return out, nil
}

// stripTestClientHelloVariables blanks the three things that legitimately vary
// between connections -- the random, the session id and the suite vector -- so
// what is left can be compared byte for byte across a walk.
func stripTestClientHelloVariables(record []byte) ([]byte, error) {
	if len(record) < 9 {
		return nil, errTestHelloMalformed
	}
	out := append([]byte(nil), record...)
	// The record and handshake lengths move with the suite vector.
	for i := 3; i < 5; i++ {
		out[i] = 0
	}
	for i := 6; i < 9; i++ {
		out[i] = 0
	}
	offset := 9 + 2 // legacy_version
	for i := 0; i < 32; i++ {
		out[offset+i] = 0
	}
	offset += 32
	sidLen := int(out[offset])
	offset++
	for i := 0; i < sidLen; i++ {
		out[offset+i] = 0
	}
	offset += sidLen
	if offset+2 > len(out) {
		return nil, errTestHelloMalformed
	}
	suiteLen := int(binary.BigEndian.Uint16(out[offset : offset+2]))
	if offset+2+suiteLen > len(out) {
		return nil, errTestHelloMalformed
	}
	// Drop the vector entirely rather than blanking it: its length is the
	// thing that changes.
	return append(append([]byte(nil), out[:offset]...), out[offset+2+suiteLen:]...), nil
}
