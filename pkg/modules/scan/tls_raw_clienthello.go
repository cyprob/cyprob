package scan

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Building a ClientHello by hand
//
// crypto/tls can only offer the 25 suites it implements, and the question
// "which suites does this server support" cannot be answered by a client that
// can only ask about 25 of the registry's 356 (cyprob#294). So the enumerator
// writes its own ClientHello, which lets it offer an arbitrary two-byte ID and
// read the server's choice out of the ServerHello without performing any
// cryptography at all.
//
// Everything here is a fixed template with exactly two variables: the cipher
// suite vector and the single pinned version in extension 43. That is not
// tidiness -- it is what makes the walk's conclusion sound. The server's refusal
// is `handshake_failure`, which it also sends for a missing group, a missing
// signature algorithm, a bad renegotiation extension and several certificate
// dead ends. Attributing a refusal to the suite list is only honest if the suite
// list is the only thing that changed, so every other byte is held constant and
// a test hashes the hello to prove it.
const (
	tlsRecordTypeHandshake  = 0x16
	tlsRecordTypeAlert      = 0x15
	tlsRecordTypeCCS        = 0x14
	tlsRecordTypeAppData    = 0x17
	tlsHandshakeTypeClient  = 0x01
	tlsHandshakeTypeServer  = 0x02
	tlsLegacyRecordVersion  = 0x0301
	tlsLegacyClientVersion  = 0x0303
	tlsMaxPlaintextRecord   = 16384
	tlsClientHelloRandomLen = 32
	tlsSessionIDLen         = 32
)

// Extension numbers, in the ascending order this builder emits them.
const (
	tlsExtServerName          = 0x0000
	tlsExtSupportedGroups     = 0x000a
	tlsExtECPointFormats      = 0x000b
	tlsExtSignatureAlgorithms = 0x000d
	tlsExtSupportedVersions   = 0x002b
	tlsExtKeyShare            = 0x0033
	tlsExtRenegotiationInfo   = 0xff01
)

var (
	errRawHelloNoSuites    = errors.New("raw_hello_no_suites")
	errRawHelloTooLarge    = errors.New("raw_hello_too_large")
	errRawHelloBadSuite    = errors.New("raw_hello_forbidden_suite")
	errRawHelloBadVersion  = errors.New("raw_hello_unsupported_version")
	errRawHelloRandomRead  = errors.New("raw_hello_random_unavailable")
	tlsSupportedGroupsBody = []byte{
		0x00, 0x08, // list length
		0x00, 0x1d, // x25519
		0x00, 0x17, // secp256r1
		0x00, 0x18, // secp384r1
		0x00, 0x19, // secp521r1
	}
	// Omitting signature_algorithms is a silent wrong-answer generator rather
	// than a missing nicety: a Go 1.2 server answers ServerHello and *then*
	// alert 40, so a probe that stops at the ServerHello records a success that
	// could never complete, while OpenSSL answers alert 40 with no ServerHello
	// at all and the same probe records the suite as unsupported. Both wrong,
	// in opposite directions.
	tlsSignatureAlgorithmsBody = []byte{
		0x00, 0x14, // list length
		0x04, 0x03, // ecdsa_secp256r1_sha256
		0x05, 0x03, // ecdsa_secp384r1_sha384
		0x06, 0x03, // ecdsa_secp521r1_sha512
		0x08, 0x04, // rsa_pss_rsae_sha256
		0x08, 0x05, // rsa_pss_rsae_sha384
		0x08, 0x06, // rsa_pss_rsae_sha512
		0x04, 0x01, // rsa_pkcs1_sha256
		0x05, 0x01, // rsa_pkcs1_sha384
		0x06, 0x01, // rsa_pkcs1_sha512
		0x02, 0x01, // rsa_pkcs1_sha1
	}
	// Uncompressed only. A compressed-only list is refused outright, and the
	// six bytes are here because old OpenSSL builds refuse to handshake without
	// the extension at all.
	tlsECPointFormatsBody = []byte{0x01, 0x00}
)

// rawClientHello is everything that varies. Nothing else about the hello is
// configurable, deliberately.
type rawClientHello struct {
	// hostname is sent as SNI when it is a name. An address literal is never
	// sent: SNI carries names, and a server may answer a literal with
	// unrecognized_name, which looks nothing like a suite verdict.
	hostname string
	// version is the single version pinned in extension 43. One version per
	// walk, because TLS 1.3's suites are a disjoint namespace and an unpinned
	// walk lets the server move between the two mid-walk.
	version uint16
	suites  []uint16
}

// buildRawClientHello encodes one record containing one ClientHello.
func buildRawClientHello(hello rawClientHello) ([]byte, error) {
	if len(hello.suites) == 0 {
		return nil, errRawHelloNoSuites
	}
	if hello.version < 0x0301 || hello.version > 0x0304 {
		return nil, fmt.Errorf("%w: 0x%04X", errRawHelloBadVersion, hello.version)
	}
	for _, id := range hello.suites {
		if !tlsSuiteIsOfferable(id) {
			return nil, fmt.Errorf("%w: 0x%04X", errRawHelloBadSuite, id)
		}
	}

	random := make([]byte, tlsClientHelloRandomLen)
	if _, err := rand.Read(random); err != nil {
		return nil, errRawHelloRandomRead
	}
	// A fresh session id every connection. Reusing one is a resumption offer,
	// and a resumed handshake reports the ticket's suite rather than a choice
	// from our offer -- an answer to a question we did not ask.
	sessionID := make([]byte, tlsSessionIDLen)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, errRawHelloRandomRead
	}

	body := make([]byte, 0, 128+2*len(hello.suites))
	body = binary.BigEndian.AppendUint16(body, tlsLegacyClientVersion)
	body = append(body, random...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)

	body = binary.BigEndian.AppendUint16(body, uint16(2*len(hello.suites)))
	for _, id := range hello.suites {
		body = binary.BigEndian.AppendUint16(body, id)
	}

	// Exactly one compression method. A list of two is refused with
	// illegal_parameter by every TLS 1.3 server.
	body = append(body, 0x01, 0x00)

	extensions := buildRawClientHelloExtensions(hello)
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)

	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, tlsHandshakeTypeClient)
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	if len(handshake) > tlsMaxPlaintextRecord {
		return nil, fmt.Errorf("%w: %d bytes", errRawHelloTooLarge, len(handshake))
	}

	record := make([]byte, 0, 5+len(handshake))
	record = append(record, tlsRecordTypeHandshake)
	// TLS 1.0 in the record layer, which is what crypto/tls itself writes for a
	// first hello: some servers fail on anything higher, and no server requires
	// more.
	record = binary.BigEndian.AppendUint16(record, tlsLegacyRecordVersion)
	record = binary.BigEndian.AppendUint16(record, uint16(len(handshake)))
	record = append(record, handshake...)
	return record, nil
}

func buildRawClientHelloExtensions(hello rawClientHello) []byte {
	out := make([]byte, 0, 128)

	if name := rawHelloSNIName(hello.hostname); name != "" {
		body := make([]byte, 0, 5+len(name))
		body = binary.BigEndian.AppendUint16(body, uint16(3+len(name)))
		body = append(body, 0x00)
		body = binary.BigEndian.AppendUint16(body, uint16(len(name)))
		body = append(body, name...)
		out = appendRawExtension(out, tlsExtServerName, body)
	}

	out = appendRawExtension(out, tlsExtSupportedGroups, tlsSupportedGroupsBody)
	out = appendRawExtension(out, tlsExtECPointFormats, tlsECPointFormatsBody)
	out = appendRawExtension(out, tlsExtSignatureAlgorithms, tlsSignatureAlgorithmsBody)

	// Note the uint8 inner length here, unlike every other vector in this hello.
	versions := []byte{0x02, byte(hello.version >> 8), byte(hello.version)}
	out = appendRawExtension(out, tlsExtSupportedVersions, versions)

	if hello.version == 0x0304 {
		// An empty client_shares list. RFC 8446 4.1.4 is exactly this: it asks
		// the server for a HelloRetryRequest naming its choice, without
		// generating any key material. OpenSSL answers a 1.3 hello with no
		// key_share extension at all with missing_extension and no ServerHello,
		// so the six bytes are not optional; a non-empty share would be key
		// material we have no use for and would be refused if it were wrong.
		out = appendRawExtension(out, tlsExtKeyShare, []byte{0x00, 0x00})
	}

	// Empty body, always: it signals RFC 5746 support without putting the
	// 0x00FF signaling value into the cipher suite vector, where a server
	// could "select" it.
	out = appendRawExtension(out, tlsExtRenegotiationInfo, []byte{0x00})
	return out
}

func appendRawExtension(dst []byte, extType uint16, body []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, extType)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(body)))
	return append(dst, body...)
}

// rawHelloSNIName returns the name to send, or "" when there is nothing
// sendable. Address literals are never sent as SNI.
func rawHelloSNIName(hostname string) string {
	hostname = strings.TrimSpace(hostname)
	hostname = strings.TrimSuffix(hostname, ".")
	if hostname == "" || len(hostname) > 255 {
		return ""
	}
	if net.ParseIP(hostname) != nil {
		return ""
	}
	if strings.ContainsAny(hostname, ":/ ") {
		return ""
	}
	return hostname
}

// tlsSuiteIsOfferable rejects the values that are not suites even though they
// live in the suite namespace. The generated registry already excludes them;
// this is the second check, because a contaminated offer produces an answer
// that looks like a result.
func tlsSuiteIsOfferable(id uint16) bool {
	switch {
	case id == 0x0000: // TLS_NULL_WITH_NULL_NULL, a placeholder
		return false
	case id == 0x00FF: // TLS_EMPTY_RENEGOTIATION_INFO_SCSV, a signal
		return false
	case id == 0x5600: // TLS_FALLBACK_SCSV -- draws inappropriate_fallback and
		// would end every version-pinned walk with an alert that looks like a
		// refusal
		return false
	case tlsSuiteIsGREASE(id):
		return false
	}
	return true
}

// tlsSuiteIsGREASE matches RFC 8701's reserved values, which exist to be
// ignored. crypto/tls has no filter for them on the cipher suite path.
func tlsSuiteIsGREASE(id uint16) bool {
	return id&0x0F0F == 0x0A0A && id&0xFF == id>>8
}
