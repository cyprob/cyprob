package scan

import (
	"encoding/base64"
	"math/bits"
	"strings"
)

// Favicon hashing follows the de-facto convention established by Shodan:
// MurmurHash3 (x86, 32-bit, seed 0) over the MIME-style base64 encoding of the
// icon bytes, reported as a signed 32-bit integer.
//
// Matching that convention is the whole point: it makes publicly shared favicon
// hashes directly usable as corpus entries, instead of forcing us to build a
// fingerprint corpus from nothing.
const (
	murmur3C1 = 0xcc9e2d51
	murmur3C2 = 0x1b873593
	// base64LineLength is the MIME line width Python's base64.encodebytes uses.
	// The hash is taken over that exact wrapped form, newlines included, so this
	// is part of the convention rather than cosmetic.
	base64LineLength = 76
)

// FaviconHash returns the Shodan-convention hash of a favicon's bytes.
func FaviconHash(content []byte) int32 {
	if len(content) == 0 {
		return 0
	}
	return int32(murmur3X86_32(mimeBase64(content), 0)) //nolint:gosec // signed by convention
}

// mimeBase64 reproduces Python's base64.encodebytes: standard base64 wrapped at
// 76 characters with a trailing newline.
func mimeBase64(content []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(content)
	var builder strings.Builder
	builder.Grow(len(encoded) + len(encoded)/base64LineLength + 2)
	for start := 0; start < len(encoded); start += base64LineLength {
		end := min(start+base64LineLength, len(encoded))
		builder.WriteString(encoded[start:end])
		builder.WriteByte('\n')
	}
	return []byte(builder.String())
}

// murmur3X86_32 implements MurmurHash3, x86 32-bit variant.
func murmur3X86_32(data []byte, seed uint32) uint32 {
	hash := seed
	length := len(data)

	// Body: consume 4-byte blocks.
	blocks := length / 4
	for i := range blocks {
		offset := i * 4
		k := uint32(data[offset]) | uint32(data[offset+1])<<8 |
			uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24

		k *= murmur3C1
		k = bits.RotateLeft32(k, 15)
		k *= murmur3C2

		hash ^= k
		hash = bits.RotateLeft32(hash, 13)
		hash = hash*5 + 0xe6546b64
	}

	// Tail: the remaining 1-3 bytes.
	var k uint32
	tail := data[blocks*4:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= murmur3C1
		k = bits.RotateLeft32(k, 15)
		k *= murmur3C2
		hash ^= k
	}

	// Finalization.
	hash ^= uint32(length) //nolint:gosec // length is non-negative
	hash ^= hash >> 16
	hash *= 0x85ebca6b
	hash ^= hash >> 13
	hash *= 0xc2b2ae35
	hash ^= hash >> 16
	return hash
}
