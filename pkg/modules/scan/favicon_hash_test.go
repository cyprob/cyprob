package scan

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Reference vectors produced by the canonical Python mmh3 implementation, which
// is what the published favicon-hash corpora are built with. A drift here would
// silently invalidate every corpus entry, so these are non-negotiable.
func TestMurmur3X86_32_ReferenceVectors(t *testing.T) {
	cases := map[string]int32{
		"":              0,
		"a":             1009084850,
		"ab":            -1681926305,
		"abc":           -1277324294,
		"abcd":          1139631978,
		"Hello, world!": -1070186941,
		"The quick brown fox jumps over the lazy dog": 776992547,
	}
	for input, want := range cases {
		got := int32(murmur3X86_32([]byte(input), 0)) //nolint:gosec // signed by convention
		require.Equalf(t, want, got, "murmur3 mismatch for %q", input)
	}
}

// The hash is taken over MIME-style base64 (76-char lines, trailing newline),
// not plain base64. Getting this wrong yields a hash that matches no corpus.
func TestMimeBase64_WrapsLikePythonEncodebytes(t *testing.T) {
	t.Run("short input still gets a trailing newline", func(t *testing.T) {
		require.Equal(t, "YQ==\n", string(mimeBase64([]byte("a"))))
	})

	t.Run("long input is wrapped at 76 characters", func(t *testing.T) {
		// 120 bytes encode to 160 base64 characters: two full 76-char lines
		// plus an 8-char remainder.
		lines := splitLines(string(mimeBase64(make([]byte, 120))))
		require.Len(t, lines, 3)
		require.Len(t, lines[0], 76)
		require.Len(t, lines[1], 76)
		require.Len(t, lines[2], 8)
	})
}

func splitLines(s string) []string {
	var out []string
	current := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, current)
			current = ""
			continue
		}
		current += string(r)
	}
	return out
}

func TestFaviconHash_EmptyContent(t *testing.T) {
	require.Zero(t, FaviconHash(nil))
	require.Zero(t, FaviconHash([]byte{}))
}

func TestFaviconHash_IsStable(t *testing.T) {
	content := []byte("fake-icon-bytes-for-stability-check")
	require.Equal(t, FaviconHash(content), FaviconHash(content))
	require.NotEqual(t, FaviconHash(content), FaviconHash(append(content, 'x')))
}
