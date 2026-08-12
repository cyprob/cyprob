package fingerprint

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// resolveFallback resolves the way production does for a service on a port the
// catalog does not recognize: the parser leaves the protocol hint empty, which
// puts the resolver into the mode that tries every rule.
func resolveFallback(t *testing.T, banner string, port int) (Result, error) {
	t.Helper()
	return NewRuleBasedResolver(loadBuiltinRules()).
		Resolve(context.Background(), Input{Protocol: "", Banner: banner, Port: port})
}

// A rule matching a phrase that almost every service utters competes with the
// rules that actually identify those services, and wins or loses by whichever
// strength happens to be higher. The fix is a narrower rule, not a strength
// war, so this pins the narrowness rather than the ordering.
//
// The validation dataset cannot see this: every DNS case in it carries
// protocol=dns and port=53, where the port bonus settles the contest. The
// regression only appears on a non-standard port with no protocol hint.
func TestRuleCollision_AVersionStringDoesNotMakeEverythingMemcached(t *testing.T) {
	for _, tc := range []struct {
		name, banner string
		port         int
		wantProduct  string
	}{
		{"BIND on a non-standard port", "named version 9.18.4", 5300, "BIND"},
		{"a web server stating its version", "nginx version 1.24.0", 8080, ""},
		{"an FTP server stating its version", "220 ProFTPD version 1.3.8", 2121, "ProFTPD"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := resolveFallback(t, tc.banner, tc.port)
			if tc.wantProduct == "" {
				if err == nil {
					require.NotEqual(t, "Memcached", result.Product,
						"a version string is not an identity")
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantProduct, result.Product)
		})
	}
}

// The narrowing must not cost Memcached its own identification. It answers
// "version" with VERSION at the start of a line and "stats" with STAT lines,
// and those shapes are what name it.
func TestRuleCollision_MemcachedIsStillIdentified(t *testing.T) {
	for _, tc := range []struct {
		name, banner string
		port         int
	}{
		{"version response", "VERSION 1.6.21\r\n", 11211},
		{"version response on a non-standard port", "VERSION 1.6.21\r\n", 11311},
		{"stats response", "STAT pid 2314\r\nSTAT uptime 91\r\n", 11211},
		{"named outright", "memcached 1.6.21", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := resolveFallback(t, tc.banner, tc.port)
			require.NoError(t, err)
			require.Equal(t, "Memcached", result.Product)
		})
	}
}

func TestRuleCollision_MemcachedStillReportsItsVersion(t *testing.T) {
	result, err := resolveFallback(t, "VERSION 1.6.21\r\n", 11211)
	require.NoError(t, err)
	require.Equal(t, "1.6.21", result.Version)
}
