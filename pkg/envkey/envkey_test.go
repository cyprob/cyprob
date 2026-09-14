package envkey

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookup_PrimaryWinsOverLegacy(t *testing.T) {
	t.Setenv("CYPROB_ENVKEY_TEST", "new")
	t.Setenv("VULNTOR_ENVKEY_TEST", "old")

	v, ok := Lookup("ENVKEY_TEST")
	assert.True(t, ok)
	assert.Equal(t, "new", v)
}

func TestLookup_LegacyFallback(t *testing.T) {
	t.Setenv("VULNTOR_ENVKEY_FALLBACK", "old")

	v, ok := Lookup("ENVKEY_FALLBACK")
	assert.True(t, ok)
	assert.Equal(t, "old", v)
	assert.Equal(t, "old", Get("ENVKEY_FALLBACK"))
}

func TestLookup_Unset(t *testing.T) {
	v, ok := Lookup("ENVKEY_NEVER_SET")
	assert.False(t, ok)
	assert.Equal(t, "", v)
	assert.Equal(t, "", Get("ENVKEY_NEVER_SET"))
}

func TestLookup_EmptyPrimaryStillWins(t *testing.T) {
	t.Setenv("CYPROB_ENVKEY_EMPTY", "")
	t.Setenv("VULNTOR_ENVKEY_EMPTY", "old")

	v, ok := Lookup("ENVKEY_EMPTY")
	assert.True(t, ok)
	assert.Equal(t, "", v)
}

func TestKeys(t *testing.T) {
	assert.Equal(t, "CYPROB_LOG_LEVEL", Key("LOG_LEVEL"))
	assert.Equal(t, "VULNTOR_LOG_LEVEL", LegacyKey("LOG_LEVEL"))
}

func TestLegacyKeysPresent(t *testing.T) {
	t.Setenv("VULNTOR_ENVKEY_PRESENT_A", "1")
	t.Setenv("VULNTOR_ENVKEY_PRESENT_B", "")

	keys := LegacyKeysPresent()
	assert.Contains(t, keys, "VULNTOR_ENVKEY_PRESENT_A")
	assert.Contains(t, keys, "VULNTOR_ENVKEY_PRESENT_B")
}

func TestWarnLegacy_OncePerKey(t *testing.T) {
	warned.Delete("ENVKEY_ONCE")
	warnLegacy("ENVKEY_ONCE")
	_, seen := warned.Load("ENVKEY_ONCE")
	assert.True(t, seen)
	// A second call must not panic or re-store; the map keeps a single entry.
	warnLegacy("ENVKEY_ONCE")
	n := 0
	warned.Range(func(k, _ any) bool {
		if k == "ENVKEY_ONCE" {
			n++
		}
		return true
	})
	assert.Equal(t, 1, n)
}
