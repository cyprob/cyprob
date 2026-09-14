// Package envkey resolves the environment variables the scanner reads for its
// own settings. Keys carry the CYPROB_ prefix. The former VULNTOR_ prefix is
// still honored as a fallback for one deprecation window so that existing
// environments keep working; each legacy key that is actually used logs one
// warning per process.
package envkey

import (
	"log/slog"
	"os"
	"strings"
	"sync"
)

const (
	// Prefix is the environment variable prefix the scanner reads first.
	Prefix = "CYPROB_"
	// LegacyPrefix is the former prefix, read only when the CYPROB_ key is unset.
	LegacyPrefix = "VULNTOR_"
)

var warned sync.Map

// Key returns the full variable name for a setting: Key("LOG_LEVEL") is "CYPROB_LOG_LEVEL".
func Key(name string) string { return Prefix + name }

// LegacyKey returns the former variable name for a setting.
func LegacyKey(name string) string { return LegacyPrefix + name }

// Lookup reads CYPROB_<name> first and VULNTOR_<name> second. A value found
// under the legacy name is returned with a deprecation warning, once per key.
func Lookup(name string) (string, bool) {
	if v, ok := os.LookupEnv(Key(name)); ok {
		return v, true
	}
	if v, ok := os.LookupEnv(LegacyKey(name)); ok {
		warnLegacy(name)
		return v, true
	}
	return "", false
}

// Get is Lookup without the presence flag; unset and empty both return "".
func Get(name string) string {
	v, _ := Lookup(name)
	return v
}

// LegacyKeysPresent lists the VULNTOR_* variables set in the environment. Callers
// that load a whole prefix at once (the configuration sources) use it to warn.
func LegacyKeysPresent() []string {
	var keys []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, LegacyPrefix) {
			continue
		}
		if i := strings.IndexByte(kv, '='); i > 0 {
			keys = append(keys, kv[:i])
		}
	}
	return keys
}

// WarnLegacyKeys logs one deprecation warning for every legacy key present.
func WarnLegacyKeys() {
	for _, k := range LegacyKeysPresent() {
		warnLegacy(strings.TrimPrefix(k, LegacyPrefix))
	}
}

func warnLegacy(name string) {
	if _, seen := warned.LoadOrStore(name, struct{}{}); seen {
		return
	}
	slog.Warn("deprecated environment variable, use the CYPROB_ prefix",
		"deprecated", LegacyKey(name), "use", Key(name))
}
