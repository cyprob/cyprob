// Package fingerprint provides functionality to resolve service banners into structured metadata.
package fingerprint

import (
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

//go:embed data/fingerprint_db.yaml
var embeddedFingerprintYAML []byte

// indirection for testing error paths
var parseYAMLFn = parseFingerprintYAML

// loadBuiltinRules loads fingerprint rules embedded in the binary.
func loadBuiltinRules() []StaticRule {
	rules, err := parseYAMLFn(embeddedFingerprintYAML)
	if err != nil {
		fmt.Printf("Failed to load embedded fingerprint rules: %v\n", err)
		return nil
	}
	return prepareRules(rules)
}

// DeclaredProtocols returns, sorted, every protocol value the shipped rules
// declare.
//
// It exists so that anything producing a protocol hint can check its
// vocabulary against the rules' rather than the two drifting apart in silence.
// The failure is not a missed match but a total one: a hint no rule declares
// is still specific enough to switch fallback off, so it excludes every
// candidate and the service resolves to nothing at all.
func DeclaredProtocols() []string {
	seen := make(map[string]struct{})
	for _, rule := range loadBuiltinRules() {
		if rule.Protocol != "" {
			seen[rule.Protocol] = struct{}{}
		}
	}

	protocols := make([]string, 0, len(seen))
	for protocol := range seen {
		protocols = append(protocols, protocol)
	}
	sort.Strings(protocols)
	return protocols
}

// loadExternalCatalog attempts to load fingerprint rules from workspace cache.
func loadExternalCatalog(cacheDir string) ([]StaticRule, error) {
	if cacheDir == "" {
		return nil, errors.New("cache directory not specified")
	}
	cachedPath := filepath.Join(cacheDir, "fingerprint.cache")
	content, err := os.ReadFile(cachedPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("read cache: %w", err)
	}
	rules, err := parseFingerprintYAML(content)
	if err != nil {
		return nil, fmt.Errorf("parse cache: %w", err)
	}
	return prepareRules(rules), nil
}
