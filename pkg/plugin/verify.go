// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// Verifier handles plugin integrity verification using checksums.
type Verifier struct {
	// Algorithm specifies the hash algorithm (default: sha256)
	Algorithm string
}

// NewVerifier creates a new plugin verifier.
func NewVerifier() *Verifier {
	return &Verifier{
		Algorithm: "sha256",
	}
}

// VerifyFile verifies a plugin file against its expected checksum.
// Returns true if the checksum matches, false otherwise.
func (v *Verifier) VerifyFile(filePath, expectedChecksum string) (bool, error) {
	if filePath == "" {
		return false, fmt.Errorf("file path cannot be empty")
	}

	if expectedChecksum == "" {
		return false, fmt.Errorf("expected checksum cannot be empty")
	}

	// Compute actual checksum
	actualChecksum, err := v.ComputeChecksum(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to compute checksum: %w", err)
	}

	// Normalize checksums (remove algorithm prefix if present)
	actualChecksum = v.normalizeChecksum(actualChecksum)
	expectedChecksum = v.normalizeChecksum(expectedChecksum)

	// Compare checksums
	return actualChecksum == expectedChecksum, nil
}

// ComputeChecksum computes the SHA-256 checksum of a file.
// Returns the checksum in hexadecimal format with algorithm prefix (e.g., "sha256:abc123...").
func (v *Verifier) ComputeChecksum(filePath string) (string, error) {
	if filePath == "" {
		return "", fmt.Errorf("file path cannot be empty")
	}

	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	// Compute SHA-256 hash
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	// Return hex-encoded checksum with algorithm prefix
	checksum := hex.EncodeToString(hash.Sum(nil))
	return fmt.Sprintf("%s:%s", v.Algorithm, checksum), nil
}

// VerifyPlugin verifies a loaded plugin against its expected checksum.
// This verifies the plugin's source file on disk.
func (v *Verifier) VerifyPlugin(plugin *YAMLPlugin, expectedChecksum string) (bool, error) {
	if plugin == nil {
		return false, fmt.Errorf("plugin cannot be nil")
	}

	if plugin.FilePath == "" {
		return false, fmt.Errorf("plugin file path is empty")
	}

	return v.VerifyFile(plugin.FilePath, expectedChecksum)
}

// VerifyAll verifies multiple plugins against their expected checksums.
// Returns a map of plugin names to verification results.
// If a plugin verification fails, the error is included in the result.
func (v *Verifier) VerifyAll(plugins []*YAMLPlugin, checksums map[string]string) map[string]*VerificationResult {
	results := make(map[string]*VerificationResult)

	for _, plugin := range plugins {
		expectedChecksum, ok := checksums[plugin.Name]
		if !ok {
			results[plugin.Name] = &VerificationResult{
				Plugin:   plugin,
				Verified: false,
				Error:    fmt.Errorf("no checksum found for plugin '%s'", plugin.Name),
			}
			continue
		}

		verified, err := v.VerifyPlugin(plugin, expectedChecksum)
		results[plugin.Name] = &VerificationResult{
			Plugin:   plugin,
			Verified: verified,
			Error:    err,
		}
	}

	return results
}

// VerificationResult represents the result of verifying a plugin.
type VerificationResult struct {
	Plugin   *YAMLPlugin
	Verified bool
	Error    error
}

// normalizeChecksum removes the algorithm prefix from a checksum if present.
// Examples:
//   - "sha256:abc123" -> "abc123"
//   - "abc123" -> "abc123"
func (v *Verifier) normalizeChecksum(checksum string) string {
	// Remove algorithm prefix if present
	if strings.Contains(checksum, ":") {
		parts := strings.SplitN(checksum, ":", 2)
		if len(parts) == 2 {
			return parts[1]
		}
	}
	return checksum
}

// ParseChecksum parses a checksum string and returns the algorithm and hex value.
// Examples:
//   - "sha256:abc123" -> ("sha256", "abc123", nil)
//   - "abc123" -> ("sha256", "abc123", nil) // default algorithm
func ParseChecksum(checksum string) (algorithm, hexValue string, err error) {
	if checksum == "" {
		return "", "", fmt.Errorf("checksum cannot be empty")
	}

	// Check if algorithm prefix is present
	if strings.Contains(checksum, ":") {
		parts := strings.SplitN(checksum, ":", 2)
		if len(parts) != 2 {
			return "", "", fmt.Errorf("invalid checksum format: %s", checksum)
		}
		return parts[0], parts[1], nil
	}

	// Default to sha256
	return "sha256", checksum, nil
}

// FormatChecksum formats a checksum with algorithm prefix.
// Example: FormatChecksum("sha256", "abc123") -> "sha256:abc123"
func FormatChecksum(algorithm, hexValue string) string {
	return fmt.Sprintf("%s:%s", algorithm, hexValue)
}
