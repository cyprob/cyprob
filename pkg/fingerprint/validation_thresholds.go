package fingerprint

import (
	"encoding/json"
	"strconv"

	"github.com/cyprob/cyprob/pkg/envkey"
)

// ValidationThresholds represents configurable validation targets.
// These thresholds determine the pass/fail criteria for validation metrics.
type ValidationThresholds struct {
	TargetFPR         float64 `json:"target_fpr"`          // False Positive Rate target (lower is better, default <10%)
	TargetTPR         float64 `json:"target_tpr"`          // True Positive Rate target (higher is better, default >80%)
	TargetPrecision   float64 `json:"target_precision"`    // Precision target (higher is better, default >85%)
	TargetF1          float64 `json:"target_f1"`           // F1 Score target (higher is better, default >0.82)
	TargetProtocols   int     `json:"target_protocols"`    // Protocol coverage target (default 20+)
	TargetVersionRate float64 `json:"target_version_rate"` // Version extraction rate target (default >70%)
	TargetPerfMs      float64 `json:"target_perf_ms"`      // Performance target in milliseconds (default <50ms)
}

// DefaultThresholds returns production-ready validation thresholds.
// These values represent the minimum acceptable quality for fingerprint detection.
func DefaultThresholds() ValidationThresholds {
	return ValidationThresholds{
		TargetFPR:         0.10, // <10% false positive rate
		TargetTPR:         0.80, // >80% true positive rate (recall)
		TargetPrecision:   0.85, // >85% precision
		TargetF1:          0.82, // >0.82 F1 score (harmonic mean of precision and recall)
		TargetProtocols:   20,   // 20+ protocols covered
		TargetVersionRate: 0.70, // >70% version extraction rate
		TargetPerfMs:      50.0, // <50ms average detection time
	}
}

// StrictThresholds returns stricter validation thresholds for high-quality requirements.
// Use this profile when accuracy is more important than coverage.
func StrictThresholds() ValidationThresholds {
	return ValidationThresholds{
		TargetFPR:         0.05, // <5% false positive rate (very strict)
		TargetTPR:         0.90, // >90% true positive rate
		TargetPrecision:   0.92, // >92% precision
		TargetF1:          0.88, // >0.88 F1 score
		TargetProtocols:   25,   // 25+ protocols
		TargetVersionRate: 0.80, // >80% version extraction
		TargetPerfMs:      30.0, // <30ms detection time
	}
}

// RelaxedThresholds returns more permissive validation thresholds.
// Use this profile during development or for experimental protocols.
func RelaxedThresholds() ValidationThresholds {
	return ValidationThresholds{
		TargetFPR:         0.15,  // <15% false positive rate
		TargetTPR:         0.70,  // >70% true positive rate
		TargetPrecision:   0.75,  // >75% precision
		TargetF1:          0.70,  // >0.70 F1 score
		TargetProtocols:   15,    // 15+ protocols
		TargetVersionRate: 0.60,  // >60% version extraction
		TargetPerfMs:      100.0, // <100ms detection time
	}
}

// loadFloatEnv loads a float from environment variable with validation (0.0-1.0 range).
// Returns defaultVal if env var is missing, invalid, or out of range.
func loadFloatEnv(key string, defaultVal float64) float64 {
	val := envkey.Get(key)
	if val == "" {
		return defaultVal
	}
	f, err := strconv.ParseFloat(val, 64)
	if err != nil || f < 0 || f > 1 {
		return defaultVal
	}
	return f
}

// loadPositiveFloatEnv loads a positive float from environment variable.
// Returns defaultVal if env var is missing, invalid, or not positive.
func loadPositiveFloatEnv(key string, defaultVal float64) float64 {
	val := envkey.Get(key)
	if val == "" {
		return defaultVal
	}
	f, err := strconv.ParseFloat(val, 64)
	if err != nil || f <= 0 {
		return defaultVal
	}
	return f
}

// loadPositiveIntEnv loads a positive int from environment variable.
// Returns defaultVal if env var is missing, invalid, or not positive.
func loadPositiveIntEnv(key string, defaultVal int) int {
	val := envkey.Get(key)
	if val == "" {
		return defaultVal
	}
	i, err := strconv.Atoi(val)
	if err != nil || i <= 0 {
		return defaultVal
	}
	return i
}

// LoadThresholdsFromEnv loads validation thresholds from environment variables.
// Environment variables override default values. Supported variables (the
// former VULNTOR_ prefix is still read as a deprecated fallback):
//   - CYPROB_VALIDATION_TARGET_FPR: False positive rate target (0.0-1.0)
//   - CYPROB_VALIDATION_TARGET_TPR: True positive rate target (0.0-1.0)
//   - CYPROB_VALIDATION_TARGET_PRECISION: Precision target (0.0-1.0)
//   - CYPROB_VALIDATION_TARGET_F1: F1 score target (0.0-1.0)
//   - CYPROB_VALIDATION_TARGET_PROTOCOLS: Protocol coverage target (int)
//   - CYPROB_VALIDATION_TARGET_VERSION_RATE: Version extraction rate target (0.0-1.0)
//   - CYPROB_VALIDATION_TARGET_PERF_MS: Performance target in milliseconds (float)
//
// Invalid values are silently ignored, falling back to defaults.
func LoadThresholdsFromEnv() ValidationThresholds {
	defaults := DefaultThresholds()
	return ValidationThresholds{
		TargetFPR:         loadFloatEnv("VALIDATION_TARGET_FPR", defaults.TargetFPR),
		TargetTPR:         loadFloatEnv("VALIDATION_TARGET_TPR", defaults.TargetTPR),
		TargetPrecision:   loadFloatEnv("VALIDATION_TARGET_PRECISION", defaults.TargetPrecision),
		TargetF1:          loadFloatEnv("VALIDATION_TARGET_F1", defaults.TargetF1),
		TargetProtocols:   loadPositiveIntEnv("VALIDATION_TARGET_PROTOCOLS", defaults.TargetProtocols),
		TargetVersionRate: loadFloatEnv("VALIDATION_TARGET_VERSION_RATE", defaults.TargetVersionRate),
		TargetPerfMs:      loadPositiveFloatEnv("VALIDATION_TARGET_PERF_MS", defaults.TargetPerfMs),
	}
}

// ToJSON exports ValidationThresholds as formatted JSON.
func (vt *ValidationThresholds) ToJSON() ([]byte, error) {
	return json.MarshalIndent(vt, "", "  ")
}

// ToJSON exports ValidationMetrics as formatted JSON for machine-readable output.
// This is useful for CI/CD integration, metrics tracking, and programmatic analysis.
func (vm *ValidationMetrics) ToJSON() ([]byte, error) {
	return json.MarshalIndent(vm, "", "  ")
}
