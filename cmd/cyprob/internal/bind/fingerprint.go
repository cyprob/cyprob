package bind

import (
	"github.com/spf13/cobra"

	"github.com/cyprob/cyprob/pkg/fingerprint"
)

// FingerprintOptions holds configuration options for the fingerprint command.
type FingerprintOptions struct {
	FilePath string
	URL      string
	CacheDir string
}

// BindFingerprintOptions extracts and validates fingerprint command flags.
//
// This function reads the fingerprint-specific flags from the Cobra command and
// constructs a properly validated FingerprintOptions struct.
//
// Flags read:
//   - --file: Load probe catalog from a local file
//   - --url: Download probe catalog from a remote URL
//   - --cache-dir: Override probe cache destination directory
//
// Returns an error if validation fails.
func BindFingerprintOptions(cmd *cobra.Command) (FingerprintOptions, error) {
	filePath, _ := cmd.Flags().GetString("file")
	url, _ := cmd.Flags().GetString("url")
	cacheDir, _ := cmd.Flags().GetString("cache-dir")

	opts := FingerprintOptions{
		FilePath: filePath,
		URL:      url,
		CacheDir: cacheDir,
	}

	if filePath == "" && url == "" {
		return opts, fingerprint.NewSourceRequiredError()
	}

	if filePath != "" && url != "" {
		return opts, fingerprint.NewSourceConflictError()
	}

	return opts, nil
}
