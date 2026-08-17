// Package bind provides centralized flag-to-options binding for CLI commands.
//
// This package implements the binding layer between Cobra command flags and
// service layer DTOs (Data Transfer Objects). By centralizing this logic,
// we ensure consistency, testability, and maintainability across all commands.
package bind

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cyprob/cyprob/pkg/plugin"
)

// formatList formats a string slice as a comma-separated list.
// Helper function for generating user-friendly error messages.
func formatList(items []string) string {
	return strings.Join(items, ", ")
}

// BindInstallOptions extracts and validates InstallOptions from command flags.
//
// This function reads the install-specific flags from the Cobra command and
// constructs a properly validated InstallOptions struct for the service layer.
//
// Validation (Defense-in-Depth):
//   - CLI layer: Early validation for better UX (this function)
//   - Service layer: Redundant validation for safety (service.Install)
//
// Flags read:
//   - --source: Optional plugin source name
//   - --force: Force re-install flag
//
// Returns an error if validation fails.
func BindInstallOptions(cmd *cobra.Command) (plugin.InstallOptions, error) {
	source, _ := cmd.Flags().GetString("source")
	force, _ := cmd.Flags().GetBool("force")

	// Validate source whitelist (CLI layer - early validation)
	if source != "" && !plugin.IsValidSource(source) {
		return plugin.InstallOptions{}, fmt.Errorf("invalid source %q (valid: %s)",
			source, formatList(plugin.ValidSources))
	}

	opts := plugin.InstallOptions{
		Source: source,
		Force:  force,
	}

	return opts, nil
}

// BindUpdateOptions extracts and validates UpdateOptions from command flags.
//
// This function reads the update-specific flags from the Cobra command and
// constructs a properly validated UpdateOptions struct for the service layer.
//
// Validation (Defense-in-Depth):
//   - CLI layer: Early validation for better UX (this function)
//   - Service layer: Redundant validation for safety (service.Update)
//
// Flags read:
//   - --category: Optional category filter (ssh, http, tls, database, network, misc)
//   - --source: Optional plugin source name
//   - --force: Force re-download flag
//   - --dry-run: Dry run mode (preview only)
//
// Returns an error if validation fails (e.g., invalid category or source).
func BindUpdateOptions(cmd *cobra.Command) (plugin.UpdateOptions, error) {
	category, _ := cmd.Flags().GetString("category")
	source, _ := cmd.Flags().GetString("source")
	force, _ := cmd.Flags().GetBool("force")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	// Validate category whitelist (CLI layer - early validation)
	if category != "" && !plugin.IsValidCategory(category) {
		return plugin.UpdateOptions{}, fmt.Errorf("invalid category %q (valid: %s)",
			category, formatList(plugin.GetValidCategories()))
	}

	// Validate source whitelist (CLI layer - early validation)
	if source != "" && !plugin.IsValidSource(source) {
		return plugin.UpdateOptions{}, fmt.Errorf("invalid source %q (valid: %s)",
			source, formatList(plugin.ValidSources))
	}

	opts := plugin.UpdateOptions{
		Source: source,
		Force:  force,
		DryRun: dryRun,
	}

	// Convert category string to Category type
	if category != "" {
		opts.Category = plugin.Category(category)
	}

	return opts, nil
}

// BindUninstallOptions extracts and validates UninstallOptions from command flags.
//
// This function reads the uninstall-specific flags from the Cobra command and
// constructs a properly validated UninstallOptions struct for the service layer.
//
// Validation (Defense-in-Depth):
//   - CLI layer: Early validation for better UX (this function)
//   - Service layer: Redundant validation for safety (service.Uninstall)
//
// Flags read:
//   - --all: Uninstall all plugins flag
//   - --category: Optional category filter (ssh, http, tls, database, network, misc)
//
// Returns an error if validation fails or if conflicting flags are provided.
func BindUninstallOptions(cmd *cobra.Command) (plugin.UninstallOptions, error) {
	all, _ := cmd.Flags().GetBool("all")
	category, _ := cmd.Flags().GetString("category")

	// Validate category whitelist (CLI layer - early validation)
	if category != "" && !plugin.IsValidCategory(category) {
		return plugin.UninstallOptions{}, fmt.Errorf("invalid category %q (valid: %s)",
			category, formatList(plugin.GetValidCategories()))
	}

	// Validate flag conflicts
	if all && category != "" {
		return plugin.UninstallOptions{}, fmt.Errorf("cannot use --all and --category together")
	}

	opts := plugin.UninstallOptions{
		All: all,
	}

	// Convert category string to Category type
	if category != "" {
		opts.Category = plugin.Category(category)
	}

	return opts, nil
}

// BindCleanOptions extracts and validates CleanOptions from command flags.
//
// This function reads the clean-specific flags from the Cobra command and
// constructs a properly validated CleanOptions struct for the service layer.
//
// Flags read:
//   - --older-than: Duration string for removing old cache entries (e.g., "720h" for 30 days)
//   - --dry-run: Dry run mode (preview only)
//
// Returns an error if the duration string is invalid.
func BindCleanOptions(cmd *cobra.Command) (plugin.CleanOptions, error) {
	olderThan, _ := cmd.Flags().GetString("older-than")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	// Parse duration
	duration, err := time.ParseDuration(olderThan)
	if err != nil {
		return plugin.CleanOptions{}, fmt.Errorf("invalid duration '%s': %w (use format like '720h' for 30 days)", olderThan, err)
	}

	opts := plugin.CleanOptions{
		OlderThan: duration,
		DryRun:    dryRun,
	}

	return opts, nil
}

// BindVerifyOptions extracts and validates VerifyOptions from command flags.
//
// This function reads the verify-specific flags from the Cobra command and
// constructs a properly validated VerifyOptions struct for the service layer.
//
// Flags read:
//   - --plugin: Optional plugin name to verify (if empty, verifies all plugins)
//
// Returns an error if validation fails.
func BindVerifyOptions(cmd *cobra.Command) (plugin.VerifyOptions, error) {
	pluginName, _ := cmd.Flags().GetString("plugin")

	opts := plugin.VerifyOptions{
		PluginID: pluginName,
	}

	return opts, nil
}
