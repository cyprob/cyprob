package commands

import (
	"path/filepath"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/cyprob/cyprob/cmd/vulntor/internal/bind"
	"github.com/cyprob/cyprob/cmd/vulntor/internal/format"
	"github.com/cyprob/cyprob/pkg/fingerprint"
	"github.com/cyprob/cyprob/pkg/fingerprint/catalogsync"
	"github.com/cyprob/cyprob/pkg/storage"
)

// NewFingerprintCommand wires CLI helpers for fingerprint catalog management.
func NewFingerprintCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "fingerprint",
		Aliases: []string{"fp"},
		Short:   "Manage fingerprint probe catalogs",
		GroupID: "core",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newFingerprintSyncCommand())
	cmd.AddCommand(newFingerprintValidateCommand())

	return cmd
}

func newFingerprintSyncCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync fingerprint probes from a remote or local source",
		RunE: func(cmd *cobra.Command, _ []string) error {
			formatter := format.FromCommand(cmd)
			// Bind flags to options using centralized binder
			opts, err := bind.BindFingerprintOptions(cmd)
			if err != nil {
				return formatter.PrintTotalFailureSummary("sync fingerprint catalog", err, fingerprint.ErrorCode(err))
			}

			destination := opts.CacheDir
			if destination == "" {
				if cfg, ok := storage.ConfigFromContext(cmd.Context()); ok {
					destination = filepath.Join(cfg.WorkspaceRoot, "cache", "fingerprint")
				} else {
					derr := fingerprint.NewStorageDisabledError()
					return formatter.PrintTotalFailureSummary("sync fingerprint catalog", derr, fingerprint.ErrorCode(derr))
				}
			}

			svc := catalogsync.Service{
				CacheDir: destination,
			}

			if opts.FilePath != "" {
				svc.Source = catalogsync.FileSource{Path: opts.FilePath}
			} else {
				svc.Source = catalogsync.HTTPSource{URL: opts.URL}
			}
			svc.Store = catalogsync.FileStore{Path: filepath.Join(destination, "probe.catalog.yaml")}

			catalog, err := svc.Sync(cmd.Context())
			if err != nil {
				wrapped := fingerprint.WrapSyncError(err)
				return formatter.PrintTotalFailureSummary("sync fingerprint catalog", wrapped, fingerprint.ErrorCode(wrapped))
			}

			log.Info().Str("cache", destination).Int("groups", len(catalog.Groups)).Int("probes", totalProbes(catalog)).Msg("fingerprint probes synced")
			return nil
		},
	}

	cmd.Flags().String("file", "", "Load probe catalog from a local file")
	cmd.Flags().String("url", "", "Download probe catalog from a remote URL")
	cmd.Flags().String("cache-dir", "", "Override probe cache destination directory")

	return cmd
}

func newFingerprintValidateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate [file]",
		Short: "Validate fingerprint database YAML file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			formatter := format.FromCommand(cmd)
			filePath := args[0]

			// Read YAML file
			rules, err := fingerprint.LoadRulesFromFile(filePath)
			if err != nil {
				return formatter.PrintTotalFailureSummary("validate fingerprint database", err, fingerprint.ErrorCode(err))
			}

			// Get flags
			strict, _ := cmd.Flags().GetBool("strict")
			jsonOutput, _ := cmd.Flags().GetBool("json")

			// Validate rules
			validator := fingerprint.NewValidator(strict)
			result := validator.Validate(rules)

			// Output results
			if jsonOutput {
				return formatter.PrintJSON(map[string]any{
					"valid":      result.IsValid(),
					"rule_count": result.RuleCount,
					"errors":     result.Errors,
					"warnings":   result.Warnings,
				})
			}

			// Text output
			log.Info().Int("rules", result.RuleCount).Msg("validating fingerprint database")

			if len(result.Errors) > 0 {
				log.Error().Int("count", len(result.Errors)).Msg("validation errors found")
				for _, err := range result.Errors {
					log.Error().
						Str("rule_id", err.RuleID).
						Str("field", err.Field).
						Str("message", err.Message).
						Msg("validation error")
				}
			}

			if len(result.Warnings) > 0 {
				log.Warn().Int("count", len(result.Warnings)).Msg("validation warnings found")
				for _, warn := range result.Warnings {
					log.Warn().
						Str("rule_id", warn.RuleID).
						Str("field", warn.Field).
						Str("message", warn.Message).
						Msg("validation warning")
				}
			}

			if !result.IsValid() {
				return formatter.PrintTotalFailureSummary("validate fingerprint database",
					fingerprint.NewValidationError(len(result.Errors), len(result.Warnings)),
					"VALIDATION_ERROR")
			}

			if strict && len(result.Warnings) > 0 {
				log.Warn().Msg("strict mode: warnings present (but validation passed)")
			}

			log.Info().Msg("validation passed")
			return nil
		},
	}

	cmd.Flags().Bool("strict", false, "Treat warnings as failures (exit code 2)")
	cmd.Flags().Bool("json", false, "Output results as JSON")

	return cmd
}

func totalProbes(catalog *fingerprint.ProbeCatalog) int {
	if catalog == nil {
		return 0
	}
	total := 0
	for _, group := range catalog.Groups {
		total += len(group.Probes)
	}
	return total
}
