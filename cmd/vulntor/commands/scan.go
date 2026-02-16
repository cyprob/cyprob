package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/cyprob/cyprob/cmd/vulntor/internal/bind"
	"github.com/cyprob/cyprob/cmd/vulntor/internal/format"
	"github.com/cyprob/cyprob/pkg/appctx"
	"github.com/cyprob/cyprob/pkg/engine"
	parsepkg "github.com/cyprob/cyprob/pkg/modules/parse" // Alias for parse package functions
	"github.com/cyprob/cyprob/pkg/output"
	"github.com/cyprob/cyprob/pkg/scanexec"
	"github.com/cyprob/cyprob/pkg/storage"
	"github.com/cyprob/cyprob/pkg/stringutil"
)

// ScanCmd defines the 'scan' command for comprehensive scanning.
var ScanCmd = &cobra.Command{
	Use:   "scan [targets...]",
	Short: "Perform a comprehensive scan on specified targets",
	Long: `Performs various scanning stages based on selected profile, level, or flags.
The command automatically plans the execution DAG using available modules.`,
	GroupID: "scan",
	Args:    cobra.ArbitraryArgs,
	RunE:    runScanCommand,
}

const (
	scanOutputFormatJSON = "json"
)

func runScanCommand(cmd *cobra.Command, args []string) error {
	formatter := format.FromCommand(cmd)
	out := setupOutputPipeline(cmd)

	// Collect targets from both --targets flag and positional arguments
	targetFlags, _ := cmd.Flags().GetStringSlice("targets")
	allTargets := make([]string, 0, len(targetFlags)+len(args))
	allTargets = append(allTargets, targetFlags...)
	allTargets = append(allTargets, args...)

	if len(allTargets) == 0 {
		return formatter.PrintTotalFailureSummary("scan", scanexec.ErrNoTargets, scanexec.ErrorCode(scanexec.ErrNoTargets))
	}

	logger := log.With().Str("command", "scan").Logger()
	logger.Info().Strs("targets", allTargets).Msg("Initializing scan command")

	// Output pipeline: Emit initialization event
	out.Diag(output.LevelVerbose, "Initializing scan command", map[string]any{
		"targets": allTargets,
	})

	// Bind flags to options using centralized binder
	params, err := bind.BindScanOptions(cmd, allTargets)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to bind scan options")
		return formatter.PrintTotalFailureSummary("scan", err, scanexec.ErrorCode(err))
	}

	svc := scanexec.NewService()

	ctxFromCmd := cmd.Context()
	if ctxFromCmd == nil && cmd.Root() != nil {
		ctxFromCmd = cmd.Root().Context()
	}
	appMgr, ok := ctxFromCmd.Value(engine.AppManagerKey).(*engine.AppManager)
	if !ok || appMgr == nil {
		appErr := fmt.Errorf("app manager missing from context")
		logger.Error().Err(appErr).Msg("AppManager not found in context.")
		return formatter.PrintTotalFailureSummary("scan", appErr, scanexec.ErrorCode(appErr))
	}
	orchestratorCtx := context.WithValue(appMgr.Context(), engine.AppManagerKey, appMgr)
	orchestratorCtx = appctx.WithConfig(orchestratorCtx, appMgr.Config())

	// Create and attach storage backend for scan result persistence
	storageConfig, err := storage.DefaultConfig()
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to get storage config, scans will not be persisted")
	} else {
		storageBackend, err := storage.NewBackend(orchestratorCtx, storageConfig)
		if err != nil {
			logger.Warn().Err(err).Msg("Failed to create storage backend, scans will not be persisted")
		} else {
			// Initialize storage
			if err := storageBackend.Initialize(orchestratorCtx); err != nil {
				logger.Warn().Err(err).Msg("Failed to initialize storage, scans will not be persisted")
			} else {
				svc = svc.WithStorage(storageBackend)
				logger.Info().Msg("Storage backend initialized for scan persistence")

				// Ensure storage is closed when scan completes
				defer func() {
					if err := storageBackend.Close(); err != nil {
						logger.Warn().Err(err).Msg("Failed to close storage backend")
					}
				}()
			}
		}
	}

	// Enable progress logging if interactive flag is set
	interactive, _ := cmd.Flags().GetBool("progress")
	if interactive {
		svc = svc.WithProgressSink(&progressLogger{
			logger: logger,
			out:    out,
		})
	}

	// Inject Output interface into context for modules to access
	// This enables real-time progress reporting (discovered hosts, open ports, etc.)
	orchestratorCtx = context.WithValue(orchestratorCtx, output.OutputKey, out)

	if params.OutputFormat == "text" {
		logger.Info().Msg("Starting scan execution with automatically planned DAG...")
		// Only show emoji message in default mode (not in verbose/debug mode)
		verbosityCount, _ := cmd.Flags().GetCount("verbosity")
		if verbosityCount == 0 {
			out.Info("Starting scan execution...")
		}
	}

	res, runErr := svc.Run(orchestratorCtx, params)
	if runErr != nil {
		logger.Error().Err(runErr).Msg("Scan execution failed")
		out.Error(runErr)
		return formatter.PrintTotalFailureSummary("scan", runErr, scanexec.ErrorCode(runErr))
	}

	dataCtx := extractDataContext(res)
	return renderScanOutput(out, formatter, params, res, dataCtx, logger)
}

func extractDataContext(res *scanexec.Result) map[string]any {
	if res != nil && res.RawContext != nil {
		return res.RawContext
	}
	return map[string]any{}
}

func renderScanOutput(out output.Output, formatter format.Formatter, params scanexec.Params, res *scanexec.Result, dataCtx map[string]any, logger zerolog.Logger) error {
	profiles, missingProfiles, profileErr := collectAssetProfiles(dataCtx)

	if missingProfiles {
		logger.Info().Msg("No 'asset.profiles' data found in scan results.")
		out.Diag(output.LevelVerbose, "No asset.profiles data found in scan results", nil)
	}
	if profileErr != nil {
		logger.Warn().Err(profileErr).Msg("Scan completed with post-processing errors")
		out.Warning(fmt.Sprintf("Scan completed with post-processing errors: %v", profileErr))
	}

	switch strings.ToLower(params.OutputFormat) {
	case scanOutputFormatJSON:
		if profiles == nil {
			profiles = []engine.AssetProfile{}
		}
		jsonData, jsonErr := json.MarshalIndent(profiles, "", "  ")
		if jsonErr != nil {
			logger.Error().Err(jsonErr).Msg("Failed to marshal AssetProfile to JSON")
			return formatter.PrintTotalFailureSummary("scan", jsonErr, scanexec.ErrorCode(jsonErr))
		}
		fmt.Println(string(jsonData))
	case "yaml":
		if profiles == nil {
			profiles = []engine.AssetProfile{}
		}
		yamlData, yamlErr := yaml.Marshal(profiles)
		if yamlErr != nil {
			logger.Error().Err(yamlErr).Msg("Failed to marshal AssetProfile to YAML")
			return formatter.PrintTotalFailureSummary("scan", yamlErr, scanexec.ErrorCode(yamlErr))
		}
		fmt.Println(string(yamlData))
	default:
		if len(profiles) > 0 {
			if res != nil {
				printScanSummary(out, res, profiles)
			}
			printAssetProfileTextOutput(out, profiles)
		} else {
			out.Info("Scan completed, but no asset profiles were generated.")
		}
	}

	return nil
}

func collectAssetProfiles(dataCtx map[string]any) ([]engine.AssetProfile, bool, error) {
	const assetProfileDataKey = "asset.profiles"

	rawProfiles, found := dataCtx[assetProfileDataKey]
	if !found || rawProfiles == nil {
		return nil, true, nil
	}

	profileList, listOk := rawProfiles.([]any)
	if !listOk {
		return nil, false, fmt.Errorf("asset profile data has unexpected type: %T", rawProfiles)
	}
	if len(profileList) == 0 || profileList[0] == nil {
		return nil, true, nil
	}

	castedProfiles, castOk := profileList[0].([]engine.AssetProfile)
	if !castOk {
		return nil, false, fmt.Errorf("could not cast asset profile data to expected type: %T", profileList[0])
	}

	return castedProfiles, false, nil
}

func printAssetProfileTextOutput(out output.Output, profiles []engine.AssetProfile) {
	out.Info("--- Scan Results ---")

	for _, asset := range profiles {
		// Target header
		out.Info(fmt.Sprintf("\n## Target: %s (IPs: %v)", asset.Target, getMapKeys(asset.ResolvedIPs)))
		out.Diag(output.LevelVerbose, "Asset details", map[string]any{
			"target":    asset.Target,
			"is_alive":  asset.IsAlive,
			"hostnames": asset.Hostnames,
		})

		out.Info(fmt.Sprintf("   Is Alive: %v", asset.IsAlive))
		if len(asset.Hostnames) > 0 {
			out.Info(fmt.Sprintf("   Hostnames: %v", asset.Hostnames))
		}

		if len(asset.OpenPorts) > 0 {
			out.Info("   --- Open Ports ---")

			// Portları sıralı göstermek için IP'leri sırala
			var sortedIPs []string
			for ip := range asset.OpenPorts {
				sortedIPs = append(sortedIPs, ip)
			}
			sort.Strings(sortedIPs)

			for _, ip := range sortedIPs {
				out.Info(fmt.Sprintf("     IP: %s", ip))
				// Portları sıralı göstermek için port numarasına göre sırala
				portProfiles := asset.OpenPorts[ip]
				sort.Slice(portProfiles, func(i, j int) bool {
					return portProfiles[i].PortNumber < portProfiles[j].PortNumber
				})

				for _, port := range portProfiles {
					out.Info(fmt.Sprintf("       - Port: %d/%s (%s)", port.PortNumber, port.Protocol, port.Status))

					if port.Service.Name != "" || port.Service.Product != "" {
						out.Info(fmt.Sprintf("         Service: %s %s %s", port.Service.Name, port.Service.Product, port.Service.Version))
					}
					if port.Service.RawBanner != "" {
						out.Info(fmt.Sprintf("         Banner: %s", stringutil.Ellipsis(port.Service.RawBanner, 80)))
					}
					if port.Service.ParsedAttributes != nil {
						attrs := port.Service.ParsedAttributes
						printedFingerprintList := false
						if rawMatches, ok := attrs["fingerprints"]; ok {
							if matches, ok := rawMatches.([]parsepkg.FingerprintParsedInfo); ok && len(matches) > 0 {
								printedFingerprintList = true
								out.Info("         Fingerprints:")
								for _, match := range matches {
									fingerprintLine := fmt.Sprintf("           - %s", match.Product)
									if match.Version != "" {
										fingerprintLine += fmt.Sprintf(" %s", match.Version)
									}
									if match.Vendor != "" {
										fingerprintLine += fmt.Sprintf(" [%s]", match.Vendor)
									}
									fingerprintLine += fmt.Sprintf(" (confidence %.2f", match.Confidence)
									if match.SourceProbe != "" {
										fingerprintLine += fmt.Sprintf(", probe %s", match.SourceProbe)
									}
									fingerprintLine += ")"
									out.Info(fingerprintLine)

									if match.CPE != "" {
										out.Info(fmt.Sprintf("             CPE: %s", match.CPE))
									}
									if match.Description != "" {
										out.Info(fmt.Sprintf("             Notes: %s", match.Description))
									}
								}
							}
						}
						if !printedFingerprintList {
							if confidence, ok := attrs["fingerprint_confidence"]; ok {
								out.Info(fmt.Sprintf("         Fingerprint Confidence: %v", confidence))
							}
							if vendor, ok := attrs["vendor"]; ok {
								out.Info(fmt.Sprintf("         Vendor: %v", vendor))
							}
							if cpe, ok := attrs["cpe"]; ok {
								out.Info(fmt.Sprintf("         CPE: %v", cpe))
							}
						}
					}

					if len(port.Vulnerabilities) > 0 {
						out.Warning("         Vulnerabilities:")
						for _, vuln := range port.Vulnerabilities {
							out.Warning(fmt.Sprintf("           - [%s] %s (%s)", vuln.Severity, vuln.ID, vuln.Summary))
						}
					}
				}
			}
		} else {
			out.Info("   No open ports found.")
		}
	}

	out.Info("\n--- End of Scan Results ---")
}

// Helper function to get keys from a map for printing.
func getMapKeys(m map[string]time.Time) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

type progressLogger struct {
	logger zerolog.Logger
	out    output.Output
}

// printScanSummary displays a human-readable summary table of scan results
func printScanSummary(out output.Output, res *scanexec.Result, profiles []engine.AssetProfile) {
	if res == nil || len(profiles) == 0 {
		return
	}

	// Calculate summary statistics
	hostsFound := len(profiles)
	totalOpenPorts := 0
	totalVulns := 0
	servicesMap := make(map[string]bool) // unique services

	for _, profile := range profiles {
		totalVulns += profile.TotalVulnerabilities
		for _, portList := range profile.OpenPorts {
			totalOpenPorts += len(portList)
			for _, port := range portList {
				if port.Service.Name != "" {
					serviceName := port.Service.Name
					if port.PortNumber > 0 {
						serviceName = fmt.Sprintf("%s (%d)", port.Service.Name, port.PortNumber)
					}
					servicesMap[serviceName] = true
				}
			}
		}
	}

	// Build services string
	var services []string
	for svc := range servicesMap {
		services = append(services, svc)
	}
	sort.Strings(services)
	servicesStr := strings.Join(services, ", ")

	// Calculate duration
	var duration string
	if res.StartTime != "" && res.EndTime != "" {
		startTime, errStart := time.Parse(time.RFC3339Nano, res.StartTime)
		endTime, errEnd := time.Parse(time.RFC3339Nano, res.EndTime)
		if errStart == nil && errEnd == nil {
			durationTime := endTime.Sub(startTime)
			duration = fmt.Sprintf("%.1fs", durationTime.Seconds())
		} else {
			duration = "N/A"
		}
	} else {
		duration = "N/A"
	}

	// Get primary target
	target := "N/A"
	if len(profiles) > 0 {
		target = profiles[0].Target
	}

	// Build summary table for Output.Table()
	headers := []string{"Metric", "Value"}
	rows := [][]string{
		{"Target", target},
		{"Duration", duration},
		{"Hosts Found", fmt.Sprintf("%d", hostsFound)},
		{"Open Ports", fmt.Sprintf("%d", totalOpenPorts)},
	}

	// Only show Services row if any services were detected
	if servicesStr != "" {
		rows = append(rows, []string{"Services", servicesStr})
	}

	// Add vulnerabilities row
	rows = append(rows, []string{"Vulnerabilities", fmt.Sprintf("%d", totalVulns)})

	// Output using Output.Table() - this will be rendered by HumanFormatter or JSONFormatter
	out.Table(headers, rows)
}

func (p *progressLogger) OnEvent(ev scanexec.ProgressEvent) {
	// Structured logging for debugging
	entry := p.logger.Info().
		Str("phase", ev.Phase).
		Str("module", ev.Module).
		Str("status", ev.Status)
	if ev.ModuleID != "" {
		entry = entry.Str("module_id", ev.ModuleID)
	}
	if ev.Message != "" {
		entry = entry.Str("message", ev.Message)
	}
	entry.Msg("scan progress")

	// User-friendly progress output via Output interface
	if p.out != nil {
		// Build progress message
		statusIcon := getStatusIcon(ev.Status)
		message := fmt.Sprintf("%s %s: %s", statusIcon, ev.Phase, ev.Module)
		if ev.Message != "" {
			message += fmt.Sprintf(" - %s", ev.Message)
		}

		// Emit as info event (HumanFormatter will style it)
		p.out.Info(message)
	}
}

// getStatusIcon returns an icon based on status
func getStatusIcon(status string) string {
	switch status {
	case "running", "started":
		return "⏳"
	case "completed", "success":
		return "✓"
	case "failed", "error":
		return "✗"
	case "skipped":
		return "⊘"
	default:
		return "•"
	}
}

func init() {
	// Flags for ScanCmd (ensure these are descriptive for the planner)
	ScanCmd.Flags().StringSliceP("targets", "t", []string{}, "Target hosts/networks (can be used multiple times or comma-separated, e.g., -t 192.168.1.1,example.com or -t 192.168.1.1 -t example.com)")
	ScanCmd.Flags().StringP("ports", "p", "", "Ports/port ranges for TCP scan (e.g., 'top-1000', '22,80,443', '1-65535')")
	ScanCmd.Flags().String("profile", "", "Predefined scan profile (e.g., 'quick_discovery', 'full_vuln_scan')")
	ScanCmd.Flags().String("level", "default", "Scan intensity level (e.g., 'light', 'default', 'comprehensive', 'intrusive')")
	ScanCmd.Flags().StringSlice("tags", []string{}, "Only include modules with these tags (comma-separated)")
	ScanCmd.Flags().StringSlice("exclude-tags", []string{}, "Exclude modules with these tags (comma-separated)")
	ScanCmd.Flags().Bool("vuln", false, "Enable vulnerability assessment modules (shortcut for a common intent)")
	ScanCmd.Flags().Bool("only-discover", false, "Run only discovery modules (scan and vuln phases are skipped)")
	ScanCmd.Flags().Bool("no-discover", false, "Skip discovery phase and proceed directly to port scanning/vuln")
	ScanCmd.Flags().Bool("progress", false, "Print live progress updates during the scan")
	ScanCmd.Flags().String("fingerprint-cache", "", "Path to fingerprint catalog cache directory")
	ScanCmd.Flags().StringP("output", "o", "text", "Output format: text, json, yaml")
	ScanCmd.Flags().String("timeout", "", "Override timeout for network operations (default: module-specific or from config file)")
	ScanCmd.Flags().Int("concurrency", 0, "Override concurrency for parallel operations (default: module-specific or from config file)")

	// Ping specific flags - planner can use these if ICMP module is selected
	ScanCmd.Flags().Bool("ping", true, "Enable ICMP host discovery (default: true)")
	ScanCmd.Flags().Int("ping-count", 1, "Number of ICMP pings per host")
	ScanCmd.Flags().Bool("allow-loopback", false, "Allow scanning loopback addresses")
}
