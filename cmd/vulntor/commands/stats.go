package commands

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/cyprob/cyprob/cmd/vulntor/internal/format"
	"github.com/cyprob/cyprob/pkg/fingerprint"
)

// NewStatsCommand creates a command for analyzing telemetry data.
func NewStatsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "stats <telemetry-file>",
		Short:   "Analyze telemetry JSONL files and generate aggregate statistics",
		GroupID: "core",
		Args:    cobra.ExactArgs(1),
		RunE:    runStats,
	}

	cmd.Flags().String("protocol", "", "Filter by protocol (e.g., ssh, http, tls)")
	cmd.Flags().String("since", "", "Start time filter (RFC3339 format: 2024-01-01T00:00:00Z)")
	cmd.Flags().String("until", "", "End time filter (RFC3339 format: 2024-01-31T23:59:59Z)")
	cmd.Flags().Int("top-n", 10, "Number of top products to include")
	cmd.Flags().Bool("json", false, "Output statistics in JSON format")

	return cmd
}

func runStats(cmd *cobra.Command, args []string) error {
	formatter := format.FromCommand(cmd)
	filePath := args[0]

	// Parse flags
	protocol, _ := cmd.Flags().GetString("protocol")
	sinceStr, _ := cmd.Flags().GetString("since")
	untilStr, _ := cmd.Flags().GetString("until")
	topN, _ := cmd.Flags().GetInt("top-n")
	outputJSON, _ := cmd.Flags().GetBool("json")

	// Build filter
	filter := &fingerprint.StatsFilter{
		Protocol: protocol,
		TopN:     topN,
	}

	// Parse time filters
	if sinceStr != "" {
		since, err := time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			return formatter.PrintTotalFailureSummary("parse --since flag", err, "INVALID_TIME_FORMAT")
		}
		filter.Since = &since
	}

	if untilStr != "" {
		until, err := time.Parse(time.RFC3339, untilStr)
		if err != nil {
			return formatter.PrintTotalFailureSummary("parse --until flag", err, "INVALID_TIME_FORMAT")
		}
		filter.Until = &until
	}

	// Analyze telemetry
	stats, err := fingerprint.AnalyzeTelemetry(filePath, filter)
	if err != nil {
		return formatter.PrintTotalFailureSummary("analyze telemetry", err, "ANALYSIS_ERROR")
	}

	// Output results
	if outputJSON {
		// JSON output
		data, err := json.MarshalIndent(stats, "", "  ")
		if err != nil {
			return formatter.PrintTotalFailureSummary("marshal JSON", err, "JSON_MARSHAL_ERROR")
		}
		fmt.Println(string(data))
	} else {
		// Human-readable output
		printHumanReadableStats(stats, filter)
	}

	return nil
}

func printHumanReadableStats(stats *fingerprint.TelemetryStats, filter *fingerprint.StatsFilter) {
	fmt.Println("Telemetry Statistics")
	fmt.Println("====================")
	fmt.Println()

	// Time range
	if !stats.StartTime.IsZero() && !stats.EndTime.IsZero() {
		fmt.Printf("Time Range: %s to %s\n", stats.StartTime.Format(time.RFC3339), stats.EndTime.Format(time.RFC3339))
		duration := stats.EndTime.Sub(stats.StartTime)
		fmt.Printf("Duration: %s\n", duration.Round(time.Second))
		fmt.Println()
	}

	// Filters applied
	if filter.Protocol != "" {
		fmt.Printf("Protocol Filter: %s\n", filter.Protocol)
		fmt.Println()
	}

	// Overall statistics
	fmt.Println("Overall Statistics")
	fmt.Println("------------------")
	fmt.Printf("Total Events:       %d\n", stats.TotalEvents)
	fmt.Printf("Successful Matches: %d\n", stats.SuccessfulMatches)
	fmt.Printf("No Matches:         %d\n", stats.NoMatches)
	fmt.Printf("Rejections:         %d\n", stats.Rejections)
	fmt.Printf("Success Rate:       %.2f%%\n", stats.SuccessRate*100)
	fmt.Println()

	// Confidence statistics
	if stats.SuccessfulMatches > 0 {
		fmt.Println("Confidence Distribution")
		fmt.Println("-----------------------")
		fmt.Printf("Min:     %.2f\n", stats.ConfidenceStats.Min)
		fmt.Printf("Max:     %.2f\n", stats.ConfidenceStats.Max)
		fmt.Printf("Average: %.2f\n", stats.ConfidenceStats.Average)
		fmt.Printf("Median:  %.2f\n", stats.ConfidenceStats.Median)
		fmt.Println()
	}

	// Protocol breakdown
	if len(stats.ProtocolStats) > 0 {
		fmt.Println("Protocol Breakdown")
		fmt.Println("------------------")
		for protocol, protocolStat := range stats.ProtocolStats {
			fmt.Printf("%s:\n", protocol)
			fmt.Printf("  Total:       %d\n", protocolStat.TotalEvents)
			fmt.Printf("  Success:     %d\n", protocolStat.SuccessfulMatches)
			fmt.Printf("  No Match:    %d\n", protocolStat.NoMatches)
			fmt.Printf("  Rejections:  %d\n", protocolStat.Rejections)
			if protocolStat.SuccessfulMatches > 0 {
				fmt.Printf("  Avg Conf:    %.2f\n", protocolStat.AvgConfidence)
			}
		}
		fmt.Println()
	}

	// Top products
	if len(stats.TopProducts) > 0 {
		fmt.Printf("Top %d Detected Products\n", len(stats.TopProducts))
		fmt.Println("------------------------")
		for i, product := range stats.TopProducts {
			if product.Vendor != "" {
				fmt.Printf("%d. %s/%s: %d detections\n", i+1, product.Vendor, product.Product, product.Count)
			} else {
				fmt.Printf("%d. %s: %d detections\n", i+1, product.Product, product.Count)
			}
		}
		fmt.Println()
	}

	// Rejection reasons
	if len(stats.RejectionReasons) > 0 {
		fmt.Println("Rejection Reasons")
		fmt.Println("-----------------")
		for reason, count := range stats.RejectionReasons {
			fmt.Printf("%s: %d\n", reason, count)
		}
		fmt.Println()
	}

	log.Info().
		Int("total_events", stats.TotalEvents).
		Int("successful_matches", stats.SuccessfulMatches).
		Float64("success_rate", stats.SuccessRate).
		Msg("telemetry analysis complete")
}
