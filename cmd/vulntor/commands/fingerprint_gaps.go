package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cyprob/cyprob/pkg/fingerprint"
)

// scanCorpusHost is the subset of a scan result this command reads. It is
// deliberately partial: the file format carries far more than the banners, and
// depending on the rest would break this tool every time the report grows.
type scanCorpusHost struct {
	Target        string `json:"target"`
	OpenPortsByIP map[string][]struct {
		PortNumber int    `json:"port_number"`
		Protocol   string `json:"protocol"`
		Service    struct {
			Name      string `json:"name"`
			RawBanner string `json:"raw_banner"`
		} `json:"service"`
	} `json:"open_ports_by_ip"`
}

func newFingerprintGapsCommand() *cobra.Command {
	var (
		showStubs bool
		minCount  int
		asJSON    bool
	)

	cmd := &cobra.Command{
		Use:   "gaps <scan.json> [scan.json...]",
		Short: "Report banners in a scan corpus that no fingerprint rule recognizes",
		Long: strings.TrimSpace(`
Reads scan results already on disk and reports which service banners no rule in
the fingerprint database recognizes, grouped by the line a rule would anchor on
and ranked by how often it was seen.

This reads local files and prints a report. It sends nothing anywhere.

The point is to write rules against what an estate actually contains rather than
against what it is assumed to contain. A device usually names itself in its
banner; the report says which of those names we are currently ignoring, and how
much each one is worth.

  cyprob scan 10.0.0.0/24 -o json > estate.json
  cyprob fingerprint gaps estate.json --stub
`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			observations, err := loadScanCorpus(args)
			if err != nil {
				return err
			}
			report := fingerprint.AnalyzeGaps(observations)

			if asJSON {
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				return encoder.Encode(report)
			}
			printGapReport(cmd, report, minCount, showStubs)
			return nil
		},
	}

	cmd.Flags().BoolVar(&showStubs, "stub", false, "Print a starting rule for each gap")
	cmd.Flags().IntVar(&minCount, "min-count", 1, "Hide gaps seen fewer times than this")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit the report as JSON")
	return cmd
}

func loadScanCorpus(paths []string) ([]fingerprint.Observation, error) {
	observations := make([]fingerprint.Observation, 0, 64)
	for _, path := range paths {
		raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied path, read-only
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var hosts []scanCorpusHost
		if err := json.Unmarshal(raw, &hosts); err != nil {
			// A single-host scan is emitted as an object rather than an array.
			var single scanCorpusHost
			if objErr := json.Unmarshal(raw, &single); objErr != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			hosts = []scanCorpusHost{single}
		}

		for _, host := range hosts {
			for ip, ports := range host.OpenPortsByIP {
				target := ip
				if target == "" {
					target = host.Target
				}
				for _, port := range ports {
					if strings.TrimSpace(port.Service.RawBanner) == "" {
						continue
					}
					// The service name is what the rules key on; the transport
					// is only a fallback, and it puts the resolver into the mode
					// that tries every rule.
					protocol := strings.TrimSpace(port.Service.Name)
					if protocol == "" {
						protocol = strings.TrimSpace(port.Protocol)
					}
					observations = append(observations, fingerprint.Observation{
						Target:   target,
						Port:     port.PortNumber,
						Protocol: protocol,
						Banner:   port.Service.RawBanner,
					})
				}
			}
		}
	}
	return observations, nil
}

func printGapReport(cmd *cobra.Command, report fingerprint.GapReport, minCount int, showStubs bool) {
	out := cmd.OutOrStdout()

	if report.Observations == 0 {
		fmt.Fprintln(out, "No banners in this corpus. Nothing to report.")
		return
	}

	share := float64(report.Unmatched) / float64(report.Observations) * 100
	fmt.Fprintf(out, "%d services with a banner, %d unrecognized (%.0f%%)\n\n",
		report.Observations, report.Unmatched, share)

	if report.Unmatched == 0 {
		fmt.Fprintln(out, "Every banner in this corpus is already recognized.")
		return
	}

	shown := 0
	for _, gap := range report.Gaps {
		if gap.Count < minCount {
			continue
		}
		shown++
		fmt.Fprintf(out, "%4dx  [%s]  %s\n", gap.Count, gap.Kind, gap.Signature)
		fmt.Fprintf(out, "       seen at: %s\n", strings.Join(gap.Samples, ", "))
		if showStubs {
			for _, line := range strings.Split(gap.RuleStub(), "\n") {
				fmt.Fprintf(out, "       %s\n", line)
			}
		}
		fmt.Fprintln(out)
	}

	if shown == 0 {
		fmt.Fprintf(out, "No gap was seen %d or more times.\n", minCount)
		return
	}
	// A banner can be counted under both its Server header and its page title,
	// so the per-signature counts deliberately do not sum to the total.
	fmt.Fprintln(out, "A banner offering two anchors appears under both, so these counts overlap.")
}
