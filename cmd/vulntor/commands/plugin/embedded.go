package plugin

import (
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/cyprob/cyprob/cmd/vulntor/internal/format"
	"github.com/cyprob/cyprob/pkg/plugin"
)

func newEmbeddedCommand() *cobra.Command {
	var (
		verbose  bool
		category string
	)

	cmd := &cobra.Command{
		Use:   "embedded",
		Short: "List embedded security check plugins",
		Long: `List all security check plugins embedded in the Vulntor binary.

These plugins are compiled into the binary and provide vulnerability detection
for common security issues across SSH, HTTP, TLS, Database, and Network protocols.`,
		Example: `  # List all embedded plugins
  vulntor plugin embedded

  # List embedded plugins with detailed information
  vulntor plugin embedded --verbose

  # List only SSH plugins
  vulntor plugin embedded --category ssh

  # List TLS plugins with details
  vulntor plugin embedded --category tls --verbose

  # JSON output
  vulntor plugin embedded --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Create formatter
			outputMode := format.ParseMode(cmd.Flag("output").Value.String())
			quiet, _ := cmd.Flags().GetBool("quiet")
			noColor, _ := cmd.Flags().GetBool("no-color")
			formatter := format.New(os.Stdout, os.Stderr, outputMode, quiet, !noColor)

			// Load embedded plugins
			plugins, err := plugin.LoadEmbeddedPlugins()
			if err != nil {
				return formatter.PrintTotalFailureSummary("load embedded plugins", err, "LOAD_ERROR")
			}

			// Filter plugins by category
			pluginsToDisplay, err := filterPluginsByCategory(plugins, category, formatter)
			if err != nil {
				return err
			}

			if len(pluginsToDisplay) == 0 {
				return formatter.PrintSummary("No embedded plugins found.")
			}

			// Sort plugins by name for consistent output
			sort.Slice(pluginsToDisplay, func(i, j int) bool {
				return pluginsToDisplay[i].Name < pluginsToDisplay[j].Name
			})

			// Print results
			return printEmbeddedResult(formatter, plugins, pluginsToDisplay, category, verbose)
		},
	}

	cmd.Flags().BoolVar(&verbose, "verbose", false, "Show detailed information")
	cmd.Flags().StringVar(&category, "category", "", "Filter by category (ssh, http, tls, database, network, misc)")

	return cmd
}

// filterPluginsByCategory filters plugins by category if specified
func filterPluginsByCategory(plugins map[plugin.Category][]*plugin.YAMLPlugin, category string, formatter format.Formatter) ([]*plugin.YAMLPlugin, error) {
	var pluginsToDisplay []*plugin.YAMLPlugin

	if category != "" {
		// Map category string to Category type
		var categoryFilter plugin.Category
		switch category {
		case "ssh":
			categoryFilter = plugin.CategorySSH
		case "http":
			categoryFilter = plugin.CategoryHTTP
		case "tls":
			categoryFilter = plugin.CategoryTLS
		case "database":
			categoryFilter = plugin.CategoryDatabase
		case "network":
			categoryFilter = plugin.CategoryNetwork
		case "misc":
			categoryFilter = plugin.CategoryMisc
		default:
			return nil, formatter.PrintTotalFailureSummary("embedded", fmt.Errorf("unknown category: %s", category), "INVALID_CATEGORY")
		}

		// Get plugins for the specified category
		if catPlugins, ok := plugins[categoryFilter]; ok {
			pluginsToDisplay = catPlugins
		} else {
			return nil, formatter.PrintSummary(fmt.Sprintf("No embedded plugins found for category: %s", category))
		}
	} else {
		// Flatten all plugins
		for _, catPlugins := range plugins {
			pluginsToDisplay = append(pluginsToDisplay, catPlugins...)
		}
	}

	return pluginsToDisplay, nil
}

// printEmbeddedResult formats and prints the embedded plugin result
func printEmbeddedResult(f format.Formatter, allPlugins map[plugin.Category][]*plugin.YAMLPlugin, pluginsToDisplay []*plugin.YAMLPlugin, category string, verbose bool) error {
	// JSON mode: output complete result as JSON
	if f.IsJSON() {
		return printEmbeddedJSON(f, allPlugins, pluginsToDisplay)
	}

	// Table mode
	return printEmbeddedTable(f, allPlugins, pluginsToDisplay, category, verbose)
}

// printEmbeddedJSON outputs embedded plugins as JSON
func printEmbeddedJSON(f format.Formatter, allPlugins map[plugin.Category][]*plugin.YAMLPlugin, pluginsToDisplay []*plugin.YAMLPlugin) error {
	// Build category counts
	categoryCount := make(map[string]int)
	for cat, catPlugins := range allPlugins {
		categoryCount[cat.String()] = len(catPlugins)
	}

	jsonResult := map[string]any{
		"plugins":     pluginsToDisplay,
		"total_count": len(pluginsToDisplay),
		"categories":  categoryCount,
	}
	return f.PrintJSON(jsonResult)
}

// printEmbeddedTable outputs embedded plugins as a table
func printEmbeddedTable(f format.Formatter, allPlugins map[plugin.Category][]*plugin.YAMLPlugin, pluginsToDisplay []*plugin.YAMLPlugin, category string, verbose bool) error {
	// Print header
	var headerMsg string
	if category != "" {
		headerMsg = fmt.Sprintf("Found %d embedded plugin(s) in category '%s'", len(pluginsToDisplay), category)
	} else {
		headerMsg = fmt.Sprintf("Found %d embedded plugin(s) total", len(pluginsToDisplay))
	}
	if err := f.PrintSummary(headerMsg); err != nil {
		return err
	}

	// Build and print table
	headers, rows := buildEmbeddedTable(pluginsToDisplay, verbose)
	if err := f.PrintTable(headers, rows); err != nil {
		return err
	}

	// Print category summary if showing all plugins
	if category == "" && !verbose {
		return printCategorySummary(f, allPlugins)
	}

	return nil
}

// buildEmbeddedTable builds table headers and rows
func buildEmbeddedTable(pluginsToDisplay []*plugin.YAMLPlugin, verbose bool) ([]string, [][]string) {
	var headers []string
	var rows [][]string

	if verbose {
		headers = []string{"Name", "Version", "Severity", "Author"}
		for _, p := range pluginsToDisplay {
			severity := string(p.Metadata.Severity)
			if severity == "" {
				severity = "info"
			}
			rows = append(rows, []string{p.Name, p.Version, severity, p.Author})
		}
	} else {
		headers = []string{"Name", "Version", "Severity"}
		for _, p := range pluginsToDisplay {
			severity := string(p.Metadata.Severity)
			if severity == "" {
				severity = "info"
			}
			rows = append(rows, []string{p.Name, p.Version, severity})
		}
	}

	return headers, rows
}

// printCategorySummary prints category breakdown and usage hints
func printCategorySummary(f format.Formatter, allPlugins map[plugin.Category][]*plugin.YAMLPlugin) error {
	// Build category count
	categoryCount := make(map[plugin.Category]int)
	for cat, catPlugins := range allPlugins {
		categoryCount[cat] = len(catPlugins)
	}

	// Sort categories for consistent output
	var categories []plugin.Category
	for cat := range categoryCount {
		categories = append(categories, cat)
	}
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].String() < categories[j].String()
	})

	// Print category breakdown
	if err := f.PrintSummary(""); err != nil {
		return err
	}
	if err := f.PrintSummary("Categories:"); err != nil {
		return err
	}
	for _, cat := range categories {
		if err := f.PrintSummary(fmt.Sprintf("  %s: %d plugins", cat.String(), categoryCount[cat])); err != nil {
			return err
		}
	}

	// Print usage hints
	if err := f.PrintSummary(""); err != nil {
		return err
	}
	if err := f.PrintSummary("Use --category flag to filter by category."); err != nil {
		return err
	}
	return f.PrintSummary("Use --verbose flag to show detailed information.")
}
