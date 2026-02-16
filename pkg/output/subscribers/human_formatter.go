// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package subscribers

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/charmbracelet/lipgloss"

	"github.com/cyprob/cyprob/pkg/output"
)

// Lipgloss styles for beautiful terminal output
var (
	// Info style - normal messages
	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("10")) // Green

	// Error style - critical errors with icon
	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")). // Red
			Bold(true)

	// Warning style - warnings with icon
	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("11")). // Yellow
			Bold(true)

	// Header style - section headers (## Target: ...)
	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("105")). // Purple
			Bold(true)

	// Port style - port numbers
	portStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("39")) // Cyan

	// Vulnerability style - security issues
	vulnerabilityStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("196")). // Bright red
				Bold(true)

	// Table header style - bold headers with border
	tableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("62")). // Blue
				BorderStyle(lipgloss.NormalBorder()).
				BorderBottom(true).
				Padding(0, 1)

	// Summary box style - scan results summary (reserved for future use)
	//nolint:unused // Will be used for future scan summary boxes
	summaryBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62")).
			Padding(0, 2)
)

// HumanFormatter renders human-friendly output (tables, colors, summaries).
// Used when --json flag is NOT present (both CE and EE use this).
type HumanFormatter struct {
	stdout       io.Writer
	stderr       io.Writer
	colorEnabled bool
}

// NewHumanFormatter creates a new HumanFormatter subscriber.
func NewHumanFormatter(stdout, stderr io.Writer, colorEnabled bool) *HumanFormatter {
	return &HumanFormatter{
		stdout:       stdout,
		stderr:       stderr,
		colorEnabled: colorEnabled,
	}
}

// Name returns the subscriber identifier.
func (s *HumanFormatter) Name() string {
	return "human-formatter"
}

// ShouldHandle decides if this subscriber cares about the event.
// HumanFormatter handles everything EXCEPT diagnostic events.
func (s *HumanFormatter) ShouldHandle(event output.OutputEvent) bool {
	// Diagnostic events are handled by DiagnosticSubscriber
	return event.Type != output.EventDiag
}

// Handle processes an output event and renders it in human-friendly format.
func (s *HumanFormatter) Handle(event output.OutputEvent) {
	switch event.Type {
	case output.EventInfo:
		s.printInfo(event.Message)

	case output.EventError:
		s.printError(event.Message)

	case output.EventWarning:
		s.printWarning(event.Message)

	case output.EventTable:
		if data, ok := event.Data.(map[string]any); ok {
			headers, _ := data["headers"].([]string)
			rows, _ := data["rows"].([][]string)
			s.printTable(headers, rows)
		}

	case output.EventProgress:
		if data, ok := event.Data.(map[string]any); ok {
			current, _ := data["current"].(int)
			total, _ := data["total"].(int)
			s.printProgress(current, total, event.Message)
		}
	}
}

// printInfo outputs an info message with smart styling based on content
func (s *HumanFormatter) printInfo(message string) {
	if !s.colorEnabled {
		_, _ = fmt.Fprintln(s.stdout, message)
		return
	}

	// Apply different styles based on message content
	var styled string
	switch {
	case strings.HasPrefix(message, "##"):
		// Section header (## Target: ...)
		styled = headerStyle.Render(message)

	case strings.Contains(message, "Port:") || strings.Contains(message, "- Port:"):
		// Port information
		styled = portStyle.Render(message)

	case strings.Contains(message, "---"):
		// Separator lines
		styled = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")). // Gray
			Render(message)

	case strings.HasPrefix(message, "Starting scan"):
		// Scan start message - make it stand out
		styled = lipgloss.NewStyle().
			Foreground(lipgloss.Color("10")). // Green
			Bold(true).
			Render("🚀 " + message)

	case strings.Contains(message, "⏳") || strings.Contains(message, "✓") || strings.Contains(message, "✗"):
		// Progress messages with status icons
		// Dim the progress messages (less prominent than main output)
		styled = lipgloss.NewStyle().
			Foreground(lipgloss.Color("244")). // Light gray
			Render(message)

	default:
		// Normal info
		styled = infoStyle.Render(message)
	}

	_, _ = fmt.Fprintln(s.stdout, styled)
}

// printError outputs an error message with icon and styling
func (s *HumanFormatter) printError(message string) {
	if !s.colorEnabled {
		_, _ = fmt.Fprintf(s.stderr, "Error: %s\n", message)
		return
	}

	styled := errorStyle.Render("❌ Error: " + message)
	_, _ = fmt.Fprintln(s.stderr, styled)
}

// printWarning outputs a warning message with icon and styling
func (s *HumanFormatter) printWarning(message string) {
	if !s.colorEnabled {
		_, _ = fmt.Fprintf(s.stdout, "Warning: %s\n", message)
		return
	}

	// Check if it's a vulnerability warning (extra highlighting)
	if strings.Contains(message, "Vulnerabilities:") || strings.Contains(message, "[") {
		styled := vulnerabilityStyle.Render("⚠️  " + message)
		_, _ = fmt.Fprintln(s.stdout, styled)
	} else {
		styled := warningStyle.Render("⚠️  Warning: " + message)
		_, _ = fmt.Fprintln(s.stdout, styled)
	}
}

// printTable outputs tabular data with beautiful headers
func (s *HumanFormatter) printTable(headers []string, rows [][]string) {
	if !s.colorEnabled {
		// Simple table without styling
		w := tabwriter.NewWriter(s.stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, strings.Join(headers, "\t"))
		for _, row := range rows {
			_, _ = fmt.Fprintln(w, strings.Join(row, "\t"))
		}
		_ = w.Flush()
		return
	}

	// Styled table with lipgloss
	w := tabwriter.NewWriter(s.stdout, 0, 0, 3, ' ', 0)

	// Print styled headers (uppercase and bold with border)
	headerLine := make([]string, len(headers))
	for i, h := range headers {
		headerLine[i] = tableHeaderStyle.Render(strings.ToUpper(h))
	}
	_, _ = fmt.Fprintln(w, strings.Join(headerLine, "\t"))

	// Print rows with subtle styling
	for _, row := range rows {
		styledRow := make([]string, len(row))
		for i, cell := range row {
			// First column (labels) - slightly bold
			if i == 0 {
				styledRow[i] = lipgloss.NewStyle().
					Foreground(lipgloss.Color("245")).
					Render(cell)
			} else {
				styledRow[i] = cell
			}
		}
		_, _ = fmt.Fprintln(w, strings.Join(styledRow, "\t"))
	}

	_ = w.Flush()
}

// printProgress outputs a progress indicator
func (s *HumanFormatter) printProgress(current, total int, message string) {
	if total > 0 {
		percentage := float64(current) / float64(total) * 100
		fmt.Fprintf(s.stdout, "\r[%3.0f%%] %s", percentage, message)
		if current == total {
			fmt.Fprintln(s.stdout) // Newline when complete
		}
	}
}
