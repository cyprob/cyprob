// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package format

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"

	"github.com/cyprob/cyprob/pkg/plugin"
)

// OutputMode defines the output format for CLI commands
type OutputMode string

const (
	// ModeJSON outputs data as JSON
	ModeJSON OutputMode = "json"
	// ModeTable outputs data as ASCII table
	ModeTable OutputMode = "table"
)

// Formatter provides consistent output formatting across CLI commands
type Formatter interface {
	// PrintJSON outputs data as JSON to stdout
	PrintJSON(data any) error

	// PrintTable outputs data as ASCII table to stdout
	PrintTable(headers []string, rows [][]string) error

	// PrintSummary outputs a summary message to stdout (unless quiet mode)
	PrintSummary(message string) error

	// PrintError outputs an error to stderr (or JSON to stdout in JSON mode)
	PrintError(err error) error

	// IsJSON returns true if the formatter is in JSON mode
	IsJSON() bool

	// PrintSuccessSummary prints a standardized success message
	PrintSuccessSummary(operation, pluginID, version string) error

	// PrintPartialFailureSummary prints partial failure with counts, errors, and suggestions
	PrintPartialFailureSummary(summary Summary) error

	// PrintTotalFailureSummary prints total failure with error and suggestions
	PrintTotalFailureSummary(operation string, err error, errorCode string) error
}

// formatter implements the Formatter interface
type formatter struct {
	stdout io.Writer
	stderr io.Writer
	mode   OutputMode
	quiet  bool
	color  bool
}

// New creates a new Formatter
func New(stdout, stderr io.Writer, mode OutputMode, quiet, color bool) Formatter {
	return &formatter{
		stdout: stdout,
		stderr: stderr,
		mode:   mode,
		quiet:  quiet,
		color:  color,
	}
}

// PrintJSON outputs data as JSON to stdout
func (f *formatter) PrintJSON(data any) error {
	enc := json.NewEncoder(f.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

// PrintTable outputs data as ASCII table to stdout
func (f *formatter) PrintTable(headers []string, rows [][]string) error {
	if f.mode == ModeJSON {
		// In JSON mode, convert table to structured data
		var items []map[string]string
		for _, row := range rows {
			item := make(map[string]string)
			for i, header := range headers {
				if i < len(row) {
					item[header] = row[i]
				}
			}
			items = append(items, item)
		}
		return f.PrintJSON(items)
	}

	// Table mode using text/tabwriter
	w := tabwriter.NewWriter(f.stdout, 0, 0, 2, ' ', 0)

	// Print header (uppercase and bold if color enabled)
	if f.color {
		headerLine := make([]string, len(headers))
		for i, h := range headers {
			headerLine[i] = color.New(color.Bold).Sprint(strings.ToUpper(h))
		}
		if _, err := fmt.Fprintln(w, strings.Join(headerLine, "\t")); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(w, strings.Join(headers, "\t")); err != nil {
			return err
		}
	}

	// Print rows
	for _, row := range rows {
		if _, err := fmt.Fprintln(w, strings.Join(row, "\t")); err != nil {
			return err
		}
	}

	return w.Flush()
}

// PrintSummary outputs a summary message to stdout (unless quiet mode)
func (f *formatter) PrintSummary(message string) error {
	if f.quiet {
		return nil
	}

	if f.mode == ModeJSON {
		// In JSON mode, summary goes to stderr (not stdout)
		_, err := fmt.Fprintln(f.stderr, message)
		return err
	}

	// Table mode: summary to stdout
	if f.color {
		_, err := color.New(color.FgGreen).Fprintln(f.stdout, message)
		return err
	}

	_, err := fmt.Fprintln(f.stdout, message)
	return err
}

// PrintError outputs an error to stderr (or JSON to stdout in JSON mode)
func (f *formatter) PrintError(err error) error {
	if err == nil {
		return nil
	}

	if f.mode == ModeJSON {
		// JSON mode: error object to stdout (machine-readable)
		return f.PrintJSON(map[string]any{
			"success":    false,
			"error":      err.Error(),
			"code":       plugin.ErrorCode(err),
			"suggestion": plugin.GetSuggestion(err),
		})
	}

	// Table mode: error to stderr (human-readable)
	var writeErr error
	if f.color {
		_, writeErr = color.New(color.FgRed).Fprintf(f.stderr, "Error: %v\n", err)
	} else {
		_, writeErr = fmt.Fprintf(f.stderr, "Error: %v\n", err)
	}

	return writeErr
}

// IsJSON returns true if the formatter is in JSON mode
func (f *formatter) IsJSON() bool {
	return f.mode == ModeJSON
}

// ValidateMode checks if the output mode is valid
func ValidateMode(mode string) error {
	switch OutputMode(mode) {
	case ModeJSON, ModeTable:
		return nil
	default:
		return fmt.Errorf("invalid output mode: %s (must be 'json' or 'table')", mode)
	}
}

// ParseMode converts a string to OutputMode
func ParseMode(mode string) OutputMode {
	switch strings.ToLower(mode) {
	case "json":
		return ModeJSON
	case "table":
		return ModeTable
	default:
		return ModeTable // default
	}
}
