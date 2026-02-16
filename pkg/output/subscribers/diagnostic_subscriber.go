// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package subscribers

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/cyprob/cyprob/pkg/output"
)

// Lipgloss styles for diagnostic messages
var (
	// Banner capture style - bright green
	bannerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("10")) // Bright green

	// Host discovery style - green
	hostStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("10")) // Green

	// Port discovery style - cyan
	portDiscoveryStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("39")) // Cyan

	// Plugin download style - blue
	pluginDownloadStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("33")) // Blue

	// Plugin skip style - yellow
	pluginSkipStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("11")) // Yellow

	// Plugin success style - green
	pluginSuccessStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("10")) // Green

	// Plugin fail style - red
	pluginFailStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")) // Red

	// Vulnerability styles - severity-based colors
	vulnCriticalStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("196")) // Bright red

	vulnHighStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")) // Red

	vulnMediumStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("11")) // Yellow

	vulnLowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("33")) // Blue

	// Service detection styles - protocol-based colors
	sshServiceStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("141")) // Purple

	httpServiceStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("45")) // Bright cyan

	// Generic diagnostic style - gray
	diagStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("244")) // Gray
)

// DiagnosticSubscriber handles diagnostic events based on verbosity level.
// Independent of output format - can be combined with HumanFormatter or JSONFormatter.
//
// Verbosity levels:
//   - LevelVerbose (1): -v flag
//   - LevelDebug (2): -vv flag
//   - LevelTrace (3): -vvv flag
type DiagnosticSubscriber struct {
	level        output.OutputLevel // Current verbosity level
	writer       io.Writer          // Where to write diagnostic output (typically stderr)
	colorEnabled bool               // Whether to use colors
}

// NewDiagnosticSubscriber creates a new DiagnosticSubscriber.
func NewDiagnosticSubscriber(level output.OutputLevel, writer io.Writer) *DiagnosticSubscriber {
	return &DiagnosticSubscriber{
		level:        level,
		writer:       writer,
		colorEnabled: true, // TODO: Auto-detect TTY
	}
}

// Name returns the subscriber identifier.
func (s *DiagnosticSubscriber) Name() string {
	return "diagnostic-subscriber"
}

// ShouldHandle decides if this subscriber cares about the event.
// ONLY handles diagnostic events (EventDiag) where event.Level <= subscriber.level.
func (s *DiagnosticSubscriber) ShouldHandle(event output.OutputEvent) bool {
	// Only handle diagnostic events
	if event.Type != output.EventDiag {
		return false
	}

	// Event level must be <= subscriber level
	// Example: If subscriber level is 2 (Debug), handle levels 1 (Verbose) and 2 (Debug), but not 3 (Trace)
	return event.Level <= s.level
}

// Handle processes a diagnostic event and renders it to stderr.
//
//nolint:gocyclo // Pattern matching requires multiple cases for different message types
func (s *DiagnosticSubscriber) Handle(event output.OutputEvent) {
	if !s.colorEnabled {
		// Plain text mode
		prefix := getLevelPrefix(event.Level)
		fmt.Fprintf(s.writer, "%s %s %s", prefix, event.Timestamp.Format("15:04:05"), event.Message)
		if len(event.Metadata) > 0 {
			fmt.Fprintf(s.writer, " %+v", event.Metadata)
		}
		fmt.Fprintln(s.writer)
		return
	}

	// Styled mode - pattern match on message content
	message := event.Message
	var styled string

	switch {
	case strings.Contains(message, "Banner captured:"):
		// Banner grab success - bright green with icon
		styled = bannerStyle.Render("  📋 " + message)

	case strings.Contains(message, "Host discovered:"):
		// Host discovery - green with icon
		styled = hostStyle.Render("  🔍 " + message)

	case strings.Contains(message, "Open port:"):
		// Port discovery - cyan with icon
		styled = portDiscoveryStyle.Render("  🔓 " + message)

	case strings.Contains(message, "Vulnerability found:"):
		// Vulnerability detection - severity-based styling with appropriate emoji
		lowerMsg := strings.ToLower(message)
		if strings.Contains(lowerMsg, "critical") {
			styled = vulnCriticalStyle.Render("  🚨 " + message)
		} else if strings.Contains(lowerMsg, "high") {
			styled = vulnHighStyle.Render("  ⚠️  " + message)
		} else if strings.Contains(lowerMsg, "medium") {
			styled = vulnMediumStyle.Render("  ⚡ " + message)
		} else {
			styled = vulnLowStyle.Render("  ℹ️  " + message)
		}

	case strings.Contains(message, "SSH service detected:"):
		// SSH service detection - purple with icon
		styled = sshServiceStyle.Render("  🔐 " + message)

	case strings.Contains(message, "HTTP service detected:"):
		// HTTP service detection - bright cyan with icon
		styled = httpServiceStyle.Render("  🌐 " + message)

	case strings.Contains(message, "Downloading ") || strings.Contains(message, "Installing "):
		// Plugin download/install in progress - blue with icon
		styled = pluginDownloadStyle.Render("  📦 " + message)

	case (strings.Contains(message, "Downloaded ") || strings.Contains(message, "Installed ")) && strings.Contains(message, "successfully"):
		// Plugin download/install success - green with icon
		styled = pluginSuccessStyle.Render("  ✓ " + message)

	case strings.Contains(message, "Skipped "):
		// Plugin skipped - yellow with icon
		styled = pluginSkipStyle.Render("  ⊘ " + message)

	case strings.Contains(message, "Failed to download ") || strings.Contains(message, "Failed to install "):
		// Plugin download/install failed - red with icon
		styled = pluginFailStyle.Render("  ✗ " + message)

	case strings.Contains(message, "Would download "):
		// Plugin dry run - blue with icon
		styled = pluginDownloadStyle.Render("  🔷 " + message)

	default:
		// Generic diagnostic - gray
		prefix := getLevelPrefix(event.Level)
		styled = diagStyle.Render(fmt.Sprintf("%s %s %s", prefix, event.Timestamp.Format("15:04:05"), message))
	}

	fmt.Fprintln(s.writer, styled)

	// Append metadata if present (dimmed)
	if len(event.Metadata) > 0 {
		metaStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
		fmt.Fprintln(s.writer, metaStyle.Render(fmt.Sprintf("    %+v", event.Metadata)))
	}
}

// getLevelPrefix returns the display prefix for a given output level.
func getLevelPrefix(level output.OutputLevel) string {
	switch level {
	case output.LevelVerbose:
		return "[VERBOSE]"
	case output.LevelDebug:
		return "[DEBUG]"
	case output.LevelTrace:
		return "[TRACE]"
	default:
		return "[INFO]"
	}
}
