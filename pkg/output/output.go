// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package output

import "time"

// contextKey is a type for context keys to avoid collisions
type contextKey string

// OutputKey is the context key for Output interface
const OutputKey contextKey = "output"

// OutputEventType defines the type of output event.
type OutputEventType string

const (
	// EventInfo represents a general information message (always visible)
	EventInfo OutputEventType = "info"

	// EventError represents an error message
	EventError OutputEventType = "error"

	// EventWarning represents a warning message
	EventWarning OutputEventType = "warning"

	// EventTable represents tabular data output
	EventTable OutputEventType = "table"

	// EventProgress represents a progress update
	EventProgress OutputEventType = "progress"

	// EventDiag represents diagnostic information (only visible with -v/-vv/-vvv)
	EventDiag OutputEventType = "diag"
)

// OutputLevel defines the verbosity level for diagnostic messages.
type OutputLevel int

const (
	// LevelNormal is the default level (always shown)
	LevelNormal OutputLevel = 0

	// LevelVerbose is shown with -v flag
	LevelVerbose OutputLevel = 1

	// LevelDebug is shown with -vv flag
	LevelDebug OutputLevel = 2

	// LevelTrace is shown with -vvv flag
	LevelTrace OutputLevel = 3
)

// OutputEvent represents a single output event emitted by business logic.
type OutputEvent struct {
	// Type identifies the event category (info, error, table, etc.)
	Type OutputEventType

	// Level specifies verbosity level (only used for EventDiag)
	Level OutputLevel

	// Message is the primary text content
	Message string

	// Data contains structured data (e.g., table headers/rows, progress values)
	Data any

	// Metadata holds additional key-value pairs for diagnostic events
	Metadata map[string]any

	// Timestamp records when the event was created
	Timestamp time.Time
}

// Output is the primary interface for business logic to emit output events.
// Business logic code uses this interface without knowing about the underlying
// rendering format (human-friendly, JSON, TUI, etc.).
type Output interface {
	// Info emits a general information message (always visible).
	// Example: out.Info("Starting vulnerability scan...")
	Info(message string)

	// Error emits an error message.
	// Example: out.Error(fmt.Errorf("failed to connect to host"))
	Error(err error)

	// Warning emits a warning message.
	// Example: out.Warning("Plugin signature could not be verified")
	Warning(message string)

	// Table emits tabular data with headers and rows.
	// Example: out.Table([]string{"Host", "Port"}, [][]string{{"192.168.1.1", "22"}})
	Table(headers []string, rows [][]string)

	// Progress emits a progress update.
	// Example: out.Progress(50, 100, "Scanning port 80/tcp")
	Progress(current, total int, message string)

	// Diag emits diagnostic information (only visible with -v/-vv/-vvv).
	// Example: out.Diag(LevelVerbose, "Cache hit", map[string]interface{}{"key": "abc"})
	Diag(level OutputLevel, message string, metadata map[string]any)
}
