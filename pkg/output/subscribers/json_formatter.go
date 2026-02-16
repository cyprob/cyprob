// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package subscribers

import (
	"encoding/json"
	"io"
	"time"

	"github.com/cyprob/cyprob/pkg/output"
)

// JSONFormatter emits structured JSON output (when --json flag is present).
// Both CE and EE use this subscriber when --json is specified.
//
// Output format: One JSON object per line (JSON Lines format).
type JSONFormatter struct {
	encoder *json.Encoder
}

// NewJSONFormatter creates a new JSONFormatter subscriber.
func NewJSONFormatter(writer io.Writer) *JSONFormatter {
	encoder := json.NewEncoder(writer)
	// No indentation - use compact JSON Lines format (one JSON object per line)
	return &JSONFormatter{
		encoder: encoder,
	}
}

// Name returns the subscriber identifier.
func (s *JSONFormatter) Name() string {
	return "json-formatter"
}

// ShouldHandle decides if this subscriber cares about the event.
// JSONFormatter handles everything EXCEPT diagnostic events.
func (s *JSONFormatter) ShouldHandle(event output.OutputEvent) bool {
	// Diagnostic events are handled by DiagnosticSubscriber
	return event.Type != output.EventDiag
}

// Handle processes an output event and renders it as JSON.
func (s *JSONFormatter) Handle(event output.OutputEvent) {
	// Convert event to JSON-friendly structure
	jsonEvent := map[string]any{
		"type":      event.Type,
		"timestamp": event.Timestamp.Format(time.RFC3339),
	}

	// Add message if present
	if event.Message != "" {
		jsonEvent["message"] = event.Message
	}

	// Add data if present
	if event.Data != nil {
		jsonEvent["data"] = event.Data
	}

	// Add metadata if present (for future use)
	if len(event.Metadata) > 0 {
		jsonEvent["metadata"] = event.Metadata
	}

	// Encode and write
	// Error is checked but ignored as per OutputSubscriber contract (cannot propagate errors)
	if err := s.encoder.Encode(jsonEvent); err != nil {
		// Silently drop event on encoding errors (e.g., broken pipe)
		return
	}
}
