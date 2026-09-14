// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package output

import "time"

// DefaultOutput is the standard implementation of the Output interface.
// It converts method calls into OutputEvent structs and emits them to the stream.
type DefaultOutput struct {
	stream *OutputEventStream
}

// NewDefaultOutput creates a new DefaultOutput that emits events to the given stream.
func NewDefaultOutput(stream *OutputEventStream) *DefaultOutput {
	return &DefaultOutput{
		stream: stream,
	}
}

// Info emits a general information message (always visible).
func (o *DefaultOutput) Info(message string) {
	o.stream.Emit(OutputEvent{
		Type:      EventInfo,
		Level:     LevelNormal,
		Message:   message,
		Timestamp: time.Now(),
	})
}

// Error emits an error message.
func (o *DefaultOutput) Error(err error) {
	o.stream.Emit(OutputEvent{
		Type:      EventError,
		Level:     LevelNormal,
		Message:   err.Error(),
		Timestamp: time.Now(),
	})
}

// Warning emits a warning message.
func (o *DefaultOutput) Warning(message string) {
	o.stream.Emit(OutputEvent{
		Type:      EventWarning,
		Level:     LevelNormal,
		Message:   message,
		Timestamp: time.Now(),
	})
}

// Table emits tabular data with headers and rows.
func (o *DefaultOutput) Table(headers []string, rows [][]string) {
	o.stream.Emit(OutputEvent{
		Type:  EventTable,
		Level: LevelNormal,
		Data: map[string]any{
			"headers": headers,
			"rows":    rows,
		},
		Timestamp: time.Now(),
	})
}

// Progress emits a progress update.
func (o *DefaultOutput) Progress(current, total int, message string) {
	o.stream.Emit(OutputEvent{
		Type:    EventProgress,
		Level:   LevelNormal,
		Message: message,
		Data: map[string]any{
			"current": current,
			"total":   total,
		},
		Timestamp: time.Now(),
	})
}

// Diag emits diagnostic information (only visible with -v/-vv/-vvv).
func (o *DefaultOutput) Diag(level OutputLevel, message string, metadata map[string]any) {
	o.stream.Emit(OutputEvent{
		Type:      EventDiag,
		Level:     level,
		Message:   message,
		Metadata:  metadata,
		Timestamp: time.Now(),
	})
}
