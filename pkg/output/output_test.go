// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/output"
	"github.com/cyprob/cyprob/pkg/output/subscribers"
)

// MockSubscriber is a test subscriber that records all events
type MockSubscriber struct {
	events []output.OutputEvent
	name   string
}

func NewMockSubscriber(name string) *MockSubscriber {
	return &MockSubscriber{
		events: make([]output.OutputEvent, 0),
		name:   name,
	}
}

func (m *MockSubscriber) Name() string {
	return m.name
}

func (m *MockSubscriber) ShouldHandle(event output.OutputEvent) bool {
	return true // Handle all events for testing
}

func (m *MockSubscriber) Handle(event output.OutputEvent) {
	m.events = append(m.events, event)
}

// TestOutputEventStream tests the OutputEventStream implementation
func TestOutputEventStream(t *testing.T) {
	t.Run("Subscribe and Emit", func(t *testing.T) {
		stream := output.NewOutputEventStream()
		mock := NewMockSubscriber("test")

		stream.Subscribe(mock)
		require.Equal(t, 1, stream.SubscriberCount())

		event := output.OutputEvent{
			Type:      output.EventInfo,
			Message:   "test message",
			Timestamp: time.Now(),
		}

		stream.Emit(event)

		require.Len(t, mock.events, 1)
		require.Equal(t, output.EventInfo, mock.events[0].Type)
		require.Equal(t, "test message", mock.events[0].Message)
	})

	t.Run("Multiple Subscribers", func(t *testing.T) {
		stream := output.NewOutputEventStream()
		mock1 := NewMockSubscriber("sub1")
		mock2 := NewMockSubscriber("sub2")

		stream.Subscribe(mock1)
		stream.Subscribe(mock2)
		require.Equal(t, 2, stream.SubscriberCount())

		event := output.OutputEvent{
			Type:      output.EventError,
			Message:   "error message",
			Timestamp: time.Now(),
		}

		stream.Emit(event)

		require.Len(t, mock1.events, 1)
		require.Len(t, mock2.events, 1)
		require.Equal(t, output.EventError, mock1.events[0].Type)
		require.Equal(t, output.EventError, mock2.events[0].Type)
	})
}

// TestDefaultOutput tests the DefaultOutput implementation
func TestDefaultOutput(t *testing.T) {
	t.Run("Info", func(t *testing.T) {
		stream := output.NewOutputEventStream()
		mock := NewMockSubscriber("test")
		stream.Subscribe(mock)

		out := output.NewDefaultOutput(stream)
		out.Info("test info")

		require.Len(t, mock.events, 1)
		require.Equal(t, output.EventInfo, mock.events[0].Type)
		require.Equal(t, "test info", mock.events[0].Message)
	})

	t.Run("Error", func(t *testing.T) {
		stream := output.NewOutputEventStream()
		mock := NewMockSubscriber("test")
		stream.Subscribe(mock)

		out := output.NewDefaultOutput(stream)
		out.Error(bytes.ErrTooLarge)

		require.Len(t, mock.events, 1)
		require.Equal(t, output.EventError, mock.events[0].Type)
		require.Contains(t, mock.events[0].Message, "too large")
	})

	t.Run("Warning", func(t *testing.T) {
		stream := output.NewOutputEventStream()
		mock := NewMockSubscriber("test")
		stream.Subscribe(mock)

		out := output.NewDefaultOutput(stream)
		out.Warning("test warning")

		require.Len(t, mock.events, 1)
		require.Equal(t, output.EventWarning, mock.events[0].Type)
		require.Equal(t, "test warning", mock.events[0].Message)
	})

	t.Run("Table", func(t *testing.T) {
		stream := output.NewOutputEventStream()
		mock := NewMockSubscriber("test")
		stream.Subscribe(mock)

		out := output.NewDefaultOutput(stream)
		headers := []string{"Host", "Port"}
		rows := [][]string{{"192.168.1.1", "22"}}
		out.Table(headers, rows)

		require.Len(t, mock.events, 1)
		require.Equal(t, output.EventTable, mock.events[0].Type)

		data, ok := mock.events[0].Data.(map[string]any)
		require.True(t, ok)
		require.Equal(t, headers, data["headers"])
		require.Equal(t, rows, data["rows"])
	})

	t.Run("Progress", func(t *testing.T) {
		stream := output.NewOutputEventStream()
		mock := NewMockSubscriber("test")
		stream.Subscribe(mock)

		out := output.NewDefaultOutput(stream)
		out.Progress(50, 100, "scanning")

		require.Len(t, mock.events, 1)
		require.Equal(t, output.EventProgress, mock.events[0].Type)
		require.Equal(t, "scanning", mock.events[0].Message)

		data, ok := mock.events[0].Data.(map[string]any)
		require.True(t, ok)
		require.Equal(t, 50, data["current"])
		require.Equal(t, 100, data["total"])
	})

	t.Run("Diag", func(t *testing.T) {
		stream := output.NewOutputEventStream()
		mock := NewMockSubscriber("test")
		stream.Subscribe(mock)

		out := output.NewDefaultOutput(stream)
		metadata := map[string]any{"key": "value"}
		out.Diag(output.LevelVerbose, "debug message", metadata)

		require.Len(t, mock.events, 1)
		require.Equal(t, output.EventDiag, mock.events[0].Type)
		require.Equal(t, output.LevelVerbose, mock.events[0].Level)
		require.Equal(t, "debug message", mock.events[0].Message)
		require.Equal(t, metadata, mock.events[0].Metadata)
	})
}

// TestJSONFormatter tests the JSONFormatter subscriber
func TestJSONFormatter(t *testing.T) {
	t.Run("Info Event", func(t *testing.T) {
		buf := &bytes.Buffer{}
		formatter := subscribers.NewJSONFormatter(buf)

		require.Equal(t, "json-formatter", formatter.Name())

		event := output.OutputEvent{
			Type:      output.EventInfo,
			Message:   "test message",
			Timestamp: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
		}

		require.True(t, formatter.ShouldHandle(event))
		formatter.Handle(event)

		var result map[string]any
		err := json.Unmarshal(buf.Bytes(), &result)
		require.NoError(t, err)

		require.Equal(t, "info", result["type"])
		require.Equal(t, "test message", result["message"])
		require.Equal(t, "2025-01-01T12:00:00Z", result["timestamp"])
	})

	t.Run("Diagnostic Event Should Not Handle", func(t *testing.T) {
		buf := &bytes.Buffer{}
		formatter := subscribers.NewJSONFormatter(buf)

		event := output.OutputEvent{
			Type:  output.EventDiag,
			Level: output.LevelVerbose,
		}

		require.False(t, formatter.ShouldHandle(event))
	})
}

// TestDiagnosticSubscriber tests the DiagnosticSubscriber
func TestDiagnosticSubscriber(t *testing.T) {
	t.Run("Verbose Level", func(t *testing.T) {
		buf := &bytes.Buffer{}
		subscriber := subscribers.NewDiagnosticSubscriber(output.LevelVerbose, buf)

		require.Equal(t, "diagnostic-subscriber", subscriber.Name())

		event := output.OutputEvent{
			Type:      output.EventDiag,
			Level:     output.LevelVerbose,
			Message:   "verbose message",
			Timestamp: time.Date(2025, 1, 1, 12, 30, 45, 0, time.UTC),
		}

		require.True(t, subscriber.ShouldHandle(event))
		subscriber.Handle(event)

		output := buf.String()
		require.Contains(t, output, "[VERBOSE]")
		require.Contains(t, output, "12:30:45")
		require.Contains(t, output, "verbose message")
	})

	t.Run("Level Filtering", func(t *testing.T) {
		buf := &bytes.Buffer{}
		subscriber := subscribers.NewDiagnosticSubscriber(output.LevelVerbose, buf)

		// Verbose level should handle verbose events
		verboseEvent := output.OutputEvent{
			Type:  output.EventDiag,
			Level: output.LevelVerbose,
		}
		require.True(t, subscriber.ShouldHandle(verboseEvent))

		// Verbose level should NOT handle debug events
		debugEvent := output.OutputEvent{
			Type:  output.EventDiag,
			Level: output.LevelDebug,
		}
		require.False(t, subscriber.ShouldHandle(debugEvent))

		// Should NOT handle non-diagnostic events
		infoEvent := output.OutputEvent{
			Type: output.EventInfo,
		}
		require.False(t, subscriber.ShouldHandle(infoEvent))
	})

	t.Run("Metadata Output", func(t *testing.T) {
		buf := &bytes.Buffer{}
		subscriber := subscribers.NewDiagnosticSubscriber(output.LevelDebug, buf)

		event := output.OutputEvent{
			Type:      output.EventDiag,
			Level:     output.LevelDebug,
			Message:   "debug message",
			Timestamp: time.Now(),
			Metadata: map[string]any{
				"plugin": "ssh-banner",
				"count":  42,
			},
		}

		subscriber.Handle(event)

		output := buf.String()
		require.Contains(t, output, "[DEBUG]")
		require.Contains(t, output, "debug message")
		require.Contains(t, output, "plugin:ssh-banner")
		require.Contains(t, output, "count:42")
	})
}

// TestHumanFormatter tests the HumanFormatter subscriber
func TestHumanFormatter(t *testing.T) {
	t.Run("Info Message", func(t *testing.T) {
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		humanFormatter := subscribers.NewHumanFormatter(stdout, stderr, false)

		require.Equal(t, "human-formatter", humanFormatter.Name())

		event := output.OutputEvent{
			Type:    output.EventInfo,
			Message: "test info",
		}

		require.True(t, humanFormatter.ShouldHandle(event))
		humanFormatter.Handle(event)

		require.Contains(t, stdout.String(), "test info")
	})

	t.Run("Error Message", func(t *testing.T) {
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		humanFormatter := subscribers.NewHumanFormatter(stdout, stderr, false)

		event := output.OutputEvent{
			Type:    output.EventError,
			Message: "test error",
		}

		humanFormatter.Handle(event)

		require.Contains(t, stderr.String(), "Error: test error")
	})

	t.Run("Warning Message", func(t *testing.T) {
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		humanFormatter := subscribers.NewHumanFormatter(stdout, stderr, false)

		event := output.OutputEvent{
			Type:    output.EventWarning,
			Message: "test warning",
		}

		humanFormatter.Handle(event)

		require.Contains(t, stdout.String(), "Warning: test warning")
	})

	t.Run("Table Output", func(t *testing.T) {
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		humanFormatter := subscribers.NewHumanFormatter(stdout, stderr, false)

		headers := []string{"Host", "Port"}
		rows := [][]string{{"192.168.1.1", "22"}}

		event := output.OutputEvent{
			Type: output.EventTable,
			Data: map[string]any{
				"headers": headers,
				"rows":    rows,
			},
		}

		humanFormatter.Handle(event)

		output := stdout.String()
		require.Contains(t, output, "Host")
		require.Contains(t, output, "Port")
		require.Contains(t, output, "192.168.1.1")
		require.Contains(t, output, "22")
	})

	t.Run("Diagnostic Events Should Not Handle", func(t *testing.T) {
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		humanFormatter := subscribers.NewHumanFormatter(stdout, stderr, false)

		event := output.OutputEvent{
			Type:  output.EventDiag,
			Level: output.LevelVerbose,
		}

		require.False(t, humanFormatter.ShouldHandle(event))
	})
}

// TestIntegration tests the complete output pipeline integration
func TestIntegration(t *testing.T) {
	t.Run("Human Mode with Diagnostics", func(t *testing.T) {
		// Setup: stdout for human, stderr for diagnostics
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}

		stream := output.NewOutputEventStream()

		// Human formatter
		stream.Subscribe(subscribers.NewHumanFormatter(stdout, stderr, false))

		// Diagnostic subscriber (verbose level)
		stream.Subscribe(subscribers.NewDiagnosticSubscriber(output.LevelVerbose, stderr))

		// Create output
		out := output.NewDefaultOutput(stream)

		// Emit events
		out.Info("Starting scan")
		out.Diag(output.LevelVerbose, "Loading plugins", map[string]any{"count": 15})
		out.Table([]string{"Host", "Port"}, [][]string{{"192.168.1.1", "22"}})

		// Verify human output
		humanOutput := stdout.String()
		require.Contains(t, humanOutput, "Starting scan")
		require.Contains(t, humanOutput, "Host")
		require.Contains(t, humanOutput, "192.168.1.1")

		// Verify diagnostic output
		diagOutput := stderr.String()
		require.Contains(t, diagOutput, "[VERBOSE]")
		require.Contains(t, diagOutput, "Loading plugins")
		require.Contains(t, diagOutput, "count:15")
	})

	t.Run("JSON Mode with Diagnostics", func(t *testing.T) {
		// Setup: stdout for JSON, stderr for diagnostics
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}

		stream := output.NewOutputEventStream()

		// JSON formatter
		stream.Subscribe(subscribers.NewJSONFormatter(stdout))

		// Diagnostic subscriber (debug level)
		stream.Subscribe(subscribers.NewDiagnosticSubscriber(output.LevelDebug, stderr))

		// Create output
		out := output.NewDefaultOutput(stream)

		// Emit events
		out.Info("Starting scan")
		out.Diag(output.LevelVerbose, "Cache hit", nil)
		out.Diag(output.LevelDebug, "Memory usage", map[string]any{"mb": 42})

		// Verify JSON output
		jsonLines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
		require.Len(t, jsonLines, 1) // Only info event (diagnostics not in JSON)

		var infoEvent map[string]any
		err := json.Unmarshal([]byte(jsonLines[0]), &infoEvent)
		require.NoError(t, err)
		require.Equal(t, "info", infoEvent["type"])
		require.Equal(t, "Starting scan", infoEvent["message"])

		// Verify diagnostic output
		diagOutput := stderr.String()
		require.Contains(t, diagOutput, "[VERBOSE]")
		require.Contains(t, diagOutput, "[DEBUG]")
		require.Contains(t, diagOutput, "Cache hit")
		require.Contains(t, diagOutput, "Memory usage")
	})
}
