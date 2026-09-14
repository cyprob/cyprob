// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package output

import "sync"

// OutputSubscriber handles output events.
// Subscribers implement rendering logic for different output formats
// (human-friendly tables, JSON, TUI, diagnostic logs, etc.).
type OutputSubscriber interface {
	// Handle processes an output event.
	// Called synchronously by OutputEventStream.Emit().
	Handle(event OutputEvent)

	// Name returns a unique identifier for this subscriber.
	// Used for debugging and logging.
	Name() string

	// ShouldHandle decides if this subscriber cares about this event.
	// Allows subscribers to filter events (e.g., DiagnosticSubscriber
	// only handles EventDiag, HumanFormatter ignores EventDiag).
	ShouldHandle(event OutputEvent) bool
}

// OutputEventStream is a minimal, synchronous event dispatcher.
// It maintains a list of subscribers and notifies them when events are emitted.
//
// Design Principles:
// - Domain-scoped (not a global event bus)
// - Synchronous dispatch (maintains stdout ordering for CLI)
// - Thread-safe subscriber management
// - Minimal abstraction (no channels, no buffering, no async)
type OutputEventStream struct {
	subscribers []OutputSubscriber
	mu          sync.RWMutex
}

// NewOutputEventStream creates a new event stream with no subscribers.
func NewOutputEventStream() *OutputEventStream {
	return &OutputEventStream{
		subscribers: make([]OutputSubscriber, 0, 4), // Pre-allocate for typical use cases
	}
}

// Subscribe registers a new subscriber to receive events.
// Subscribers are called in registration order.
// Thread-safe.
func (s *OutputEventStream) Subscribe(sub OutputSubscriber) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscribers = append(s.subscribers, sub)
}

// Emit dispatches an event to all registered subscribers.
// Calls each subscriber's Handle() method synchronously if ShouldHandle() returns true.
// Thread-safe for concurrent emissions.
func (s *OutputEventStream) Emit(event OutputEvent) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, sub := range s.subscribers {
		if sub.ShouldHandle(event) {
			sub.Handle(event)
		}
	}
}

// SubscriberCount returns the number of registered subscribers.
// Useful for testing and debugging.
func (s *OutputEventStream) SubscriberCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.subscribers)
}
