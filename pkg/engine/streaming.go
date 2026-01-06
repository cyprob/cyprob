// Package engine provides streaming event capabilities for real-time scan result reporting.
// This enables per-target granularity instead of batch-level processing.
package engine

import (
	"context"
	"sync"
	"time"
)

// StreamEventType represents the type of streaming event.
type StreamEventType string

const (
	// EventTypeTargetStarted is emitted when a target (IP) begins scanning.
	EventTypeTargetStarted StreamEventType = "target.started"

	// EventTypeTargetCompleted is emitted when a target finishes scanning.
	EventTypeTargetCompleted StreamEventType = "target.completed"

	// EventTypePortOpen is emitted when an open port is discovered (real-time).
	EventTypePortOpen StreamEventType = "port.open"

	// EventTypeServiceDetected is emitted when a service is identified on a port.
	EventTypeServiceDetected StreamEventType = "service.detected"

	// EventTypeVulnFound is emitted when a vulnerability is discovered.
	EventTypeVulnFound StreamEventType = "vuln.found"
)

// StreamEvent represents a single streaming event during scan execution.
// Events are published in real-time as scan progress occurs.
type StreamEvent interface {
	// EventType returns the type of this event.
	EventType() StreamEventType

	// Timestamp returns when this event occurred.
	Timestamp() time.Time

	// Data returns the event-specific payload.
	Data() any
}

// TargetStartedEvent is emitted when a target (IP) begins scanning.
type TargetStartedEvent struct {
	TargetIP  string    // IP address being scanned
	Phase     string    // Scan phase (port_scan, vuln_scan, etc.)
	timestamp time.Time // When scanning started
}

func (e *TargetStartedEvent) EventType() StreamEventType { return EventTypeTargetStarted }
func (e *TargetStartedEvent) Timestamp() time.Time       { return e.timestamp }
func (e *TargetStartedEvent) Data() any                  { return e }

// NewTargetStartedEvent creates a new target started event.
func NewTargetStartedEvent(targetIP, phase string) *TargetStartedEvent {
	return &TargetStartedEvent{
		TargetIP:  targetIP,
		Phase:     phase,
		timestamp: time.Now(),
	}
}

// TargetCompletedEvent is emitted when a target finishes scanning.
// This is the primary event for per-IP streaming.
type TargetCompletedEvent struct {
	TargetIP  string        // IP address that completed
	Phase     string        // Scan phase that completed
	OpenPorts []int         // List of open ports found
	Duration  time.Duration // How long this target took
	timestamp time.Time     // When target completed
}

func (e *TargetCompletedEvent) EventType() StreamEventType { return EventTypeTargetCompleted }
func (e *TargetCompletedEvent) Timestamp() time.Time       { return e.timestamp }
func (e *TargetCompletedEvent) Data() any                  { return e }

// NewTargetCompletedEvent creates a new target completed event.
func NewTargetCompletedEvent(targetIP, phase string, openPorts []int, duration time.Duration) *TargetCompletedEvent {
	return &TargetCompletedEvent{
		TargetIP:  targetIP,
		Phase:     phase,
		OpenPorts: openPorts,
		Duration:  duration,
		timestamp: time.Now(),
	}
}

// PortOpenEvent is emitted when an open port is discovered (real-time, during scan).
type PortOpenEvent struct {
	TargetIP  string    // IP address
	Port      int       // Port number
	Protocol  string    // tcp or udp
	timestamp time.Time // When port was discovered
}

func (e *PortOpenEvent) EventType() StreamEventType { return EventTypePortOpen }
func (e *PortOpenEvent) Timestamp() time.Time       { return e.timestamp }
func (e *PortOpenEvent) Data() any                  { return e }

// NewPortOpenEvent creates a new port open event.
func NewPortOpenEvent(targetIP string, port int, protocol string) *PortOpenEvent {
	return &PortOpenEvent{
		TargetIP:  targetIP,
		Port:      port,
		Protocol:  protocol,
		timestamp: time.Now(),
	}
}

// ServiceDetectedEvent is emitted when a service is identified on a port.
type ServiceDetectedEvent struct {
	TargetIP    string    // IP address
	Port        int       // Port number
	ServiceName string    // Detected service (e.g., "http", "ssh")
	Version     string    // Version string (optional)
	Banner      string    // Service banner (optional)
	timestamp   time.Time // When service was detected
}

func (e *ServiceDetectedEvent) EventType() StreamEventType { return EventTypeServiceDetected }
func (e *ServiceDetectedEvent) Timestamp() time.Time       { return e.timestamp }
func (e *ServiceDetectedEvent) Data() any                  { return e }

// NewServiceDetectedEvent creates a new service detected event.
func NewServiceDetectedEvent(targetIP string, port int, serviceName, version, banner string) *ServiceDetectedEvent {
	return &ServiceDetectedEvent{
		TargetIP:    targetIP,
		Port:        port,
		ServiceName: serviceName,
		Version:     version,
		Banner:      banner,
		timestamp:   time.Now(),
	}
}

// VulnFoundEvent is emitted when a vulnerability is discovered.
type VulnFoundEvent struct {
	TargetIP   string    // IP address
	VulnID     string    // Vulnerability identifier (CVE, plugin ID, etc.)
	Severity   string    // Severity level (critical, high, medium, low)
	Port       int       // Affected port (0 if host-level)
	PluginName string    // Plugin that detected the vulnerability
	timestamp  time.Time // When vulnerability was found
}

func (e *VulnFoundEvent) EventType() StreamEventType { return EventTypeVulnFound }
func (e *VulnFoundEvent) Timestamp() time.Time       { return e.timestamp }
func (e *VulnFoundEvent) Data() any                  { return e }

// NewVulnFoundEvent creates a new vulnerability found event.
func NewVulnFoundEvent(targetIP, vulnID, severity string, port int, pluginName string) *VulnFoundEvent {
	return &VulnFoundEvent{
		TargetIP:   targetIP,
		VulnID:     vulnID,
		Severity:   severity,
		Port:       port,
		PluginName: pluginName,
		timestamp:  time.Now(),
	}
}

// StreamHandler handles streaming events.
// Implementations receive events as they occur during scan execution.
type StreamHandler interface {
	// OnEvent is called when a streaming event occurs.
	// Implementations MUST NOT block - perform async processing if needed.
	OnEvent(ctx context.Context, event StreamEvent) error
}

// StreamPublisher publishes streaming events to registered handlers.
// This is the core component for real-time event distribution.
type StreamPublisher struct {
	handlers []StreamHandler
	mu       sync.RWMutex
}

// NewStreamPublisher creates a new stream publisher.
func NewStreamPublisher() *StreamPublisher {
	return &StreamPublisher{
		handlers: make([]StreamHandler, 0),
	}
}

// Subscribe registers a handler to receive streaming events.
// Handlers are called in the order they were registered.
func (p *StreamPublisher) Subscribe(handler StreamHandler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handlers = append(p.handlers, handler)
}

// Publish emits an event to all registered handlers.
// Events are published asynchronously to prevent blocking scan execution.
func (p *StreamPublisher) Publish(ctx context.Context, event StreamEvent) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Publish to all handlers in parallel (non-blocking)
	for _, handler := range p.handlers {
		go func(h StreamHandler) {
			// Ignore handler errors - streaming is best-effort
			_ = h.OnEvent(ctx, event)
		}(handler)
	}
}

// Context injection keys for StreamPublisher.
// This allows passing the publisher through context to scan modules.

type streamPublisherKeyType struct{}

var streamPublisherKey = streamPublisherKeyType{}

// WithStreamPublisher injects a StreamPublisher into the context.
// Use this when initializing scan execution to enable streaming.
//
// Example:
//
//	publisher := engine.NewStreamPublisher()
//	publisher.Subscribe(myHandler)
//	ctx = engine.WithStreamPublisher(ctx, publisher)
//	discovery.TCPPortDiscovery(ctx, targets, ports) // Will emit events
func WithStreamPublisher(ctx context.Context, publisher *StreamPublisher) context.Context {
	return context.WithValue(ctx, streamPublisherKey, publisher)
}

// GetStreamPublisher retrieves the StreamPublisher from context.
// Returns nil if no publisher was injected.
func GetStreamPublisher(ctx context.Context) *StreamPublisher {
	if pub, ok := ctx.Value(streamPublisherKey).(*StreamPublisher); ok {
		return pub
	}
	return nil
}

// PublishEvent is a convenience function to publish an event using the context's publisher.
// If no publisher exists in context, this is a no-op (streaming disabled).
//
// Example:
//
//	engine.PublishEvent(ctx, engine.NewPortOpenEvent("192.168.1.1", 443, "tcp"))
func PublishEvent(ctx context.Context, event StreamEvent) {
	if pub := GetStreamPublisher(ctx); pub != nil {
		pub.Publish(ctx, event)
	}
}
