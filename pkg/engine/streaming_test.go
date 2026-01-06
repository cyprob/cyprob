package engine

import (
	"context"
	"sync"
	"testing"
	"time"
)

// MockStreamHandler is a test handler that records events.
type MockStreamHandler struct {
	events []StreamEvent
	mu     sync.Mutex
}

func (h *MockStreamHandler) OnEvent(ctx context.Context, event StreamEvent) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, event)
	return nil
}

func (h *MockStreamHandler) GetEvents() []StreamEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	eventsCopy := make([]StreamEvent, len(h.events))
	copy(eventsCopy, h.events)
	return eventsCopy
}

func (h *MockStreamHandler) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.events)
}

func (h *MockStreamHandler) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = nil
}

// TestStreamPublisherSubscribe tests handler registration.
func TestStreamPublisherSubscribe(t *testing.T) {
	publisher := NewStreamPublisher()
	handler := &MockStreamHandler{}

	publisher.Subscribe(handler)

	// Publish event
	ctx := context.Background()
	event := NewTargetStartedEvent("192.168.1.1", "port_scan")
	publisher.Publish(ctx, event)

	// Allow async processing
	time.Sleep(10 * time.Millisecond)

	if handler.Count() != 1 {
		t.Errorf("Expected 1 event, got %d", handler.Count())
	}
}

// TestStreamPublisherMultipleHandlers tests multiple handlers receive events.
func TestStreamPublisherMultipleHandlers(t *testing.T) {
	publisher := NewStreamPublisher()
	handler1 := &MockStreamHandler{}
	handler2 := &MockStreamHandler{}

	publisher.Subscribe(handler1)
	publisher.Subscribe(handler2)

	ctx := context.Background()
	event := NewPortOpenEvent("192.168.1.1", 443, "tcp")
	publisher.Publish(ctx, event)

	// Allow async processing
	time.Sleep(10 * time.Millisecond)

	if handler1.Count() != 1 {
		t.Errorf("Handler1: Expected 1 event, got %d", handler1.Count())
	}
	if handler2.Count() != 1 {
		t.Errorf("Handler2: Expected 1 event, got %d", handler2.Count())
	}
}

// TestStreamPublisherNoHandlers tests publishing with no handlers (no panic).
func TestStreamPublisherNoHandlers(t *testing.T) {
	publisher := NewStreamPublisher()
	ctx := context.Background()
	event := NewTargetCompletedEvent("192.168.1.1", "port_scan", []int{80, 443}, 5*time.Second)

	// Should not panic
	publisher.Publish(ctx, event)
}

// TestTargetStartedEvent tests TargetStartedEvent creation and properties.
func TestTargetStartedEvent(t *testing.T) {
	event := NewTargetStartedEvent("10.0.0.1", "vuln_scan")

	if event.EventType() != EventTypeTargetStarted {
		t.Errorf("Expected EventTypeTargetStarted, got %v", event.EventType())
	}

	if event.TargetIP != "10.0.0.1" {
		t.Errorf("Expected IP 10.0.0.1, got %s", event.TargetIP)
	}

	if event.Phase != "vuln_scan" {
		t.Errorf("Expected phase vuln_scan, got %s", event.Phase)
	}

	if event.Timestamp().IsZero() {
		t.Error("Timestamp should not be zero")
	}

	if event.Data() != event {
		t.Error("Data() should return self")
	}
}

// TestTargetCompletedEvent tests TargetCompletedEvent creation.
func TestTargetCompletedEvent(t *testing.T) {
	openPorts := []int{22, 80, 443}
	duration := 3 * time.Second
	event := NewTargetCompletedEvent("192.168.1.100", "port_scan", openPorts, duration)

	if event.EventType() != EventTypeTargetCompleted {
		t.Errorf("Expected EventTypeTargetCompleted, got %v", event.EventType())
	}

	if event.TargetIP != "192.168.1.100" {
		t.Errorf("Expected IP 192.168.1.100, got %s", event.TargetIP)
	}

	if len(event.OpenPorts) != 3 {
		t.Errorf("Expected 3 open ports, got %d", len(event.OpenPorts))
	}

	if event.Duration != duration {
		t.Errorf("Expected duration %v, got %v", duration, event.Duration)
	}
}

// TestPortOpenEvent tests PortOpenEvent creation.
func TestPortOpenEvent(t *testing.T) {
	event := NewPortOpenEvent("172.16.0.50", 8080, "tcp")

	if event.EventType() != EventTypePortOpen {
		t.Errorf("Expected EventTypePortOpen, got %v", event.EventType())
	}

	if event.TargetIP != "172.16.0.50" {
		t.Errorf("Expected IP 172.16.0.50, got %s", event.TargetIP)
	}

	if event.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", event.Port)
	}

	if event.Protocol != "tcp" {
		t.Errorf("Expected protocol tcp, got %s", event.Protocol)
	}
}

// TestServiceDetectedEvent tests ServiceDetectedEvent creation.
func TestServiceDetectedEvent(t *testing.T) {
	event := NewServiceDetectedEvent("10.10.10.10", 443, "https", "nginx/1.18.0", "Server: nginx")

	if event.EventType() != EventTypeServiceDetected {
		t.Errorf("Expected EventTypeServiceDetected, got %v", event.EventType())
	}

	if event.ServiceName != "https" {
		t.Errorf("Expected service https, got %s", event.ServiceName)
	}

	if event.Version != "nginx/1.18.0" {
		t.Errorf("Expected version nginx/1.18.0, got %s", event.Version)
	}

	if event.Banner != "Server: nginx" {
		t.Errorf("Expected banner 'Server: nginx', got %s", event.Banner)
	}
}

// TestVulnFoundEvent tests VulnFoundEvent creation.
func TestVulnFoundEvent(t *testing.T) {
	event := NewVulnFoundEvent("192.168.1.1", "CVE-2024-1234", "critical", 443, "ssl-heartbleed")

	if event.EventType() != EventTypeVulnFound {
		t.Errorf("Expected EventTypeVulnFound, got %v", event.EventType())
	}

	if event.VulnID != "CVE-2024-1234" {
		t.Errorf("Expected vuln ID CVE-2024-1234, got %s", event.VulnID)
	}

	if event.Severity != "critical" {
		t.Errorf("Expected severity critical, got %s", event.Severity)
	}

	if event.Port != 443 {
		t.Errorf("Expected port 443, got %d", event.Port)
	}

	if event.PluginName != "ssl-heartbleed" {
		t.Errorf("Expected plugin ssl-heartbleed, got %s", event.PluginName)
	}
}

// TestContextInjection tests WithStreamPublisher and GetStreamPublisher.
func TestContextInjection(t *testing.T) {
	publisher := NewStreamPublisher()
	ctx := WithStreamPublisher(context.Background(), publisher)

	retrievedPublisher := GetStreamPublisher(ctx)
	if retrievedPublisher != publisher {
		t.Error("Retrieved publisher should be the same instance")
	}
}

// TestContextInjectionNil tests GetStreamPublisher with no publisher in context.
func TestContextInjectionNil(t *testing.T) {
	ctx := context.Background()
	retrievedPublisher := GetStreamPublisher(ctx)

	if retrievedPublisher != nil {
		t.Error("Expected nil publisher when not injected")
	}
}

// TestPublishEventWithContext tests PublishEvent convenience function.
func TestPublishEventWithContext(t *testing.T) {
	publisher := NewStreamPublisher()
	handler := &MockStreamHandler{}
	publisher.Subscribe(handler)

	ctx := WithStreamPublisher(context.Background(), publisher)
	event := NewTargetStartedEvent("10.0.0.1", "port_scan")

	PublishEvent(ctx, event)

	// Allow async processing
	time.Sleep(10 * time.Millisecond)

	if handler.Count() != 1 {
		t.Errorf("Expected 1 event, got %d", handler.Count())
	}
}

// TestPublishEventNoPublisherInContext tests PublishEvent with no publisher (no-op).
func TestPublishEventNoPublisherInContext(t *testing.T) {
	ctx := context.Background()
	event := NewTargetCompletedEvent("192.168.1.1", "port_scan", []int{}, 1*time.Second)

	// Should not panic
	PublishEvent(ctx, event)
}

// TestConcurrentPublish tests concurrent event publishing (thread safety).
func TestConcurrentPublish(t *testing.T) {
	publisher := NewStreamPublisher()
	handler := &MockStreamHandler{}
	publisher.Subscribe(handler)

	ctx := context.Background()
	eventCount := 100

	var wg sync.WaitGroup
	for i := range eventCount {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			event := NewPortOpenEvent("192.168.1.1", 80+idx, "tcp")
			publisher.Publish(ctx, event)
		}(i)
	}

	wg.Wait()
	time.Sleep(50 * time.Millisecond) // Allow async processing

	receivedCount := handler.Count()
	if receivedCount != eventCount {
		t.Errorf("Expected %d events, got %d", eventCount, receivedCount)
	}
}

// TestEventTimestampOrdering tests that events have proper timestamps.
func TestEventTimestampOrdering(t *testing.T) {
	event1 := NewTargetStartedEvent("10.0.0.1", "port_scan")
	time.Sleep(5 * time.Millisecond)
	event2 := NewTargetCompletedEvent("10.0.0.1", "port_scan", []int{80}, 1*time.Second)

	if !event2.Timestamp().After(event1.Timestamp()) {
		t.Error("Event2 timestamp should be after Event1")
	}
}
