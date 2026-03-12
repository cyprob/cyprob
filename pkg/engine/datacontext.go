package engine

import (
	"fmt"
	"maps"
	"reflect"
	"sync"
	"time"
)

// Cardinality mirrors DataCardinality but as an internal enum for schema storage.
// We reuse DataCardinality string values from module.go to avoid duplication.
type Cardinality = DataCardinality

// dataKeySchema stores expected type and cardinality for a key.
type dataKeySchema struct {
	typ         reflect.Type
	cardinality Cardinality
}

// DataContext provides typed accessors with a schema for runtime validation.
type DataContext struct {
	mu     sync.RWMutex
	schema map[string]dataKeySchema
	data   map[string]any
}

// Expose RLock/RUnlock to satisfy legacy tests expecting embedded RWMutex methods.
func (dc *DataContext) RLock()   { dc.mu.RLock() }
func (dc *DataContext) RUnlock() { dc.mu.RUnlock() }

func NewDataContext() *DataContext {
	return &DataContext{
		schema: make(map[string]dataKeySchema),
		data:   make(map[string]any),
	}
}

// RegisterCommonSchema registers commonly used keys with sensible defaults.
// It is safe to call multiple times (idempotent).
//
// Note: Some complex types (e.g., asset.profiles, discovery results, parse results)
// are deferred to avoid import cycles. Modules that produce these keys should
// register their own schemas using RegisterType() with concrete types.
func RegisterCommonSchema(dc *DataContext) {
	// Config keys (CardinalitySingle)
	_ = dc.RegisterType("config.targets", reflect.TypeFor[[]string](), CardinalitySingle)
	_ = dc.RegisterType("config.ports", reflect.TypeFor[[]int](), CardinalitySingle)

	// Simple parse keys (CardinalityList) - primitive types
	// Note: For CardinalityList, register slice types ([]T) not element types (T)
	_ = dc.RegisterType("ssh.banner", reflect.TypeFor[[]string](), CardinalityList)
	_ = dc.RegisterType("ssh.version", reflect.TypeFor[[]string](), CardinalityList)
	_ = dc.RegisterType("snmp.version", reflect.TypeFor[[]string](), CardinalityList)
	_ = dc.RegisterType("snmp.community", reflect.TypeFor[[]string](), CardinalityList)
	_ = dc.RegisterType("http.server", reflect.TypeFor[[]string](), CardinalityList)
	_ = dc.RegisterType("service.port", reflect.TypeFor[[]int](), CardinalityList)

	// Phase 1.8: TLS protocol-level keys (CardinalityList)
	_ = dc.RegisterType("tls.version", reflect.TypeFor[[]string](), CardinalityList)
	_ = dc.RegisterType("tls.cipher_suite", reflect.TypeFor[[]string](), CardinalityList)
	_ = dc.RegisterType("tls.server_name", reflect.TypeFor[[]string](), CardinalityList)

	// Phase 1.8: TLS certificate-level keys (CardinalityList)
	_ = dc.RegisterType("tls.certificate.issuer", reflect.TypeFor[[]string](), CardinalityList)
	_ = dc.RegisterType("tls.certificate.common_name", reflect.TypeFor[[]string](), CardinalityList)
	_ = dc.RegisterType("tls.certificate.dns_names", reflect.TypeFor[[]string](), CardinalityList)
	_ = dc.RegisterType("tls.certificate.not_before", reflect.TypeFor[[]time.Time](), CardinalityList)
	_ = dc.RegisterType("tls.certificate.not_after", reflect.TypeFor[[]time.Time](), CardinalityList)
	_ = dc.RegisterType("tls.certificate.is_expired", reflect.TypeFor[[]bool](), CardinalityList)
	_ = dc.RegisterType("tls.certificate.is_self_signed", reflect.TypeFor[[]bool](), CardinalityList)

	// Complex types deferred to modules to avoid import cycles:
	// - discovery.live_hosts (discovery.ICMPPingDiscoveryResult)
	// - discovery.open_tcp_ports (discovery.TCPPortDiscoveryResult)
	// - service.banner.tcp (scan.BannerGrabResult)
	// - service.http.details (parse.HTTPParsedInfo)
	// - service.ssh.details (scan.SSHServiceInfo)
	// - service.fingerprint.details (parse.FingerprintParsedInfo)
	// - evaluation.vulnerabilities (evaluation.VulnerabilityResult)
	// - asset.profiles ([]engine.AssetProfile)
	//
	// Modules producing these keys should call:
	//   dc.RegisterType(key, reflect.TypeOf(MyType{}), cardinality)
}

// --- Legacy-compatible helpers used by orchestrator (to keep build green) ---

// SetInitial stores an initial input value directly, overwriting if exists.
// Note: Does not validate against schema; reserved for bootstrap paths.
func (dc *DataContext) SetInitial(key string, value any) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	dc.data[key] = value
}

// AddOrAppendToList appends to a list value, promoting existing non-list to list when necessary.
func (dc *DataContext) AddOrAppendToList(key string, value any) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if existing, ok := dc.data[key]; ok {
		if list, ok := existing.([]any); ok {
			dc.data[key] = append(list, value)
		} else {
			dc.data[key] = []any{existing, value}
		}
	} else {
		dc.data[key] = []any{value}
	}
}

// Set is a legacy alias for AddOrAppendToList, preserved for tests.
func (dc *DataContext) Set(key string, value any) { dc.AddOrAppendToList(key, value) }

// Get returns untyped value and found flag (legacy accessor).
func (dc *DataContext) Get(key string) (any, bool) {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	v, ok := dc.data[key]
	return v, ok
}

// GetAll returns a shallow copy of the internal map (legacy accessor).
func (dc *DataContext) GetAll() map[string]any {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	out := make(map[string]any, len(dc.data))
	maps.Copy(out, dc.data)
	return out
}

// Register declares a key with expected type T and cardinality.
// RegisterType declares a key with expected reflect.Type and cardinality.
func (dc *DataContext) RegisterType(key string, typ reflect.Type, card Cardinality) error {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if typ == nil {
		return fmt.Errorf("nil type for key %s", key)
	}
	dc.schema[key] = dataKeySchema{typ: typ, cardinality: card}
	return nil
}

// PublishValue sets the entire value for a key (CardinalitySingle) with runtime validation.
func (dc *DataContext) PublishValue(key string, value any) error {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	sch, ok := dc.schema[key]
	if !ok {
		return fmt.Errorf("key not registered: %s", key)
	}
	if sch.cardinality != CardinalitySingle {
		return fmt.Errorf("key %s is not CardinalitySingle", key)
	}
	if err := dc.checkTypeLocked(sch, value); err != nil {
		return err
	}
	dc.data[key] = value
	return nil
}

// AppendValue adds a single item for list cardinality keys. The stored value becomes a slice.
func (dc *DataContext) AppendValue(key string, item any) error {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	sch, ok := dc.schema[key]
	if !ok {
		return fmt.Errorf("key not registered: %s", key)
	}
	if sch.cardinality != CardinalityList {
		return fmt.Errorf("key %s is not CardinalityList", key)
	}
	// For list, schema type is []T. Accept either first append to create []T or append to existing []T.
	// Build a new slice of the expected element type.
	// Validate by comparing against schema typ for []T.
	// Derive []T type from schema.typ.
	expected := sch.typ // expected is a slice type, e.g., []T
	// Ensure stored value is a slice of expected element type.
	// Validate item type matches slice element type
	elemType := expected.Elem() // Get T from []T
	itemValue := reflect.ValueOf(item)
	if itemValue.Type() != elemType {
		return fmt.Errorf("type mismatch for key %s: expected element type %s, got %s", key, elemType, itemValue.Type())
	}

	cur, exists := dc.data[key]
	if !exists {
		// Initialize new slice with item
		slice := reflect.MakeSlice(expected, 0, 1)
		slice = reflect.Append(slice, itemValue)
		dc.data[key] = slice.Interface()
		return nil
	}
	rv := reflect.ValueOf(cur)
	if rv.Type() != expected {
		return fmt.Errorf("type mismatch for key %s: expected %s, got %s", key, expected, rv.Type())
	}
	dc.data[key] = reflect.Append(rv, itemValue).Interface()
	return nil
}

// GetValue returns the stored value for a key with validation against schema type.
func (dc *DataContext) GetValue(key string) (any, error) {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	sch, ok := dc.schema[key]
	if !ok {
		return nil, fmt.Errorf("key not registered: %s", key)
	}
	v, ok := dc.data[key]
	if !ok {
		return nil, fmt.Errorf("key has no value: %s", key)
	}
	// Validate type
	if err := dc.checkTypeLocked(sch, v); err != nil {
		return nil, err
	}
	return v, nil
}

func (dc *DataContext) checkTypeLocked(sch dataKeySchema, v any) error {
	vt := reflect.TypeOf(v)
	if vt == nil { // allow nil set only if expected is a pointer/interface
		if sch.typ.Kind() != reflect.Interface && sch.typ.Kind() != reflect.Pointer && sch.typ.Kind() != reflect.Slice && sch.typ.Kind() != reflect.Map {
			return fmt.Errorf("type mismatch: expected %s, got <nil>", sch.typ)
		}
		return nil
	}
	if vt != sch.typ {
		return fmt.Errorf("type mismatch: expected %s, got %s", sch.typ, vt)
	}
	return nil
}

// ---------- Generic helper functions (package-level, not methods) ----------

// Register registers schema with type parameter by forwarding to RegisterType.
func Register[T any](dc *DataContext, key string, card Cardinality) error {
	var zero T
	t := reflect.TypeOf(zero)
	if t == nil {
		t = reflect.TypeFor[T]()
	}
	return dc.RegisterType(key, t, card)
}

// Publish publishes a typed value using runtime validation.
func Publish[T any](dc *DataContext, key string, value T) error {
	return dc.PublishValue(key, value)
}

// Append appends a typed item to a list key.
func Append[T any](dc *DataContext, key string, item T) error {
	return dc.AppendValue(key, item)
}

// Get retrieves a typed value with a type assertion after validation.
func Get[T any](dc *DataContext, key string) (T, error) {
	var zero T
	v, err := dc.GetValue(key)
	if err != nil {
		return zero, err
	}
	typed, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf("type assertion failed for key %s", key)
	}
	return typed, nil
}
