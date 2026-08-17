// pkg/engine/module.go
package engine

import (
	"context"
	"reflect"
	"time"
)

// ModuleType represents the category of the module.
type ModuleType string

const (
	DiscoveryModuleType     ModuleType = "discovery"     // For host, port, or service discovery
	ScanModuleType          ModuleType = "scan"          // For active scanning, probing, banner grabbing
	ParseModuleType         ModuleType = "parse"         // For parsing raw data into structured information
	EvaluationModuleType    ModuleType = "evaluation"    // For vulnerability checks, compliance checks, etc.
	ReportingModuleType     ModuleType = "reporting"     // For generating reports
	OutputModuleType        ModuleType = "output"        // For sending results to different sinks
	OrchestrationModuleType ModuleType = "orchestration" // Meta-modules that can manage other modules
)

// DataType represents the expected Go type of a DataKey as a string.
// Examples: "[]string", "int", "discovery.ICMPPingDiscoveryResult", "[]scan.BannerGrabResult"
type DataType string

// DataCardinality indicates if a DataKey represents a single item or a list of items.
type DataCardinality string

const (
	CardinalitySingle DataCardinality = "single" // Represents a single data item (struct, int, string, etc.)
	CardinalityList   DataCardinality = "list"   // Represents a list/slice of data items (e.g., []string, []MyStruct)
)

// DataContractEntry, bir DataKey'in tipini ve kardinalitesini tanımlar.
type DataContractEntry struct {
	Key          string          `json:"key" yaml:"key"`                                     // DataKey adı (örn: "discovery.live_hosts")
	DataType     reflect.Type    `json:"-" yaml:"-"`                                         // Beklenen Go tipi (JSON/YAML'a serileştirilmez, çalışma zamanında kullanılır)
	DataTypeName string          `json:"data_type_name" yaml:"data_type_name"`               // Tipin string temsili (örn: "[]string", "discovery.ICMPPingDiscoveryResult")
	Cardinality  DataCardinality `json:"cardinality" yaml:"cardinality"`                     // Is the Data field for this key a single item or a list of items?
	IsList       bool            `json:"is_list" yaml:"is_list"`                             // Bu anahtarın değeri bir liste mi (birden fazla öğe içerebilir mi)?
	IsOptional   bool            `json:"is_optional,omitempty" yaml:"is_optional,omitempty"` // Bu girdi/çıktı opsiyonel mi?
	Description  string          `json:"description,omitempty" yaml:"description,omitempty"`
}

// ActivationTrigger (önceki yanıttaki gibi kalabilir veya geliştirilebilir)
type ActivationTrigger struct {
	DataKey        string `json:"data_key" yaml:"data_key"`
	ValueCondition string `json:"value_condition,omitempty" yaml:"value_condition,omitempty"`
	ConditionType  string `json:"condition_type,omitempty"` // "equals", "contains", "regex", "version_lt"
}

// ModuleMetadata holds common information for all modules.
type ModuleMetadata struct {
	ID          string     // Unique identifier for the module instance in a DAG
	Name        string     // Human-readable name of the module type (e.g., "ICMP Ping Discovery")
	Version     string     // Version of the module implementation
	Description string     // Brief description of what the module does
	Type        ModuleType // Category of the module (discovery, scan, etc.)
	Author      string     // Author of the module
	Tags        []string   // Tags for categorization or filtering

	// Defines what data keys this module consumes from the data context or previous modules.
	// Example: ["config.targets", "discovery.live_hosts"]
	Consumes []DataContractEntry `json:"consumes,omitempty" yaml:"consumes,omitempty"`
	// Defines what data keys this module can produce.
	// Example: ["discovery.live_hosts", "asset.ip_addresses"]
	Produces []DataContractEntry `json:"produces,omitempty" yaml:"produces,omitempty"`

	// Defines module-specific configuration parameters and their types/defaults.
	// This could be a more structured type or a map for flexibility.
	ConfigSchema map[string]ParameterDefinition

	ActivationTriggers []ActivationTrigger `json:"activation_triggers,omitempty" yaml:"activation_triggers,omitempty"`
	IsDynamic          bool                `json:"is_dynamic,omitempty" yaml:"is_dynamic,omitempty"`

	// Opsiyonel ek alanlar:
	EstimatedCost    int      `json:"estimated_cost,omitempty" yaml:"estimated_cost,omitempty"`       // 1-5 arası (1:hızlı, 5:çok yavaş)
	RequiredFeatures []string `json:"required_features,omitempty" yaml:"required_features,omitempty"` // Lisans için
}

// ParameterDefinition describes a configuration parameter for a module.
type ParameterDefinition struct {
	Description string
	Type        string // e.g., "string", "int", "bool", "duration", "[]string"
	Required    bool
	Default     any
}

// ModuleOutput represents the data produced by a module's execution.
type ModuleOutput struct {
	// FromModuleName is the ID of the module instance that produced this output.
	FromModuleName string
	// DataKey is a string key identifying the type or nature of the data.
	// Allows consumers to understand what this data represents.
	// e.g., "discovery.live_hosts", "service.banner.ssh", "vulnerability.CVE-2021-44228"
	DataKey string
	// Data is the actual payload.
	Data any
	// Error if the module execution failed for this specific output.
	Error error
	// Timestamp when the data was produced.
	Timestamp time.Time
	// Target associated with this output, if applicable (e.g., IP address, hostname).
	Target string
}

// Module is the core interface that all functional units in Cyprob should implement.
type Module interface {
	// Metadata returns descriptive information about the module.
	Metadata() ModuleMetadata

	// Init initializes the module with its specific configuration.
	// The config map is typically derived from the DAG definition.
	Init(instanceID string, moduleConfig map[string]any) error

	// Execute runs the module's main logic.
	// It takes the current execution context, a map of input data (keyed by DataKey),
	// and a channel to send its outputs.
	Execute(ctx context.Context, inputs map[string]any, outputChan chan<- ModuleOutput) error
}

// ModuleLifecycle is an optional lifecycle interface that a Module can implement
// to participate in orchestrator-managed setup/start/teardown phases. This is
// opt-in and does not change the existing Module API.
//
// Note: Method names are prefixed with Lifecycle to avoid clashing with the
// existing Module.Init signature.
type ModuleLifecycle interface {
	// LifecycleInit performs runtime initialization with a context (e.g., open connections).
	LifecycleInit(ctx context.Context) error
	// LifecycleStart activates long-running resources before Execute.
	LifecycleStart(ctx context.Context) error
	// LifecycleStop releases resources; orchestrator calls this best-effort with a timeout.
	LifecycleStop(ctx context.Context) error
}
