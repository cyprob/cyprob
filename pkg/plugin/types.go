// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"fmt"
	"time"
)

// PluginType defines the category of the plugin.
type PluginType string

const (
	// EvaluationType plugins perform vulnerability checks and compliance validation
	EvaluationType PluginType = "evaluation"

	// OutputType plugins handle result formatting and output
	OutputType PluginType = "output"

	// IntegrationType plugins integrate with external systems
	IntegrationType PluginType = "integration"
)

// Severity levels for findings
type Severity string

const (
	CriticalSeverity Severity = "critical"
	HighSeverity     Severity = "high"
	MediumSeverity   Severity = "medium"
	LowSeverity      Severity = "low"
	InfoSeverity     Severity = "info"
)

// YAMLPlugin represents a YAML-based plugin definition.
// This is the complete plugin structure that gets loaded from disk.
type YAMLPlugin struct {
	// Required fields
	ID      string     `yaml:"id,omitempty" json:"id,omitempty"` // Unique slug identifier (e.g., "ssh-default-credentials")
	Name    string     `yaml:"name" json:"name"`
	Version string     `yaml:"version" json:"version"`
	Type    PluginType `yaml:"type" json:"type"`
	Author  string     `yaml:"author" json:"author"`

	// Metadata
	Metadata PluginMetadata `yaml:"metadata" json:"metadata"`

	// Execution control
	Triggers []Trigger `yaml:"triggers,omitempty" json:"triggers,omitempty"`

	// Matching rules
	Match *MatchBlock `yaml:"match,omitempty" json:"match,omitempty"`

	// Output format
	Output OutputBlock `yaml:"output" json:"output"`

	// Internal (populated at runtime)
	FilePath  string    `yaml:"-" json:"-"` // Path to YAML file
	LoadedAt  time.Time `yaml:"-" json:"-"` // When loaded
	Signature string    `yaml:"signature,omitempty" json:"signature,omitempty"`
}

// PluginMetadata contains additional information about the plugin.
type PluginMetadata struct {
	CVE        string   `yaml:"cve,omitempty" json:"cve,omitempty"`
	Severity   Severity `yaml:"severity" json:"severity"`
	Tags       []string `yaml:"tags" json:"tags"`
	References []string `yaml:"references,omitempty" json:"references,omitempty"`
}

// Trigger defines when a plugin should be evaluated.
// Triggers are evaluated against the DataContext to determine if the plugin
// is relevant for the current scan.
type Trigger struct {
	DataKey   string `yaml:"data_key" json:"data_key"`     // DataContext key to watch
	Condition string `yaml:"condition" json:"condition"`   // exists, equals, version_lt, etc.
	Value     any    `yaml:"value,omitempty" json:"value"` // Condition value (type depends on condition)
}

// MatchBlock defines the matching logic for the plugin.
type MatchBlock struct {
	Logic string      `yaml:"logic" json:"logic"` // AND, OR, NOT
	Rules []MatchRule `yaml:"rules" json:"rules"` // List of rules to evaluate
}

// MatchRule is a single matching rule within a MatchBlock.
type MatchRule struct {
	Field    string `yaml:"field" json:"field"`       // Data field to check
	Operator string `yaml:"operator" json:"operator"` // equals, contains, matches, version_*, etc.
	Value    any    `yaml:"value" json:"value"`       // Expected value
}

// OutputBlock defines the output format when a match succeeds.
type OutputBlock struct {
	Vulnerability bool              `yaml:"vulnerability" json:"vulnerability"`
	Severity      Severity          `yaml:"severity,omitempty" json:"severity,omitempty"`
	Message       string            `yaml:"message" json:"message"`
	Remediation   string            `yaml:"remediation,omitempty" json:"remediation,omitempty"`
	Reference     string            `yaml:"reference,omitempty" json:"reference,omitempty"`
	Metadata      map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"` // Custom metadata
}

// YAMLMatchResult is the result of evaluating a YAML plugin against a data context.
type YAMLMatchResult struct {
	Matched       bool
	Plugin        *YAMLPlugin
	Output        OutputBlock
	EvaluatedAt   time.Time
	ExecutionTime time.Duration
}

// Validate validates the plugin structure.
func (p *YAMLPlugin) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("plugin name is required")
	}

	// ID is required (must be explicitly set in YAML)
	if p.ID == "" {
		return fmt.Errorf("plugin ID is required")
	}

	if p.Version == "" {
		return fmt.Errorf("plugin version is required")
	}

	if p.Type == "" {
		return fmt.Errorf("plugin type is required")
	}

	if p.Author == "" {
		return fmt.Errorf("plugin author is required")
	}

	// Validate severity
	if p.Metadata.Severity == "" {
		return fmt.Errorf("plugin severity is required")
	}

	validSeverities := map[Severity]bool{
		CriticalSeverity: true,
		HighSeverity:     true,
		MediumSeverity:   true,
		LowSeverity:      true,
		InfoSeverity:     true,
	}

	if !validSeverities[p.Metadata.Severity] {
		return fmt.Errorf("invalid severity: %s (must be critical, high, medium, low, or info)", p.Metadata.Severity)
	}

	// Validate triggers
	for i, trigger := range p.Triggers {
		if trigger.DataKey == "" {
			return fmt.Errorf("trigger[%d]: data_key is required", i)
		}
		if trigger.Condition == "" {
			return fmt.Errorf("trigger[%d]: condition is required", i)
		}
	}

	// Validate match block
	if p.Match != nil {
		if err := p.Match.Validate(); err != nil {
			return fmt.Errorf("match block validation failed: %w", err)
		}
	}

	// Validate output block
	if p.Output.Message == "" {
		return fmt.Errorf("output message is required")
	}

	return nil
}

// Validate validates the match block structure.
func (m *MatchBlock) Validate() error {
	if m.Logic == "" {
		return fmt.Errorf("match logic is required")
	}

	validLogic := map[string]bool{
		"AND": true,
		"OR":  true,
		"NOT": true,
	}

	if !validLogic[m.Logic] {
		return fmt.Errorf("invalid match logic: %s (must be AND, OR, or NOT)", m.Logic)
	}

	if len(m.Rules) == 0 {
		return fmt.Errorf("match rules cannot be empty")
	}

	for i, rule := range m.Rules {
		if rule.Field == "" {
			return fmt.Errorf("rule[%d]: field is required", i)
		}
		if rule.Operator == "" {
			return fmt.Errorf("rule[%d]: operator is required", i)
		}
	}

	return nil
}
