// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPlugin_Validate(t *testing.T) {
	tests := []struct {
		name    string
		plugin  *YAMLPlugin
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid plugin",
			plugin: &YAMLPlugin{
				ID:      "test",
				Name:    "Test Plugin",
				Version: "1.0.0",
				Type:    EvaluationType,
				Author:  "test-author",
				Metadata: PluginMetadata{
					Severity: HighSeverity,
					Tags:     []string{"test"},
				},
				Output: OutputBlock{
					Message: "Test message",
				},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			plugin: &YAMLPlugin{
				ID:      "test",
				Version: "1.0.0",
				Type:    EvaluationType,
				Author:  "test",
				Metadata: PluginMetadata{
					Severity: HighSeverity,
				},
				Output: OutputBlock{
					Message: "Test",
				},
			},
			wantErr: true,
			errMsg:  "plugin name is required",
		},
		{
			name: "missing version",
			plugin: &YAMLPlugin{
				ID:     "test",
				Name:   "Test",
				Type:   EvaluationType,
				Author: "test",
				Metadata: PluginMetadata{
					Severity: HighSeverity,
				},
				Output: OutputBlock{
					Message: "Test",
				},
			},
			wantErr: true,
			errMsg:  "plugin version is required",
		},
		{
			name: "missing type",
			plugin: &YAMLPlugin{
				ID:      "test",
				Name:    "Test",
				Version: "1.0.0",
				Author:  "test",
				Metadata: PluginMetadata{
					Severity: HighSeverity,
				},
				Output: OutputBlock{
					Message: "Test",
				},
			},
			wantErr: true,
			errMsg:  "plugin type is required",
		},
		{
			name: "missing author",
			plugin: &YAMLPlugin{
				ID:      "test",
				Name:    "Test",
				Version: "1.0.0",
				Type:    EvaluationType,
				Metadata: PluginMetadata{
					Severity: HighSeverity,
				},
				Output: OutputBlock{
					Message: "Test",
				},
			},
			wantErr: true,
			errMsg:  "plugin author is required",
		},
		{
			name: "missing severity",
			plugin: &YAMLPlugin{
				ID:       "test",
				Name:     "Test",
				Version:  "1.0.0",
				Type:     EvaluationType,
				Author:   "test",
				Metadata: PluginMetadata{},
				Output: OutputBlock{
					Message: "Test",
				},
			},
			wantErr: true,
			errMsg:  "plugin severity is required",
		},
		{
			name: "invalid severity",
			plugin: &YAMLPlugin{
				ID:      "test",
				Name:    "Test",
				Version: "1.0.0",
				Type:    EvaluationType,
				Author:  "test",
				Metadata: PluginMetadata{
					Severity: "super-critical",
				},
				Output: OutputBlock{
					Message: "Test",
				},
			},
			wantErr: true,
			errMsg:  "invalid severity",
		},
		{
			name: "missing output message",
			plugin: &YAMLPlugin{
				ID:      "test",
				Name:    "Test",
				Version: "1.0.0",
				Type:    EvaluationType,
				Author:  "test",
				Metadata: PluginMetadata{
					Severity: HighSeverity,
				},
				Output: OutputBlock{},
			},
			wantErr: true,
			errMsg:  "output message is required",
		},
		{
			name: "trigger missing data_key",
			plugin: &YAMLPlugin{
				ID:      "test",
				Name:    "Test",
				Version: "1.0.0",
				Type:    EvaluationType,
				Author:  "test",
				Metadata: PluginMetadata{
					Severity: HighSeverity,
				},
				Triggers: []Trigger{
					{Condition: "exists", Value: true},
				},
				Output: OutputBlock{
					Message: "Test",
				},
			},
			wantErr: true,
			errMsg:  "data_key is required",
		},
		{
			name: "trigger missing condition",
			plugin: &YAMLPlugin{
				ID:      "test",
				Name:    "Test",
				Version: "1.0.0",
				Type:    EvaluationType,
				Author:  "test",
				Metadata: PluginMetadata{
					Severity: HighSeverity,
				},
				Triggers: []Trigger{
					{DataKey: "test", Value: true},
				},
				Output: OutputBlock{
					Message: "Test",
				},
			},
			wantErr: true,
			errMsg:  "condition is required",
		},
		{
			name: "invalid match block",
			plugin: &YAMLPlugin{
				ID:      "test",
				Name:    "Test",
				Version: "1.0.0",
				Type:    EvaluationType,
				Author:  "test",
				Metadata: PluginMetadata{
					Severity: HighSeverity,
				},
				Match: &MatchBlock{
					Logic: "INVALID",
					Rules: []MatchRule{
						{Field: "test", Operator: "equals", Value: "test"},
					},
				},
				Output: OutputBlock{
					Message: "Test",
				},
			},
			wantErr: true,
			errMsg:  "match block validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.plugin.Validate()

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMatchBlock_Validate(t *testing.T) {
	tests := []struct {
		name    string
		match   *MatchBlock
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid match block",
			match: &MatchBlock{
				Logic: "AND",
				Rules: []MatchRule{
					{Field: "test", Operator: "equals", Value: "test"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing logic",
			match: &MatchBlock{
				Rules: []MatchRule{
					{Field: "test", Operator: "equals", Value: "test"},
				},
			},
			wantErr: true,
			errMsg:  "match logic is required",
		},
		{
			name: "invalid logic",
			match: &MatchBlock{
				Logic: "XOR",
				Rules: []MatchRule{
					{Field: "test", Operator: "equals", Value: "test"},
				},
			},
			wantErr: true,
			errMsg:  "invalid match logic",
		},
		{
			name: "empty rules",
			match: &MatchBlock{
				Logic: "AND",
				Rules: []MatchRule{},
			},
			wantErr: true,
			errMsg:  "match rules cannot be empty",
		},
		{
			name: "rule missing field",
			match: &MatchBlock{
				Logic: "AND",
				Rules: []MatchRule{
					{Operator: "equals", Value: "test"},
				},
			},
			wantErr: true,
			errMsg:  "field is required",
		},
		{
			name: "rule missing operator",
			match: &MatchBlock{
				Logic: "AND",
				Rules: []MatchRule{
					{Field: "test", Value: "test"},
				},
			},
			wantErr: true,
			errMsg:  "operator is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.match.Validate()

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSeverityValues(t *testing.T) {
	// Test that all severity constants are defined
	require.Equal(t, Severity("critical"), CriticalSeverity)
	require.Equal(t, Severity("high"), HighSeverity)
	require.Equal(t, Severity("medium"), MediumSeverity)
	require.Equal(t, Severity("low"), LowSeverity)
	require.Equal(t, Severity("info"), InfoSeverity)
}

func TestPluginTypeValues(t *testing.T) {
	// Test that all plugin type constants are defined
	require.Equal(t, PluginType("evaluation"), EvaluationType)
	require.Equal(t, PluginType("output"), OutputType)
	require.Equal(t, PluginType("integration"), IntegrationType)
}
