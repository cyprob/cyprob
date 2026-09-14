// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEvaluator_Evaluate(t *testing.T) {
	evaluator := NewEvaluator()

	tests := []struct {
		name        string
		plugin      *YAMLPlugin
		context     map[string]any
		wantMatched bool
		wantErr     bool
	}{
		{
			name: "triggered and matched",
			plugin: &YAMLPlugin{
				ID:      "test-plugin",
				Name:    "Test Plugin",
				Version: "1.0.0",
				Type:    EvaluationType,
				Author:  "test",
				Metadata: PluginMetadata{
					Severity: HighSeverity,
					Tags:     []string{"test"},
				},
				Triggers: []Trigger{
					{DataKey: "ssh.version", Condition: "exists", Value: true},
				},
				Match: &MatchBlock{
					Logic: "AND",
					Rules: []MatchRule{
						{Field: "ssh.version", Operator: "version_lt", Value: "8.0"},
					},
				},
				Output: OutputBlock{
					Vulnerability: true,
					Message:       "Vulnerable SSH version",
				},
			},
			context: map[string]any{
				"ssh.version": "7.4.0",
			},
			wantMatched: true,
		},
		{
			name: "triggered but not matched",
			plugin: &YAMLPlugin{
				ID:      "test-plugin",
				Name:    "Test Plugin",
				Version: "1.0.0",
				Type:    EvaluationType,
				Author:  "test",
				Metadata: PluginMetadata{
					Severity: HighSeverity,
					Tags:     []string{"test"},
				},
				Triggers: []Trigger{
					{DataKey: "ssh.version", Condition: "exists", Value: true},
				},
				Match: &MatchBlock{
					Logic: "AND",
					Rules: []MatchRule{
						{Field: "ssh.version", Operator: "version_lt", Value: "7.0"},
					},
				},
				Output: OutputBlock{
					Vulnerability: true,
					Message:       "Vulnerable SSH version",
				},
			},
			context: map[string]any{
				"ssh.version": "8.0.0",
			},
			wantMatched: false,
		},
		{
			name: "not triggered",
			plugin: &YAMLPlugin{
				ID:      "test-plugin",
				Name:    "Test Plugin",
				Version: "1.0.0",
				Type:    EvaluationType,
				Author:  "test",
				Metadata: PluginMetadata{
					Severity: HighSeverity,
					Tags:     []string{"test"},
				},
				Triggers: []Trigger{
					{DataKey: "ssh.version", Condition: "exists", Value: true},
				},
				Match: &MatchBlock{
					Logic: "AND",
					Rules: []MatchRule{
						{Field: "ssh.version", Operator: "version_lt", Value: "8.0"},
					},
				},
				Output: OutputBlock{
					Vulnerability: true,
					Message:       "Vulnerable SSH version",
				},
			},
			context: map[string]any{
				"http.server": "Apache",
			},
			wantMatched: false,
		},
		{
			name: "no triggers - always match",
			plugin: &YAMLPlugin{
				ID:      "test-plugin",
				Name:    "Test Plugin",
				Version: "1.0.0",
				Type:    EvaluationType,
				Author:  "test",
				Metadata: PluginMetadata{
					Severity: InfoSeverity,
					Tags:     []string{"test"},
				},
				Triggers: []Trigger{},
				Match: &MatchBlock{
					Logic: "AND",
					Rules: []MatchRule{
						{Field: "service", Operator: "equals", Value: "ssh"},
					},
				},
				Output: OutputBlock{
					Vulnerability: false,
					Message:       "SSH service detected",
				},
			},
			context: map[string]any{
				"service": "ssh",
			},
			wantMatched: true,
		},
		{
			name: "no match block - always match if triggered",
			plugin: &YAMLPlugin{
				ID:      "test-plugin",
				Name:    "Test Plugin",
				Version: "1.0.0",
				Type:    EvaluationType,
				Author:  "test",
				Metadata: PluginMetadata{
					Severity: InfoSeverity,
					Tags:     []string{"test"},
				},
				Triggers: []Trigger{
					{DataKey: "service", Condition: "equals", Value: "ssh"},
				},
				Match: nil,
				Output: OutputBlock{
					Vulnerability: false,
					Message:       "SSH service detected",
				},
			},
			context: map[string]any{
				"service": "ssh",
			},
			wantMatched: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.Evaluate(tt.plugin, tt.context)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, tt.wantMatched, result.Matched)
			require.Equal(t, tt.plugin, result.Plugin)

			if result.Matched {
				require.Equal(t, tt.plugin.Output.Message, result.Output.Message)
			}

			// Verify execution time is recorded
			require.NotZero(t, result.ExecutionTime)
		})
	}
}

func TestEvaluator_EvaluateAll(t *testing.T) {
	evaluator := NewEvaluator()

	plugin1 := &YAMLPlugin{
		ID:      "plugin-1",
		Name:    "Plugin 1",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Triggers: []Trigger{
			{DataKey: "ssh.version", Condition: "exists", Value: true},
		},
		Match: &MatchBlock{
			Logic: "AND",
			Rules: []MatchRule{
				{Field: "ssh.version", Operator: "version_lt", Value: "8.0"},
			},
		},
		Output: OutputBlock{
			Vulnerability: true,
			Message:       "Vulnerable SSH",
		},
	}

	plugin2 := &YAMLPlugin{
		ID:      "plugin-2",
		Name:    "Plugin 2",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: MediumSeverity,
			Tags:     []string{"test"},
		},
		Triggers: []Trigger{
			{DataKey: "http.server", Condition: "exists", Value: true},
		},
		Match: &MatchBlock{
			Logic: "AND",
			Rules: []MatchRule{
				{Field: "http.server", Operator: "contains", Value: "Apache"},
			},
		},
		Output: OutputBlock{
			Vulnerability: true,
			Message:       "Apache detected",
		},
	}

	plugins := []*YAMLPlugin{plugin1, plugin2}

	context := map[string]any{
		"ssh.version": "7.4.0",
		"http.server": "Apache/2.4",
	}

	results, err := evaluator.EvaluateAll(plugins, context)
	require.NoError(t, err)
	require.Len(t, results, 2)

	// Both plugins should match
	require.True(t, results[0].Matched)
	require.True(t, results[1].Matched)
}

func TestEvaluator_Evaluate_TriggerError(t *testing.T) {
	evaluator := NewEvaluator()

	plugin := &YAMLPlugin{
		ID:      "test-plugin",
		Name:    "Test Plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Triggers: []Trigger{
			{DataKey: "version", Condition: "version_lt", Value: "invalid.version"},
		},
		Output: OutputBlock{
			Message: "Test",
		},
	}

	context := map[string]any{
		"version": "1.0.0",
	}

	_, err := evaluator.Evaluate(plugin, context)
	require.Error(t, err)
	require.Contains(t, err.Error(), "trigger evaluation failed")
}

func TestEvaluator_Evaluate_MatchError(t *testing.T) {
	evaluator := NewEvaluator()

	plugin := &YAMLPlugin{
		ID:      "test-plugin",
		Name:    "Test Plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Triggers: []Trigger{
			{DataKey: "version", Condition: "exists", Value: true},
		},
		Match: &MatchBlock{
			Logic: "AND",
			Rules: []MatchRule{
				{Field: "version", Operator: "version_lt", Value: "invalid.version"},
			},
		},
		Output: OutputBlock{
			Message: "Test",
		},
	}

	context := map[string]any{
		"version": "1.0.0",
	}

	_, err := evaluator.Evaluate(plugin, context)
	require.Error(t, err)
	require.Contains(t, err.Error(), "match evaluation failed")
}

func TestEvaluator_Evaluate_SeverityOverride(t *testing.T) {
	evaluator := NewEvaluator()

	tests := []struct {
		name             string
		pluginSeverity   Severity
		outputSeverity   Severity
		expectedSeverity Severity
	}{
		{
			name:             "output severity overrides plugin severity",
			pluginSeverity:   HighSeverity,
			outputSeverity:   CriticalSeverity,
			expectedSeverity: CriticalSeverity,
		},
		{
			name:             "plugin severity used when output severity is empty",
			pluginSeverity:   MediumSeverity,
			outputSeverity:   "",
			expectedSeverity: MediumSeverity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &YAMLPlugin{
				ID:      "test-plugin",
				Name:    "Test Plugin",
				Version: "1.0.0",
				Type:    EvaluationType,
				Author:  "test",
				Metadata: PluginMetadata{
					Severity: tt.pluginSeverity,
					Tags:     []string{"test"},
				},
				Triggers: []Trigger{
					{DataKey: "service", Condition: "equals", Value: "ssh"},
				},
				Output: OutputBlock{
					Vulnerability: true,
					Message:       "Test",
					Severity:      tt.outputSeverity,
				},
			}

			context := map[string]any{
				"service": "ssh",
			}

			result, err := evaluator.Evaluate(plugin, context)
			require.NoError(t, err)
			require.True(t, result.Matched)
			require.Equal(t, tt.expectedSeverity, result.Output.Severity)
		})
	}
}

func TestEvaluator_EvaluateAll_WithError(t *testing.T) {
	evaluator := NewEvaluator()

	plugin1 := &YAMLPlugin{
		ID:      "valid-plugin",
		Name:    "Valid Plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Match: &MatchBlock{
			Logic: "AND",
			Rules: []MatchRule{
				{Field: "service", Operator: "equals", Value: "ssh"},
			},
		},
		Output: OutputBlock{
			Message: "Valid",
		},
	}

	// Plugin with invalid trigger (will cause error)
	plugin2 := &YAMLPlugin{
		ID:      "invalid-plugin",
		Name:    "Invalid Plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Triggers: []Trigger{
			{DataKey: "version", Condition: "version_lt", Value: "invalid.version"},
		},
		Output: OutputBlock{
			Message: "Invalid",
		},
	}

	plugins := []*YAMLPlugin{plugin1, plugin2}

	context := map[string]any{
		"service": "ssh",
		"version": "1.0.0",
	}

	_, err := evaluator.EvaluateAll(plugins, context)
	require.Error(t, err)
	require.Contains(t, err.Error(), "plugin[1]")
	require.Contains(t, err.Error(), "Invalid Plugin")
}

func TestEvaluator_EvaluateMatched_NoMatches(t *testing.T) {
	evaluator := NewEvaluator()

	plugin := &YAMLPlugin{
		ID:      "non-matching-plugin",
		Name:    "Non-Matching Plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Match: &MatchBlock{
			Logic: "AND",
			Rules: []MatchRule{
				{Field: "service", Operator: "equals", Value: "http"},
			},
		},
		Output: OutputBlock{
			Message: "Test",
		},
	}

	plugins := []*YAMLPlugin{plugin}

	context := map[string]any{
		"service": "ssh",
	}

	results, err := evaluator.EvaluateMatched(plugins, context)
	require.NoError(t, err)
	require.Len(t, results, 0) // No matches
}

func TestEvaluator_EvaluateMatched_WithError(t *testing.T) {
	evaluator := NewEvaluator()

	// Plugin with invalid trigger (will cause error)
	plugin := &YAMLPlugin{
		ID:      "invalid-plugin",
		Name:    "Invalid Plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Triggers: []Trigger{
			{DataKey: "version", Condition: "version_lt", Value: "invalid.version"},
		},
		Output: OutputBlock{
			Message: "Test",
		},
	}

	plugins := []*YAMLPlugin{plugin}

	context := map[string]any{
		"version": "1.0.0",
	}

	_, err := evaluator.EvaluateMatched(plugins, context)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid Plugin")
}

func TestEvaluator_EvaluateMatched(t *testing.T) {
	evaluator := NewEvaluator()

	plugin1 := &YAMLPlugin{
		ID:      "matching-plugin",
		Name:    "Matching Plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: HighSeverity,
			Tags:     []string{"test"},
		},
		Match: &MatchBlock{
			Logic: "AND",
			Rules: []MatchRule{
				{Field: "service", Operator: "equals", Value: "ssh"},
			},
		},
		Output: OutputBlock{
			Vulnerability: true,
			Message:       "SSH detected",
		},
	}

	plugin2 := &YAMLPlugin{
		ID:      "non-matching-plugin",
		Name:    "Non-Matching Plugin",
		Version: "1.0.0",
		Type:    EvaluationType,
		Author:  "test",
		Metadata: PluginMetadata{
			Severity: MediumSeverity,
			Tags:     []string{"test"},
		},
		Match: &MatchBlock{
			Logic: "AND",
			Rules: []MatchRule{
				{Field: "service", Operator: "equals", Value: "http"},
			},
		},
		Output: OutputBlock{
			Vulnerability: true,
			Message:       "HTTP detected",
		},
	}

	plugins := []*YAMLPlugin{plugin1, plugin2}

	context := map[string]any{
		"service": "ssh",
	}

	results, err := evaluator.EvaluateMatched(plugins, context)
	require.NoError(t, err)
	require.Len(t, results, 1)

	// Only plugin1 should match
	require.Equal(t, "Matching Plugin", results[0].Plugin.Name)
	require.True(t, results[0].Matched)
}
