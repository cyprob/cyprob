// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTriggerEvaluator_ShouldTrigger(t *testing.T) {
	te := NewTriggerEvaluator()

	tests := []struct {
		name     string
		triggers []Trigger
		context  map[string]any
		want     bool
		wantErr  bool
	}{
		{
			name:     "no triggers - always trigger",
			triggers: []Trigger{},
			context:  map[string]any{},
			want:     true,
		},
		{
			name: "exists - key exists",
			triggers: []Trigger{
				{DataKey: "ssh.version", Condition: "exists", Value: true},
			},
			context: map[string]any{
				"ssh.version": "7.4.0",
			},
			want: true,
		},
		{
			name: "exists - key does not exist",
			triggers: []Trigger{
				{DataKey: "ssh.version", Condition: "exists", Value: true},
			},
			context: map[string]any{},
			want:    false,
		},
		{
			name: "equals - match",
			triggers: []Trigger{
				{DataKey: "service", Condition: "equals", Value: "ssh"},
			},
			context: map[string]any{
				"service": "ssh",
			},
			want: true,
		},
		{
			name: "equals - no match",
			triggers: []Trigger{
				{DataKey: "service", Condition: "equals", Value: "ssh"},
			},
			context: map[string]any{
				"service": "http",
			},
			want: false,
		},
		{
			name: "contains - match",
			triggers: []Trigger{
				{DataKey: "banner", Condition: "contains", Value: "OpenSSH"},
			},
			context: map[string]any{
				"banner": "OpenSSH_7.4p1 Ubuntu",
			},
			want: true,
		},
		{
			name: "version_lt - true",
			triggers: []Trigger{
				{DataKey: "ssh.version", Condition: "version_lt", Value: "8.0"},
			},
			context: map[string]any{
				"ssh.version": "7.4.0",
			},
			want: true,
		},
		{
			name: "version_lt - false",
			triggers: []Trigger{
				{DataKey: "ssh.version", Condition: "version_lt", Value: "7.0"},
			},
			context: map[string]any{
				"ssh.version": "7.4.0",
			},
			want: false,
		},
		{
			name: "multiple triggers - all satisfied",
			triggers: []Trigger{
				{DataKey: "service", Condition: "equals", Value: "ssh"},
				{DataKey: "ssh.version", Condition: "version_lt", Value: "8.0"},
			},
			context: map[string]any{
				"service":     "ssh",
				"ssh.version": "7.4.0",
			},
			want: true,
		},
		{
			name: "multiple triggers - one not satisfied",
			triggers: []Trigger{
				{DataKey: "service", Condition: "equals", Value: "ssh"},
				{DataKey: "ssh.version", Condition: "version_lt", Value: "7.0"},
			},
			context: map[string]any{
				"service":     "ssh",
				"ssh.version": "7.4.0",
			},
			want: false,
		},
		{
			name: "in - match",
			triggers: []Trigger{
				{DataKey: "service", Condition: "in", Value: []any{"ssh", "telnet", "ftp"}},
			},
			context: map[string]any{
				"service": "ssh",
			},
			want: true,
		},
		{
			name: "notIn - match",
			triggers: []Trigger{
				{DataKey: "service", Condition: "notIn", Value: []any{"http", "https"}},
			},
			context: map[string]any{
				"service": "ssh",
			},
			want: true,
		},
		{
			name: "gt - true",
			triggers: []Trigger{
				{DataKey: "port", Condition: "gt", Value: 1000},
			},
			context: map[string]any{
				"port": 8080,
			},
			want: true,
		},
		{
			name: "unknown condition",
			triggers: []Trigger{
				{DataKey: "service", Condition: "unknown_condition", Value: "ssh"},
			},
			context: map[string]any{
				"service": "ssh",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := te.ShouldTrigger(tt.triggers, tt.context)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// Additional tests for missing trigger conditions

func TestTriggerEvaluator_AllConditions(t *testing.T) {
	te := NewTriggerEvaluator()

	tests := []struct {
		name     string
		triggers []Trigger
		context  map[string]any
		want     bool
		wantErr  bool
	}{
		// matches (regex)
		{
			name: "matches - regex match",
			triggers: []Trigger{
				{DataKey: "banner", Condition: "matches", Value: "OpenSSH_\\d+\\.\\d+"},
			},
			context: map[string]any{
				"banner": "OpenSSH_7.4p1",
			},
			want: true,
		},
		{
			name: "matches - regex no match",
			triggers: []Trigger{
				{DataKey: "banner", Condition: "matches", Value: "Dropbear"},
			},
			context: map[string]any{
				"banner": "OpenSSH_7.4p1",
			},
			want: false,
		},
		{
			name: "matches - key missing",
			triggers: []Trigger{
				{DataKey: "banner", Condition: "matches", Value: "OpenSSH"},
			},
			context: map[string]any{},
			want:    false,
		},

		// version_gt
		{
			name: "version_gt - true",
			triggers: []Trigger{
				{DataKey: "version", Condition: "version_gt", Value: "1.0.0"},
			},
			context: map[string]any{
				"version": "2.0.0",
			},
			want: true,
		},
		{
			name: "version_gt - false",
			triggers: []Trigger{
				{DataKey: "version", Condition: "version_gt", Value: "2.0.0"},
			},
			context: map[string]any{
				"version": "1.0.0",
			},
			want: false,
		},

		// version_eq
		{
			name: "version_eq - equal",
			triggers: []Trigger{
				{DataKey: "version", Condition: "version_eq", Value: "1.2.3"},
			},
			context: map[string]any{
				"version": "1.2.3",
			},
			want: true,
		},
		{
			name: "version_eq - not equal",
			triggers: []Trigger{
				{DataKey: "version", Condition: "version_eq", Value: "1.2.3"},
			},
			context: map[string]any{
				"version": "1.2.4",
			},
			want: false,
		},

		// version_lte
		{
			name: "version_lte - less",
			triggers: []Trigger{
				{DataKey: "version", Condition: "version_lte", Value: "2.0.0"},
			},
			context: map[string]any{
				"version": "1.0.0",
			},
			want: true,
		},
		{
			name: "version_lte - equal",
			triggers: []Trigger{
				{DataKey: "version", Condition: "version_lte", Value: "2.0.0"},
			},
			context: map[string]any{
				"version": "2.0.0",
			},
			want: true,
		},

		// version_gte
		{
			name: "version_gte - greater",
			triggers: []Trigger{
				{DataKey: "version", Condition: "version_gte", Value: "1.0.0"},
			},
			context: map[string]any{
				"version": "2.0.0",
			},
			want: true,
		},
		{
			name: "version_gte - equal",
			triggers: []Trigger{
				{DataKey: "version", Condition: "version_gte", Value: "1.0.0"},
			},
			context: map[string]any{
				"version": "1.0.0",
			},
			want: true,
		},

		// gte (numeric)
		{
			name: "gte - greater",
			triggers: []Trigger{
				{DataKey: "count", Condition: "gte", Value: 10},
			},
			context: map[string]any{
				"count": 20,
			},
			want: true,
		},
		{
			name: "gte - equal",
			triggers: []Trigger{
				{DataKey: "count", Condition: "gte", Value: 10},
			},
			context: map[string]any{
				"count": 10,
			},
			want: true,
		},
		{
			name: "gte - less",
			triggers: []Trigger{
				{DataKey: "count", Condition: "gte", Value: 10},
			},
			context: map[string]any{
				"count": 5,
			},
			want: false,
		},

		// lt (numeric)
		{
			name: "lt - true",
			triggers: []Trigger{
				{DataKey: "count", Condition: "lt", Value: 10},
			},
			context: map[string]any{
				"count": 5,
			},
			want: true,
		},
		{
			name: "lt - false",
			triggers: []Trigger{
				{DataKey: "count", Condition: "lt", Value: 10},
			},
			context: map[string]any{
				"count": 20,
			},
			want: false,
		},

		// lte (numeric)
		{
			name: "lte - less",
			triggers: []Trigger{
				{DataKey: "count", Condition: "lte", Value: 10},
			},
			context: map[string]any{
				"count": 5,
			},
			want: true,
		},
		{
			name: "lte - equal",
			triggers: []Trigger{
				{DataKey: "count", Condition: "lte", Value: 10},
			},
			context: map[string]any{
				"count": 10,
			},
			want: true,
		},
		{
			name: "lte - greater",
			triggers: []Trigger{
				{DataKey: "count", Condition: "lte", Value: 10},
			},
			context: map[string]any{
				"count": 20,
			},
			want: false,
		},

		// Test missing keys for all conditions
		{
			name: "equals - key missing",
			triggers: []Trigger{
				{DataKey: "service", Condition: "equals", Value: "ssh"},
			},
			context: map[string]any{},
			want:    false,
		},
		{
			name: "contains - key missing",
			triggers: []Trigger{
				{DataKey: "banner", Condition: "contains", Value: "OpenSSH"},
			},
			context: map[string]any{},
			want:    false,
		},
		{
			name: "version_lt - key missing",
			triggers: []Trigger{
				{DataKey: "version", Condition: "version_lt", Value: "1.0.0"},
			},
			context: map[string]any{},
			want:    false,
		},
		{
			name: "version_gt - key missing",
			triggers: []Trigger{
				{DataKey: "version", Condition: "version_gt", Value: "1.0.0"},
			},
			context: map[string]any{},
			want:    false,
		},
		{
			name: "version_eq - key missing",
			triggers: []Trigger{
				{DataKey: "version", Condition: "version_eq", Value: "1.0.0"},
			},
			context: map[string]any{},
			want:    false,
		},
		{
			name: "version_lte - key missing",
			triggers: []Trigger{
				{DataKey: "version", Condition: "version_lte", Value: "1.0.0"},
			},
			context: map[string]any{},
			want:    false,
		},
		{
			name: "version_gte - key missing",
			triggers: []Trigger{
				{DataKey: "version", Condition: "version_gte", Value: "1.0.0"},
			},
			context: map[string]any{},
			want:    false,
		},
		{
			name: "gt - key missing",
			triggers: []Trigger{
				{DataKey: "count", Condition: "gt", Value: 10},
			},
			context: map[string]any{},
			want:    false,
		},
		{
			name: "gte - key missing",
			triggers: []Trigger{
				{DataKey: "count", Condition: "gte", Value: 10},
			},
			context: map[string]any{},
			want:    false,
		},
		{
			name: "lt - key missing",
			triggers: []Trigger{
				{DataKey: "count", Condition: "lt", Value: 10},
			},
			context: map[string]any{},
			want:    false,
		},
		{
			name: "lte - key missing",
			triggers: []Trigger{
				{DataKey: "count", Condition: "lte", Value: 10},
			},
			context: map[string]any{},
			want:    false,
		},
		{
			name: "in - key missing",
			triggers: []Trigger{
				{DataKey: "service", Condition: "in", Value: []any{"ssh", "http"}},
			},
			context: map[string]any{},
			want:    false,
		},
		{
			name: "notIn - key missing",
			triggers: []Trigger{
				{DataKey: "service", Condition: "notIn", Value: []any{"ssh", "http"}},
			},
			context: map[string]any{},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := te.ShouldTrigger(tt.triggers, tt.context)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestTriggerEvaluator_ErrorCases(t *testing.T) {
	te := NewTriggerEvaluator()

	tests := []struct {
		name     string
		triggers []Trigger
		context  map[string]any
	}{
		{
			name: "exists - invalid value type",
			triggers: []Trigger{
				{DataKey: "key", Condition: "exists", Value: "not a bool"},
			},
			context: map[string]any{
				"key": "value",
			},
		},
		{
			name: "matches - invalid regex",
			triggers: []Trigger{
				{DataKey: "banner", Condition: "matches", Value: "[invalid(regex"},
			},
			context: map[string]any{
				"banner": "test",
			},
		},
		{
			name: "version_lt - invalid version",
			triggers: []Trigger{
				{DataKey: "version", Condition: "version_lt", Value: "not.a.version"},
			},
			context: map[string]any{
				"version": "1.0.0",
			},
		},
		{
			name: "gt - invalid number",
			triggers: []Trigger{
				{DataKey: "count", Condition: "gt", Value: 10},
			},
			context: map[string]any{
				"count": "not a number",
			},
		},
		{
			name: "in - invalid format",
			triggers: []Trigger{
				{DataKey: "service", Condition: "in", Value: "not an array"},
			},
			context: map[string]any{
				"service": "ssh",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := te.ShouldTrigger(tt.triggers, tt.context)
			require.Error(t, err)
		})
	}
}

func TestTriggerEvaluator_NotExists(t *testing.T) {
	te := NewTriggerEvaluator()

	tests := []struct {
		name     string
		triggers []Trigger
		context  map[string]any
	}{
		{
			name: "exists - invalid value type",
			triggers: []Trigger{
				{DataKey: "key", Condition: "exists", Value: "not a bool"},
			},
			context: map[string]any{
				"key": "value",
			},
		},
		{
			name: "matches - invalid regex",
			triggers: []Trigger{
				{DataKey: "banner", Condition: "matches", Value: "[invalid(regex"},
			},
			context: map[string]any{
				"banner": "test",
			},
		},
		{
			name: "version_lt - invalid version",
			triggers: []Trigger{
				{DataKey: "version", Condition: "version_lt", Value: "not.a.version"},
			},
			context: map[string]any{
				"version": "1.0.0",
			},
		},
		{
			name: "gt - invalid number",
			triggers: []Trigger{
				{DataKey: "count", Condition: "gt", Value: 10},
			},
			context: map[string]any{
				"count": "not a number",
			},
		},
		{
			name: "in - invalid format",
			triggers: []Trigger{
				{DataKey: "service", Condition: "in", Value: "not an array"},
			},
			context: map[string]any{
				"service": "ssh",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := te.ShouldTrigger(tt.triggers, tt.context)
			require.Error(t, err)
		})
	}
}
