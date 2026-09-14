// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatcherEngine_StringOperators(t *testing.T) {
	m := NewMatcherEngine()

	tests := []struct {
		name     string
		operator string
		actual   any
		expected any
		want     bool
		wantErr  bool
	}{
		// Equals
		{
			name:     "equals - match",
			operator: "equals",
			actual:   "test",
			expected: "test",
			want:     true,
		},
		{
			name:     "equals - no match",
			operator: "equals",
			actual:   "test",
			expected: "other",
			want:     false,
		},

		// Contains
		{
			name:     "contains - match",
			operator: "contains",
			actual:   "hello world",
			expected: "world",
			want:     true,
		},
		{
			name:     "contains - no match",
			operator: "contains",
			actual:   "hello world",
			expected: "foo",
			want:     false,
		},

		// StartsWith
		{
			name:     "startsWith - match",
			operator: "startsWith",
			actual:   "OpenSSH_8.2",
			expected: "OpenSSH",
			want:     true,
		},
		{
			name:     "startsWith - no match",
			operator: "startsWith",
			actual:   "OpenSSH_8.2",
			expected: "Dropbear",
			want:     false,
		},

		// EndsWith
		{
			name:     "endsWith - match",
			operator: "endsWith",
			actual:   "server.conf",
			expected: ".conf",
			want:     true,
		},
		{
			name:     "endsWith - no match",
			operator: "endsWith",
			actual:   "server.conf",
			expected: ".txt",
			want:     false,
		},

		// Matches (regex)
		{
			name:     "matches - simple regex",
			operator: "matches",
			actual:   "OpenSSH_8.2",
			expected: "OpenSSH_\\d+\\.\\d+",
			want:     true,
		},
		{
			name:     "matches - no match",
			operator: "matches",
			actual:   "OpenSSH_8.2",
			expected: "Dropbear",
			want:     false,
		},
		{
			name:     "matches - invalid regex",
			operator: "matches",
			actual:   "test",
			expected: "[invalid(regex",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opFunc, ok := m.operators[tt.operator]
			require.True(t, ok, "operator not found: %s", tt.operator)

			got, err := opFunc(tt.actual, tt.expected)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestMatcherEngine_NumericOperators(t *testing.T) {
	m := NewMatcherEngine()

	tests := []struct {
		name     string
		operator string
		actual   any
		expected any
		want     bool
		wantErr  bool
	}{
		// Greater than
		{
			name:     "gt - true",
			operator: "gt",
			actual:   10,
			expected: 5,
			want:     true,
		},
		{
			name:     "gt - false",
			operator: "gt",
			actual:   5,
			expected: 10,
			want:     false,
		},

		// Greater than or equal
		{
			name:     "gte - equal",
			operator: "gte",
			actual:   10,
			expected: 10,
			want:     true,
		},
		{
			name:     "gte - greater",
			operator: "gte",
			actual:   10,
			expected: 5,
			want:     true,
		},
		{
			name:     "gte - less",
			operator: "gte",
			actual:   5,
			expected: 10,
			want:     false,
		},

		// Less than
		{
			name:     "lt - true",
			operator: "lt",
			actual:   5,
			expected: 10,
			want:     true,
		},
		{
			name:     "lt - false",
			operator: "lt",
			actual:   10,
			expected: 5,
			want:     false,
		},

		// Less than or equal
		{
			name:     "lte - equal",
			operator: "lte",
			actual:   10,
			expected: 10,
			want:     true,
		},
		{
			name:     "lte - less",
			operator: "lte",
			actual:   5,
			expected: 10,
			want:     true,
		},
		{
			name:     "lte - greater",
			operator: "lte",
			actual:   10,
			expected: 5,
			want:     false,
		},

		// Between
		{
			name:     "between - inside range",
			operator: "between",
			actual:   5,
			expected: []any{1, 10},
			want:     true,
		},
		{
			name:     "between - outside range",
			operator: "between",
			actual:   15,
			expected: []any{1, 10},
			want:     false,
		},
		{
			name:     "between - at boundary",
			operator: "between",
			actual:   10,
			expected: []any{1, 10},
			want:     true,
		},
		{
			name:     "between - invalid format",
			operator: "between",
			actual:   5,
			expected: 10,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opFunc, ok := m.operators[tt.operator]
			require.True(t, ok, "operator not found: %s", tt.operator)

			got, err := opFunc(tt.actual, tt.expected)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestMatcherEngine_VersionOperators(t *testing.T) {
	m := NewMatcherEngine()

	tests := []struct {
		name     string
		operator string
		actual   any
		expected any
		want     bool
		wantErr  bool
	}{
		// Version equal
		{
			name:     "version_eq - equal",
			operator: "version_eq",
			actual:   "1.2.3",
			expected: "1.2.3",
			want:     true,
		},
		{
			name:     "version_eq - not equal",
			operator: "version_eq",
			actual:   "1.2.3",
			expected: "1.2.4",
			want:     false,
		},

		// Version less than
		{
			name:     "version_lt - true",
			operator: "version_lt",
			actual:   "1.2.3",
			expected: "2.0.0",
			want:     true,
		},
		{
			name:     "version_lt - false",
			operator: "version_lt",
			actual:   "2.0.0",
			expected: "1.2.3",
			want:     false,
		},

		// Version greater than
		{
			name:     "version_gt - true",
			operator: "version_gt",
			actual:   "2.0.0",
			expected: "1.2.3",
			want:     true,
		},
		{
			name:     "version_gt - false",
			operator: "version_gt",
			actual:   "1.2.3",
			expected: "2.0.0",
			want:     false,
		},

		// Version less than or equal
		{
			name:     "version_lte - less",
			operator: "version_lte",
			actual:   "1.2.3",
			expected: "2.0.0",
			want:     true,
		},
		{
			name:     "version_lte - equal",
			operator: "version_lte",
			actual:   "1.2.3",
			expected: "1.2.3",
			want:     true,
		},

		// Version greater than or equal
		{
			name:     "version_gte - greater",
			operator: "version_gte",
			actual:   "2.0.0",
			expected: "1.2.3",
			want:     true,
		},
		{
			name:     "version_gte - equal",
			operator: "version_gte",
			actual:   "1.2.3",
			expected: "1.2.3",
			want:     true,
		},

		// Version between
		{
			name:     "version_between - inside range",
			operator: "version_between",
			actual:   "1.5.0",
			expected: []any{"1.0.0", "2.0.0"},
			want:     true,
		},
		{
			name:     "version_between - outside range",
			operator: "version_between",
			actual:   "3.0.0",
			expected: []any{"1.0.0", "2.0.0"},
			want:     false,
		},

		// Invalid versions
		{
			name:     "version_eq - invalid actual",
			operator: "version_eq",
			actual:   "not-a-version",
			expected: "1.2.3",
			wantErr:  true,
		},
		{
			name:     "version_eq - invalid expected",
			operator: "version_eq",
			actual:   "1.2.3",
			expected: "not-a-version",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opFunc, ok := m.operators[tt.operator]
			require.True(t, ok, "operator not found: %s", tt.operator)

			got, err := opFunc(tt.actual, tt.expected)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestMatcherEngine_LogicalOperators(t *testing.T) {
	m := NewMatcherEngine()

	tests := []struct {
		name     string
		operator string
		actual   any
		expected any
		want     bool
		wantErr  bool
	}{
		// Exists
		{
			name:     "exists - true",
			operator: "exists",
			actual:   "anything",
			expected: true,
			want:     true,
		},
		{
			name:     "exists - invalid expected",
			operator: "exists",
			actual:   "anything",
			expected: "not-a-bool",
			wantErr:  true,
		},

		// In
		{
			name:     "in - found",
			operator: "in",
			actual:   "admin",
			expected: []any{"admin", "root", "user"},
			want:     true,
		},
		{
			name:     "in - not found",
			operator: "in",
			actual:   "guest",
			expected: []any{"admin", "root", "user"},
			want:     false,
		},
		{
			name:     "in - invalid expected",
			operator: "in",
			actual:   "admin",
			expected: "not-an-array",
			wantErr:  true,
		},

		// NotIn
		{
			name:     "notIn - not found",
			operator: "notIn",
			actual:   "guest",
			expected: []any{"admin", "root", "user"},
			want:     true,
		},
		{
			name:     "notIn - found",
			operator: "notIn",
			actual:   "admin",
			expected: []any{"admin", "root", "user"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opFunc, ok := m.operators[tt.operator]
			require.True(t, ok, "operator not found: %s", tt.operator)

			got, err := opFunc(tt.actual, tt.expected)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestMatcherEngine_Evaluate(t *testing.T) {
	m := NewMatcherEngine()

	tests := []struct {
		name    string
		match   *MatchBlock
		context map[string]any
		want    bool
		wantErr bool
	}{
		{
			name: "AND logic - all true",
			match: &MatchBlock{
				Logic: "AND",
				Rules: []MatchRule{
					{Field: "service", Operator: "equals", Value: "ssh"},
					{Field: "port", Operator: "equals", Value: "22"},
				},
			},
			context: map[string]any{
				"service": "ssh",
				"port":    "22",
			},
			want: true,
		},
		{
			name: "AND logic - one false",
			match: &MatchBlock{
				Logic: "AND",
				Rules: []MatchRule{
					{Field: "service", Operator: "equals", Value: "ssh"},
					{Field: "port", Operator: "equals", Value: "23"},
				},
			},
			context: map[string]any{
				"service": "ssh",
				"port":    "22",
			},
			want: false,
		},
		{
			name: "OR logic - one true",
			match: &MatchBlock{
				Logic: "OR",
				Rules: []MatchRule{
					{Field: "service", Operator: "equals", Value: "ssh"},
					{Field: "service", Operator: "equals", Value: "telnet"},
				},
			},
			context: map[string]any{
				"service": "ssh",
			},
			want: true,
		},
		{
			name: "OR logic - all false",
			match: &MatchBlock{
				Logic: "OR",
				Rules: []MatchRule{
					{Field: "service", Operator: "equals", Value: "telnet"},
					{Field: "service", Operator: "equals", Value: "ftp"},
				},
			},
			context: map[string]any{
				"service": "ssh",
			},
			want: false,
		},
		{
			name: "NOT logic - should be false",
			match: &MatchBlock{
				Logic: "NOT",
				Rules: []MatchRule{
					{Field: "service", Operator: "equals", Value: "ssh"},
				},
			},
			context: map[string]any{
				"service": "ssh",
			},
			want: false,
		},
		{
			name: "NOT logic - should be true",
			match: &MatchBlock{
				Logic: "NOT",
				Rules: []MatchRule{
					{Field: "service", Operator: "equals", Value: "telnet"},
				},
			},
			context: map[string]any{
				"service": "ssh",
			},
			want: true,
		},
		{
			name: "complex - version check",
			match: &MatchBlock{
				Logic: "AND",
				Rules: []MatchRule{
					{Field: "ssh.version", Operator: "version_lt", Value: "8.5"},
					{Field: "ssh.banner", Operator: "contains", Value: "OpenSSH"},
				},
			},
			context: map[string]any{
				"ssh.version": "7.4.0",
				"ssh.banner":  "OpenSSH_7.4p1",
			},
			want: true,
		},
		{
			name:    "nil match block",
			match:   nil,
			context: map[string]any{},
			wantErr: true,
		},
		{
			name: "empty rules",
			match: &MatchBlock{
				Logic: "AND",
				Rules: []MatchRule{},
			},
			context: map[string]any{},
			wantErr: true,
		},
		{
			name: "unknown operator",
			match: &MatchBlock{
				Logic: "AND",
				Rules: []MatchRule{
					{Field: "service", Operator: "unknown_op", Value: "ssh"},
				},
			},
			context: map[string]any{
				"service": "ssh",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := m.Evaluate(tt.match, tt.context)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestMatcherEngine_CustomOperator(t *testing.T) {
	m := NewMatcherEngine()

	// Register custom operator
	m.RegisterOperator("custom_test", func(actual, expected any) (bool, error) {
		return toString(actual) == "custom", nil
	})

	match := &MatchBlock{
		Logic: "AND",
		Rules: []MatchRule{
			{Field: "value", Operator: "custom_test", Value: "anything"},
		},
	}

	context := map[string]any{
		"value": "custom",
	}

	got, err := m.Evaluate(match, context)
	require.NoError(t, err)
	require.True(t, got)
}

// Additional tests for better coverage

func TestUtilityFunctions_ToString(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  string
	}{
		{
			name:  "string",
			input: "hello",
			want:  "hello",
		},
		{
			name:  "int",
			input: 42,
			want:  "42",
		},
		{
			name:  "int64",
			input: int64(123456789),
			want:  "123456789",
		},
		{
			name:  "float64",
			input: 3.14,
			want:  "3.14",
		},
		{
			name:  "bool true",
			input: true,
			want:  "true",
		},
		{
			name:  "bool false",
			input: false,
			want:  "false",
		},
		{
			name:  "nil",
			input: nil,
			want:  "",
		},
		{
			name:  "other type (struct)",
			input: struct{ Name string }{Name: "test"},
			want:  "{test}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toString(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestUtilityFunctions_ToFloat64(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		want    float64
		wantErr bool
	}{
		{
			name:  "float64",
			input: 3.14,
			want:  3.14,
		},
		{
			name:  "float32",
			input: float32(2.5),
			want:  2.5,
		},
		{
			name:  "int",
			input: 42,
			want:  42.0,
		},
		{
			name:  "int64",
			input: int64(100),
			want:  100.0,
		},
		{
			name:  "int32",
			input: int32(50),
			want:  50.0,
		},
		{
			name:  "string number",
			input: "123.45",
			want:  123.45,
		},
		{
			name:    "string non-number",
			input:   "not a number",
			wantErr: true,
		},
		{
			name:    "unsupported type",
			input:   struct{}{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toFloat64(tt.input)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestNumericOperators_ErrorCases(t *testing.T) {
	tests := []struct {
		name     string
		operator string
		actual   any
		expected any
	}{
		{
			name:     "gt - invalid actual",
			operator: "gt",
			actual:   "not a number",
			expected: 10,
		},
		{
			name:     "gt - invalid expected",
			operator: "gt",
			actual:   10,
			expected: "not a number",
		},
		{
			name:     "gte - invalid actual",
			operator: "gte",
			actual:   struct{}{},
			expected: 10,
		},
		{
			name:     "lt - invalid actual",
			operator: "lt",
			actual:   "abc",
			expected: 10,
		},
		{
			name:     "lte - invalid expected",
			operator: "lte",
			actual:   10,
			expected: "xyz",
		},
	}

	m := NewMatcherEngine()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opFunc := m.operators[tt.operator]
			_, err := opFunc(tt.actual, tt.expected)
			require.Error(t, err)
		})
	}
}

func TestVersionOperators_ErrorCases(t *testing.T) {
	tests := []struct {
		name     string
		operator string
		actual   any
		expected any
	}{
		{
			name:     "version_lt - invalid actual version",
			operator: "version_lt",
			actual:   "not.a.version",
			expected: "1.0.0",
		},
		{
			name:     "version_lt - invalid expected version",
			operator: "version_lt",
			actual:   "1.0.0",
			expected: "invalid",
		},
		{
			name:     "version_gt - invalid actual",
			operator: "version_gt",
			actual:   "v999.999.999.999.999",
			expected: "1.0.0",
		},
		{
			name:     "version_gte - invalid actual",
			operator: "version_gte",
			actual:   "bad-version",
			expected: "1.0.0",
		},
		{
			name:     "version_lte - invalid expected",
			operator: "version_lte",
			actual:   "1.0.0",
			expected: "not-valid",
		},
		{
			name:     "version_between - invalid format",
			operator: "version_between",
			actual:   "1.5.0",
			expected: "not an array",
		},
		{
			name:     "version_between - invalid min",
			operator: "version_between",
			actual:   "1.5.0",
			expected: []any{"bad-version", "2.0.0"},
		},
		{
			name:     "version_between - invalid max",
			operator: "version_between",
			actual:   "1.5.0",
			expected: []any{"1.0.0", "bad-max"},
		},
	}

	m := NewMatcherEngine()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opFunc := m.operators[tt.operator]
			_, err := opFunc(tt.actual, tt.expected)
			require.Error(t, err)
		})
	}
}

func TestBetweenOperator_ErrorCases(t *testing.T) {
	m := NewMatcherEngine()
	opBetween := m.operators["between"]

	tests := []struct {
		name     string
		actual   any
		expected any
	}{
		{
			name:     "invalid format - not array",
			actual:   5,
			expected: 10,
		},
		{
			name:     "invalid format - wrong length",
			actual:   5,
			expected: []any{1},
		},
		{
			name:     "invalid min value",
			actual:   5,
			expected: []any{"not a number", 10},
		},
		{
			name:     "invalid max value",
			actual:   5,
			expected: []any{1, "not a number"},
		},
		{
			name:     "invalid actual value",
			actual:   "not a number",
			expected: []any{1, 10},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := opBetween(tt.actual, tt.expected)
			require.Error(t, err)
		})
	}
}

// Additional coverage tests for missing edge cases

func TestMatcherEngine_Evaluate_NilMatchBlock(t *testing.T) {
	m := NewMatcherEngine()

	_, err := m.Evaluate(nil, map[string]any{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "match block is nil")
}

func TestMatcherEngine_Evaluate_NoRules(t *testing.T) {
	m := NewMatcherEngine()

	match := &MatchBlock{
		Logic: "AND",
		Rules: []MatchRule{},
	}

	_, err := m.Evaluate(match, map[string]any{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no rules to evaluate")
}

func TestMatcherEngine_EvaluateRule_UnknownOperator(t *testing.T) {
	m := NewMatcherEngine()

	match := &MatchBlock{
		Logic: "AND",
		Rules: []MatchRule{
			{Field: "test", Operator: "unknown_operator", Value: "test"},
		},
	}

	context := map[string]any{
		"test": "value",
	}

	_, err := m.Evaluate(match, context)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown operator")
}

func TestMatcherEngine_EvaluateRule_FieldNotInContext(t *testing.T) {
	m := NewMatcherEngine()

	match := &MatchBlock{
		Logic: "AND",
		Rules: []MatchRule{
			{Field: "missing_field", Operator: "equals", Value: "test"},
		},
	}

	context := map[string]any{
		"other_field": "value",
	}

	// Should return false when field is missing
	result, err := m.Evaluate(match, context)
	require.NoError(t, err)
	require.False(t, result)
}

// Numeric operator expected value error cases

func TestNumericOperators_ExpectedValueErrors(t *testing.T) {
	tests := []struct {
		name     string
		operator func(actual, expected any) (bool, error)
		actual   any
		expected any
	}{
		{
			name:     "gte - invalid expected",
			operator: opGreaterThanOrEqual,
			actual:   10,
			expected: "not a number",
		},
		{
			name:     "lt - invalid expected",
			operator: opLessThan,
			actual:   10,
			expected: "not a number",
		},
		{
			name:     "lte - invalid expected",
			operator: opLessThanOrEqual,
			actual:   10,
			expected: "not a number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.operator(tt.actual, tt.expected)
			require.Error(t, err)
		})
	}
}

// Version operator expected value error cases

func TestVersionOperators_ExpectedValueErrors(t *testing.T) {
	tests := []struct {
		name     string
		operator func(actual, expected any) (bool, error)
		actual   any
		expected any
	}{
		{
			name:     "version_gt - invalid expected",
			operator: opVersionGreaterThan,
			actual:   "1.0.0",
			expected: "invalid.version",
		},
		{
			name:     "version_lte - invalid expected",
			operator: opVersionLessThanOrEqual,
			actual:   "1.0.0",
			expected: "invalid.version",
		},
		{
			name:     "version_gte - invalid expected",
			operator: opVersionGreaterThanOrEqual,
			actual:   "1.0.0",
			expected: "invalid.version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.operator(tt.actual, tt.expected)
			require.Error(t, err)
		})
	}
}

func TestVersionBetween_MaxVersionError(t *testing.T) {
	_, err := opVersionBetween("1.5.0", []any{"1.0.0", "invalid.max"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid max version")
}

func TestVersionBetween_ActualVersionError(t *testing.T) {
	_, err := opVersionBetween("invalid.version", []any{"1.0.0", "2.0.0"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid actual version")
}

// Missing actual value error cases

func TestNumericOperators_ActualValueErrors(t *testing.T) {
	tests := []struct {
		name     string
		operator func(actual, expected any) (bool, error)
		actual   any
		expected any
	}{
		{
			name:     "lte - invalid actual",
			operator: opLessThanOrEqual,
			actual:   "not a number",
			expected: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.operator(tt.actual, tt.expected)
			require.Error(t, err)
		})
	}
}

func TestVersionOperators_ActualValueErrors(t *testing.T) {
	tests := []struct {
		name     string
		operator func(actual, expected any) (bool, error)
		actual   any
		expected any
	}{
		{
			name:     "version_lte - invalid actual",
			operator: opVersionLessThanOrEqual,
			actual:   "invalid.version",
			expected: "1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.operator(tt.actual, tt.expected)
			require.Error(t, err)
		})
	}
}

func TestMatcherEngine_Evaluate_UnknownLogic(t *testing.T) {
	m := NewMatcherEngine()

	match := &MatchBlock{
		Logic: "UNKNOWN_LOGIC",
		Rules: []MatchRule{
			{Field: "test", Operator: "equals", Value: "value"},
		},
	}

	context := map[string]any{
		"test": "value",
	}

	_, err := m.Evaluate(match, context)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown logic")
}
