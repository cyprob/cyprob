// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/rs/zerolog/log"
)

// MatcherEngine evaluates matching rules against a data context.
type MatcherEngine struct {
	operators map[string]OperatorFunc
}

// OperatorFunc is a function that evaluates a single rule.
// It takes the actual value from context and the expected value from the rule.
type OperatorFunc func(actual, expected any) (bool, error)

// NewMatcherEngine creates a new matcher engine with built-in operators.
func NewMatcherEngine() *MatcherEngine {
	m := &MatcherEngine{
		operators: make(map[string]OperatorFunc),
	}

	// Register built-in operators
	m.registerBuiltinOperators()

	return m
}

// RegisterOperator registers a custom operator.
func (m *MatcherEngine) RegisterOperator(name string, fn OperatorFunc) {
	m.operators[name] = fn
}

// Evaluate evaluates a match block against a data context.
// The context is a map of field paths to values.
func (m *MatcherEngine) Evaluate(match *MatchBlock, context map[string]any) (bool, error) {
	if match == nil {
		return false, fmt.Errorf("match block is nil")
	}

	if len(match.Rules) == 0 {
		return false, fmt.Errorf("no rules to evaluate")
	}

	// Evaluate all rules
	results := make([]bool, len(match.Rules))
	for i, rule := range match.Rules {
		result, err := m.evaluateRule(rule, context)
		if err != nil {
			return false, fmt.Errorf("rule[%d] evaluation failed: %w", i, err)
		}
		results[i] = result
	}

	// Apply logic
	switch match.Logic {
	case "AND":
		return allTrue(results), nil
	case "OR":
		return anyTrue(results), nil
	case "NOT":
		return !anyTrue(results), nil
	default:
		return false, fmt.Errorf("unknown logic: %s", match.Logic)
	}
}

// evaluateRule evaluates a single match rule against the context.
func (m *MatcherEngine) evaluateRule(rule MatchRule, context map[string]any) (bool, error) {
	// Get actual value from context
	actual, ok := context[rule.Field]
	if !ok {
		// Field doesn't exist in context
		log.Debug().
			Str("field", rule.Field).
			Msg("Rule field not found in context")
		return false, nil
	}

	// Get operator function
	opFunc, ok := m.operators[rule.Operator]
	if !ok {
		return false, fmt.Errorf("unknown operator: %s", rule.Operator)
	}

	// Debug log the comparison
	log.Debug().
		Str("field", rule.Field).
		Str("operator", rule.Operator).
		Interface("actual", actual).
		Interface("expected", rule.Value).
		Str("actual_type", fmt.Sprintf("%T", actual)).
		Str("expected_type", fmt.Sprintf("%T", rule.Value)).
		Msg("Evaluating rule")

	// Execute operator
	result, err := opFunc(actual, rule.Value)

	log.Debug().
		Str("field", rule.Field).
		Bool("result", result).
		Err(err).
		Msg("Rule evaluation result")

	return result, err
}

// registerBuiltinOperators registers all built-in operators.
func (m *MatcherEngine) registerBuiltinOperators() {
	// String operators
	m.RegisterOperator("equals", opEquals)
	m.RegisterOperator("contains", opContains)
	m.RegisterOperator("startsWith", opStartsWith)
	m.RegisterOperator("endsWith", opEndsWith)
	m.RegisterOperator("matches", opMatches)

	// Numeric operators
	m.RegisterOperator("gt", opGreaterThan)
	m.RegisterOperator("gte", opGreaterThanOrEqual)
	m.RegisterOperator("lt", opLessThan)
	m.RegisterOperator("lte", opLessThanOrEqual)
	m.RegisterOperator("between", opBetween)

	// Version operators
	m.RegisterOperator("version_eq", opVersionEqual)
	m.RegisterOperator("version_lt", opVersionLessThan)
	m.RegisterOperator("version_gt", opVersionGreaterThan)
	m.RegisterOperator("version_lte", opVersionLessThanOrEqual)
	m.RegisterOperator("version_gte", opVersionGreaterThanOrEqual)
	m.RegisterOperator("version_between", opVersionBetween)

	// Logical operators
	m.RegisterOperator("exists", opExists)
	m.RegisterOperator("in", opIn)
	m.RegisterOperator("notIn", opNotIn)
}

// String Operators

func opEquals(actual, expected any) (bool, error) {
	return toString(actual) == toString(expected), nil
}

func opContains(actual, expected any) (bool, error) {
	return strings.Contains(toString(actual), toString(expected)), nil
}

func opStartsWith(actual, expected any) (bool, error) {
	return strings.HasPrefix(toString(actual), toString(expected)), nil
}

func opEndsWith(actual, expected any) (bool, error) {
	return strings.HasSuffix(toString(actual), toString(expected)), nil
}

func opMatches(actual, expected any) (bool, error) {
	pattern := toString(expected)
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, fmt.Errorf("invalid regex pattern: %w", err)
	}
	return re.MatchString(toString(actual)), nil
}

// Numeric Operators

func opGreaterThan(actual, expected any) (bool, error) {
	a, err := toFloat64(actual)
	if err != nil {
		return false, err
	}
	e, err := toFloat64(expected)
	if err != nil {
		return false, err
	}
	return a > e, nil
}

func opGreaterThanOrEqual(actual, expected any) (bool, error) {
	a, err := toFloat64(actual)
	if err != nil {
		return false, err
	}
	e, err := toFloat64(expected)
	if err != nil {
		return false, err
	}
	return a >= e, nil
}

func opLessThan(actual, expected any) (bool, error) {
	a, err := toFloat64(actual)
	if err != nil {
		return false, err
	}
	e, err := toFloat64(expected)
	if err != nil {
		return false, err
	}
	return a < e, nil
}

func opLessThanOrEqual(actual, expected any) (bool, error) {
	a, err := toFloat64(actual)
	if err != nil {
		return false, err
	}
	e, err := toFloat64(expected)
	if err != nil {
		return false, err
	}
	return a <= e, nil
}

func opBetween(actual, expected any) (bool, error) {
	a, err := toFloat64(actual)
	if err != nil {
		return false, err
	}

	// Expected should be [min, max]
	bounds, ok := expected.([]any)
	if !ok || len(bounds) != 2 {
		return false, fmt.Errorf("between operator requires [min, max] array")
	}

	min, err := toFloat64(bounds[0])
	if err != nil {
		return false, err
	}

	max, err := toFloat64(bounds[1])
	if err != nil {
		return false, err
	}

	return a >= min && a <= max, nil
}

// Version Operators

func opVersionEqual(actual, expected any) (bool, error) {
	av, err := semver.NewVersion(toString(actual))
	if err != nil {
		return false, fmt.Errorf("invalid actual version: %w", err)
	}

	ev, err := semver.NewVersion(toString(expected))
	if err != nil {
		return false, fmt.Errorf("invalid expected version: %w", err)
	}

	return av.Equal(ev), nil
}

func opVersionLessThan(actual, expected any) (bool, error) {
	av, err := semver.NewVersion(toString(actual))
	if err != nil {
		return false, fmt.Errorf("invalid actual version: %w", err)
	}

	ev, err := semver.NewVersion(toString(expected))
	if err != nil {
		return false, fmt.Errorf("invalid expected version: %w", err)
	}

	return av.LessThan(ev), nil
}

func opVersionGreaterThan(actual, expected any) (bool, error) {
	av, err := semver.NewVersion(toString(actual))
	if err != nil {
		return false, fmt.Errorf("invalid actual version: %w", err)
	}

	ev, err := semver.NewVersion(toString(expected))
	if err != nil {
		return false, fmt.Errorf("invalid expected version: %w", err)
	}

	return av.GreaterThan(ev), nil
}

func opVersionLessThanOrEqual(actual, expected any) (bool, error) {
	av, err := semver.NewVersion(toString(actual))
	if err != nil {
		return false, fmt.Errorf("invalid actual version: %w", err)
	}

	ev, err := semver.NewVersion(toString(expected))
	if err != nil {
		return false, fmt.Errorf("invalid expected version: %w", err)
	}

	return av.LessThan(ev) || av.Equal(ev), nil
}

func opVersionGreaterThanOrEqual(actual, expected any) (bool, error) {
	av, err := semver.NewVersion(toString(actual))
	if err != nil {
		return false, fmt.Errorf("invalid actual version: %w", err)
	}

	ev, err := semver.NewVersion(toString(expected))
	if err != nil {
		return false, fmt.Errorf("invalid expected version: %w", err)
	}

	return av.GreaterThan(ev) || av.Equal(ev), nil
}

func opVersionBetween(actual, expected any) (bool, error) {
	av, err := semver.NewVersion(toString(actual))
	if err != nil {
		return false, fmt.Errorf("invalid actual version: %w", err)
	}

	// Expected should be [min, max]
	bounds, ok := expected.([]any)
	if !ok || len(bounds) != 2 {
		return false, fmt.Errorf("version_between operator requires [min, max] array")
	}

	minV, err := semver.NewVersion(toString(bounds[0]))
	if err != nil {
		return false, fmt.Errorf("invalid min version: %w", err)
	}

	maxV, err := semver.NewVersion(toString(bounds[1]))
	if err != nil {
		return false, fmt.Errorf("invalid max version: %w", err)
	}

	return (av.GreaterThan(minV) || av.Equal(minV)) && (av.LessThan(maxV) || av.Equal(maxV)), nil
}

// Logical Operators

func opExists(actual, expected any) (bool, error) {
	// Actual value exists if we reach here (context lookup succeeded)
	// Expected should be true/false
	exp, ok := expected.(bool)
	if !ok {
		return false, fmt.Errorf("exists operator requires boolean value")
	}
	return exp, nil
}

func opIn(actual, expected any) (bool, error) {
	actualStr := toString(actual)

	// Expected should be an array
	list, ok := expected.([]any)
	if !ok {
		return false, fmt.Errorf("in operator requires array value")
	}

	for _, item := range list {
		if toString(item) == actualStr {
			return true, nil
		}
	}

	return false, nil
}

func opNotIn(actual, expected any) (bool, error) {
	result, err := opIn(actual, expected)
	return !result, err
}

// Utility functions

func toString(v any) string {
	if v == nil {
		return ""
	}

	switch val := v.(type) {
	case string:
		return val
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(val)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func toFloat64(v any) (float64, error) {
	switch val := v.(type) {
	case float64:
		return val, nil
	case float32:
		return float64(val), nil
	case int:
		return float64(val), nil
	case int64:
		return float64(val), nil
	case int32:
		return float64(val), nil
	case string:
		return strconv.ParseFloat(val, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", v)
	}
}

func allTrue(values []bool) bool {
	for _, v := range values {
		if !v {
			return false
		}
	}
	return true
}

func anyTrue(values []bool) bool {
	for _, v := range values {
		if v {
			return true
		}
	}
	return false
}
