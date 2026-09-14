// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"fmt"
)

// TriggerEvaluator evaluates trigger conditions against a data context.
type TriggerEvaluator struct {
	matcher *MatcherEngine
}

// NewTriggerEvaluator creates a new trigger evaluator.
func NewTriggerEvaluator() *TriggerEvaluator {
	return &TriggerEvaluator{
		matcher: NewMatcherEngine(),
	}
}

// ShouldTrigger checks if a plugin should be triggered based on the data context.
// Returns true if ALL triggers are satisfied.
func (t *TriggerEvaluator) ShouldTrigger(triggers []Trigger, context map[string]any) (bool, error) {
	if len(triggers) == 0 {
		// No triggers means always trigger
		return true, nil
	}

	for i, trigger := range triggers {
		satisfied, err := t.evaluateTrigger(trigger, context)
		if err != nil {
			return false, fmt.Errorf("trigger[%d] evaluation failed: %w", i, err)
		}

		if !satisfied {
			// Any unsatisfied trigger means don't trigger
			return false, nil
		}
	}

	// All triggers satisfied
	return true, nil
}

// evaluateTrigger evaluates a single trigger condition.
func (t *TriggerEvaluator) evaluateTrigger(trigger Trigger, context map[string]any) (bool, error) {
	// Get value from context
	actual, exists := context[trigger.DataKey]

	switch trigger.Condition {
	case "exists":
		// Check if the data key exists in the context
		expectedExists, ok := trigger.Value.(bool)
		if !ok {
			return false, fmt.Errorf("exists condition requires boolean value")
		}
		return exists == expectedExists, nil

	case "equals":
		// Check if value equals expected
		if !exists {
			return false, nil
		}
		return toString(actual) == toString(trigger.Value), nil

	case "contains":
		// Check if value contains substring
		if !exists {
			return false, nil
		}
		return t.matcher.operators["contains"](actual, trigger.Value)

	case "matches":
		// Check if value matches regex
		if !exists {
			return false, nil
		}
		return t.matcher.operators["matches"](actual, trigger.Value)

	case "version_lt":
		// Check if version is less than expected
		if !exists {
			return false, nil
		}
		return t.matcher.operators["version_lt"](actual, trigger.Value)

	case "version_gt":
		// Check if version is greater than expected
		if !exists {
			return false, nil
		}
		return t.matcher.operators["version_gt"](actual, trigger.Value)

	case "version_eq":
		// Check if version equals expected
		if !exists {
			return false, nil
		}
		return t.matcher.operators["version_eq"](actual, trigger.Value)

	case "version_lte":
		// Check if version is less than or equal to expected
		if !exists {
			return false, nil
		}
		return t.matcher.operators["version_lte"](actual, trigger.Value)

	case "version_gte":
		// Check if version is greater than or equal to expected
		if !exists {
			return false, nil
		}
		return t.matcher.operators["version_gte"](actual, trigger.Value)

	case "gt":
		// Greater than (numeric)
		if !exists {
			return false, nil
		}
		return t.matcher.operators["gt"](actual, trigger.Value)

	case "gte":
		// Greater than or equal (numeric)
		if !exists {
			return false, nil
		}
		return t.matcher.operators["gte"](actual, trigger.Value)

	case "lt":
		// Less than (numeric)
		if !exists {
			return false, nil
		}
		return t.matcher.operators["lt"](actual, trigger.Value)

	case "lte":
		// Less than or equal (numeric)
		if !exists {
			return false, nil
		}
		return t.matcher.operators["lte"](actual, trigger.Value)

	case "in":
		// Value in list
		if !exists {
			return false, nil
		}
		return t.matcher.operators["in"](actual, trigger.Value)

	case "notIn":
		// Value not in list
		if !exists {
			return false, nil
		}
		return t.matcher.operators["notIn"](actual, trigger.Value)

	default:
		return false, fmt.Errorf("unknown trigger condition: %s", trigger.Condition)
	}
}
