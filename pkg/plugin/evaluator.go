// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// Evaluator evaluates plugins against a data context.
type Evaluator struct {
	matcher *MatcherEngine
	trigger *TriggerEvaluator
}

// NewEvaluator creates a new plugin evaluator.
func NewEvaluator() *Evaluator {
	return &Evaluator{
		matcher: NewMatcherEngine(),
		trigger: NewTriggerEvaluator(),
	}
}

// Evaluate evaluates a YAML plugin against a data context.
// Returns a YAMLMatchResult indicating if the plugin matched and the output.
func (e *Evaluator) Evaluate(plugin *YAMLPlugin, context map[string]any) (*YAMLMatchResult, error) {
	start := time.Now()

	result := &YAMLMatchResult{
		Plugin:      plugin,
		EvaluatedAt: start,
		Matched:     false,
	}

	// Check if plugin should be triggered
	shouldTrigger, err := e.trigger.ShouldTrigger(plugin.Triggers, context)
	if err != nil {
		return nil, fmt.Errorf("trigger evaluation failed: %w", err)
	}

	log.Debug().
		Str("plugin", plugin.Name).
		Bool("should_trigger", shouldTrigger).
		Msg("Plugin trigger evaluation result")

	if !shouldTrigger {
		// Plugin not triggered, skip evaluation
		log.Debug().
			Str("plugin", plugin.Name).
			Msg("Plugin not triggered, skipping match evaluation")
		result.ExecutionTime = time.Since(start)
		return result, nil
	}

	// Evaluate match block if present
	if plugin.Match != nil {
		log.Debug().
			Str("plugin", plugin.Name).
			Msg("Evaluating match block")

		matched, err := e.matcher.Evaluate(plugin.Match, context)
		if err != nil {
			return nil, fmt.Errorf("match evaluation failed: %w", err)
		}

		log.Debug().
			Str("plugin", plugin.Name).
			Bool("matched", matched).
			Msg("Match evaluation result")

		result.Matched = matched
	} else {
		// No match block means always match if triggered
		log.Debug().
			Str("plugin", plugin.Name).
			Msg("No match block, always match when triggered")
		result.Matched = true
	}

	// Set output if matched
	if result.Matched {
		result.Output = plugin.Output

		// Override severity if specified in output
		if result.Output.Severity == "" {
			result.Output.Severity = plugin.Metadata.Severity
		}

		log.Debug().
			Str("plugin", plugin.Name).
			Str("severity", string(result.Output.Severity)).
			Str("message", result.Output.Message).
			Msg("Plugin matched - vulnerability detected")
	}

	result.ExecutionTime = time.Since(start)
	return result, nil
}

// EvaluateAll evaluates multiple YAML plugins against a data context.
// Returns all match results (both matched and not matched).
func (e *Evaluator) EvaluateAll(plugins []*YAMLPlugin, context map[string]any) ([]*YAMLMatchResult, error) {
	results := make([]*YAMLMatchResult, 0, len(plugins))

	for i, plugin := range plugins {
		result, err := e.Evaluate(plugin, context)
		if err != nil {
			return nil, fmt.Errorf("plugin[%d] (%s) evaluation failed: %w", i, plugin.Name, err)
		}
		results = append(results, result)
	}

	return results, nil
}

// EvaluateMatched evaluates multiple YAML plugins and returns only matched results.
func (e *Evaluator) EvaluateMatched(plugins []*YAMLPlugin, context map[string]any) ([]*YAMLMatchResult, error) {
	allResults, err := e.EvaluateAll(plugins, context)
	if err != nil {
		return nil, err
	}

	matched := make([]*YAMLMatchResult, 0)
	for _, result := range allResults {
		if result.Matched {
			matched = append(matched, result)
		}
	}

	return matched, nil
}
