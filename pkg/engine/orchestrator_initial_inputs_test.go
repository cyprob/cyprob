package engine

import (
	"bytes"
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

// Ensure that when config.targets comes with wrong type, we fall back to legacy SetInitial
func TestOrchestrator_InitialInputs_ConfigTargets_WrongType_Fallback(t *testing.T) {
	// Minimal DAG with a no-op module to satisfy orchestrator requirements
	dag := &DAGDefinition{Name: "seed-fallback", Nodes: []DAGNodeConfig{{InstanceID: "noop1", ModuleType: "noop"}}}
	RegisterModuleFactory("noop", func() Module { return &minimalTestModule{meta: ModuleMetadata{Produces: nil}} })
	orc, err := NewOrchestrator(dag)
	require.NoError(t, err)

	// Pass wrong type (string instead of []string)
	_, runErr := orc.Run(context.Background(), map[string]any{"config.targets": "10.0.0.1"})
	require.NoError(t, runErr)

	// Legacy storage should keep raw value accessible via GetAll
	all := orc.dataCtx.GetAll()
	v, ok := all["config.targets"]
	require.True(t, ok)
	require.Equal(t, "10.0.0.1", v)
}

// TestOrchestrator_Run_WithInitialInputs verifies that a root module consuming
// an initial input (e.g., config.targets) runs successfully without dependency issues.
func TestOrchestrator_Run_WithInitialInputs(t *testing.T) {
	receivedTargets := []string{}

	RegisterModuleFactory("initial-consumer", func() Module {
		return &mockModule{
			meta: ModuleMetadata{
				Name:     "initial-consumer",
				Type:     DiscoveryModuleType,
				Consumes: []DataContractEntry{{Key: "config.targets"}},
				Produces: []DataContractEntry{{Key: "discovery.results"}},
			},
			execFunc: func(ctx context.Context, inputs map[string]any, out chan<- ModuleOutput) error {
				// Capture received targets to verify they were passed correctly
				if targets, ok := inputs["config.targets"].([]string); ok {
					receivedTargets = targets
				}
				out <- ModuleOutput{DataKey: "discovery.results", Data: "scan-complete"}
				return nil
			},
		}
	})
	defer delete(moduleRegistry, "initial-consumer")

	dag := &DAGDefinition{
		Name: "initial-inputs-test",
		Nodes: []DAGNodeConfig{
			{InstanceID: "discovery", ModuleType: "initial-consumer", Config: map[string]any{}},
		},
	}

	orc, err := NewOrchestrator(dag)
	require.NoError(t, err)

	initialInputs := map[string]any{
		"config.targets": []string{"192.168.1.1", "192.168.1.2"},
	}

	results, runErr := orc.Run(context.Background(), initialInputs)
	require.NoError(t, runErr)

	// Verify the module received the initial inputs
	require.Equal(t, []string{"192.168.1.1", "192.168.1.2"}, receivedTargets)

	// Verify the output was produced
	require.Contains(t, results, "discovery.results")
}

// TestOrchestrator_InitialInputsNoFalseWarning verifies that initial inputs
// do NOT trigger the "Consumed key not produced by any other DAG node" debug log.
// This is the core test for the fix we are implementing.
func TestOrchestrator_InitialInputsNoFalseWarning(t *testing.T) {
	// Capture logs to verify no false warning is emitted
	var logBuffer bytes.Buffer
	originalLogger := log.Logger
	log.Logger = zerolog.New(&logBuffer).Level(zerolog.DebugLevel)
	defer func() { log.Logger = originalLogger }()

	RegisterModuleFactory("initial-consumer-log", func() Module {
		return &mockModule{
			meta: ModuleMetadata{
				Name:     "initial-consumer-log",
				Type:     DiscoveryModuleType,
				Consumes: []DataContractEntry{{Key: "config.targets"}},
			},
			execFunc: func(ctx context.Context, inputs map[string]any, out chan<- ModuleOutput) error {
				return nil
			},
		}
	})
	defer delete(moduleRegistry, "initial-consumer-log")

	dag := &DAGDefinition{
		Name: "no-false-warning-test",
		Nodes: []DAGNodeConfig{
			{InstanceID: "consumer", ModuleType: "initial-consumer-log", Config: map[string]any{}},
		},
	}

	orc, err := NewOrchestrator(dag)
	require.NoError(t, err)

	initialInputs := map[string]any{
		"config.targets": []string{"10.0.0.1"},
	}

	_, runErr := orc.Run(context.Background(), initialInputs)
	require.NoError(t, runErr)

	// The log should NOT contain the misleading message about config.targets
	// not being produced by any DAG node (because it's an initial input)
	logOutput := logBuffer.String()
	require.NotContains(t, logOutput, "Consumed key not produced by any other DAG node")
}

func TestOrchestrator_OptionalInputNoWarning(t *testing.T) {
	var logBuffer bytes.Buffer
	originalLogger := log.Logger
	log.Logger = zerolog.New(&logBuffer).Level(zerolog.DebugLevel)
	defer func() { log.Logger = originalLogger }()

	RegisterModuleFactory("optional-consumer", func() Module {
		return &mockModule{
			meta: ModuleMetadata{
				Name: "optional-consumer",
				Type: EvaluationModuleType,
				Consumes: []DataContractEntry{
					{Key: "optional.data", IsOptional: true},
					{Key: "required.data", IsOptional: false},
				},
			},
			execFunc: func(ctx context.Context, inputs map[string]any, out chan<- ModuleOutput) error {
				return nil
			},
		}
	})
	defer delete(moduleRegistry, "optional-consumer")

	dag := &DAGDefinition{
		Name: "optional-input-test",
		Nodes: []DAGNodeConfig{
			{InstanceID: "opt", ModuleType: "optional-consumer"},
		},
	}

	_, _ = NewOrchestrator(dag)

	logOutput := logBuffer.String()
	// Should NOT warn for optional.data
	require.NotContains(t, logOutput, "consumed_key=optional.data", "Should not warn for missing optional key")

	// SHOULD warn for required.data. Note: Zerolog uses JSON format by default in these tests.
	// Look for the JSON key-value pair.
	require.Contains(t, logOutput, "\"consumed_key\":\"required.data\"", "Should warn for missing required key")
}

func TestOrchestrator_Run_RuntimeLogFiltering(t *testing.T) {
	var logBuffer bytes.Buffer
	originalLogger := log.Logger
	log.Logger = zerolog.New(&logBuffer).Level(zerolog.DebugLevel)
	defer func() { log.Logger = originalLogger }()

	// Module consuming 1 optional and 1 required input
	RegisterModuleFactory("runtime-consumer", func() Module {
		return &mockModule{
			meta: ModuleMetadata{
				Name: "runtime-consumer",
				Type: EvaluationModuleType,
				Consumes: []DataContractEntry{
					{Key: "rt.optional", IsOptional: true},
					{Key: "rt.required", IsOptional: false},
				},
			},
			execFunc: func(ctx context.Context, inputs map[string]any, out chan<- ModuleOutput) error {
				return nil
			},
		}
	})
	defer delete(moduleRegistry, "runtime-consumer")

	dag := &DAGDefinition{
		Name: "runtime-log-test",
		Nodes: []DAGNodeConfig{
			{InstanceID: "rt", ModuleType: "runtime-consumer"},
		},
	}

	orc, err := NewOrchestrator(dag)
	require.NoError(t, err)

	// Run without providing any inputs
	_, _ = orc.Run(context.Background(), nil)

	logOutput := logBuffer.String()

	// 1. Should NOT log about MISSING OPTIONAL "rt.optional" at Debug level (it's Trace now)
	require.NotContains(t, logOutput, "rt.optional", "Should NOT log missing optional runtime input at Debug level")

	// 2. Should WARNING log about MISSING REQUIRED "rt.required"
	require.Contains(t, logOutput, "REQUIRED input key 'rt.required' not found", "Should WARN for missing required runtime input")
}
