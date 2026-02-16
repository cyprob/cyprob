// Copyright 2025 Vulntor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package dag

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cyprob/cyprob/cmd/vulntor/internal/bind"
	"github.com/cyprob/cyprob/pkg/engine"
)

func TestExportCommand_DefaultYAML(t *testing.T) {
	opts := bind.DAGExportOptions{
		Output:     "", // stdout
		Format:     "yaml",
		Targets:    "192.168.1.1",
		Ports:      "80,443",
		Vuln:       false,
		NoDiscover: false,
	}

	// Redirect stdout to capture output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runExport(opts)

	// Restore stdout
	_ = w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	// Read captured output
	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])

	// Verify YAML output
	var dag engine.DAGSchema
	err = yaml.Unmarshal([]byte(output), &dag)
	require.NoError(t, err)
	require.Equal(t, "scan-dag", dag.Name)
	require.Equal(t, "1.0", dag.Version)
	require.NotEmpty(t, dag.Nodes)
}

func TestExportCommand_ToFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.yaml")

	opts := bind.DAGExportOptions{
		Output:     outputFile,
		Format:     "yaml",
		Targets:    "10.0.0.1",
		Ports:      "22,80,443",
		Vuln:       false,
		NoDiscover: false,
	}

	err := runExport(opts)
	require.NoError(t, err)

	// Verify file was created
	require.FileExists(t, outputFile)

	// Read and verify content
	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	var dag engine.DAGSchema
	err = yaml.Unmarshal(data, &dag)
	require.NoError(t, err)
	require.Equal(t, "scan-dag", dag.Name)
	require.Contains(t, dag.Description, "10.0.0.1")
}

func TestExportCommand_JSONFormat(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "output.json")

	opts := bind.DAGExportOptions{
		Output:     outputFile,
		Format:     "json",
		Targets:    "192.168.1.1",
		Ports:      "80",
		Vuln:       false,
		NoDiscover: false,
	}

	err := runExport(opts)
	require.NoError(t, err)

	// Verify file exists
	require.FileExists(t, outputFile)

	// Read and verify JSON
	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	var dag engine.DAGSchema
	err = json.Unmarshal(data, &dag)
	require.NoError(t, err)
	require.Equal(t, "scan-dag", dag.Name)
}

func TestExportCommand_WithVuln(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "vuln.yaml")

	opts := bind.DAGExportOptions{
		Output:     outputFile,
		Format:     "yaml",
		Targets:    "192.168.1.1",
		Ports:      "80",
		Vuln:       true, // Enable vuln
		NoDiscover: false,
	}

	err := runExport(opts)
	require.NoError(t, err)

	// Read DAG
	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	var dag engine.DAGSchema
	err = yaml.Unmarshal(data, &dag)
	require.NoError(t, err)

	// Verify vuln-eval node exists
	hasVulnNode := false
	for _, node := range dag.Nodes {
		if node.ID == "vuln-eval" {
			hasVulnNode = true
			require.Equal(t, "vuln-eval", node.Module)
			require.Contains(t, node.Produces, "vuln.findings")
			break
		}
	}
	require.True(t, hasVulnNode, "Expected vuln-eval node when --vuln is enabled")
}

func TestExportCommand_NoDiscover(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "no-discover.yaml")

	opts := bind.DAGExportOptions{
		Output:     outputFile,
		Format:     "yaml",
		Targets:    "192.168.1.1",
		Ports:      "80",
		Vuln:       false,
		NoDiscover: true, // Skip discovery
	}

	err := runExport(opts)
	require.NoError(t, err)

	// Read DAG
	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	var dag engine.DAGSchema
	err = yaml.Unmarshal(data, &dag)
	require.NoError(t, err)

	// Verify discovery-tcp node does NOT exist
	for _, node := range dag.Nodes {
		require.NotEqual(t, "discovery-tcp", node.ID, "Discovery node should not exist with --no-discover")
	}
}

func TestExportCommand_InvalidFormat(t *testing.T) {
	cmd := newExportCommand()
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(errOut)

	cmd.SetArgs([]string{"--format", "xml"})

	err := cmd.Execute()
	require.NoError(t, err)

	output := out.String()
	require.Contains(t, output, "✗ Failed to export DAG")
	require.Contains(t, output, "Use --format yaml or --format json")
}

func TestExportCommand_InvalidOutputPath(t *testing.T) {
	opts := bind.DAGExportOptions{
		Output:     "/nonexistent/directory/output.yaml",
		Format:     "yaml",
		Targets:    "192.168.1.1",
		Ports:      "80",
		Vuln:       false,
		NoDiscover: false,
	}

	err := runExport(opts)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to write output file")
}

func TestCreateExampleDAG_BasicStructure(t *testing.T) {
	opts := bind.DAGExportOptions{
		Targets:    "192.168.1.1",
		Ports:      "22,80,443",
		Vuln:       false,
		NoDiscover: false,
	}

	dag := createExampleDAG(opts)

	require.NotNil(t, dag)
	require.Equal(t, "scan-dag", dag.Name)
	require.Equal(t, "1.0", dag.Version)
	require.Contains(t, dag.Description, "192.168.1.1")
	require.NotEmpty(t, dag.Nodes)

	// Verify required nodes exist
	nodeIDs := make(map[string]bool)
	for _, node := range dag.Nodes {
		nodeIDs[node.ID] = true
	}

	require.True(t, nodeIDs["config-loader"], "config-loader node should exist")
	require.True(t, nodeIDs["discovery-tcp"], "discovery-tcp node should exist")
	require.True(t, nodeIDs["port-scan"], "port-scan node should exist")
	require.True(t, nodeIDs["banner-grab"], "banner-grab node should exist")
	require.True(t, nodeIDs["fingerprint"], "fingerprint node should exist")
	require.True(t, nodeIDs["report"], "report node should exist")
}

func TestCreateExampleDAG_ConfigNode(t *testing.T) {
	opts := bind.DAGExportOptions{
		Targets:    "10.0.0.0/24",
		Ports:      "1-1000",
		Vuln:       false,
		NoDiscover: false,
	}

	dag := createExampleDAG(opts)

	// Find config-loader node
	var configNode *engine.DAGNode
	for i := range dag.Nodes {
		if dag.Nodes[i].ID == "config-loader" {
			configNode = &dag.Nodes[i]
			break
		}
	}

	require.NotNil(t, configNode, "config-loader node should exist")
	require.Equal(t, "config", configNode.Module)
	require.Contains(t, configNode.Produces, "config.targets")
	require.Contains(t, configNode.Produces, "config.ports")

	// Verify config values
	require.Equal(t, "10.0.0.0/24", configNode.Config["targets"])
	require.Equal(t, "1-1000", configNode.Config["ports"])
}

func TestCreateExampleDAG_DependencyChain(t *testing.T) {
	opts := bind.DAGExportOptions{
		Targets:    "192.168.1.1",
		Ports:      "80",
		Vuln:       true,
		NoDiscover: false,
	}

	dag := createExampleDAG(opts)

	// Build node index
	nodeIndex := make(map[string]*engine.DAGNode)
	for i := range dag.Nodes {
		nodeIndex[dag.Nodes[i].ID] = &dag.Nodes[i]
	}

	// Verify dependency chain
	discoveryNode := nodeIndex["discovery-tcp"]
	require.Contains(t, discoveryNode.DependsOn, "config-loader")

	portScanNode := nodeIndex["port-scan"]
	require.Contains(t, portScanNode.DependsOn, "config-loader")
	require.Contains(t, portScanNode.DependsOn, "discovery-tcp")

	bannerNode := nodeIndex["banner-grab"]
	require.Contains(t, bannerNode.DependsOn, "port-scan")

	fingerprintNode := nodeIndex["fingerprint"]
	require.Contains(t, fingerprintNode.DependsOn, "banner-grab")

	vulnNode := nodeIndex["vuln-eval"]
	require.Contains(t, vulnNode.DependsOn, "fingerprint")

	reportNode := nodeIndex["report"]
	require.Contains(t, reportNode.DependsOn, "fingerprint")
	require.Contains(t, reportNode.DependsOn, "vuln-eval")
}

func TestCreateExampleDAG_DataFlow(t *testing.T) {
	opts := bind.DAGExportOptions{
		Targets:    "192.168.1.1",
		Ports:      "80",
		Vuln:       false,
		NoDiscover: false,
	}

	dag := createExampleDAG(opts)

	// Validate DAG is valid
	result := dag.Validate()
	require.True(t, result.IsValid(), "Generated DAG should be valid")

	// Build node index
	nodeIndex := make(map[string]*engine.DAGNode)
	for i := range dag.Nodes {
		nodeIndex[dag.Nodes[i].ID] = &dag.Nodes[i]
	}

	// Verify data flow
	discoveryNode := nodeIndex["discovery-tcp"]
	require.Contains(t, discoveryNode.Consumes, "config.targets")
	require.Contains(t, discoveryNode.Produces, "discovery.live_hosts")

	portScanNode := nodeIndex["port-scan"]
	require.Contains(t, portScanNode.Consumes, "discovery.live_hosts")
	require.Contains(t, portScanNode.Produces, "scan.open_ports")

	bannerNode := nodeIndex["banner-grab"]
	require.Contains(t, bannerNode.Consumes, "scan.open_ports")
	require.Contains(t, bannerNode.Produces, "scan.banners")
}

func TestNewExportCommand(t *testing.T) {
	cmd := newExportCommand()

	require.NotNil(t, cmd)
	require.Equal(t, "export", cmd.Use)
	require.NotEmpty(t, cmd.Short)
	require.NotEmpty(t, cmd.Long)
	require.NotEmpty(t, cmd.Example)

	// Check flags exist
	outputFlag := cmd.Flags().Lookup("output")
	require.NotNil(t, outputFlag)
	require.Equal(t, "o", outputFlag.Shorthand)

	formatFlag := cmd.Flags().Lookup("format")
	require.NotNil(t, formatFlag)
	require.Equal(t, "yaml", formatFlag.DefValue)

	targetsFlag := cmd.Flags().Lookup("targets")
	require.NotNil(t, targetsFlag)

	portsFlag := cmd.Flags().Lookup("ports")
	require.NotNil(t, portsFlag)

	vulnFlag := cmd.Flags().Lookup("vuln")
	require.NotNil(t, vulnFlag)

	noDiscoverFlag := cmd.Flags().Lookup("no-discover")
	require.NotNil(t, noDiscoverFlag)
}
