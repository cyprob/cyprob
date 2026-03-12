package scan

import (
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
)

const nativeProbeModuleAuthor = "Vulntor Team"

type tcpNativeProbeMetadataSpec struct {
	moduleID              string
	moduleName            string
	description           string
	outputKey             string
	outputType            string
	outputDescription     string
	tags                  []string
	consumes              []engine.DataContractEntry
	timeoutDefault        string
	connectTimeoutDefault string
	ioTimeoutDefault      string
	extraConfigParameters map[string]engine.ParameterDefinition
}

func buildTCPNativeProbeMetadata(spec tcpNativeProbeMetadataSpec) engine.ModuleMetadata {
	return engine.ModuleMetadata{
		ID:          spec.moduleID,
		Name:        spec.moduleName,
		Description: spec.description,
		Version:     "0.1.0",
		Type:        engine.ScanModuleType,
		Author:      nativeProbeModuleAuthor,
		Tags:        append([]string(nil), spec.tags...),
		Consumes:    append([]engine.DataContractEntry(nil), spec.consumes...),
		Produces: []engine.DataContractEntry{
			{
				Key:          spec.outputKey,
				DataTypeName: spec.outputType,
				Cardinality:  engine.CardinalityList,
				Description:  spec.outputDescription,
			},
		},
		ConfigSchema: buildTCPNativeProbeConfigSchema(
			spec.timeoutDefault,
			spec.connectTimeoutDefault,
			spec.ioTimeoutDefault,
			spec.extraConfigParameters,
		),
	}
}

func buildTCPNativeProbeConfigSchema(
	timeoutDefault string,
	connectTimeoutDefault string,
	ioTimeoutDefault string,
	extra map[string]engine.ParameterDefinition,
) map[string]engine.ParameterDefinition {
	schema := map[string]engine.ParameterDefinition{
		"timeout": {
			Description: "Total timeout budget per target.",
			Type:        "duration",
			Required:    false,
			Default:     timeoutDefault,
		},
		"connect_timeout": {
			Description: "TCP connect timeout per attempt.",
			Type:        "duration",
			Required:    false,
			Default:     connectTimeoutDefault,
		},
		"io_timeout": {
			Description: "Read/write timeout per attempt.",
			Type:        "duration",
			Required:    false,
			Default:     ioTimeoutDefault,
		},
		"retries": {
			Description: "Retry count per strategy.",
			Type:        "int",
			Required:    false,
			Default:     0,
		},
	}
	for key, definition := range extra {
		schema[key] = definition
	}
	return schema
}

func nativeOpenTCPPortsConsume(optional bool, description string) engine.DataContractEntry {
	return engine.DataContractEntry{
		Key:          "discovery.open_tcp_ports",
		DataTypeName: "discovery.TCPPortDiscoveryResult",
		Cardinality:  engine.CardinalityList,
		IsOptional:   optional,
		Description:  description,
	}
}

func nativeBannerConsume(description string) engine.DataContractEntry {
	return engine.DataContractEntry{
		Key:          "service.banner.tcp",
		DataTypeName: "scan.BannerGrabResult",
		Cardinality:  engine.CardinalityList,
		IsOptional:   true,
		Description:  description,
	}
}

func nativeOriginalTargetsConsume(description string) engine.DataContractEntry {
	return engine.DataContractEntry{
		Key:          "config.original_cli_targets",
		DataTypeName: "[]string",
		Cardinality:  engine.CardinalitySingle,
		IsOptional:   true,
		Description:  description,
	}
}

func initCommonTCPProbeOptions(
	meta *engine.ModuleMetadata,
	instanceID string,
	configMap map[string]any,
	totalTimeout *time.Duration,
	connectTimeout *time.Duration,
	ioTimeout *time.Duration,
	retries *int,
) {
	meta.ID = instanceID
	if configMap == nil {
		return
	}
	if d, ok := parseDurationConfig(configMap["timeout"]); ok && d > 0 {
		*totalTimeout = d
	}
	if d, ok := parseDurationConfig(configMap["connect_timeout"]); ok && d > 0 {
		*connectTimeout = d
	}
	if d, ok := parseDurationConfig(configMap["io_timeout"]); ok && d > 0 {
		*ioTimeout = d
	}
	if value, ok := configMap["retries"].(int); ok && value >= 0 {
		*retries = value
	}
	if value, ok := configMap["retries"].(float64); ok && value >= 0 {
		*retries = int(value)
	}
}

func parseOptionalPortList(configMap map[string]any, key string) []int {
	if configMap == nil {
		return nil
	}
	return parseExtraPortsConfig(configMap[key])
}
