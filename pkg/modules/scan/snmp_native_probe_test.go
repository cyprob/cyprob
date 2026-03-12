package scan

import (
	"context"
	"testing"
	"time"

	"github.com/cyprob/cyprob/internal/testutil/snmptest"
	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/require"
)

func TestSNMPCandidatesFromOpenPorts(t *testing.T) {
	candidates := snmpCandidatesFromOpenPorts(discovery.UDPPortDiscoveryResult{
		Target:    "192.0.2.10",
		OpenPorts: []int{53, 161, 162},
	})
	require.Len(t, candidates, 1)
	require.Equal(t, "192.0.2.10", candidates[0].target)
	require.Equal(t, 161, candidates[0].port)
}

func TestProbeSNMPDetails_PublicV2cSuccess(t *testing.T) {
	host, port, cleanup := snmptest.StartServer(t, snmptest.DefaultConfig())
	defer cleanup()

	result := probeSNMPDetails(context.Background(), host, port, defaultSNMPProbeOptions())
	require.True(t, result.SNMPProbe)
	require.Equal(t, "SNMPv2c", result.SNMPVersion)
	require.Equal(t, "public", result.Community)
	require.Equal(t, "Net-SNMP", result.ProductHint)
	require.Equal(t, "Net-SNMP Project", result.VendorHint)
	require.True(t, result.WeakCommunity)
	require.False(t, result.WeakProtocol)
	require.Len(t, result.Attempts, 1)
	require.True(t, result.Attempts[0].Success)
}

func TestProbeSNMPDetails_PrivateV1FallbackOrder(t *testing.T) {
	host, port, cleanup := snmptest.StartServer(t, snmptest.ServerConfig{
		AllowedCommunity: "private",
		AllowedVersion:   gosnmp.Version1,
		SysDescr:         "Cisco IOS Software, Version 15.7(3)M8",
		SysObjectID:      ".1.3.6.1.4.1.9.1.1208",
		SysName:          "edge-router",
	})
	defer cleanup()

	opts := defaultSNMPProbeOptions()
	opts.TotalTimeout = 4 * time.Second
	result := probeSNMPDetails(context.Background(), host, port, opts)
	require.True(t, result.SNMPProbe)
	require.Equal(t, "SNMPv1", result.SNMPVersion)
	require.Equal(t, "private", result.Community)
	require.True(t, result.WeakProtocol)
	require.True(t, result.WeakCommunity)
	require.Equal(t, "Cisco", result.VendorHint)
	require.Equal(t, "Cisco IOS", result.ProductHint)
	require.Len(t, result.Attempts, 4)
	require.Equal(t, "public", result.Attempts[0].Community)
	require.Equal(t, "SNMPv2c", result.Attempts[0].VersionTry)
	require.False(t, result.Attempts[0].Success)
	require.Equal(t, "public", result.Attempts[1].Community)
	require.Equal(t, "SNMPv1", result.Attempts[1].VersionTry)
	require.False(t, result.Attempts[1].Success)
	require.Equal(t, "private", result.Attempts[2].Community)
	require.Equal(t, "SNMPv2c", result.Attempts[2].VersionTry)
	require.False(t, result.Attempts[2].Success)
	require.Equal(t, "private", result.Attempts[3].Community)
	require.Equal(t, "SNMPv1", result.Attempts[3].VersionTry)
	require.True(t, result.Attempts[3].Success)
}

func TestProbeSNMPDetails_DecodeError(t *testing.T) {
	originalExecute := executeSNMPAttemptFunc
	executeSNMPAttemptFunc = func(ctx context.Context, target string, port int, plan snmpAttemptPlan, perAttemptTimeout time.Duration) (snmpProbeOutcome, error) {
		return snmpProbeOutcome{duration: 10 * time.Millisecond}, errSNMPDecode
	}
	defer func() { executeSNMPAttemptFunc = originalExecute }()

	result := probeSNMPDetails(context.Background(), "192.0.2.40", 161, defaultSNMPProbeOptions())
	require.False(t, result.SNMPProbe)
	require.Equal(t, "decode_error", result.ProbeError)
}

func TestProbeSNMPDetails_NoResponse(t *testing.T) {
	host, port, cleanup := snmptest.StartServer(t, snmptest.ServerConfig{
		AllowedCommunity: "public",
		AllowedVersion:   gosnmp.Version2c,
		NoResponse:       true,
	})
	defer cleanup()

	opts := defaultSNMPProbeOptions()
	opts.TotalTimeout = 2 * time.Second
	opts.PerAttemptTimeout = 200 * time.Millisecond
	result := probeSNMPDetails(context.Background(), host, port, opts)
	require.False(t, result.SNMPProbe)
	require.Equal(t, "no_response", result.ProbeError)
}

func TestSNMPNativeProbeModuleExecuteProducesCompatibilityKeys(t *testing.T) {
	module := newSNMPNativeProbeModule()
	require.NoError(t, module.Init("test-snmp-native-probe", map[string]any{
		"timeout":             "2s",
		"per_attempt_timeout": "700ms",
	}))

	originalProbeFunc := probeSNMPDetailsFunc
	probeSNMPDetailsFunc = func(ctx context.Context, target string, port int, opts SNMPProbeOptions) SNMPServiceInfo {
		return SNMPServiceInfo{
			Target:      target,
			Port:        port,
			SNMPProbe:   true,
			SNMPVersion: "SNMPv2c",
			Community:   "public",
			SysDescr:    "Net-SNMP 5.9",
		}
	}
	defer func() { probeSNMPDetailsFunc = originalProbeFunc }()

	outputChan := make(chan engine.ModuleOutput, 8)
	err := module.Execute(context.Background(), map[string]any{
		"discovery.open_udp_ports": []any{
			discovery.UDPPortDiscoveryResult{Target: "192.0.2.50", OpenPorts: []int{161}},
		},
	}, outputChan)
	require.NoError(t, err)
	close(outputChan)

	var details []SNMPServiceInfo
	var versions []string
	var communities []string
	for item := range outputChan {
		switch item.DataKey {
		case "service.snmp.details":
			detail, ok := item.Data.(SNMPServiceInfo)
			require.True(t, ok)
			details = append(details, detail)
		case "snmp.version":
			value, ok := item.Data.(string)
			require.True(t, ok)
			versions = append(versions, value)
		case "snmp.community":
			value, ok := item.Data.(string)
			require.True(t, ok)
			communities = append(communities, value)
		}
	}

	require.Len(t, details, 1)
	require.Len(t, versions, 1)
	require.Len(t, communities, 1)
	require.Equal(t, "SNMPv2c", versions[0])
	require.Equal(t, "public", communities[0])
}
