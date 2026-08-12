package scan

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

// stubMDNSMulticast replaces the segment-wide query so unit tests never put a
// datagram on the network.
func stubMDNSMulticast(t *testing.T, answers map[string]MDNSServiceInfo) {
	t.Helper()
	original := mdnsMulticastCollectF
	t.Cleanup(func() { mdnsMulticastCollectF = original })
	mdnsMulticastCollectF = func(context.Context, MDNSProbeOptions) map[string]MDNSServiceInfo {
		return answers
	}
}

// stubMDNSUnicast replaces the per-target probe.
func stubMDNSUnicast(t *testing.T, results map[string]MDNSServiceInfo) {
	t.Helper()
	original := probeMDNSDetailsFunc
	t.Cleanup(func() { probeMDNSDetailsFunc = original })
	probeMDNSDetailsFunc = func(_ context.Context, target string, port int, _ MDNSProbeOptions) MDNSServiceInfo {
		if result, ok := results[target]; ok {
			return result
		}
		return MDNSServiceInfo{Target: target, Port: port, ProbeError: "no_response"}
	}
}

func mdnsExecute(t *testing.T, inputs map[string]any) map[string]MDNSServiceInfo {
	t.Helper()
	module := newMDNSNativeProbeModule()
	outputs := make(chan engine.ModuleOutput, 16)
	require.NoError(t, module.Execute(context.Background(), inputs, outputs))
	close(outputs)

	reported := map[string]MDNSServiceInfo{}
	for out := range outputs {
		info, ok := out.Data.(MDNSServiceInfo)
		require.True(t, ok, "output data must be MDNSServiceInfo")
		reported[out.Target] = info
	}
	return reported
}

// mdnsScopeInputs puts targets in scope without reporting any open port, which
// is the case the multicast pass exists for.
func mdnsScopeInputs(targets ...string) map[string]any {
	scanned := make([]any, 0, len(targets))
	for _, target := range targets {
		scanned = append(scanned, discovery.UDPPortDiscoveryResult{Target: target})
	}
	return map[string]any{"discovery.open_udp_ports": scanned}
}

// mdnsOpenPortInputs additionally reports UDP/5353 open, which is what makes a
// target a unicast candidate.
func mdnsOpenPortInputs(targets ...string) map[string]any {
	scanned := make([]any, 0, len(targets))
	for _, target := range targets {
		scanned = append(scanned, discovery.UDPPortDiscoveryResult{
			Target: target, OpenPorts: []int{mdnsPort},
		})
	}
	return map[string]any{"discovery.open_udp_ports": scanned}
}

// The multicast query reaches the whole segment, so devices nobody asked to
// scan will answer. Those must not become assets.
func TestMDNSExecute_OnlyReportsMulticastRespondersInScope(t *testing.T) {
	stubMDNSMulticast(t, map[string]MDNSServiceInfo{
		"192.0.2.10":   {Target: "192.0.2.10", MDNSProbe: true, ServiceTypes: []string{"_hap._tcp.local."}},
		"198.51.100.7": {Target: "198.51.100.7", MDNSProbe: true, ServiceTypes: []string{"_hap._tcp.local."}},
	})
	stubMDNSUnicast(t, nil)

	reported := mdnsExecute(t, mdnsScopeInputs("192.0.2.10"))

	require.Len(t, reported, 1)
	require.Contains(t, reported, "192.0.2.10")
	require.NotContains(t, reported, "198.51.100.7",
		"a responder that was never a target must not be reported")
}

// The point of the multicast pass: a host whose UDP/5353 the port scan never
// reported open is not a unicast candidate at all, so before this it produced
// no mDNS output whatsoever.
func TestMDNSExecute_ReportsHostWithNoOpenPortDetected(t *testing.T) {
	stubMDNSMulticast(t, map[string]MDNSServiceInfo{
		"192.0.2.29": {
			Target:       "192.0.2.29",
			MDNSProbe:    true,
			ServiceTypes: []string{"_companion-link._tcp.local."},
		},
	})
	stubMDNSUnicast(t, nil)

	// The host is in scope but has no open UDP port recorded.
	reported := mdnsExecute(t, mdnsScopeInputs("192.0.2.29"))

	require.Contains(t, reported, "192.0.2.29")
	info := reported["192.0.2.29"]
	require.True(t, info.MDNSProbe)
	require.Equal(t, "Apple", info.VendorHint,
		"an Apple-only service names the vendor when no model is published")
}

// A record seen only over multicast must reach the identity, which means the
// derivation has to run again over the union of both transports.
func TestMDNSExecute_MulticastRecordsCompleteTheIdentity(t *testing.T) {
	stubMDNSUnicast(t, map[string]MDNSServiceInfo{
		"192.0.2.20": {
			Target:       "192.0.2.20",
			Port:         mdnsPort,
			MDNSProbe:    true,
			ServiceTypes: []string{"_androidtvremote2._tcp.local."},
			TXTAttrs:     map[string]string{},
		},
	})
	stubMDNSMulticast(t, map[string]MDNSServiceInfo{
		"192.0.2.20": {
			Target:       "192.0.2.20",
			MDNSProbe:    true,
			ServiceTypes: []string{"_googlecast._tcp.local."},
			TXTAttrs:     map[string]string{"md": "MIBOX3"},
		},
	})

	info := mdnsExecute(t, mdnsOpenPortInputs("192.0.2.20"))["192.0.2.20"]

	require.Equal(t, "MIBOX3", info.Model,
		"the model lives only in the multicast-only record")
	require.Equal(t, deviceTypeMediaDevice, info.DeviceType)
	require.Contains(t, info.ServiceTypes, "_androidtvremote2._tcp.local.")
	require.Contains(t, info.ServiceTypes, "_googlecast._tcp.local.")
}

// Re-deriving over the union must replace the whole identity, not leave a
// product string built from the model the earlier pass reported.
func TestMDNSExecute_DerivedFieldsAreRecomputedNotPatched(t *testing.T) {
	stubMDNSUnicast(t, map[string]MDNSServiceInfo{
		"192.0.2.40": {
			Target: "192.0.2.40", Port: mdnsPort, MDNSProbe: true,
			TXTAttrs: map[string]string{"md": "OldModel"},
			Model:    "OldModel", ProductHint: "OldModel",
		},
	})
	stubMDNSMulticast(t, map[string]MDNSServiceInfo{
		"192.0.2.40": {
			Target: "192.0.2.40", MDNSProbe: true,
			// "model" outranks "md" in the derivation order.
			TXTAttrs: map[string]string{"model": "NewModel"},
		},
	})

	info := mdnsExecute(t, mdnsOpenPortInputs("192.0.2.40"))["192.0.2.40"]

	require.Equal(t, "NewModel", info.Model)
	require.Equal(t, "NewModel", info.ProductHint,
		"the product string must follow the model it was derived from")
}

// A host that answered multicast is a responder even when the unicast attempt
// timed out, which is exactly the asymmetry this pass exists to cover.
func TestMDNSExecute_MulticastAnswerClearsUnicastFailure(t *testing.T) {
	stubMDNSUnicast(t, map[string]MDNSServiceInfo{
		"192.0.2.30": {Target: "192.0.2.30", Port: mdnsPort, ProbeError: "no_response"},
	})
	stubMDNSMulticast(t, map[string]MDNSServiceInfo{
		"192.0.2.30": {Target: "192.0.2.30", MDNSProbe: true, ServiceTypes: []string{"_ipp._tcp.local."}},
	})

	info := mdnsExecute(t, mdnsOpenPortInputs("192.0.2.30"))["192.0.2.30"]

	require.True(t, info.MDNSProbe)
	require.Empty(t, info.ProbeError, "a host that answered is not a failure")
	require.Equal(t, deviceTypePrinter, info.DeviceType)
}

func TestMDNSExecute_MulticastDisabledKeepsUnicastOnly(t *testing.T) {
	stubMDNSUnicast(t, nil)
	original := mdnsMulticastCollectF
	t.Cleanup(func() { mdnsMulticastCollectF = original })
	called := false
	mdnsMulticastCollectF = func(context.Context, MDNSProbeOptions) map[string]MDNSServiceInfo {
		called = true
		return nil
	}

	module := newMDNSNativeProbeModule()
	require.NoError(t, module.Init("mdns", map[string]any{"multicast_enabled": false}))
	outputs := make(chan engine.ModuleOutput, 4)
	require.NoError(t, module.Execute(context.Background(), mdnsScopeInputs("192.0.2.10"), outputs))
	close(outputs)

	require.False(t, called, "multicast must not be sent when it is disabled")
	require.Empty(t, outputs, "no open UDP/5353 means no unicast candidate either")
}

func TestMDNSExecute_NoTargetsIsANoOp(t *testing.T) {
	stubMDNSMulticast(t, map[string]MDNSServiceInfo{
		"192.0.2.10": {Target: "192.0.2.10", MDNSProbe: true},
	})
	require.Empty(t, mdnsExecute(t, map[string]any{}))
}

// The merge fills gaps; it does not let a second answer overwrite a field the
// first one already stated.
func TestMergeMDNSInfo_FillsOnlyWhatIsMissing(t *testing.T) {
	dst := MDNSServiceInfo{
		Hostname:     "first.local",
		ServiceTypes: []string{"_airplay._tcp.local."},
		TXTAttrs:     map[string]string{"md": "first"},
	}
	mergeMDNSInfo(&dst, MDNSServiceInfo{
		Hostname:     "second.local",
		InstanceName: "Living Room",
		ServiceTypes: []string{"_googlecast._tcp.local.", "_airplay._tcp.local."},
		TXTAttrs:     map[string]string{"md": "second", "fw": "1.2.3"},
	})

	require.Equal(t, "first.local", dst.Hostname)
	require.Equal(t, "first", dst.TXTAttrs["md"])
	require.Equal(t, "Living Room", dst.InstanceName, "an empty field is filled")
	require.Equal(t, "1.2.3", dst.TXTAttrs["fw"], "an absent key is added")
	require.Len(t, dst.ServiceTypes, 2, "service types are unioned, not duplicated")
}

// AirPlay and RAOP are licensed to third parties, so they must not be read as
// an Apple vendor signal — the Sony television on the test segment advertises
// AirPlay.
func TestAdvertisesAppleOnlyService(t *testing.T) {
	require.True(t, advertisesAppleOnlyService([]string{"_companion-link._tcp.local."}))
	require.True(t, advertisesAppleOnlyService([]string{"_RDLINK._TCP.LOCAL."}))
	require.False(t, advertisesAppleOnlyService([]string{"_airplay._tcp.local."}))
	require.False(t, advertisesAppleOnlyService([]string{"_raop._tcp.local."}))
	require.False(t, advertisesAppleOnlyService(nil))
}

func TestDeriveMDNSIdentity_AppleServiceDoesNotOverrideAStatedVendor(t *testing.T) {
	result := MDNSServiceInfo{
		ServiceTypes: []string{"_companion-link._tcp.local."},
		TXTAttrs:     map[string]string{"manufacturer": "Someone Else"},
	}
	deriveMDNSIdentity(&result)
	require.Equal(t, "Someone Else", result.VendorHint)
}

// TestMDNSMulticast_Live exercises a real segment. Skipped unless MDNS_LIVE=1:
// MDNS_LIVE=1 go test ./pkg/modules/scan/ -run MDNSMulticast.*Live -v
func TestMDNSMulticast_Live(t *testing.T) {
	if os.Getenv("MDNS_LIVE") == "" {
		t.Skip("set MDNS_LIVE=1 to run the live mDNS multicast test")
	}
	opts := defaultMDNSProbeOptions()
	opts.ListenTimeout = 5 * time.Second
	found := collectMDNSMulticast(context.Background(), opts)
	for host, info := range found {
		deriveMDNSIdentity(&info)
		t.Logf("%s: services=%v vendor=%q model=%q type=%q",
			host, info.ServiceTypes, info.VendorHint, info.Model, info.DeviceType)
	}
	require.NotEmpty(t, found, "expected at least one mDNS responder on this segment")
}

// The multicast pass sends eighteen datagrams and a TXT key keeps the first
// value it sees, so applying answers in arrival order would let the network
// decide which model string survives: the same host could report a different
// product between two runs. Records are collected first and ordered by content
// before being parsed, which this pins by feeding the same answers in both
// orders and requiring the same result.
func TestCollectMDNSMulticast_ResultDoesNotDependOnArrivalOrder(t *testing.T) {
	first := buildMDNSResponse(t, mdnsDeviceInfo,
		[]string{"Device._device-info._tcp.local."}, "", []string{"model=FirstAnswer"})
	second := buildMDNSResponse(t, "_googlecast._tcp.local.",
		[]string{"Cast._googlecast._tcp.local."}, "", []string{"model=SecondAnswer"})

	forward := mergeMDNSPackets("192.0.2.10", [][]byte{first, second})
	reverse := mergeMDNSPackets("192.0.2.10", [][]byte{second, first})
	deriveMDNSIdentity(&forward)
	deriveMDNSIdentity(&reverse)

	require.Equal(t, forward.Model, reverse.Model,
		"the surviving value must not depend on which datagram arrived first")
	require.NotEmpty(t, forward.Model)
}

// deriveMDNSIdentity resets what it derives, so running it twice over the same
// records gives the same answer and a stale value from an earlier pass cannot
// survive. Without that, a field guarded by "only if empty" keeps a value
// derived from one transport while its siblings are recomputed from both.
func TestDeriveMDNSIdentity_IsIdempotentAndClearsStaleDerivations(t *testing.T) {
	info := MDNSServiceInfo{
		ServiceTypes: []string{"_ipp._tcp.local."},
		TXTAttrs:     map[string]string{"ty": "OfficeJet 9010"},
		// Left over from an earlier derivation over different records.
		Model:       "StaleModel",
		ProductHint: "Stale Product",
		VendorHint:  "StaleVendor",
		VersionHint: "0.0.0",
		DeviceType:  deviceTypeMediaDevice,
	}

	deriveMDNSIdentity(&info)
	once := info
	deriveMDNSIdentity(&info)

	require.Equal(t, once, info, "deriving twice must not change the answer")
	require.Equal(t, "OfficeJet 9010", info.Model)
	require.Equal(t, deviceTypePrinter, info.DeviceType)
	require.NotContains(t, info.ProductHint, "Stale")
	require.Empty(t, info.VersionHint, "no record states a version, so none is claimed")
}
