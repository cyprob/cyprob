package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

func TestParseSSDPReply(t *testing.T) {
	reply := "HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=1900\r\n" +
		"LOCATION: http://192.0.2.10:8008/ssdp/device-desc.xml\r\n" +
		"SERVER: Linux/4.9.113, UPnP/1.0, Chromecast/1.6.18\r\n" +
		"USN: uuid:502a40f6-17a8-32a5-2d26-f200dae60262::upnp:rootdevice\r\n\r\n"

	info := parseSSDPReply(reply)
	require.Equal(t, "http://192.0.2.10:8008/ssdp/device-desc.xml", info.Location)
	require.Equal(t, "Linux/4.9.113, UPnP/1.0, Chromecast/1.6.18", info.Server)
	require.Equal(t, "uuid:502a40f6-17a8-32a5-2d26-f200dae60262", info.UDN,
		"the USN suffix is the service, not the device identity")
}

func TestApplySSDPDescription(t *testing.T) {
	body := `<?xml version="1.0"?><root><device>
		<friendlyName>LS MI</friendlyName>
		<manufacturer>Xiaomi</manufacturer>
		<modelName>MIBOX3</modelName>
		<serialNumber>ABC123</serialNumber>
	</device></root>`

	var info SSDPDeviceInfo
	applySSDPDescription(&info, body)
	require.Equal(t, "LS MI", info.FriendlyName)
	require.Equal(t, "Xiaomi", info.Manufacturer)
	require.Equal(t, "MIBOX3", info.ModelName)
	require.Equal(t, "ABC123", info.SerialNumber)
}

func TestApplySSDPDescription_FirstValueWins(t *testing.T) {
	// A description embeds several devices; the root device comes first and is
	// the one that identifies the box.
	body := `<root>
		<device><manufacturer>Xiaomi</manufacturer><modelName>MIBOX3</modelName></device>
		<device><manufacturer>Generic</manufacturer><modelName>Renderer</modelName></device>
	</root>`
	var info SSDPDeviceInfo
	applySSDPDescription(&info, body)
	require.Equal(t, "Xiaomi", info.Manufacturer)
	require.Equal(t, "MIBOX3", info.ModelName)
}

func TestSanitizeSSDPValue(t *testing.T) {
	require.Equal(t, "AB[31mC", sanitizeSSDPValue("AB\x1b[31mC"),
		"a hostile reply must not carry escapes into a report")
	require.Len(t, sanitizeSSDPValue(strings.Repeat("x", 500)), 256,
		"a device does not get to claim an unbounded name")
}

// A device must not be able to point the scanner at a host of its choosing.
func TestSSDPLocationBelongsToTarget(t *testing.T) {
	require.True(t, ssdpLocationBelongsToTarget("http://192.0.2.10:8008/desc.xml", "192.0.2.10"))
	require.True(t, ssdpLocationBelongsToTarget("http://192.0.2.10/desc.xml", "192.0.2.10"))
	require.False(t, ssdpLocationBelongsToTarget("http://10.0.0.1:8008/desc.xml", "192.0.2.10"),
		"a location naming another host is a redirect the target chose")
	require.False(t, ssdpLocationBelongsToTarget("http://internal.example.com/desc.xml", "192.0.2.10"))
	require.False(t, ssdpLocationBelongsToTarget("file:///etc/passwd", "192.0.2.10"))
	require.False(t, ssdpLocationBelongsToTarget("", "192.0.2.10"))
}

func TestFetchSSDPDescription_RejectsForeignLocation(t *testing.T) {
	var reached bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	info := SSDPDeviceInfo{Target: "192.0.2.10", Location: server.URL + "/desc.xml"}
	fetchSSDPDescription(context.Background(), &info, time.Second)

	require.False(t, reached, "the scanner must not follow a location off the target")
	require.NotEmpty(t, info.ProbeError)
	require.Empty(t, info.Location)
}

func TestFetchSSDPDescription_ReadsIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<root><device>
			<friendlyName>Living Room</friendlyName>
			<manufacturer>Xiaomi</manufacturer>
			<modelName>MIBOX3</modelName>
		</device></root>`))
	}))
	defer server.Close()

	host, _, _ := strings.Cut(strings.TrimPrefix(server.URL, "http://"), ":")
	info := SSDPDeviceInfo{Target: host, Location: server.URL + "/desc.xml"}
	fetchSSDPDescription(context.Background(), &info, 2*time.Second)

	require.Empty(t, info.ProbeError)
	require.Equal(t, "Xiaomi", info.Manufacturer)
	require.Equal(t, "MIBOX3", info.ModelName)
	require.Equal(t, "Living Room", info.FriendlyName)
}

// A multicast query reaches hosts nobody asked to scan; those must not become
// assets.
func TestSSDPExecute_OnlyReportsHostsInScope(t *testing.T) {
	originalCollect := ssdpCollectFunc
	originalDescribe := ssdpDescribeFn
	defer func() {
		ssdpCollectFunc = originalCollect
		ssdpDescribeFn = originalDescribe
	}()
	ssdpCollectFunc = func(context.Context, []string, SSDPProbeOptions) map[string]SSDPDeviceInfo {
		return map[string]SSDPDeviceInfo{
			"192.0.2.10": {Target: "192.0.2.10", SSDPProbe: true, ModelName: "MIBOX3"},
			"198.51.100.7": {Target: "198.51.100.7", SSDPProbe: true,
				ModelName: "SomeoneElsesDevice"},
		}
	}
	ssdpDescribeFn = func(context.Context, *SSDPDeviceInfo, time.Duration) {}

	module := newSSDPProbeModule()
	outputs := make(chan engine.ModuleOutput, 8)
	err := module.Execute(context.Background(),
		map[string]any{"discovery.live_hosts": discovery.ICMPPingDiscoveryResult{
			LiveHosts: []string{"192.0.2.10"},
		}}, outputs)
	require.NoError(t, err)
	close(outputs)

	var reported []string
	for out := range outputs {
		reported = append(reported, out.Target)
	}
	require.Equal(t, []string{"192.0.2.10"}, reported,
		"only requested targets may be reported as assets")
}

func TestSSDPExecute_NoTargetsIsANoOp(t *testing.T) {
	module := newSSDPProbeModule()
	outputs := make(chan engine.ModuleOutput, 1)
	require.NoError(t, module.Execute(context.Background(), map[string]any{}, outputs))
	require.Empty(t, outputs)
}

// TestSSDPProbe_Live exercises a real segment. Skipped unless SSDP_LIVE_TARGETS
// is set, e.g. SSDP_LIVE_TARGETS=192.168.0.32,192.168.0.131 go test -run SSDP.*Live
func TestSSDPProbe_Live(t *testing.T) {
	raw := os.Getenv("SSDP_LIVE_TARGETS")
	if raw == "" {
		t.Skip("set SSDP_LIVE_TARGETS to run the live SSDP probe test")
	}
	targets := strings.Split(raw, ",")
	opts := defaultSSDPProbeOptions()
	replies := collectSSDPReplies(context.Background(), targets, opts)
	require.NotEmpty(t, replies, "expected at least one SSDP responder")

	for _, target := range targets {
		info, ok := replies[strings.TrimSpace(target)]
		if !ok {
			t.Logf("%s: no SSDP reply", target)
			continue
		}
		if info.Location != "" {
			fetchSSDPDescription(context.Background(), &info, opts.RequestTimeout)
		}
		t.Logf("%s: manufacturer=%q model=%q name=%q serial=%q server=%q err=%q",
			info.Target, info.Manufacturer, info.ModelName, info.FriendlyName,
			info.SerialNumber, info.Server, info.ProbeError)
	}
}

// A scan of explicitly named targets runs no ping sweep. Requiring live hosts
// would drop this module from the plan for exactly those scans.
func TestSSDPTargetsInScope(t *testing.T) {
	t.Run("port-scan targets alone are enough", func(t *testing.T) {
		targets := ssdpTargetsInScope(map[string]any{
			"discovery.open_udp_ports": []any{
				discovery.UDPPortDiscoveryResult{Target: "192.0.2.10", OpenPorts: []int{1900}},
			},
		})
		require.Equal(t, []string{"192.0.2.10"}, targets)
	})

	t.Run("live hosts widen the set without duplicating", func(t *testing.T) {
		targets := ssdpTargetsInScope(map[string]any{
			"discovery.live_hosts": discovery.ICMPPingDiscoveryResult{
				LiveHosts: []string{"192.0.2.10", "192.0.2.11"},
			},
			"discovery.open_udp_ports": []any{
				discovery.UDPPortDiscoveryResult{Target: "192.0.2.10"},
			},
		})
		require.Equal(t, []string{"192.0.2.10", "192.0.2.11"}, targets)
	})

	t.Run("no inputs means no targets", func(t *testing.T) {
		require.Empty(t, ssdpTargetsInScope(map[string]any{}))
	})
}

// The module must survive a plan without host discovery, which is what made it
// silently vanish before.
func TestSSDPExecute_RunsWithoutHostDiscovery(t *testing.T) {
	originalCollect := ssdpCollectFunc
	originalDescribe := ssdpDescribeFn
	defer func() {
		ssdpCollectFunc = originalCollect
		ssdpDescribeFn = originalDescribe
	}()
	ssdpCollectFunc = func(context.Context, []string, SSDPProbeOptions) map[string]SSDPDeviceInfo {
		return map[string]SSDPDeviceInfo{"192.0.2.10": {Target: "192.0.2.10", SSDPProbe: true}}
	}
	ssdpDescribeFn = func(context.Context, *SSDPDeviceInfo, time.Duration) {}

	module := newSSDPProbeModule()
	outputs := make(chan engine.ModuleOutput, 4)
	require.NoError(t, module.Execute(context.Background(), map[string]any{
		"discovery.open_udp_ports": []any{
			discovery.UDPPortDiscoveryResult{Target: "192.0.2.10", OpenPorts: []int{1900}},
		},
	}, outputs))
	close(outputs)
	require.Len(t, outputs, 1)
}
