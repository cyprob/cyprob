package scan

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestProbeMDNSDetails_Live exercises the probe against a real mDNS responder on
// the local link. It is skipped unless MDNS_LIVE_ADDR is set, because unicast
// mDNS needs an actual DNS-SD device on the same segment. Run with:
//
//	MDNS_LIVE_ADDR=192.168.1.10 go test ./pkg/modules/scan -run MDNSDetails_Live -v
func TestProbeMDNSDetails_Live(t *testing.T) {
	addr := os.Getenv("MDNS_LIVE_ADDR")
	if addr == "" {
		t.Skip("set MDNS_LIVE_ADDR to run the live mDNS probe test")
	}

	result := probeMDNSDetails(context.Background(), addr, mdnsPort, MDNSProbeOptions{
		TotalTimeout: 6 * time.Second,
		IOTimeout:    1500 * time.Millisecond,
	})

	require.True(t, result.MDNSProbe, "expected an mDNS response; error=%q", result.ProbeError)
	require.NotEmpty(t, result.ServiceTypes, "expected advertised service types")

	t.Logf("host=%s instance=%q hostname=%q", addr, result.InstanceName, result.Hostname)
	t.Logf("  services=%s", strings.Join(result.ServiceTypes, " "))
	t.Logf("  vendor=%q model=%q version=%q deviceType=%q",
		result.VendorHint, result.Model, result.VersionHint, result.DeviceType)
	t.Logf("  product=%q", result.ProductHint)
}
