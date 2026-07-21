package scan

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestProbeSNMPDetails_V3LiveAuthPriv exercises the real SNMPv3 (USM) authPriv
// path against a live net-snmp daemon. It is skipped unless SNMP_V3_LIVE_ADDR
// is set, because the unit-test mock does not implement USM. Run with:
//
//	SNMP_V3_LIVE_ADDR=127.0.0.1:16100 go test ./pkg/modules/scan -run V3LiveAuthPriv
//
// against an snmpd configured with:
//
//	createUser monitor SHA "authpass123" AES "privpass123"
func TestProbeSNMPDetails_V3LiveAuthPriv(t *testing.T) {
	addr := os.Getenv("SNMP_V3_LIVE_ADDR")
	if addr == "" {
		t.Skip("set SNMP_V3_LIVE_ADDR to run the live SNMPv3 integration test")
	}
	host, port := splitHostPortForTest(t, addr)

	opts := SNMPProbeOptions{
		TotalTimeout:      4 * time.Second,
		PerAttemptTimeout: 1500 * time.Millisecond,
		V3Username:        "monitor",
		V3AuthProtocol:    "SHA",
		V3AuthPassphrase:  "authpass123",
		V3PrivProtocol:    "AES",
		V3PrivPassphrase:  "privpass123",
	}

	result := probeSNMPDetails(context.Background(), host, port, opts)

	require.True(t, result.SNMPProbe, "expected a successful SNMP probe; error=%q", result.ProbeError)
	require.Equal(t, "SNMPv3", result.SNMPVersion)
	require.Equal(t, "authPriv", result.SecurityLevel)
	require.Equal(t, "monitor", result.User)
	require.Empty(t, result.Community, "v3 result must not carry a community")
	require.False(t, result.WeakProtocol, "v3 must not be flagged weak")
	require.NotEmpty(t, result.SysDescr, "expected sysDescr from the agent")
	t.Logf("v3 authPriv sysDescr = %q", result.SysDescr)
}

func splitHostPortForTest(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return host, port
}
