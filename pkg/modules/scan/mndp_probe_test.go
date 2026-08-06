package scan

import (
	"context"
	"encoding/binary"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

// mndpAnnouncement builds a packet in the wire format, so the parser is
// exercised against the protocol rather than against its own encoder.
func mndpAnnouncement(fields map[uint16][]byte) []byte {
	packet := make([]byte, 0, 128)
	packet = append(packet, 0x12, 0xb5, 0x00, 0x00)

	// Deterministic order keeps the fixture stable across runs.
	for _, fieldType := range []uint16{1, 5, 7, 8, 11, 12, 16} {
		value, ok := fields[fieldType]
		if !ok {
			continue
		}
		header := make([]byte, 4)
		binary.BigEndian.PutUint16(header[0:2], fieldType)
		binary.BigEndian.PutUint16(header[2:4], uint16(len(value)))
		packet = append(packet, header...)
		packet = append(packet, value...)
	}
	return packet
}

// The fixture is the announcement captured from a live RouterOS device, so a
// change in the parser is measured against real traffic.
func TestParseMNDPAnnouncement(t *testing.T) {
	packet := mndpAnnouncement(map[uint16][]byte{
		1:  {0x08, 0x55, 0x31, 0xe3, 0xde, 0xe7},
		5:  []byte("Habib"),
		7:  []byte("6.49.10 (long-term)"),
		8:  []byte("MikroTik"),
		11: []byte("3ERZ-421L"),
		12: []byte("RB3011UiAS"),
		16: []byte("bridge1/ether1"),
	})

	info := parseMNDPAnnouncement(packet)
	require.True(t, info.MNDPProbe)
	require.Equal(t, "Habib", info.Identity)
	require.Equal(t, "MikroTik", info.Platform)
	require.Equal(t, "RB3011UiAS", info.Board)
	require.Equal(t, "6.49.10 (long-term)", info.Version)
	require.Equal(t, "3ERZ-421L", info.SoftwareID)
	require.Equal(t, "bridge1/ether1", info.Interface)
	require.Equal(t, "08:55:31:e3:de:e7", info.MACAddress)
}

// Version-based CVE matching needs the release on its own; the suffix a device
// appends is not part of it.
func TestParseMNDPAnnouncement_VersionNumber(t *testing.T) {
	for _, tc := range []struct{ announced, want string }{
		{"6.49.10 (long-term)", "6.49.10"},
		{"7.14 (stable)", "7.14"},
		{"6.48", "6.48"},
		{"(unknown)", ""},
	} {
		info := parseMNDPAnnouncement(mndpAnnouncement(map[uint16][]byte{7: []byte(tc.announced)}))
		require.Equal(t, tc.want, info.VersionNumber, "announced %q", tc.announced)
	}
}

// The request this probe broadcasts is a four-byte packet and arrives back from
// the local interface; it names nothing and must not become a neighbor.
func TestParseMNDPAnnouncement_EmptyRequestIsNotAnIdentity(t *testing.T) {
	require.False(t, parseMNDPAnnouncement([]byte{0, 0, 0, 0}).MNDPProbe)
	require.False(t, parseMNDPAnnouncement(nil).MNDPProbe)
}

func TestParseMNDPAnnouncement_TruncatedInputIsRejectedWithoutPanicking(t *testing.T) {
	full := mndpAnnouncement(map[uint16][]byte{
		5:  []byte("Habib"),
		12: []byte("RB3011UiAS"),
	})
	for cut := 0; cut < len(full); cut++ {
		_ = parseMNDPAnnouncement(full[:cut])
	}

	// A length larger than the packet must not read past the end.
	lying := mndpAnnouncement(map[uint16][]byte{5: []byte("Habib")})
	binary.BigEndian.PutUint16(lying[6:8], 0xffff)
	require.False(t, parseMNDPAnnouncement(lying).MNDPProbe)
}

// A hostile or corrupt announcement must not carry escapes into a report.
func TestSanitizeMNDPText(t *testing.T) {
	require.Equal(t, "AB[31mC", sanitizeMNDPText([]byte("AB\x1b[31mC")))
	require.Len(t, sanitizeMNDPText(make([]byte, 400)), 0, "control bytes are stripped entirely")
}

// The request reaches the whole segment, so devices nobody asked to scan will
// answer. Those must not become assets.
func TestMNDPExecute_OnlyReportsHostsInScope(t *testing.T) {
	original := mndpCollectFunc
	defer func() { mndpCollectFunc = original }()
	mndpCollectFunc = func(context.Context, MNDPProbeOptions) map[string]MNDPNeighborInfo {
		return map[string]MNDPNeighborInfo{
			"192.0.2.10":   {Target: "192.0.2.10", MNDPProbe: true, Board: "RB3011UiAS"},
			"198.51.100.7": {Target: "198.51.100.7", MNDPProbe: true, Board: "SomeoneElsesRouter"},
		}
	}

	module := newMNDPProbeModule()
	outputs := make(chan engine.ModuleOutput, 8)
	require.NoError(t, module.Execute(context.Background(), map[string]any{
		"discovery.open_udp_ports": []any{
			discovery.UDPPortDiscoveryResult{Target: "192.0.2.10"},
		},
	}, outputs))
	close(outputs)

	var reported []string
	for out := range outputs {
		reported = append(reported, out.Target)
	}
	require.Equal(t, []string{"192.0.2.10"}, reported,
		"only requested targets may be reported as assets")
}

func TestMNDPExecute_NoTargetsIsANoOp(t *testing.T) {
	module := newMNDPProbeModule()
	outputs := make(chan engine.ModuleOutput, 1)
	require.NoError(t, module.Execute(context.Background(), map[string]any{}, outputs))
	require.Empty(t, outputs)
}

// TestMNDPProbe_Live exercises a real segment. Skipped unless MNDP_LIVE=1, e.g.
// MNDP_LIVE=1 go test ./pkg/modules/scan/ -run MNDP.*Live
func TestMNDPProbe_Live(t *testing.T) {
	if os.Getenv("MNDP_LIVE") == "" {
		t.Skip("set MNDP_LIVE=1 to run the live MNDP probe test")
	}
	found := collectMNDPAnnouncements(context.Background(),
		MNDPProbeOptions{TotalTimeout: 10 * time.Second, ListenTimeout: 8 * time.Second})
	for host, info := range found {
		t.Logf("%s: platform=%q board=%q version=%q (%s) identity=%q software_id=%q mac=%q",
			host, info.Platform, info.Board, info.Version, info.VersionNumber,
			info.Identity, info.SoftwareID, info.MACAddress)
	}
	require.NotEmpty(t, found, "expected at least one MNDP announcement on this segment")
}
