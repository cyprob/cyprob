package scan

import (
	"context"
	"encoding/binary"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/modules/discovery"
)

// nbnsResponse assembles a node status response so the parser can be exercised
// against the wire format rather than against its own encoder.
func nbnsResponse(names []NBNSName, mac []byte) []byte {
	header := make([]byte, nbnsHeaderLen)
	binary.BigEndian.PutUint16(header[0:2], 0x1337)
	binary.BigEndian.PutUint16(header[6:8], 1) // ANCOUNT
	packet := make([]byte, 0, nbnsHeaderLen+nbnsEncodedNameLen)
	packet = append(packet, header...)

	var wildcard [16]byte
	wildcard[0] = '*'
	packet = append(packet, encodeNetBIOSName(wildcard)...)

	fixed := make([]byte, 10) // TYPE, CLASS, TTL, RDLENGTH
	binary.BigEndian.PutUint16(fixed[0:2], nbnsNodeStatusType)
	binary.BigEndian.PutUint16(fixed[2:4], nbnsClassIN)
	packet = append(packet, fixed...)

	packet = append(packet, byte(len(names)))
	for _, entry := range names {
		field := make([]byte, nbnsNameEntryLen)
		copy(field[0:15], padNetBIOSName(entry.Name))
		field[15] = entry.Suffix
		if entry.IsGroup {
			binary.BigEndian.PutUint16(field[16:18], nbnsGroupFlag)
		}
		packet = append(packet, field...)
	}
	return append(packet, mac...)
}

func padNetBIOSName(name string) []byte {
	padded := []byte("               ")
	copy(padded, name)
	return padded
}

func TestBuildNBNSNodeStatusRequest(t *testing.T) {
	request := buildNBNSNodeStatusRequest()
	require.Len(t, request, nbnsHeaderLen+nbnsEncodedNameLen+4)
	require.Equal(t, uint16(1), binary.BigEndian.Uint16(request[4:6]), "exactly one question")
	require.Equal(t, uint16(nbnsNodeStatusType), binary.BigEndian.Uint16(request[len(request)-4:len(request)-2]))
	// The wildcard "*" first-level encodes to "CK" followed by 30 'A's.
	require.Equal(t, "CK", string(request[13:15]))
	require.Equal(t, byte(0x20), request[12], "encoded names are always 32 characters")
}

func TestParseNBNSNodeStatus(t *testing.T) {
	t.Run("names and adapter MAC are recovered", func(t *testing.T) {
		mac := []byte{0x00, 0x11, 0x32, 0x43, 0xc8, 0xff}
		response := nbnsResponse([]NBNSName{
			{Name: "GALANAS", Suffix: nbnsSuffixWorkstation},
			{Name: "WORKGROUP", Suffix: nbnsSuffixWorkstation, IsGroup: true},
		}, mac)

		names, gotMAC, err := parseNBNSNodeStatus(response)
		require.NoError(t, err)
		require.Len(t, names, 2)
		require.Equal(t, "GALANAS", names[0].Name)
		require.False(t, names[0].IsGroup)
		require.True(t, names[1].IsGroup)
		require.Equal(t, "00:11:32:43:c8:ff", gotMAC)
	})

	t.Run("an all-zero adapter MAC is not reported", func(t *testing.T) {
		response := nbnsResponse([]NBNSName{{Name: "HOST", Suffix: nbnsSuffixWorkstation}},
			[]byte{0, 0, 0, 0, 0, 0})
		_, mac, err := parseNBNSNodeStatus(response)
		require.NoError(t, err)
		require.Empty(t, mac, "a zero MAC is an absent value, not an identity")
	})

	t.Run("a missing statistics section is not an error", func(t *testing.T) {
		response := nbnsResponse([]NBNSName{{Name: "HOST", Suffix: nbnsSuffixWorkstation}}, nil)
		names, mac, err := parseNBNSNodeStatus(response)
		require.NoError(t, err)
		require.Len(t, names, 1)
		require.Empty(t, mac)
	})

	t.Run("control characters are stripped from names", func(t *testing.T) {
		// A hostile or corrupt reply must not carry escapes into a report.
		response := nbnsResponse([]NBNSName{{Name: "AB\x1b[31mC", Suffix: nbnsSuffixWorkstation}}, nil)
		names, _, err := parseNBNSNodeStatus(response)
		require.NoError(t, err)
		require.Equal(t, "AB[31mC", names[0].Name)
	})

	t.Run("truncated input is rejected without panicking", func(t *testing.T) {
		full := nbnsResponse([]NBNSName{
			{Name: "HOST", Suffix: nbnsSuffixWorkstation},
			{Name: "GROUP", Suffix: nbnsSuffixWorkstation, IsGroup: true},
		}, []byte{1, 2, 3, 4, 5, 6})
		for cut := 0; cut < len(full); cut++ {
			_, _, _ = parseNBNSNodeStatus(full[:cut])
		}
	})

	t.Run("a response with no answer is rejected", func(t *testing.T) {
		empty := make([]byte, nbnsHeaderLen)
		_, _, err := parseNBNSNodeStatus(empty)
		require.Error(t, err)
	})

	t.Run("a name count larger than the payload is rejected", func(t *testing.T) {
		response := nbnsResponse([]NBNSName{{Name: "HOST", Suffix: nbnsSuffixWorkstation}}, nil)
		response[nbnsHeaderLen+nbnsEncodedNameLen+10] = 0xff // claim 255 names
		_, _, err := parseNBNSNodeStatus(response)
		require.Error(t, err)
	})
}

func TestApplyNBNSRoles(t *testing.T) {
	t.Run("unique and group names separate host from domain", func(t *testing.T) {
		info := NBNSNodeInfo{Names: []NBNSName{
			{Name: "HP90C295", Suffix: nbnsSuffixWorkstation},
			{Name: "WORKGROUP", Suffix: nbnsSuffixWorkstation, IsGroup: true},
			{Name: "HP90C295", Suffix: nbnsSuffixFileServer},
		}}
		applyNBNSRoles(&info)
		require.Equal(t, "HP90C295", info.ComputerName)
		require.Equal(t, "WORKGROUP", info.Domain)
		require.True(t, info.ServesSMB)
		require.False(t, info.IsDomainController)
	})

	t.Run("the domain controller group name is recognized", func(t *testing.T) {
		info := NBNSNodeInfo{Names: []NBNSName{
			{Name: "DC01", Suffix: nbnsSuffixWorkstation},
			{Name: "CORP", Suffix: nbnsSuffixDomainCtrl, IsGroup: true},
		}}
		applyNBNSRoles(&info)
		require.Equal(t, "DC01", info.ComputerName)
		require.Equal(t, "CORP", info.Domain)
		require.True(t, info.IsDomainController)
	})

	t.Run("the messenger name is only a user when it differs from the host", func(t *testing.T) {
		same := NBNSNodeInfo{Names: []NBNSName{
			{Name: "DESKTOP-1", Suffix: nbnsSuffixWorkstation},
			{Name: "DESKTOP-1", Suffix: nbnsSuffixMessenger},
		}}
		applyNBNSRoles(&same)
		require.Empty(t, same.UserName, "repeating the hostname is not a user")

		distinct := NBNSNodeInfo{Names: []NBNSName{
			{Name: "DESKTOP-1", Suffix: nbnsSuffixWorkstation},
			{Name: "YAHYA", Suffix: nbnsSuffixMessenger},
		}}
		applyNBNSRoles(&distinct)
		require.Equal(t, "YAHYA", distinct.UserName)
	})
}

func TestNBNSCandidatesFromOpenPorts(t *testing.T) {
	candidates := nbnsCandidatesFromOpenPorts(discovery.UDPPortDiscoveryResult{
		Target:    "192.0.2.10",
		OpenPorts: []int{53, 137, 161, 5353},
	})
	require.Len(t, candidates, 1, "only the NetBIOS name service port is probed")
	require.Equal(t, nbnsPort, candidates[0].port)
	require.Equal(t, "192.0.2.10", candidates[0].target)
}

func TestProbeNBNSDetails_ResolvesVendorFromAdapterMAC(t *testing.T) {
	// The adapter MAC in the reply yields a vendor even when the local
	// neighbor table has no entry for the target.
	original := nbnsExchangeFunc
	defer func() { nbnsExchangeFunc = original }()
	nbnsExchangeFunc = func(context.Context, string, int, []byte, time.Duration) ([]byte, error) {
		return nbnsResponse([]NBNSName{
			{Name: "GALANAS", Suffix: nbnsSuffixWorkstation},
			{Name: "WORKGROUP", Suffix: nbnsSuffixWorkstation, IsGroup: true},
		}, []byte{0x00, 0x11, 0x32, 0x43, 0xc8, 0xff}), nil
	}

	info := probeNBNSDetails(context.Background(), "192.0.2.10", nbnsPort, defaultNBNSProbeOptions())
	require.True(t, info.NBNSProbe)
	require.Equal(t, "GALANAS", info.ComputerName)
	require.Equal(t, "WORKGROUP", info.Domain)
	require.Equal(t, "00:11:32:43:c8:ff", info.MACAddress)
	require.Equal(t, "Synology Incorporated", info.VendorHint)
	require.Empty(t, info.ProbeError)
}

func TestProbeNBNSDetails_NoResponseIsNotAnIdentity(t *testing.T) {
	info := probeNBNSDetails(context.Background(), "192.0.2.1", nbnsPort,
		NBNSProbeOptions{TotalTimeout: 300 * time.Millisecond, IOTimeout: 200 * time.Millisecond})
	require.False(t, info.NBNSProbe)
	require.NotEmpty(t, info.ProbeError)
	require.Empty(t, info.ComputerName)
}

// TestProbeNBNSDetails_Live exercises a real host. Skipped unless NBNS_LIVE_ADDR
// is set, e.g. NBNS_LIVE_ADDR=192.168.0.131 go test -run NBNS.*Live
func TestProbeNBNSDetails_Live(t *testing.T) {
	addr := os.Getenv("NBNS_LIVE_ADDR")
	if addr == "" {
		t.Skip("set NBNS_LIVE_ADDR to run the live NetBIOS probe test")
	}
	info := probeNBNSDetails(context.Background(), addr, nbnsPort, defaultNBNSProbeOptions())
	t.Logf("host=%s name=%q domain=%q user=%q", addr, info.ComputerName, info.Domain, info.UserName)
	t.Logf("  mac=%q vendor=%q smb=%v dc=%v err=%q",
		info.MACAddress, info.VendorHint, info.ServesSMB, info.IsDomainController, info.ProbeError)
	for _, entry := range info.Names {
		t.Logf("  name=%-16q suffix=0x%02x group=%v", entry.Name, entry.Suffix, entry.IsGroup)
	}
	require.Empty(t, info.ProbeError)
	require.NotEmpty(t, info.ComputerName)
}
