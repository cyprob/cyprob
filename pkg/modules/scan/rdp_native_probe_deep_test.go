package scan

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestParseRDPNegotiationDetails_ResponseFlags(t *testing.T) {
	response := []byte{
		0x03, 0x00, 0x00, 0x13,
		0x0e, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00,
		0x02, 0x18, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00,
	}

	details := parseRDPNegotiationDetails(response)
	if details.selectedProtocol != "hybrid_ex" {
		t.Fatalf("expected hybrid_ex, got %q", details.selectedProtocol)
	}
	if !details.restrictedAdminSupported {
		t.Fatalf("expected restricted admin support")
	}
	if !details.restrictedAuthSupported {
		t.Fatalf("expected redirected auth support")
	}
}

func TestProbeRDPDetails_CollectsDeepMetadata(t *testing.T) {
	serverTime := time.Date(2026, time.March, 16, 11, 5, 32, 0, time.UTC)
	challenge := buildTestNTLMChallenge(
		"Prod2022",
		"Prod2022",
		"Prod2022",
		"Prod2022",
		"Prod2022",
		serverTime,
		10,
		0,
		20348,
	)

	host, port, cleanup := startFakeRDPDeepMetadataServer(t, "Prod2022", challenge)
	defer cleanup()

	result := probeRDPDetails(context.Background(), host, port, RDPProbeOptions{
		TotalTimeout:   5 * time.Second,
		ConnectTimeout: time.Second,
		IOTimeout:      time.Second,
		Retries:        0,
	})

	if !result.RDPProbe {
		t.Fatalf("expected rdp_probe=true, got false with error %q", result.Error)
	}
	if result.RDPDetected != "x224-confirm" {
		t.Fatalf("expected x224-confirm, got %q", result.RDPDetected)
	}
	if result.SelectedProtocol != "hybrid" {
		t.Fatalf("expected base selected protocol hybrid, got %q", result.SelectedProtocol)
	}
	if result.HybridExCapable == nil || !*result.HybridExCapable {
		t.Fatalf("expected hybridex_capable=true, got %+v", result.HybridExCapable)
	}
	if result.RestrictedAdminCapable == nil || !*result.RestrictedAdminCapable {
		t.Fatalf("expected restrictedadmin_capable=true, got %+v", result.RestrictedAdminCapable)
	}
	if result.RestrictedAuthCapable == nil || !*result.RestrictedAuthCapable {
		t.Fatalf("expected restrictedauth_capable=true, got %+v", result.RestrictedAuthCapable)
	}
	if result.CertSubjectCN != "Prod2022" {
		t.Fatalf("expected cert subject Prod2022, got %q", result.CertSubjectCN)
	}
	if !result.CertIsSelfSigned {
		t.Fatalf("expected self-signed cert")
	}
	if result.CertSHA256 == "" {
		t.Fatalf("expected cert sha256")
	}
	if result.NTLMComputerName != "Prod2022" {
		t.Fatalf("expected NTLM computer name Prod2022, got %q", result.NTLMComputerName)
	}
	if result.NTLMDNSComputerName != "Prod2022" {
		t.Fatalf("expected NTLM DNS computer name Prod2022, got %q", result.NTLMDNSComputerName)
	}
	if result.OSBuild != 20348 {
		t.Fatalf("expected os build 20348, got %d", result.OSBuild)
	}
	if result.OSMajorVersion != "10" || result.OSMinorVersion != "0" {
		t.Fatalf("expected os major/minor 10/0, got %q/%q", result.OSMajorVersion, result.OSMinorVersion)
	}
	if result.LocalTime.IsZero() {
		t.Fatalf("expected local time to be populated")
	}
}

func startFakeRDPDeepMetadataServer(t *testing.T, certHost string, challenge []byte) (string, int, func()) {
	t.Helper()

	ln := mustListenTCP(t, "127.0.0.1:0")
	tlsConfig := mustSelfSignedTLSConfig(t, certHost)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleFakeRDPDeepMetadataConn(conn, tlsConfig, challenge)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, func() { _ = ln.Close() }
}

func handleFakeRDPDeepMetadataConn(conn net.Conn, tlsConfig *tls.Config, challenge []byte) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	req := make([]byte, 512)
	n, err := conn.Read(req)
	if err != nil {
		return
	}
	flags, requestedProtocols := parseTestRDPRequest(req[:n])
	selectedProtocol := selectTestRDPProtocol(requestedProtocols)
	responseFlags := byte(0)
	if (flags & 0x01) == 0x01 {
		responseFlags |= 0x08
	}
	if (flags & 0x02) == 0x02 {
		responseFlags |= 0x10
	}
	if _, err := conn.Write(buildTestRDPConfirmResponse(selectedProtocol, responseFlags)); err != nil {
		return
	}

	if selectedProtocol != 0x01 && selectedProtocol != 0x02 && selectedProtocol != 0x08 {
		return
	}

	tlsConn := tls.Server(conn, tlsConfig)
	defer func() { _ = tlsConn.Close() }()
	_ = tlsConn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	payload := make([]byte, 4096)
	n, err = tlsConn.Read(payload)
	if err != nil {
		return
	}
	if bytes.Contains(payload[:n], []byte("NTLMSSP\x00\x01\x00\x00\x00")) {
		_, _ = tlsConn.Write(challenge)
	}
}

func parseTestRDPRequest(req []byte) (byte, uint32) {
	if len(req) < 12 {
		return 0, 0
	}
	negReq := req[len(req)-8:]
	return negReq[1], binary.LittleEndian.Uint32(negReq[4:8])
}

func selectTestRDPProtocol(requestedProtocols uint32) uint32 {
	switch {
	case requestedProtocols&0x00000008 != 0:
		return 0x00000008
	case requestedProtocols&0x00000002 != 0:
		return 0x00000002
	case requestedProtocols&0x00000001 != 0:
		return 0x00000001
	default:
		return 0x00000000
	}
}

func buildTestRDPConfirmResponse(selectedProtocol uint32, responseFlags byte) []byte {
	resp := []byte{
		0x03, 0x00, 0x00, 0x13,
		0x0e, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00,
		0x02, responseFlags, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	binary.LittleEndian.PutUint32(resp[15:19], selectedProtocol)
	return resp
}

func buildTestNTLMChallenge(targetName string, nbComputer string, nbDomain string, dnsComputer string, dnsDomain string, serverTime time.Time, major byte, minor byte, build uint16) []byte {
	targetNameBytes := utf16LEBytes(targetName)
	avPairs := make([]byte, 0, 128)
	avPairs = appendAVPair(avPairs, 1, utf16LEBytes(nbComputer))
	avPairs = appendAVPair(avPairs, 2, utf16LEBytes(nbDomain))
	avPairs = appendAVPair(avPairs, 3, utf16LEBytes(dnsComputer))
	avPairs = appendAVPair(avPairs, 4, utf16LEBytes(dnsDomain))
	avPairs = appendAVPair(avPairs, 5, utf16LEBytes(dnsDomain))
	avPairs = appendAVPair(avPairs, 7, filetimeBytes(serverTime))
	avPairs = appendAVPair(avPairs, 0, nil)

	targetNameOffset := 56
	targetInfoOffset := targetNameOffset + len(targetNameBytes)
	msg := make([]byte, targetInfoOffset+len(avPairs))
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 2)
	binary.LittleEndian.PutUint16(msg[12:14], uint16(len(targetNameBytes)))
	binary.LittleEndian.PutUint16(msg[14:16], uint16(len(targetNameBytes)))
	binary.LittleEndian.PutUint32(msg[16:20], uint32(targetNameOffset))
	binary.LittleEndian.PutUint32(msg[20:24], 0x02888205)
	copy(msg[24:32], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(avPairs)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(avPairs)))
	binary.LittleEndian.PutUint32(msg[44:48], uint32(targetInfoOffset))
	msg[48] = major
	msg[49] = minor
	binary.LittleEndian.PutUint16(msg[50:52], build)
	msg[55] = 15
	copy(msg[targetNameOffset:], targetNameBytes)
	copy(msg[targetInfoOffset:], avPairs)
	return msg
}

func appendAVPair(dst []byte, avID uint16, value []byte) []byte {
	entry := make([]byte, 4)
	binary.LittleEndian.PutUint16(entry[0:2], avID)
	binary.LittleEndian.PutUint16(entry[2:4], uint16(len(value)))
	dst = append(dst, entry...)
	dst = append(dst, value...)
	return dst
}

func utf16LEBytes(input string) []byte {
	raw := []rune(input)
	out := make([]byte, 0, len(raw)*2)
	for _, r := range raw {
		buf := make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, uint16(r))
		out = append(out, buf...)
	}
	return out
}

func filetimeBytes(value time.Time) []byte {
	filetime := (value.UTC().UnixNano() / 100) + 116444736000000000
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, uint64(filetime))
	return out
}
