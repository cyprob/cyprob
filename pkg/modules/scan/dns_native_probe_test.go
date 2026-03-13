package scan

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/discovery"
	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSNativeProbeModule_ExecuteFiltersCandidates(t *testing.T) {
	original := probeDNSDetailsFunc
	t.Cleanup(func() { probeDNSDetailsFunc = original })

	var seen []string
	probeDNSDetailsFunc = func(ctx context.Context, target string, port int, transport string, options DNSProbeOptions) DNSServiceInfo {
		seen = append(seen, fmt.Sprintf("%s:%d/%s", target, port, transport))
		return DNSServiceInfo{Target: target, Port: port, Transport: transport, DNSProbe: true}
	}

	module := newDNSNativeProbeModule()
	if err := module.Init("test-dns-native", map[string]any{}); err != nil {
		t.Fatalf("init: %v", err)
	}

	outputs := make(chan engine.ModuleOutput, 8)
	err := module.Execute(context.Background(), map[string]any{
		"discovery.open_tcp_ports": []any{
			discovery.TCPPortDiscoveryResult{Target: "192.0.2.10", OpenPorts: []int{53, 80}},
		},
		"discovery.open_udp_ports": []any{
			discovery.UDPPortDiscoveryResult{Target: "192.0.2.10", OpenPorts: []int{53, 161}},
		},
	}, outputs)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(outputs)

	slices.Sort(seen)
	expected := []string{"192.0.2.10:53/tcp", "192.0.2.10:53/udp"}
	if !slices.Equal(seen, expected) {
		t.Fatalf("unexpected candidates: got %v want %v", seen, expected)
	}
}

func TestProbeDNSDetails_UDPVersionBindPreferred(t *testing.T) {
	host, port, cleanup := startTestUDPDNSServer(t, func(query dnsmessage.Message) ([]byte, bool) {
		return buildTestDNSResponse(t, query, testDNSResponseSpec{
			recursionAvailable: query.Questions[0].Name.String() == dnsVersionBindName,
			authoritative:      query.Questions[0].Name.String() == dnsVersionBindName,
			nsRecords:          []string{"a.root-servers.net."},
			txtAnswers:         []string{"BIND 9.16.23"},
		}), true
	})
	defer cleanup()

	result := probeDNSDetails(context.Background(), host, port, dnsTransportUDP, defaultDNSProbeOptions())
	if !result.DNSProbe {
		t.Fatalf("expected dns probe success: %+v", result)
	}
	if !result.NSQueryResponded || !result.VersionBindResponded || !result.VersionBindSupported {
		t.Fatalf("unexpected dns response flags: %+v", result)
	}
	if result.VersionBind != "BIND 9.16.23" {
		t.Fatalf("unexpected version.bind value: %q", result.VersionBind)
	}
	if result.ProductHint != "BIND" || result.VendorHint != "ISC" || result.VersionHint != "9.16.23" {
		t.Fatalf("unexpected hints: %+v", result)
	}
	if !result.RecursionAvailable || !result.AuthoritativeAnswer {
		t.Fatalf("expected top-level fields from version.bind response, got %+v", result)
	}
}

func TestProbeDNSDetails_UDPVersionBindRefusedFallsBackToRootNS(t *testing.T) {
	host, port, cleanup := startTestUDPDNSServer(t, func(query dnsmessage.Message) ([]byte, bool) {
		name := query.Questions[0].Name.String()
		if name == dnsVersionBindName {
			return buildTestDNSResponse(t, query, testDNSResponseSpec{
				rcode: dnsmessage.RCodeRefused,
			}), true
		}
		return buildTestDNSResponse(t, query, testDNSResponseSpec{
			recursionAvailable: true,
			nsRecords:          []string{"a.root-servers.net."},
		}), true
	})
	defer cleanup()

	result := probeDNSDetails(context.Background(), host, port, dnsTransportUDP, defaultDNSProbeOptions())
	if !result.DNSProbe {
		t.Fatalf("expected dns probe success: %+v", result)
	}
	if !result.VersionBindResponded || result.VersionBindSupported {
		t.Fatalf("unexpected version.bind semantics: %+v", result)
	}
	if result.ResponseCode != "NOERROR" {
		t.Fatalf("expected top-level response from root NS response, got %q", result.ResponseCode)
	}
	if result.VersionBind != "" || result.ProductHint != "" || result.VersionHint != "" {
		t.Fatalf("version.bind-derived fields should be empty on unsupported response: %+v", result)
	}
	if len(result.NSRecords) == 0 {
		t.Fatalf("expected NS records from root response")
	}
}

func TestProbeDNSDetails_TCPVersionBindSuccess(t *testing.T) {
	host, port, cleanup := startTestTCPDNSServer(t, func(query dnsmessage.Message) ([]byte, bool) {
		return buildTestDNSResponse(t, query, testDNSResponseSpec{
			nsRecords:  []string{"a.root-servers.net."},
			txtAnswers: []string{"PowerDNS Recursor 4.9.0"},
		}), true
	})
	defer cleanup()

	result := probeDNSDetails(context.Background(), host, port, dnsTransportTCP, defaultDNSProbeOptions())
	if !result.DNSProbe || result.Transport != dnsTransportTCP {
		t.Fatalf("expected tcp dns success, got %+v", result)
	}
	if result.ProductHint != "PowerDNS Recursor" || result.VendorHint != "PowerDNS" || result.VersionHint != "4.9.0" {
		t.Fatalf("unexpected TCP hints: %+v", result)
	}
}

func TestProbeDNSDetails_UDPNoResponse(t *testing.T) {
	host, port, cleanup := startTestUDPDNSServer(t, func(query dnsmessage.Message) ([]byte, bool) {
		return nil, false
	})
	defer cleanup()

	options := defaultDNSProbeOptions()
	options.IOTimeout = 150 * time.Millisecond
	result := probeDNSDetails(context.Background(), host, port, dnsTransportUDP, options)
	if result.ProbeError != "no_response" {
		t.Fatalf("expected no_response, got %+v", result)
	}
}

func TestProbeDNSDetails_TCPConnectFailure(t *testing.T) {
	options := defaultDNSProbeOptions()
	options.ConnectTimeout = 150 * time.Millisecond
	result := probeDNSDetails(context.Background(), "127.0.0.1", 1, dnsTransportTCP, options)
	if result.ProbeError != "connect_failed" {
		t.Fatalf("expected connect_failed, got %+v", result)
	}
}

func TestProbeDNSDetails_UDPProtocolMismatch(t *testing.T) {
	host, port, cleanup := startTestUDPDNSServer(t, func(query dnsmessage.Message) ([]byte, bool) {
		return []byte{0x01, 0x02, 0x03}, true
	})
	defer cleanup()

	result := probeDNSDetails(context.Background(), host, port, dnsTransportUDP, defaultDNSProbeOptions())
	if result.ProbeError != "protocol_mismatch" {
		t.Fatalf("expected protocol_mismatch, got %+v", result)
	}
}

func TestProbeDNSDetails_UDPDecodeError(t *testing.T) {
	host, port, cleanup := startTestUDPDNSServer(t, func(query dnsmessage.Message) ([]byte, bool) {
		packet := make([]byte, 13)
		binary.BigEndian.PutUint16(packet[0:2], query.Header.ID)
		packet[2] = 0x81
		packet[3] = 0x80
		packet[5] = 0x01
		packet[12] = 0xff
		return packet, true
	})
	defer cleanup()

	result := probeDNSDetails(context.Background(), host, port, dnsTransportUDP, defaultDNSProbeOptions())
	if result.ProbeError != "decode_error" {
		t.Fatalf("expected decode_error, got %+v", result)
	}
}

type testDNSResponseSpec struct {
	rcode              dnsmessage.RCode
	recursionAvailable bool
	authoritative      bool
	nsRecords          []string
	txtAnswers         []string
}

func buildTestDNSResponse(t *testing.T, query dnsmessage.Message, spec testDNSResponseSpec) []byte {
	t.Helper()

	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 query.Header.ID,
			Response:           true,
			Authoritative:      spec.authoritative,
			RecursionAvailable: spec.recursionAvailable,
			RCode:              spec.rcode,
		},
		Questions: query.Questions,
	}
	if spec.rcode == 0 {
		spec.rcode = dnsmessage.RCodeSuccess
		response.Header.RCode = spec.rcode
	}

	name := query.Questions[0].Name
	switch query.Questions[0].Type {
	case dnsmessage.TypeNS:
		for _, record := range spec.nsRecords {
			nsName, err := dnsmessage.NewName(record)
			if err != nil {
				t.Fatalf("new ns name: %v", err)
			}
			response.Answers = append(response.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 300},
				Body:   &dnsmessage.NSResource{NS: nsName},
			})
		}
	case dnsmessage.TypeTXT:
		for _, answer := range spec.txtAnswers {
			response.Answers = append(response.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassCHAOS, TTL: 0},
				Body:   &dnsmessage.TXTResource{TXT: []string{answer}},
			})
		}
	}

	packet, err := response.Pack()
	if err != nil {
		t.Fatalf("pack response: %v", err)
	}
	return packet
}

func startTestUDPDNSServer(t *testing.T, handler func(query dnsmessage.Message) ([]byte, bool)) (string, int, func()) {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, dnsResponseMaxBytes)
		for {
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if err := query.Unpack(buffer[:n]); err != nil {
				continue
			}
			response, ok := handler(query)
			if !ok {
				continue
			}
			_, _ = conn.WriteTo(response, addr)
		}
	}()

	return packetListenerTarget(conn), packetListenerPort(conn), func() {
		_ = conn.Close()
		<-done
	}
}

func startTestTCPDNSServer(t *testing.T, handler func(query dnsmessage.Message) ([]byte, bool)) (string, int, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				lengthBuf := make([]byte, 2)
				if _, err := io.ReadFull(conn, lengthBuf); err != nil {
					return
				}
				length := int(binary.BigEndian.Uint16(lengthBuf))
				packet := make([]byte, length)
				if _, err := io.ReadFull(conn, packet); err != nil {
					return
				}
				var query dnsmessage.Message
				if err := query.Unpack(packet); err != nil {
					return
				}
				response, ok := handler(query)
				if !ok {
					return
				}
				frame := make([]byte, 2+len(response))
				binary.BigEndian.PutUint16(frame[0:2], uint16(len(response)))
				copy(frame[2:], response)
				_, _ = conn.Write(frame)
			}(conn)
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, func() {
		_ = listener.Close()
		<-done
	}
}

func packetListenerTarget(conn net.PacketConn) string {
	addr, _ := net.ResolveUDPAddr("udp", conn.LocalAddr().String())
	return addr.IP.String()
}

func packetListenerPort(conn net.PacketConn) int {
	addr, _ := net.ResolveUDPAddr("udp", conn.LocalAddr().String())
	return addr.Port
}

func TestSelectDNSPrimaryResponsePrefersFirstValidFallback(t *testing.T) {
	first := &dnsQueryResponse{responded: true, responseCode: "SERVFAIL"}
	selected := selectDNSPrimaryResponse(nil, nil, first)
	if selected != first {
		t.Fatalf("expected first valid response fallback")
	}
}

func TestClassifyDNSAttemptError_UDPNoResponse(t *testing.T) {
	if got := classifyDNSAttemptError(errDNSNoResponse, dnsTransportUDP); got != "no_response" {
		t.Fatalf("unexpected classification: %q", got)
	}
}

func TestClassifyDNSParseError_ShortPacket(t *testing.T) {
	if got := classifyDNSParseError([]byte{0x01}, errDNSMismatch); got != "protocol_mismatch" {
		t.Fatalf("unexpected parse classification: %q", got)
	}
}

func TestDNSNativeProbeServerHelpers(t *testing.T) {
	var calls atomic.Int32
	host, port, cleanup := startTestUDPDNSServer(t, func(query dnsmessage.Message) ([]byte, bool) {
		calls.Add(1)
		return buildTestDNSResponse(t, query, testDNSResponseSpec{nsRecords: []string{"a.root-servers.net."}}), true
	})
	defer cleanup()

	result := probeDNSDetails(context.Background(), host, port, dnsTransportUDP, defaultDNSProbeOptions())
	if !result.DNSProbe || calls.Load() == 0 {
		t.Fatalf("expected helper server to answer dns probe, got %+v", result)
	}
}
