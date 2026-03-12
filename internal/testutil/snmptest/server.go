package snmptest

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

type ServerConfig struct {
	AllowedCommunity string
	AllowedVersion   gosnmp.SnmpVersion
	SysDescr         string
	SysObjectID      string
	SysName          string
	Variables        []gosnmp.SnmpPDU
	Malformed        bool
	NoResponse       bool
}

type request struct {
	version   gosnmp.SnmpVersion
	community string
	requestID uint32
}

//nolint:gocyclo // Test UDP responder keeps protocol handling inline for readability.
func StartServer(t *testing.T, cfg ServerConfig) (string, int, func()) {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	host, portStr, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		_ = conn.Close()
		t.Fatalf("split host port: %v", err)
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("lookup port: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Go(func() {
		buf := make([]byte, 2048)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-stop:
						return
					default:
						continue
					}
				}
				select {
				case <-stop:
					return
				default:
					return
				}
			}

			req, err := decodeRequest(buf[:n])
			if err != nil || cfg.NoResponse {
				continue
			}
			if cfg.AllowedCommunity != "" && req.community != cfg.AllowedCommunity {
				continue
			}
			if req.version != cfg.AllowedVersion {
				continue
			}

			var payload []byte
			if cfg.Malformed {
				payload = []byte{0x30, 0x01, 0x00}
			} else {
				variables := cfg.Variables
				if len(variables) == 0 {
					variables = []gosnmp.SnmpPDU{
						{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: []byte(cfg.SysDescr)},
						{Name: ".1.3.6.1.2.1.1.2.0", Type: gosnmp.ObjectIdentifier, Value: cfg.SysObjectID},
						{Name: ".1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: []byte(cfg.SysName)},
					}
				}
				packet := gosnmp.SnmpPacket{
					Version:   req.version,
					Community: req.community,
					PDUType:   gosnmp.GetResponse,
					RequestID: req.requestID,
					Variables: variables,
				}
				payload, err = packet.MarshalMsg()
				if err != nil {
					continue
				}
			}
			_, _ = conn.WriteTo(payload, addr)
		}
	})

	cleanup := func() {
		close(stop)
		_ = conn.Close()
		wg.Wait()
	}
	return host, port, cleanup
}

func decodeRequest(data []byte) (request, error) {
	req := request{}
	tag, outer, _, err := readTLV(data, 0)
	if err != nil {
		return req, err
	}
	if tag != 0x30 {
		return req, fmt.Errorf("unexpected outer tag %x", tag)
	}

	tag, versionValue, next, err := readTLV(outer, 0)
	if err != nil || tag != 0x02 {
		return req, fmt.Errorf("parse version: %w", err)
	}
	versionInt, err := parseInt(versionValue)
	if err != nil {
		return req, err
	}
	req.version = gosnmp.SnmpVersion(versionInt)

	tag, communityValue, next, err := readTLV(outer, next)
	if err != nil || tag != 0x04 {
		return req, fmt.Errorf("parse community: %w", err)
	}
	req.community = string(communityValue)

	tag, pduValue, _, err := readTLV(outer, next)
	if err != nil || tag != 0xa0 {
		return req, fmt.Errorf("parse pdu: %w", err)
	}
	tag, requestIDValue, _, err := readTLV(pduValue, 0)
	if err != nil || tag != 0x02 {
		return req, fmt.Errorf("parse request id: %w", err)
	}
	requestID, err := parseInt(requestIDValue)
	if err != nil {
		return req, err
	}
	req.requestID = uint32(requestID) //nolint:gosec
	return req, nil
}

func readTLV(data []byte, offset int) (byte, []byte, int, error) {
	if offset >= len(data) {
		return 0, nil, offset, fmt.Errorf("offset beyond buffer")
	}
	tag := data[offset]
	length, next, err := readLength(data, offset+1)
	if err != nil {
		return 0, nil, offset, err
	}
	end := next + length
	if end > len(data) {
		return 0, nil, offset, fmt.Errorf("length beyond buffer")
	}
	return tag, data[next:end], end, nil
}

func readLength(data []byte, offset int) (int, int, error) {
	if offset >= len(data) {
		return 0, offset, fmt.Errorf("missing length")
	}
	first := data[offset]
	if first&0x80 == 0 {
		return int(first), offset + 1, nil
	}
	count := int(first & 0x7f)
	if count <= 0 || count > 4 || offset+1+count > len(data) {
		return 0, offset, fmt.Errorf("invalid length")
	}
	var length int
	for i := range count {
		length = (length << 8) | int(data[offset+1+i])
	}
	return length, offset + 1 + count, nil
}

func parseInt(data []byte) (int, error) {
	if len(data) == 0 || len(data) > 4 {
		return 0, fmt.Errorf("invalid integer length")
	}
	buf := make([]byte, 4)
	copy(buf[4-len(data):], data)
	return int(binary.BigEndian.Uint32(buf)), nil
}

func DefaultConfig() ServerConfig {
	return ServerConfig{
		AllowedCommunity: "public",
		AllowedVersion:   gosnmp.Version2c,
		SysDescr:         "Net-SNMP 5.9",
		SysObjectID:      ".1.3.6.1.4.1.8072.3.2.10",
		SysName:          "snmp-test-host",
	}
}

func NormalizeHost(host string) string {
	return strings.TrimSpace(host)
}
