package discovery

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultUDPPorts_IncludesIPMI pins the port alongside its payload. A port
// in the list without a payload is probed with an empty datagram, which a BMC
// does not answer -- the port would read closed on a host that is running one.
func TestDefaultUDPPorts_IncludesIPMI(t *testing.T) {
	assert.Contains(t, strings.Split(defaultUDPPorts, ","), "623")
	require.NotEmpty(t, getDefaultUDPPayloads()[623],
		"623 in the port list without a payload probes with an empty datagram")
}

// TestIPMIPayload_IsAWellFormedRequest recomputes the framing from the bytes
// rather than restating them.
//
// The payload was constructed from the specification and then confirmed in the
// field only in the sense that one BMC replied to it. A mistyped byte would
// still send something, get no answer, and read exactly like a host with no
// BMC -- silence, which is the failure mode this whole area keeps producing.
// Deriving the lengths and both checksums here means a transcription error
// fails the build instead of the scan.
func TestIPMIPayload_IsAWellFormedRequest(t *testing.T) {
	payload := getDefaultUDPPayloads()[623]
	require.Len(t, payload, 23, "RMCP header (14) plus a 9-byte IPMI message")

	// RMCP header: version 6, reserved 0, sequence 0xff (no ACK requested),
	// message class 0x07 (IPMI).
	assert.Equal(t, []byte{0x06, 0x00, 0xff, 0x07}, payload[:4], "RMCP header")

	declaredLen := int(payload[13])
	message := payload[14:]
	require.Equal(t, declaredLen, len(message),
		"the declared IPMI message length must match the bytes that follow it")

	// Checksum 1 covers rsAddr and netFn/rsLUN; checksum 2 covers rqAddr
	// through the last data byte. Both are two's complement.
	wantChk1 := byte(-(int(message[0]) + int(message[1])))
	assert.Equal(t, wantChk1, message[2], "checksum 1")

	sum := 0
	for _, b := range message[3 : len(message)-1] {
		sum += int(b)
	}
	assert.Equal(t, byte(-sum), message[len(message)-1], "checksum 2")

	assert.Equal(t, byte(0x20), message[0], "rsAddr must address the BMC")
	assert.Equal(t, byte(0x06), message[1]>>2, "netFn must be App")
	assert.Equal(t, byte(0x38), message[5], "cmd must be Get Channel Authentication Capabilities")
	assert.Equal(t, byte(0x0e), message[6], "channel 0x0e means the channel the request arrived on")
	assert.Equal(t, byte(0x04), message[7], "requested privilege level: administrator")
}
