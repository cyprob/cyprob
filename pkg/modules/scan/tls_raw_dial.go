package scan

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

// One dial, one hello, one flight, close.
//
// Nothing is written after the ClientHello. crypto/tls sends close_notify only
// once a handshake has completed, and in TLS 1.3 a plaintext record sent after
// the server has installed its keys is a protocol violation the server logs --
// so a well-meant polite close is noisier than silence, not quieter.
const (
	rawDialIdleTimeout     = 2 * time.Second
	rawDialAbsoluteTimeout = 6 * time.Second
)

var errRawDialNoResponse = errors.New("no_response")

// rawDialOutcome separates the three things a dial can learn, because a
// transport failure that gets written down as a refusal ends a walk early and
// silently shortens the answer.
type rawDialOutcome struct {
	Flight    rawServerFlight
	Transport string
	Err       error
}

func dialRawTLSForServerHello(
	ctx context.Context,
	target string,
	hostname string,
	port int,
	offer []uint16,
	pinnedVersion uint16,
	opts TLSProbeOptions,
) rawDialOutcome {
	hello, err := buildRawClientHello(rawClientHello{
		hostname: hostname,
		version:  pinnedVersion,
		suites:   offer,
	})
	if err != nil {
		// Our own hello is wrong. That is a bug on this side and must never be
		// recorded against the server.
		return rawDialOutcome{Transport: "hello_build_failed", Err: err}
	}

	connectTimeout := opts.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = tlsEnumerationDialTimeout
	}
	dialer := &net.Dialer{Timeout: connectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target, strconv.Itoa(port)))
	if err != nil {
		return rawDialOutcome{Transport: string(classifyRawTransportError(err, "connect")), Err: err}
	}
	defer func() { _ = conn.Close() }()

	absolute := time.Now().Add(rawDialAbsoluteTimeout)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(absolute) {
		absolute = deadline
	}
	if err := conn.SetWriteDeadline(absolute); err != nil {
		return rawDialOutcome{Transport: "deadline_failed", Err: err}
	}
	if _, err := conn.Write(hello); err != nil {
		return rawDialOutcome{Transport: string(classifyRawTransportError(err, "write")), Err: err}
	}

	flight, err := readRawServerFlight(&rawDeadlineReader{conn: conn, absolute: absolute})
	if err != nil {
		return rawDialOutcome{Flight: flight, Transport: string(classifyRawTransportError(err, "read")), Err: err}
	}
	return rawDialOutcome{Flight: flight}
}

// rawDeadlineReader arms two deadlines that a hostile peer cannot defeat by
// choosing between them. The per-read deadline is re-armed before every read,
// which alone is beaten by one byte every second; the absolute deadline bounds
// the connection however slowly the bytes arrive.
type rawDeadlineReader struct {
	conn     net.Conn
	absolute time.Time
}

func (r *rawDeadlineReader) Read(p []byte) (int, error) {
	now := time.Now()
	if !now.Before(r.absolute) {
		return 0, context.DeadlineExceeded
	}
	deadline := now.Add(rawDialIdleTimeout)
	if r.absolute.Before(deadline) {
		deadline = r.absolute
	}
	if err := r.conn.SetReadDeadline(deadline); err != nil {
		return 0, err
	}
	return r.conn.Read(p)
}

// classifyRawTransportError names what happened on the wire. The names are the
// vocabulary a later reader needs to tell "the server ran out of suites" from
// "the server stopped talking to us", which are indistinguishable in the
// verdict alone.
func classifyRawTransportError(err error, stage string) ProbeCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errRawNotTLS):
		return ProbeCodeNotTLS
	case errors.Is(err, errRawMalformed), errors.Is(err, errRawDuplicateExtension):
		return ProbeCodeMalformed
	case errors.Is(err, errRawTooManyRecords), errors.Is(err, errRawTooManyBytes),
		errors.Is(err, errRawNonAdvancingPeer), errors.Is(err, errRawTooManyExtensions):
		return ProbeCodePeerExceededBudget
	case errors.Is(err, io.EOF):
		// A clean close at a record boundary. The server declined to answer,
		// which is not the same as declining our suites.
		return ProbeCodeEOFBeforeRecord
	case errors.Is(err, io.ErrUnexpectedEOF):
		return ProbeCodeEOFMidRecord
	case errors.Is(err, context.DeadlineExceeded):
		return ProbeCodeReadDeadline
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		if stage == "connect" {
			return ProbeCodeConnectTimeout
		}
		return ProbeCodeReadDeadline
	}
	switch stage {
	case "connect":
		return ProbeCodeConnectFailed
	case "write":
		return ProbeCodeWriteFailed
	case "read":
		return ProbeCodeReadFailed
	}
	// A stage nobody named. Returning a code built by concatenation is what
	// this replaces: it produced write_failed and read_failed, which no
	// inventory of this package could see, because a synthesized code is
	// invisible to any walk over literals or constants (cyprob-ee#461).
	return ProbeCodeProbeFailed
}
