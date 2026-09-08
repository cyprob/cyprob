package scan

// Probe error codes, in one place
//
// Every native probe classifies why it failed into a short code, and until this
// file those codes were string literals scattered across the classifier
// functions in this package. cyprob-ee#461 needs them in one place for a reason
// beyond tidiness: an outcome bucket is derived from the code, and a code that
// exists only as a literal inside one function cannot be enumerated, mapped or
// checked.
//
// The blindness was already real rather than hypothetical. A first inventory of
// this package walked the classifiers looking for returned string literals and
// reported 46 codes. It missed cert_parse_failed, because that one had already
// been given a named constant, and a walk looking for literals does not see a
// constant. A registry removes the question of which form a code happens to be
// written in.
//
// ProbeCode is a defined type rather than an alias so a bare literal cannot be
// passed where a code is expected without saying so. It converts to string at
// the boundaries that need it, which is every JSON field these end up in.
type ProbeCode string

const (
	ProbeCodeAuthTLSFailed          ProbeCode = "auth_tls_failed"
	ProbeCodeBannerReadFailed       ProbeCode = "banner_read_failed"
	ProbeCodeBindFailed             ProbeCode = "bind_failed"
	ProbeCodeBudgetExceeded         ProbeCode = "budget_exceeded"
	ProbeCodeCanceled               ProbeCode = "canceled"
	ProbeCodeCertParseFailed        ProbeCode = "cert_parse_failed"
	ProbeCodeConnectFailed          ProbeCode = "connect_failed"
	ProbeCodeConnectRefused         ProbeCode = "connect_refused"
	ProbeCodeConnectTimeout         ProbeCode = "connect_timeout"
	ProbeCodeConnectTunnelFailed    ProbeCode = "connect_tunnel_failed"
	ProbeCodeConnectionRefused      ProbeCode = "connection_refused"
	ProbeCodeConnectionReset        ProbeCode = "connection_reset"
	ProbeCodeDecodeError            ProbeCode = "decode_error"
	ProbeCodeEnumNotSupported       ProbeCode = "enum_not_supported"
	ProbeCodeEOFBeforeRecord        ProbeCode = "eof_before_record"
	ProbeCodeEOFMidRecord           ProbeCode = "eof_mid_record"
	ProbeCodeHandshakeFailed        ProbeCode = "handshake_failed"
	ProbeCodeHTTPRequestFailed      ProbeCode = "http_request_failed"
	ProbeCodeHTTPResponseInvalid    ProbeCode = "http_response_invalid"
	ProbeCodeInvalidSMB2Dialect     ProbeCode = "invalid_smb2_dialect"
	ProbeCodeKEXParseFailed         ProbeCode = "kex_parse_failed"
	ProbeCodeLookupFailed           ProbeCode = "lookup_failed"
	ProbeCodeMalformed              ProbeCode = "malformed"
	ProbeCodeMetadataFailed         ProbeCode = "metadata_failed"
	ProbeCodeMgmtFailed             ProbeCode = "mgmt_failed"
	ProbeCodeNoBanner               ProbeCode = "no_banner"
	ProbeCodeNoResponse             ProbeCode = "no_response"
	ProbeCodeNoRoute                ProbeCode = "no_route"
	ProbeCodeNotTLS                 ProbeCode = "not_tls"
	ProbeCodeNetBIOSSessionRejected ProbeCode = "netbios_session_rejected"
	ProbeCodeNTLMChallengeNotFound  ProbeCode = "ntlm_challenge_not_found"
	ProbeCodePeerExceededBudget     ProbeCode = "peer_exceeded_budget"
	ProbeCodeProbeFailed            ProbeCode = "probe_failed"
	ProbeCodeProtocolError          ProbeCode = "protocol_error"
	ProbeCodeProtocolMismatch       ProbeCode = "protocol_mismatch"
	ProbeCodeQueryFailed            ProbeCode = "query_failed"
	ProbeCodeReadDeadline           ProbeCode = "read_deadline"
	ProbeCodeReadFailed             ProbeCode = "read_failed"
	ProbeCodeRefused                ProbeCode = "refused"
	ProbeCodeSessionSetupFailed     ProbeCode = "session_setup_failed"
	ProbeCodeShortResponse          ProbeCode = "short_response"
	ProbeCodeSMB2NegotiateFailed    ProbeCode = "smb2_negotiate_failed"
	ProbeCodeStarttlsFailed         ProbeCode = "starttls_failed"
	ProbeCodeTimeout                ProbeCode = "timeout"
	ProbeCodeTLSError               ProbeCode = "tls_error"
	ProbeCodeTLSFailed              ProbeCode = "tls_failed"
	ProbeCodeTLSHandshakeFailed     ProbeCode = "tls_handshake_failed"
	ProbeCodeUnexpectedSMB2Command  ProbeCode = "unexpected_smb2_command"
	ProbeCodeUnknownResponse        ProbeCode = "unknown_response"
	ProbeCodeUnknownSMBSignature    ProbeCode = "unknown_smb_signature"
	ProbeCodeWriteFailed            ProbeCode = "write_failed"
)

// probeCodeRegistry is every code this package can produce. It exists so the
// set can be walked -- by the outcome mapping, and by the tests that hold the
// two together.
var probeCodeRegistry = []ProbeCode{
	ProbeCodeAuthTLSFailed,
	ProbeCodeBannerReadFailed,
	ProbeCodeBindFailed,
	ProbeCodeBudgetExceeded,
	ProbeCodeCanceled,
	ProbeCodeCertParseFailed,
	ProbeCodeConnectFailed,
	ProbeCodeConnectRefused,
	ProbeCodeConnectTimeout,
	ProbeCodeConnectTunnelFailed,
	ProbeCodeConnectionRefused,
	ProbeCodeConnectionReset,
	ProbeCodeDecodeError,
	ProbeCodeEnumNotSupported,
	ProbeCodeEOFBeforeRecord,
	ProbeCodeEOFMidRecord,
	ProbeCodeHandshakeFailed,
	ProbeCodeHTTPRequestFailed,
	ProbeCodeHTTPResponseInvalid,
	ProbeCodeInvalidSMB2Dialect,
	ProbeCodeKEXParseFailed,
	ProbeCodeLookupFailed,
	ProbeCodeMalformed,
	ProbeCodeMetadataFailed,
	ProbeCodeMgmtFailed,
	ProbeCodeNoBanner,
	ProbeCodeNoResponse,
	ProbeCodeNoRoute,
	ProbeCodeNotTLS,
	ProbeCodeNetBIOSSessionRejected,
	ProbeCodeNTLMChallengeNotFound,
	ProbeCodePeerExceededBudget,
	ProbeCodeProbeFailed,
	ProbeCodeProtocolError,
	ProbeCodeProtocolMismatch,
	ProbeCodeQueryFailed,
	ProbeCodeReadDeadline,
	ProbeCodeReadFailed,
	ProbeCodeRefused,
	ProbeCodeSessionSetupFailed,
	ProbeCodeShortResponse,
	ProbeCodeSMB2NegotiateFailed,
	ProbeCodeStarttlsFailed,
	ProbeCodeTimeout,
	ProbeCodeTLSError,
	ProbeCodeTLSFailed,
	ProbeCodeTLSHandshakeFailed,
	ProbeCodeUnexpectedSMB2Command,
	ProbeCodeUnknownResponse,
	ProbeCodeUnknownSMBSignature,
	ProbeCodeWriteFailed,
}

// probeCodeByValue is the registry keyed for lookup. It is built once because
// ParseProbeCode is called per probe result, and a linear scan over 51 entries
// at that rate is a cost with nothing to show for it.
var probeCodeByValue = func() map[string]ProbeCode {
	byValue := make(map[string]ProbeCode, len(probeCodeRegistry))
	for _, code := range probeCodeRegistry {
		byValue[string(code)] = code
	}
	return byValue
}()

// ParseProbeCode turns an untrusted string into a registered code, and reports
// false when this package does not produce that value.
//
// It takes a string rather than a ProbeCode on purpose. The values that need
// checking arrive as strings -- from a JSON payload, a database row, a map that
// crossed a process boundary -- and a function taking ProbeCode would force the
// caller to convert first, which is exactly the unchecked conversion this
// exists to remove. ProbeCode(untrusted) always compiles and always succeeds;
// ParseProbeCode is the only way to get one that means something.
//
// The empty string is not a code and returns false: it is the absence of an
// error, not an error nobody registered. Callers that treat "no error" and
// "unknown error" the same way have a bug, and this makes them say so.
//
// cyprob/cyprob-ee#461 uses it at the boundary where CE's scan output is read
// back out of a map: an unknown value is kept verbatim as the reason, gets no
// outcome, and is counted. That counter is the reason this returns a bool
// rather than falling back to a code of its own.
func ParseProbeCode(value string) (ProbeCode, bool) {
	code, ok := probeCodeByValue[value]
	return code, ok
}
