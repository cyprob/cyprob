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
	ProbeCodeAuthTLSFailed         ProbeCode = "auth_tls_failed"
	ProbeCodeBannerReadFailed      ProbeCode = "banner_read_failed"
	ProbeCodeBindFailed            ProbeCode = "bind_failed"
	ProbeCodeBudgetExceeded        ProbeCode = "budget_exceeded"
	ProbeCodeCanceled              ProbeCode = "canceled"
	ProbeCodeCertParseFailed       ProbeCode = "cert_parse_failed"
	ProbeCodeConnectFailed         ProbeCode = "connect_failed"
	ProbeCodeConnectRefused        ProbeCode = "connect_refused"
	ProbeCodeConnectTimeout        ProbeCode = "connect_timeout"
	ProbeCodeConnectTunnelFailed   ProbeCode = "connect_tunnel_failed"
	ProbeCodeConnectionRefused     ProbeCode = "connection_refused"
	ProbeCodeConnectionReset       ProbeCode = "connection_reset"
	ProbeCodeDecodeError           ProbeCode = "decode_error"
	ProbeCodeEnumNotSupported      ProbeCode = "enum_not_supported"
	ProbeCodeEOFBeforeRecord       ProbeCode = "eof_before_record"
	ProbeCodeEOFMidRecord          ProbeCode = "eof_mid_record"
	ProbeCodeHandshakeFailed       ProbeCode = "handshake_failed"
	ProbeCodeHTTPRequestFailed     ProbeCode = "http_request_failed"
	ProbeCodeHTTPResponseInvalid   ProbeCode = "http_response_invalid"
	ProbeCodeInvalidSMB2Dialect    ProbeCode = "invalid_smb2_dialect"
	ProbeCodeKEXParseFailed        ProbeCode = "kex_parse_failed"
	ProbeCodeLookupFailed          ProbeCode = "lookup_failed"
	ProbeCodeMalformed             ProbeCode = "malformed"
	ProbeCodeMetadataFailed        ProbeCode = "metadata_failed"
	ProbeCodeMgmtFailed            ProbeCode = "mgmt_failed"
	ProbeCodeNoBanner              ProbeCode = "no_banner"
	ProbeCodeNoResponse            ProbeCode = "no_response"
	ProbeCodeNoRoute               ProbeCode = "no_route"
	ProbeCodeNotTLS                ProbeCode = "not_tls"
	ProbeCodeNTLMChallengeNotFound ProbeCode = "ntlm_challenge_not_found"
	ProbeCodePeerExceededBudget    ProbeCode = "peer_exceeded_budget"
	ProbeCodeProbeFailed           ProbeCode = "probe_failed"
	ProbeCodeProtocolError         ProbeCode = "protocol_error"
	ProbeCodeProtocolMismatch      ProbeCode = "protocol_mismatch"
	ProbeCodeQueryFailed           ProbeCode = "query_failed"
	ProbeCodeReadDeadline          ProbeCode = "read_deadline"
	ProbeCodeReadFailed            ProbeCode = "read_failed"
	ProbeCodeRefused               ProbeCode = "refused"
	ProbeCodeSessionSetupFailed    ProbeCode = "session_setup_failed"
	ProbeCodeShortResponse         ProbeCode = "short_response"
	ProbeCodeSMB2NegotiateFailed   ProbeCode = "smb2_negotiate_failed"
	ProbeCodeStarttlsFailed        ProbeCode = "starttls_failed"
	ProbeCodeTimeout               ProbeCode = "timeout"
	ProbeCodeTLSError              ProbeCode = "tls_error"
	ProbeCodeTLSFailed             ProbeCode = "tls_failed"
	ProbeCodeTLSHandshakeFailed    ProbeCode = "tls_handshake_failed"
	ProbeCodeUnexpectedSMB2Command ProbeCode = "unexpected_smb2_command"
	ProbeCodeUnknownResponse       ProbeCode = "unknown_response"
	ProbeCodeWriteFailed           ProbeCode = "write_failed"
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
	ProbeCodeWriteFailed,
}
