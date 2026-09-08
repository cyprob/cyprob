package scan

// Outcome buckets, derived from the probe error codes
//
// A probe result carries a code (probe_error_codes.go) saying what went wrong.
// cyprob-ee#461 needs a second, much smaller answer alongside it: is there a
// service here at all? The codes cannot answer that on their own -- there are
// 49 of them, several mean more than one thing, and nothing outside this
// package can be expected to know which. So the mapping lives here, next to the
// registry, and EE imports it rather than restating it. A copy on the EE side
// would be a second source of truth that compiles.
//
// Four buckets, and a fifth answer that is not a bucket:
//
//	ok          -- the service answered and we understood it
//	rejected    -- the peer read what we sent and refused it; its own verdict
//	unreachable -- nothing arrived; no evidence a service exists here
//	unreadable  -- bytes arrived and our parser refused them
//	""          -- this code does not support any of those claims
//
// The empty answer is the load-bearing one. 15 of the 49 codes carry it, and
// they are not an oversight: they are the catch-all default arms, the codes
// whose live emitters straddle the line between "nothing arrived" and "bytes
// arrived", the two that describe our own abort rather than the target, and one
// that is dead. Forcing those into a bucket would put a claim in the database
// that the evidence does not support, and -- worse -- would make it
// indistinguishable from a derived one. Left empty, the gap is countable:
// `WHERE outcome IS NULL GROUP BY reason` is the work queue for splitting them,
// and it is the same list this file states by hand.
//
// The same argument decides the unknown code. See OutcomeForProbeCode.
type Outcome string

const (
	OutcomeOK          Outcome = "ok"
	OutcomeRejected    Outcome = "rejected"
	OutcomeUnreachable Outcome = "unreachable"
	OutcomeUnreadable  Outcome = "unreadable"
)

// outcomeBuckets is the closed set of buckets. A test renders the SQL CHECK
// clause from it, so the Go set and the database's set cannot drift apart
// unless someone writes both by hand.
var outcomeBuckets = []Outcome{
	OutcomeOK,
	OutcomeRejected,
	OutcomeUnreachable,
	OutcomeUnreadable,
}

// noClaim is why a code carries no bucket. An entry that leaves outcome empty
// without one of these is a bug, not a default -- a test enforces that, for the
// same reason the registry test makes its exclusions state a reason: an
// exclusion with no justification next to it outlives the thing it excused.
type noClaim string

const (
	// noClaimCatchAll is an unguarded default arm. Its content is whatever the
	// arms above it did not take, so it changes when one of them changes.
	noClaimCatchAll noClaim = "catch-all: an unguarded default; its content changes when an arm above it does"
	// noClaimStraddle is a code whose live emitters disagree across the line
	// between "nothing arrived" and "bytes arrived" -- the one line the buckets
	// must not blur.
	noClaimStraddle noClaim = "straddle: live emitters disagree across the terminal-claim line"
	// noClaimScannerSide describes our own budget or cancellation. Counting an
	// operator shutdown as target behavior is worse than counting nothing.
	noClaimScannerSide noClaim = "scanner-side: describes our abort or budget, not the target"
	// noClaimDead is a code no emitter produces. A constrained value that
	// cannot occur is a permanent zero on every dashboard.
	noClaimDead noClaim = "dead: no emitter produces it"
)

type outcomeEntry struct {
	// outcome is the bucket, or "" when this code supports no claim.
	outcome Outcome
	// reason is required exactly when outcome is "" and forbidden otherwise.
	reason noClaim
	// note is one line of evidence: for a mapped code, the mechanism that
	// decides its bucket; for an unmapped one, what would have to change in CE
	// for it to get one.
	note string
}

// probeCodeOutcomes maps every registered code to a bucket or to no claim. A
// test asserts it covers probeCodeRegistry exactly, in both directions, so a
// new code cannot ship without someone deciding what it asserts about the
// target.
var probeCodeOutcomes = map[ProbeCode]outcomeEntry{
	ProbeCodeAuthTLSFailed: {
		outcome: OutcomeRejected,
		note:    "FEAT advertised AUTH TLS, we sent it, the reply parsed and its code is neither 234 nor 334: a peer verdict, read",
	},
	ProbeCodeBannerReadFailed: {
		reason: noClaimCatchAll,
		note:   "classifyFTPBannerError returns it from both the eof arm and the default; a FEAT read failing after a well-formed 220 lands here too",
	},
	ProbeCodeBindFailed: {
		outcome: OutcomeUnreadable,
		note:    "validateRPCBindAck refusing a response already read: short, wrong RPC version, wrong packet type",
	},
	ProbeCodeBudgetExceeded: {
		reason: noClaimScannerSide,
		note:   "the pre-dial ctx.Err() guard in rpc_followup_probe.go; nothing was sent",
	},
	ProbeCodeCanceled: {
		reason: noClaimScannerSide,
		note:   "probeCtx has its own timeout, so context.Canceled can only be the parent scan being canceled",
	},
	ProbeCodeCertParseFailed: {
		outcome: OutcomeUnreadable,
		note:    "the Certificate message arrived and our x509 parser refused it; the arm sits above the tls: arm for exactly this reason",
	},
	ProbeCodeConnectFailed: {
		outcome: OutcomeUnreachable,
		note:    "every emitter is a dial error, in eight probes; guarded defaults are called only with the dialer's error in hand",
	},
	ProbeCodeConnectRefused: {
		reason: noClaimStraddle,
		note:   "classifyConnectTunnelStatus returns it for a proxy's 403/405/407 (rejected), classifyConnectTunnelError for ECONNREFUSED on the dial (unreachable)",
	},
	ProbeCodeConnectTimeout: {
		outcome: OutcomeUnreachable,
		note:    "a wait at the connect stage with nothing readable",
	},
	ProbeCodeConnectTunnelFailed: {
		reason: noClaimCatchAll,
		note:   "the default in both tunnel classifiers plus two bare literals; measured members span all four buckets",
	},
	ProbeCodeConnectionRefused: {
		outcome: OutcomeUnreachable,
		note:    "favicon's ECONNREFUSED, reachable only from the dial inside client.Do",
	},
	ProbeCodeConnectionReset: {
		outcome: OutcomeUnreachable,
		note:    "a favicon body-read failure becomes empty_body instead, so this is a teardown before any readable HTTP answer existed",
	},
	ProbeCodeDecodeError: {
		outcome: OutcomeUnreadable,
		note:    "DNS's guarded default (a >=12-byte packet in hand) and SNMP's decode arms: the peer answered and our parser refused",
	},
	ProbeCodeEnumNotSupported: {
		outcome: OutcomeOK,
		note:    "negotiate succeeded and the host is SMB1; the same wire exchange reports no error at all when IncludeEnum is off. reason must be allowed on ok rows",
	},
	ProbeCodeEOFBeforeRecord: {
		reason: noClaimStraddle,
		note:   "io.EOF at any record boundary: an immediate close, but also a complete 5-byte header or a full CCS record already in Flight.FirstBytes",
	},
	ProbeCodeEOFMidRecord: {
		outcome: OutcomeUnreadable,
		note:    "io.ErrUnexpectedEOF, which io.ReadFull returns only after a partial read: truncated bytes definitely arrived",
	},
	ProbeCodeHandshakeFailed: {
		outcome: OutcomeUnreadable,
		note:    "the arm tests a string, not a peer verdict, and its base case is a plaintext listener on a TLS-looking port",
	},
	ProbeCodeHTTPRequestFailed: {
		reason: noClaimCatchAll,
		note:   "classifyWINRMProbeError's default; measured members include bare EOF, connection reset and Go's HTTP-response-to-HTTPS-client",
	},
	ProbeCodeHTTPResponseInvalid: {
		outcome: OutcomeUnreadable,
		note:    "malformed HTTP response / bad status line from net/http's reader: bytes arrived and no response could be made of them",
	},
	ProbeCodeInvalidSMB2Dialect: {
		outcome: OutcomeUnreadable,
		note:    "reached only after signature, command, NTSTATUS and structureSize all passed; the 0x0202 floor is ours, not the server's",
	},
	ProbeCodeKEXParseFailed: {
		outcome: OutcomeUnreadable,
		note:    "every emitter is a parser downstream of a successful banner read; truncated packets leave as probe_failed instead",
	},
	ProbeCodeLookupFailed: {
		outcome: OutcomeRejected,
		note:    "reachable only after validateRPCBindAck passed: a live DCERPC peer that stopped talking when asked for the endpoint list",
	},
	ProbeCodeMalformed: {
		outcome: OutcomeUnreadable,
		note:    "errRawMalformed and errRawDuplicateExtension; every site is a parse refusal over bytes already read",
	},
	ProbeCodeMetadataFailed: {
		reason: noClaimCatchAll,
		note:   "classifyRDPMetadataError's default; short/unknown RDP responses sit beside refused dials and broken pipes",
	},
	ProbeCodeMgmtFailed: {
		outcome: OutcomeRejected,
		note:    "same structure as lookup_failed: only after validateRPCBindAck passed and the anonymous bind was recorded",
	},
	ProbeCodeNoBanner: {
		reason: noClaimStraddle,
		note:   "returned on io.EOF while hunting an SSH- line and after 20 complete non-SSH lines; the emit site holds the line and throws it away",
	},
	ProbeCodeNoResponse: {
		reason: noClaimStraddle,
		note:   "silence in DNS, mDNS and IPMI, but a fully decoded empty-varbind GetResponse in SNMP and a malformed HTTP response in favicon",
	},
	ProbeCodeNoStrategyExecuted: {
		reason: noClaimScannerSide,
		note:   "no probe strategy ran at all, so nothing was sent and nothing was heard. Distinct from probe_failed, which means we tried: collapsing the two reports a target we never contacted as one that did not answer",
	},
	ProbeCodeNoRoute: {
		outcome: OutcomeUnreachable,
		note:    "EHOSTUNREACH from the dial",
	},
	ProbeCodeNotTLS: {
		outcome: OutcomeUnreadable,
		note:    "returned only at records==1: five bytes arrived and the header is SSLv2, an unknown content type or an impossible version",
	},
	ProbeCodeNetBIOSSessionRejected: {
		outcome: OutcomeRejected,
		note:    "a NetBIOS NEGATIVE SESSION RESPONSE, 0x83: the far end read our called name and refused it. Only 0x83 -- any other first byte stays in probe_failed, because a retarget is not a refusal and garbage is not a verdict",
	},
	ProbeCodeNTLMChallengeNotFound: {
		outcome: OutcomeUnreadable,
		note:    "a bytes.Index over the raw frame; the call sites interpolate an NTSTATUS but branch on nothing, and smb2StatusCode returns 0 for any short frame",
	},
	ProbeCodePeerExceededBudget: {
		outcome: OutcomeUnreadable,
		note:    "all four counters can only trip after records were read",
	},
	ProbeCodeProbeFailed: {
		reason: noClaimCatchAll,
		note:   "the default arm of eleven classifiers; inside classifySMBProbeError alone it holds a NetBIOS refusal, three parse failures and every dial error",
	},
	ProbeCodeProtocolError: {
		outcome: OutcomeRejected,
		note:    "SMTP's five session sites are each reachable only after readResponse parsed a reply; starttls_failed never reaches probe level, so this is SMTP's only rejected code",
	},
	ProbeCodeProtocolMismatch: {
		outcome: OutcomeUnreadable,
		note:    "a parser refusing bytes in MySQL, Postgres, Redis, FTP and telnet; two divergent emitters are over-claimed in the safe direction",
	},
	ProbeCodeQueryFailed: {
		reason: noClaimCatchAll,
		note:   "classifyDNSAttemptError's default; dial errors are claimed two arms earlier, so its one certainty is that unreachable is false",
	},
	ProbeCodeReadDeadline: {
		outcome: OutcomeUnreachable,
		note:    "a deadline expiry at a non-connect stage; the approved set puts a timeout in unreachable by definition",
	},
	ProbeCodeReadFailed: {
		reason: noClaimStraddle,
		note:   "a non-timeout read error mid-flight, in practice ECONNRESET -- but readRawServerFlight may already have set FirstBytes, and nothing routes that elsewhere",
	},
	ProbeCodeRefused: {
		outcome: OutcomeUnreachable,
		note:    "every emitter is a dial error, and no probe here embeds peer bytes in an error string, so the word cannot have arrived from the far end",
	},
	ProbeCodeSessionSetupFailed: {
		reason: noClaimDead,
		note:   "classifySMBProbeError tests for session_setup_status, which appears nowhere else in the repository; delete the arm or wire it up",
	},
	ProbeCodeShortResponse: {
		outcome: OutcomeUnreadable,
		note:    "truncation checks over a received frame in RDP and SMB; the TLS arm is dead",
	},
	ProbeCodeSMB2NegotiateFailed: {
		outcome: OutcomeRejected,
		note:    "valid SMB2 header, command==0 so the server parsed our NEGOTIATE, NTSTATUS not SUCCESS: the peer's own verdict, branched on",
	},
	ProbeCodeStarttlsFailed: {
		outcome: OutcomeRejected,
		note:    "we sent STARTTLS, the reply parsed and its code is not 220; handshake errors cannot reach it. Never surfaced at probe level today",
	},
	ProbeCodeTimeout: {
		outcome: OutcomeUnreachable,
		note:    "mandated by the approved set. Recorded exception: the arm is unconditional, so it also absorbs stalls after the peer answered",
	},
	ProbeCodeTLSError: {
		outcome: OutcomeRejected,
		note:    "favicon only: InsecureSkipVerify removes verification errors and net/http rewrites plaintext-on-HTTPS away, leaving parsed peer alerts",
	},
	ProbeCodeTLSFailed: {
		outcome: OutcomeUnreadable,
		note:    "SMTP's raw crypto/tls with no net/http rewrite, so a non-TLS 465 listener lands squarely here",
	},
	ProbeCodeTLSHandshakeFailed: {
		reason: noClaimCatchAll,
		note:   "a specific-sounding name over two total catch-alls; MySQL's fires for a broken pipe written before tls.Client exists, FTP's for a host never contacted",
	},
	ProbeCodeUnexpectedSMB2Command: {
		outcome: OutcomeUnreadable,
		note:    "after the 0xFE SMB signature and before the status check: a well-formed frame arrived and it is not the message we asked for",
	},
	ProbeCodeUnknownResponse: {
		outcome: OutcomeUnreadable,
		note:    ">=7 bytes read and the first two are not a TPKT frame header",
	},
	ProbeCodeUnknownSMBSignature: {
		outcome: OutcomeUnreadable,
		note:    "a frame of at least 76 bytes arrived and its four-byte signature is neither \\xFFSMB nor \\xFESMB; our parser refusing bytes we received",
	},
	ProbeCodeWriteFailed: {
		outcome: OutcomeUnreachable,
		note:    "a non-timeout error writing the ClientHello; no read has happened yet, so no bytes can have arrived",
	},
}

// OutcomeForProbeCode returns the bucket a code asserts about the target.
//
// known is false for a code this table does not list. The caller must store the
// code and leave the outcome unset -- it must never substitute a bucket of its
// own. The reasoning is in cyprob-ee#461: codes go missing from a hand-written
// table when a new probe or a new classifier arm ships, and new probes are
// written for services that answer, so the unknown population is biased toward
// answering targets. Defaulting them to unreachable marks live services dead;
// defaulting them to unreadable turns that bucket into the sink probe_failed
// already was. Left unset the gap is visible and countable.
//
// A mapped code can also return an empty outcome with known true: see the type
// comment. Callers that need to tell the two apart must check known, not the
// emptiness of the bucket.
func OutcomeForProbeCode(code ProbeCode) (outcome Outcome, known bool) {
	entry, ok := probeCodeOutcomes[code]
	if !ok {
		return "", false
	}
	return entry.outcome, true
}
