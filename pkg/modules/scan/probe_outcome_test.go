package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
)

// The outcome mapping is 49 hand-written decisions over a vocabulary produced by
// 27 hand-written classifiers. Nothing stops the two from drifting except these
// tests, and drift here is silent: a code that quietly changes bucket does not
// fail anything, it just makes a dashboard wrong.
//
// Three of them do the load-bearing work:
//
//   - TheTableCoversTheRegistryExactly makes a new code un-shippable until
//     somebody decides what it claims about the target.
//   - EveryCodeIsPinnedThroughItsClassifier drives the real classifiers with
//     realistic error text, so the table is held against what the code does
//     rather than against what this file says it does. It also covers the
//     registry, which makes the coverage claim behavioral.
//   - EveryUnmappedCodeStatesWhy keeps the 15 empty entries from becoming a
//     habit: an entry with no bucket has to carry its reason next to itself.
//
// Note what is deliberately absent: a test asserting every classifier's
// reachable codes are table keys. That already follows from
// TestProbeCodes_EveryClassifierUsesTheRegistry (a classifier can only return a
// registry constant) and TheTableCoversTheRegistryExactly (every registry entry
// is a key). A test that cannot fail while two others pass measures nothing.

func TestProbeOutcomes_TheTableCoversTheRegistryExactly(t *testing.T) {
	t.Parallel()

	if len(probeCodeRegistry) == 0 {
		t.Fatal("the registry is empty, so this test compares nothing")
	}
	if len(probeCodeOutcomes) == 0 {
		t.Fatal("the outcome table is empty, so this test compares nothing")
	}

	registry := map[ProbeCode]bool{}
	for _, code := range probeCodeRegistry {
		registry[code] = true
		if _, mapped := probeCodeOutcomes[code]; !mapped {
			t.Errorf("%q is a registered code with no outcome entry; "+
				"a code nobody decided about is a row EE cannot bucket", code)
		}
	}

	orphans := make([]string, 0)
	for code := range probeCodeOutcomes {
		if !registry[code] {
			orphans = append(orphans, string(code))
		}
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Errorf("the outcome table maps codes that no longer exist: %v", orphans)
	}
}

func TestProbeOutcomes_EveryBucketIsOneOfFour(t *testing.T) {
	t.Parallel()

	allowed := map[Outcome]bool{}
	for _, bucket := range outcomeBuckets {
		if allowed[bucket] {
			t.Errorf("%q appears in outcomeBuckets twice", bucket)
		}
		allowed[bucket] = true
	}
	if len(allowed) == 0 {
		t.Fatal("outcomeBuckets is empty, so every value below would be rejected for the wrong reason")
	}

	used := map[Outcome]int{}
	for code, entry := range probeCodeOutcomes {
		if entry.outcome == "" {
			continue
		}
		if !allowed[entry.outcome] {
			t.Errorf("%q maps to %q, which is not one of the four buckets; "+
				"a fifth value is a schema change, not an edit", code, entry.outcome)
		}
		used[entry.outcome]++
	}

	// A bucket nothing lands in is either a dead branch of the schema or a
	// mapping mistake, and both are worth seeing.
	for bucket := range allowed {
		if used[bucket] == 0 {
			t.Errorf("no code maps to %q; the bucket exists and nothing can produce it", bucket)
		}
	}
	t.Logf("ok=%d rejected=%d unreachable=%d unreadable=%d no-claim=%d",
		used[OutcomeOK], used[OutcomeRejected], used[OutcomeUnreachable], used[OutcomeUnreadable],
		len(probeCodeOutcomes)-used[OutcomeOK]-used[OutcomeRejected]-used[OutcomeUnreachable]-used[OutcomeUnreadable])
}

// The database has to constrain the same four values, and the only way to be
// sure it does is to render the constraint here and let EE's migration copy the
// file rather than retype the list. Two hand-written sets cannot be kept in
// agreement; one written set and one generated file can.
func TestProbeOutcomes_TheCheckClauseMatchesTheGoldenFile(t *testing.T) {
	t.Parallel()

	quoted := make([]string, 0, len(outcomeBuckets))
	for _, bucket := range outcomeBuckets {
		quoted = append(quoted, fmt.Sprintf("'%s'", bucket))
	}
	rendered := fmt.Sprintf("CHECK (outcome IS NULL OR outcome IN (%s))", strings.Join(quoted, ", "))

	const golden = "testdata/outcome_check_clause.sql"
	raw, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read %s: %v", golden, err)
	}
	if want := strings.TrimSpace(string(raw)); want != rendered {
		t.Errorf("%s is stale.\n  file: %s\n  code: %s\n"+
			"Update the file and the EE migration generated from it in the same change.",
			golden, want, rendered)
	}
}

// An entry with no bucket has to say why, and an entry with one must not: a
// stated reason beside a real bucket reads as a doubt that is not there, and
// the day the reason stops being true nothing notices.
func TestProbeOutcomes_EveryUnmappedCodeStatesWhy(t *testing.T) {
	t.Parallel()

	reasons := map[noClaim]bool{
		noClaimCatchAll:    true,
		noClaimStraddle:    true,
		noClaimScannerSide: true,
		noClaimDead:        true,
	}

	unmapped := 0
	for code, entry := range probeCodeOutcomes {
		if strings.TrimSpace(entry.note) == "" {
			t.Errorf("%q carries no note; the evidence for a bucket has to survive the person who found it", code)
		}
		if entry.outcome == "" {
			unmapped++
			if entry.reason == "" {
				t.Errorf("%q claims no outcome and gives no reason; that is a forgotten entry, not a decision", code)
				continue
			}
			if !reasons[entry.reason] {
				t.Errorf("%q gives the reason %q, which is not one of the four; "+
					"a free-text reason cannot be counted or queried", code, entry.reason)
			}
			continue
		}
		if entry.reason != "" {
			t.Errorf("%q maps to %q and also states a no-claim reason (%q); one of the two is wrong",
				code, entry.outcome, entry.reason)
		}
	}
	if unmapped == 0 {
		t.Error("no code is unmapped, so the half of this test that matters checked nothing")
	}
	t.Logf("%d codes carry no bucket, each with a stated reason", unmapped)
}

func TestProbeOutcomes_AnUnknownCodeStaysUnknown(t *testing.T) {
	t.Parallel()

	if outcome, known := OutcomeForProbeCode("wat"); known || outcome != "" {
		t.Errorf("OutcomeForProbeCode(%q) = (%q, %v); an unlisted code must not be given a bucket",
			"wat", outcome, known)
	}

	// Values that reach the reported error fields today without being probe
	// codes at all. They are here so that the day one of them is promoted to a
	// real code, this list is where it is noticed -- and so that "description
	// unreadable", which is an English sentence rather than a code, cannot be
	// filed under the bucket whose name it happens to contain.
	live := []string{
		"status_404", "request_error", "empty_body", "no_candidate", "dial_error",
		"invalid_port", "enum_failed",
		"redirect_budget_exceeded", "print_port_write_blocked", "description unreadable",
	}
	for _, value := range live {
		outcome, known := OutcomeForProbeCode(ProbeCode(value))
		if known || outcome != "" {
			t.Errorf("OutcomeForProbeCode(%q) = (%q, %v); it is not in the registry, "+
				"so promoting it to a code is a change somebody has to make on purpose",
				value, outcome, known)
		}
	}

	// A mapped code with no bucket must still be known, or the caller cannot
	// tell "we decided this says nothing" from "we have never seen this".
	outcome, known := OutcomeForProbeCode(ProbeCodeProbeFailed)
	if !known {
		t.Errorf("OutcomeForProbeCode(%q) reports unknown; a decided no-claim is not an unknown code",
			ProbeCodeProbeFailed)
	}
	if outcome != "" {
		t.Errorf("OutcomeForProbeCode(%q) = %q; it is the default arm of eleven classifiers and claims nothing",
			ProbeCodeProbeFailed, outcome)
	}
}

// One case per code, driven through the classifier that produces it in
// production. This is what stops the table from being right about a code the
// classifier no longer emits that way: reorder two arms in any classifier here
// and a case fails.
//
// The error text is the realistic one for each arm -- the wire message, the
// sentinel, or the internal marker the probe wraps -- not a string invented to
// match the arm.
func TestProbeOutcomes_EveryCodeIsPinnedThroughItsClassifier(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		got     ProbeCode
		want    ProbeCode
		outcome Outcome
	}{
		{"tls timeout", classifyTLSProbeError(errors.New("dial tcp 10.0.0.1:443: i/o timeout")), ProbeCodeTimeout, OutcomeUnreachable},
		{"ssh refused", classifySSHProbeError(errors.New("dial tcp 10.0.0.1:22: connect: connection refused")), ProbeCodeRefused, OutcomeUnreachable},
		{"tls cert parse", classifyTLSProbeError(errors.New("tls: failed to parse certificate from server: x509: negative serial number")), ProbeCodeCertParseFailed, OutcomeUnreadable},
		{"tls plaintext listener", classifyTLSProbeError(errors.New("tls: first record does not look like a TLS handshake")), ProbeCodeHandshakeFailed, OutcomeUnreadable},
		{"tls residual", classifyTLSProbeError(errors.New("no usable strategy")), ProbeCodeProbeFailed, ""},
		{"ssh no banner", classifySSHProbeError(errors.New("no_banner")), ProbeCodeNoBanner, ""},
		{"ssh kex", classifySSHProbeError(errors.New("kex_parse_failed: truncated name-list")), ProbeCodeKEXParseFailed, OutcomeUnreadable},
		{"smtp session verdict", classifySMTPProbeError(errors.New("protocol_error: 421 service not available")), ProbeCodeProtocolError, OutcomeRejected},
		{"smtp starttls", classifySMTPProbeError(errors.New("starttls_failed: 502 command not implemented")), ProbeCodeStarttlsFailed, OutcomeRejected},
		{"smtp plaintext 465", classifySMTPProbeError(errors.New("tls: first record does not look like a TLS handshake")), ProbeCodeTLSFailed, OutcomeUnreadable},
		{"favicon canceled", classifyFaviconError(context.Canceled), ProbeCodeCanceled, ""},
		{"favicon refused", classifyFaviconError(errors.New("dial tcp 10.0.0.1:443: connect: connection refused")), ProbeCodeConnectionRefused, OutcomeUnreachable},
		{"favicon reset", classifyFaviconError(errors.New("read tcp 10.0.0.1:443: read: connection reset by peer")), ProbeCodeConnectionReset, OutcomeUnreachable},
		{"favicon no route", classifyFaviconError(errors.New("dial tcp 10.0.0.1:443: connect: no route to host")), ProbeCodeNoRoute, OutcomeUnreachable},
		{"favicon peer alert", classifyFaviconError(errors.New("remote error: tls: handshake failure")), ProbeCodeTLSError, OutcomeRejected},
		{"mdns silence", classifyMDNSError(errMDNSNoResponse), ProbeCodeNoResponse, ""},
		{"dns short packet", classifyDNSParseError([]byte{0x00, 0x01}, errors.New("unpack")), ProbeCodeProtocolMismatch, OutcomeUnreadable},
		{"dns unpack", classifyDNSParseError(make([]byte, 12), errors.New("dns: overflow unpacking")), ProbeCodeDecodeError, OutcomeUnreadable},
		{"dns residual", classifyDNSAttemptError(errors.New("read tcp 10.0.0.1:53: read: connection reset by peer"), "tcp"), ProbeCodeQueryFailed, ""},
		{"mysql dial", classifyMySQLConnectError(errors.New("dial tcp 10.0.0.1:3306: connect: connection refused")), ProbeCodeConnectFailed, OutcomeUnreachable},
		{"mysql tls catch-all", classifyMySQLTLSError(errors.New("write: broken pipe")), ProbeCodeTLSHandshakeFailed, ""},
		{"winrm bad response", classifyWINRMProbeError(errors.New("malformed HTTP response \"\\x15\\x03\\x03\"")), ProbeCodeHTTPResponseInvalid, OutcomeUnreadable},
		{"winrm residual", classifyWINRMProbeError(errors.New("EOF")), ProbeCodeHTTPRequestFailed, ""},
		{"winrm body is not xml", classifyWINRMIdentifyError(errors.New("XML syntax error on line 1"), false), ProbeCodeIdentifyFailed, OutcomeUnreadable},
		{"winrm xml without an identify response", classifyWINRMIdentifyError(nil, false), ProbeCodeIdentifyFailed, OutcomeUnreadable},
		{"smb ntlm", classifySMBProbeError(errors.New("ntlm_challenge_not_found status=0x00000000")), ProbeCodeNTLMChallengeNotFound, OutcomeUnreadable},
		{"smb1 enum", classifySMBProbeError(errors.New("enum_not_supported_for_smb1")), ProbeCodeEnumNotSupported, OutcomeOK},
		{"smb negotiate verdict", classifySMBProbeError(errors.New("smb2_negotiate_status=0xc0000022")), ProbeCodeSMB2NegotiateFailed, OutcomeRejected},
		{"smb dialect floor", classifySMBProbeError(errors.New("invalid_smb2_dialect=0x0201")), ProbeCodeInvalidSMB2Dialect, OutcomeUnreadable},
		{"smb wrong command", classifySMBProbeError(errors.New("unexpected_smb2_command=5")), ProbeCodeUnexpectedSMB2Command, OutcomeUnreadable},
		{"smb called-name refusal", classifySMBProbeError(errors.New("netbios_session_rejected")), ProbeCodeNetBIOSSessionRejected, OutcomeRejected},
		{"smb wrong signature", classifySMBProbeError(errors.New("unknown_smb_signature")), ProbeCodeUnknownSMBSignature, OutcomeUnreadable},
		{"smb unexpected netbios byte", classifySMBProbeError(errors.New("netbios_session_unexpected_0x84")), ProbeCodeProbeFailed, ""},
		{"smb session setup", classifySMBProbeError(errors.New("session_setup_status=0xc000006d")), ProbeCodeSessionSetupFailed, ""},
		{"rdp truncated", classifyRDPProbeError(errors.New("short_rdp_response n=4")), ProbeCodeShortResponse, OutcomeUnreadable},
		{"rdp not tpkt", classifyRDPProbeError(errors.New("unknown_rdp_response")), ProbeCodeUnknownResponse, OutcomeUnreadable},
		{"rdp metadata residual", classifyRDPMetadataError(errors.New("write: broken pipe")), ProbeCodeMetadataFailed, ""},
		{"ftp banner eof", classifyFTPBannerError(io.EOF), ProbeCodeBannerReadFailed, ""},
		{"ftp feat refusal", classifyFTPFeatError(nil, ftpResponse{Code: 500}), ProbeCodeFeatFailed, OutcomeRejected},
		{"ftp syst refusal", classifyFTPSystError(nil, ftpResponse{Code: 500}), ProbeCodeSystFailed, OutcomeRejected},
		// The other side of what used to be one code. It has to resolve to a
		// different code than the two above or the straddle is still there.
		{"ftp feat read failure", classifyFTPFeatError(io.EOF, ftpResponse{}), ProbeCodeBannerReadFailed, ""},
		{"ftp auth tls verdict", classifyFTPTLSError(errors.New("auth_tls_failed: 500 unknown command")), ProbeCodeAuthTLSFailed, OutcomeRejected},
		{"postgres parser", classifyPostgresError(errors.New("protocol_mismatch: unexpected first byte 0x48")), ProbeCodeProtocolMismatch, OutcomeUnreadable},
		{"snmp decode", classifySNMPProbeError(errSNMPDecode), ProbeCodeDecodeError, OutcomeUnreadable},
		{"rpc budget", classifyRPCProbeError(errors.New("budget_exceeded")), ProbeCodeBudgetExceeded, ""},
		{"rpc endpoint list", classifyRPCProbeError(errors.New("lookup_failed: read tcp: EOF")), ProbeCodeLookupFailed, OutcomeRejected},
		{"rpc mgmt", classifyRPCProbeError(errors.New("mgmt_failed: read tcp: EOF")), ProbeCodeMgmtFailed, OutcomeRejected},
		{"rpc bind ack", classifyRPCProbeError(errors.New("bind_failed: unexpected_packet_type_13")), ProbeCodeBindFailed, OutcomeUnreadable},
		{"tunnel timeout", classifyConnectTunnelError(errors.New("dial tcp 10.0.0.1:8080: i/o timeout")), ProbeCodeConnectTimeout, OutcomeUnreachable},
		{"tunnel proxy denial", classifyConnectTunnelStatus(http.StatusProxyAuthRequired), ProbeCodeConnectRefused, ""},
		{"tunnel residual", classifyConnectTunnelStatus(http.StatusBadGateway), ProbeCodeConnectTunnelFailed, ""},
		{"raw not tls", classifyRawTransportError(errRawNotTLS, "read"), ProbeCodeNotTLS, OutcomeUnreadable},
		{"raw malformed", classifyRawTransportError(errRawMalformed, "read"), ProbeCodeMalformed, OutcomeUnreadable},
		{"raw budget", classifyRawTransportError(errRawTooManyRecords, "read"), ProbeCodePeerExceededBudget, OutcomeUnreadable},
		{"raw clean close", classifyRawTransportError(io.EOF, "read"), ProbeCodeEOFBeforeRecord, ""},
		{"raw truncated record", classifyRawTransportError(io.ErrUnexpectedEOF, "read"), ProbeCodeEOFMidRecord, OutcomeUnreadable},
		{"raw deadline", classifyRawTransportError(context.DeadlineExceeded, "read"), ProbeCodeReadDeadline, OutcomeUnreachable},
		{"raw write", classifyRawTransportError(errors.New("write: broken pipe"), "write"), ProbeCodeWriteFailed, OutcomeUnreachable},
		{"raw read", classifyRawTransportError(errors.New("read: connection reset by peer"), "read"), ProbeCodeReadFailed, ""},
		{"raw unnamed stage", classifyRawTransportError(errors.New("read: connection reset by peer"), ""), ProbeCodeProbeFailed, ""},
	}

	pinned := map[ProbeCode]bool{}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s: the classifier returned %q, the case expects %q; "+
				"an arm moved and the mapping below it is now about a different error",
				tc.name, tc.got, tc.want)
			continue
		}
		outcome, known := OutcomeForProbeCode(tc.want)
		if !known {
			t.Errorf("%s: %q is produced in production and the table does not list it", tc.name, tc.want)
			continue
		}
		if outcome != tc.outcome {
			t.Errorf("%s: %q maps to %q, the case expects %q", tc.name, tc.want, outcome, tc.outcome)
		}
		pinned[tc.want] = true
	}

	// Every code CE emits is reachable through one of its classifiers, so this
	// coverage claim is behavioral rather than a second copy of the registry: a
	// code nothing here produces is a code whose bucket rests on nobody's
	// measurement.
	//
	// The exception is the shared half of the vocabulary. producedOnlyByEE names
	// codes this package defines and does not emit, and no case here can drive
	// one -- there is no CE classifier to drive. That half is proved on the EE
	// side, by a test that walks this same map and asserts each code really is
	// produced there. Neither test proves the property alone; together they do,
	// and the map is the shared input rather than either side's private list.
	missing := make([]string, 0)
	for _, code := range probeCodeRegistry {
		if _, outside := codesProducedOutsideAClassifier[code]; outside {
			if pinned[code] {
				t.Errorf("%q is listed as produced outside a classifier and a classifier produces it here; "+
					"the exemption is stale and hides a real coverage loss", code)
			}
			continue
		}
		if pinned[code] {
			// A code that both a CE classifier produces and the map claims is
			// EE-only. The exemption is then false, and it would hide a real
			// coverage loss the day the CE arm changes.
			if producer, exempt := producedOnlyByEE[code]; exempt {
				t.Errorf("%q is listed in producedOnlyByEE (%s) and a CE classifier produces it here; "+
					"an exemption from a check that would pass is an exemption that hides the next failure",
					code, producer)
			}
			continue
		}
		if _, exempt := producedOnlyByEE[code]; exempt {
			continue
		}
		missing = append(missing, string(code))
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("no case drives a classifier to produce: %v", missing)
	}
	t.Logf("%d codes pinned through %d cases, %d defined here and produced by EE",
		len(pinned), len(cases), len(producedOnlyByEE))
}

// producedOnlyByEE is vocabulary data rather than test plumbing -- it lives in
// the registry file and is read by a test on each side. These are the checks
// that keep it from becoming a place to put anything inconvenient.
func TestProbeOutcomes_TheSharedHalfOfTheVocabularyIsDeclaredProperly(t *testing.T) {
	t.Parallel()

	// producedOnlyByEE is empty today: the code it was built for turned out to
	// be unreachable in EE. So most of this test is vacuous right now, and that
	// is stated rather than left to be discovered -- a passing test over an
	// empty set proves nothing about the checks it contains. What it does hold
	// is the shape, for the first real case; and the mutations recorded on
	// cyprob#348 and cyprob#350 were run against a populated map.
	if len(producedOnlyByEE) == 0 {
		t.Log("producedOnlyByEE is empty; every per-entry check below is vacuous")
	}

	registry := map[ProbeCode]bool{}
	for _, code := range probeCodeRegistry {
		registry[code] = true
	}

	for code, producer := range producedOnlyByEE {
		if !registry[code] {
			t.Errorf("producedOnlyByEE names %q, which is not a registered code; "+
				"a word defined nowhere is not part of the vocabulary", code)
		}
		if strings.TrimSpace(producer) == "" {
			t.Errorf("%q is listed with no producer named; an exemption nobody can check is a note", code)
		}
		if _, mapped := probeCodeOutcomes[code]; !mapped {
			t.Errorf("%q is exempt from CE's coverage check and has no outcome entry; "+
				"the exemption is about who emits it, not about whether anyone decided what it claims", code)
		}
	}

	// The exported reader is what EE's half of the proof reads. A reader that
	// disagrees with the map is a reader that lets EE prove the wrong list.
	exported := ProbeCodesProducedOnlyByEE()
	if len(exported) != len(producedOnlyByEE) {
		t.Errorf("ProbeCodesProducedOnlyByEE returned %d codes and the map holds %d",
			len(exported), len(producedOnlyByEE))
	}
	for _, code := range exported {
		if _, listed := producedOnlyByEE[code]; !listed {
			t.Errorf("ProbeCodesProducedOnlyByEE returned %q, which the map does not list", code)
		}
	}
	// Vacuous while the map holds one entry -- a one-element slice is sorted
	// whatever the comparison says, and reversing the sort in the reader does
	// not fail this. It is kept because it stops being vacuous the moment a
	// second code is added, and stated because a check that cannot fail should
	// not be read as coverage.
	if !sort.SliceIsSorted(exported, func(i, j int) bool { return exported[i] < exported[j] }) {
		t.Error("ProbeCodesProducedOnlyByEE is documented as sorted and is not; a caller diffing two runs would see noise")
	}
	// The copy is a copy. A caller that mutates it must not reach the map.
	if len(exported) > 0 {
		exported[0] = "mutated"
		if _, leaked := producedOnlyByEE["mutated"]; leaked {
			t.Error("mutating the returned slice reached producedOnlyByEE")
		}
		if again := ProbeCodesProducedOnlyByEE(); len(again) > 0 && again[0] == "mutated" {
			t.Error("the returned slice aliases something the next caller sees")
		}
	}

	// The growth rule, enforced rather than only written down. A handful is a
	// vocabulary with two speakers; a longer list is a second scanner that has
	// drifted, and the answer to that is cyprob-ee#480's consolidation.
	const enoughToMeanSomethingElse = 5
	if len(producedOnlyByEE) > enoughToMeanSomethingElse {
		t.Errorf("producedOnlyByEE holds %d codes. Past %d it stops being a shared vocabulary and "+
			"starts being a second one: fold the EE probes into CE (cyprob-ee#480) rather than "+
			"adding another entry here",
			len(producedOnlyByEE), enoughToMeanSomethingElse)
	}
}

// Outcomes is what EE renders its CHECK constraint from, so the two sets cannot
// drift. These are the checks that keep the reader honest -- the same three the
// exported registry reader carries, for the same reasons.
func TestProbeOutcomes_TheExportedBucketListMatchesTheSet(t *testing.T) {
	t.Parallel()

	exported := Outcomes()
	if len(exported) != len(outcomeBuckets) {
		t.Errorf("Outcomes returned %d buckets and outcomeBuckets holds %d", len(exported), len(outcomeBuckets))
	}
	inSet := map[Outcome]bool{}
	for _, bucket := range outcomeBuckets {
		inSet[bucket] = true
	}
	for _, bucket := range exported {
		if !inSet[bucket] {
			t.Errorf("Outcomes returned %q, which is not a bucket", bucket)
		}
	}
	if !sort.SliceIsSorted(exported, func(i, j int) bool { return exported[i] < exported[j] }) {
		t.Error("Outcomes is documented as sorted and is not; a caller rendering SQL from it would produce a different clause per run")
	}

	// A copy, not an alias. A reader that caches and hands every caller the same
	// slice lets one of them rewrite the set for all the others.
	if len(exported) > 0 {
		exported[0] = "mutated"
		for _, bucket := range outcomeBuckets {
			if bucket == "mutated" {
				t.Fatal("mutating the returned slice reached outcomeBuckets")
			}
		}
		if again := Outcomes(); len(again) > 0 && again[0] == "mutated" {
			t.Error("the returned slice aliases something the next caller sees")
		}
	}

	// Unlike ProbeCodesProducedOnlyByEE, this set has four members, so the
	// sortedness check above is not vacuous: reversing the comparison in the
	// reader fails it.
	if len(Outcomes()) < 2 {
		t.Error("fewer than two buckets, which would make the sortedness check above prove nothing")
	}
}

// codesProducedOutsideAClassifier are registry codes CE emits without going
// through a classify* function -- a bare literal at the site that knows the
// answer. They cannot be driven through a classifier here because no classifier
// returns them.
//
// It is now empty, which is what cyprob#360 was for. feat_failed and syst_failed
// left it with the FTP half (cyprob#363: classifyFTPFeatError,
// classifyFTPSystError), identify_failed with the WinRM half
// (classifyWINRMIdentifyError), and every registry code is reachable through
// some CE classifier again.
//
// Kept rather than deleted, for the same reason producedOnlyByEE is kept empty:
// the check above reads it, and a named empty map states "no code is exempt"
// where a deleted one would leave the next person to add an exemption with no
// place that explains what an exemption costs. Note that the loop below asserts
// nothing while it is empty -- the claim is carried by the pin test above, which
// now has to drive every code.
var codesProducedOutsideAClassifier = map[ProbeCode]string{}

// The exemption above must not outlive the codes it excuses.
func TestProbeOutcomes_TheOutsideAClassifierListIsCurrent(t *testing.T) {
	t.Parallel()

	registry := map[ProbeCode]bool{}
	for _, code := range probeCodeRegistry {
		registry[code] = true
	}
	for code, reason := range codesProducedOutsideAClassifier {
		if !registry[code] {
			t.Errorf("%q is excused and is not a registered code", code)
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("%q is excused with no reason", code)
		}
		if _, mapped := probeCodeOutcomes[code]; !mapped {
			t.Errorf("%q is excused from the classifier pin and has no outcome entry; "+
				"the exemption is about who emits it, not about whether anyone decided what it claims", code)
		}
	}
}
