package scan

import (
	"context"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/fingerprint"
)

// A TLS-only service on a port nobody thought to list answers nothing in plain
// text, and the scan records an empty banner — no error, no hint, nothing for a
// fingerprint rule or a tagger to read. Ten hypervisor reverse-proxies on 9080
// were invisible this way: plain HTTP returns nothing at all, HTTPS returns 200.
//
// The catalog gates the TLS probe on an explicit port list (`https-get` carries
// port_include 443, 8443, 9443), and the existing fallback pass only runs when
// *no* port-specific probe matched at all. On 9080 the HTTP probe does match, so
// neither path ever reaches TLS.
//
// Widening the port list is the wrong shape of fix: the next service on the next
// unlisted port is the same bug again, and attempting TLS everywhere costs a
// handshake per service for very little — measured on one estate, of the
// banner-less ports outside the list only 9080 answered TLS at all. What is
// cheap and general is to try TLS exactly where the evidence says it might help:
// the port answered nothing, so there is nothing to lose by asking again.

// runTLSFallbackPass retries with a TLS probe when the active pass produced no
// banner at all.
//
// It runs only on complete silence, not on a poor result: a port that answered
// something has already told us what it is, and re-probing it would spend a
// handshake to overwrite an answer we have. Probe IDs already attempted are
// skipped, so this cannot repeat work the main pass did.
func (m *BannerGrabModule) runTLSFallbackPass(
	ctx context.Context,
	target string,
	probeHost string,
	port int,
	catalog *fingerprint.ProbeCatalog,
	observations *[]engine.ProbeObservation,
	lastError *string,
	hintAcc *hintAccumulator,
	attempted map[string]struct{},
) {
	if catalog == nil || ctx.Err() != nil {
		return
	}
	if selectPrimaryBannerObservation(*observations).Banner != "" {
		return
	}

	for _, spec := range catalog.FallbackProbesFor(port, hintAcc.slice()) {
		if !spec.UseTLS {
			continue
		}
		if _, done := attempted[spec.ID]; done {
			continue
		}
		if ctx.Err() != nil {
			return
		}

		attempted[spec.ID] = struct{}{}
		obs := m.executeProbeSpec(ctx, target, probeHost, port, spec)
		if respHint := protocolHintFromBanner(obs.Response); respHint != "" {
			hintAcc.add(respHint)
		}
		classifyHTTPProbeObservation(&obs)
		m.collectObservation(observations, obs, lastError)

		if selectPrimaryBannerObservation(*observations).Banner != "" {
			m.logger.Debug().
				Str("probe_id", spec.ID).
				Int("port", port).
				Msg("TLS fallback produced a banner on a port with no plain-text response")
			return
		}
	}
}
