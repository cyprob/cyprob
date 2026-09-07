package scan

import (
	"crypto/tls"
	"net"
	"strings"
)

// The observation channel
//
// A scanner has no bar of its own. A client sets a floor because of what it is
// about to trust and carry; an instrument sets one only to decide what it will
// report, which is not the same decision. So the paths that carry traffic --
// banners, HTTP requests, anything an identity is derived from -- keep the
// strict configuration they have, and observation happens on a channel that is
// deliberately separate and deliberately wide.
//
// The channel exists because the failure was inverted with respect to risk:
// a server that speaks only TLS 1.0, or negotiates only suites Go excludes by
// default, refuses the ordinary ClientHello outright, and the refused
// handshake costs the certificate, the version and everything derived from
// them. The estate's worst-configured host was the one the scan knew least
// about.
//
// What the channel is allowed to do is the whole of its definition: dial,
// read the negotiated version, the negotiated suite and the certificate off
// the connection state, and close. It sends nothing and it carries nothing.
// That is what makes "observe over a weak connection, never transact over
// one" a property of the structure rather than a rule someone has to remember.
const tlsObservationStrategyName = "tls-observation"

// buildTLSObservationStrategy returns the channel's single strategy. SNI is
// still sent when the target is a name rather than an address, because a
// server that selects its certificate by SNI would otherwise be observed
// presenting the wrong one -- that is about naming the right service, not
// about lowering a bar.
func buildTLSObservationStrategy(hostname string) tlsProbeStrategy {
	strategy := tlsProbeStrategy{name: tlsObservationStrategyName, observation: true}
	hostname = strings.TrimSpace(hostname)
	if hostname != "" && net.ParseIP(hostname) == nil {
		strategy.useSNI = true
	}
	return strategy
}

// applyTLSObservationConfig widens a dial to the channel's terms: floor at TLS
// 1.0 and every suite crypto/tls implements, secure and insecure alike.
//
// Both halves are needed and neither substitutes for the other. A server whose
// problem is the version refuses the handshake no matter which suites are
// offered, and a server whose problem is the suite refuses it no matter how
// low the floor goes. The two populations overlap heavily on old management
// interfaces, which is exactly where this matters.
//
// The ceiling is left alone. crypto/tls picks the highest version both sides
// accept, so lowering the floor cannot drag a modern server down; it only
// stops the client from refusing an old one. Note the consequence for what may
// be claimed from this: a successful dial reports the best version the server
// will agree to, which is not evidence about what else it would have accepted.
// Establishing that a server *also* supports TLS 1.0 needs a dial pinned to
// TLS 1.0, which is enumeration and belongs to the same channel but is not
// this function.
func applyTLSObservationConfig(config *tls.Config) {
	config.MinVersion = tls.VersionTLS10
	config.CipherSuites = tlsObservationCipherSuiteIDs()
}

// tlsObservationCipherSuiteIDs is every suite crypto/tls implements: the
// default client list plus the ones excluded from it. The insecure ones are
// added to the defaults rather than replacing them, so a server offering a
// mix still negotiates the best suite it has instead of the worst.
//
// This governs TLS 1.0-1.2 only. TLS 1.3 suites are not configurable in
// crypto/tls and are unaffected either way.
func tlsObservationCipherSuiteIDs() []uint16 {
	secure := tls.CipherSuites()
	insecure := tls.InsecureCipherSuites()
	ids := make([]uint16, 0, len(secure)+len(insecure))
	for _, suite := range secure {
		ids = append(ids, suite.ID)
	}
	for _, suite := range insecure {
		ids = append(ids, suite.ID)
	}
	return ids
}
