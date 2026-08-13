package parse

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/fingerprint"
)

// A protocol hint no rule declares is worse than no hint at all: it is specific
// enough to switch the resolver's fallback off, so it excludes every candidate
// and the service resolves to nothing. The two vocabularies live in different
// packages -- the hint table here, the rules in pkg/fingerprint -- and nothing
// held them together, so five of them had drifted apart unnoticed.
//
// This test is the thing that was missing. It sweeps the entire port space
// rather than a list of ports somebody thought of, because the list somebody
// thinks of is how the last five got in.
//
// It has to live in this package: pkg/modules/parse imports pkg/fingerprint, so
// the same assertion written over there is an import cycle.
func TestPortHintsAreDeclaredBySomeRule(t *testing.T) {
	declared := make(map[string]bool)
	for _, protocol := range fingerprint.DeclaredProtocols() {
		declared[protocol] = true
	}
	require.NotEmpty(t, declared, "the shipped rules must declare protocols")

	for port := 1; port <= 65535; port++ {
		hint := detectProtocolFromPort(port)
		if hint == "" {
			// Deliberate: it puts the resolver into the mode that tries
			// every rule, which is the right answer for a port whose
			// service no rule identifies.
			continue
		}
		require.True(t, declared[hint],
			"port %d hints %q, which no rule declares -- the resolver will "+
				"exclude every candidate and identify nothing on that port",
			port, hint)
	}
}

// The hint the resolver is actually handed is the normalized one, and
// normalization can introduce a value the table never returned: https survived
// it until this was written.
func TestNormalizedHintsAreDeclaredBySomeRule(t *testing.T) {
	declared := make(map[string]bool)
	for _, protocol := range fingerprint.DeclaredProtocols() {
		declared[protocol] = true
	}

	// Responses chosen to reach both sides of the https branch and the
	// generic-transport path, since those are what normalization keys on.
	responses := []string{
		"",
		"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n",
		"\x16\x03\x01\x00\xa5\x01",
		"SSH-2.0-OpenSSH_9.6p1\r\n",
		"220 mail.example.com ESMTP Postfix\r\n",
	}

	for _, serviceName := range []string{"", "tcp", "udp", "https"} {
		for _, transport := range []string{"tcp", "udp"} {
			for port := 1; port <= 65535; port++ {
				for _, response := range responses {
					hint := ResolverProtocolHint(serviceName, transport, port, response)
					if hint == "" {
						continue
					}
					require.True(t, declared[hint],
						"service=%q transport=%q port=%d yields hint %q, which no rule declares",
						serviceName, transport, port, hint)
				}
			}
		}
	}
}

// The defect the vocabulary guard describes, stated as the answers it costs.
// The port 445 row is the control: same banner, same rules, a hint that is
// declared -- so what differs on 139 is the hint and nothing else.
func TestHintDoesNotCostTheMatch(t *testing.T) {
	resolver := fingerprint.GetFingerprintResolver()

	for _, tc := range []struct {
		name, serviceName, banner, want string
		port                            int
	}{
		{
			name: "Elasticsearch on 9200", serviceName: "", port: 9200,
			banner: `{"name":"node1","cluster_name":"es","version":{"number":"8.11.1"}}`,
			want:   "Elasticsearch",
		},
		{
			name: "RabbitMQ on 5672", serviceName: "", port: 5672,
			banner: "AMQP\x00\x00\x09\x01", want: "RabbitMQ",
		},
		{
			name: "SMB on 139", serviceName: "", port: 139,
			banner: "\x00\x00\x00\x85\xffSMBr\x00\x00\x00\x00 Windows Server 2019 6.3",
			want:   "Windows SMB",
		},
		{
			name: "SMB on 445, the control", serviceName: "", port: 445,
			banner: "\x00\x00\x00\x85\xffSMBr\x00\x00\x00\x00 Windows Server 2019 6.3",
			want:   "Windows SMB",
		},
		{
			name: "SSH answering on 443", serviceName: "https", port: 443,
			banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n", want: "OpenSSH",
		},
		{
			name: "SMTP answering on 8443", serviceName: "https", port: 8443,
			banner: "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", want: "Postfix",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hint := ResolverProtocolHint(tc.serviceName, "tcp", tc.port, tc.banner)

			result, err := resolver.Resolve(context.Background(), fingerprint.Input{
				Protocol: hint, Banner: tc.banner, Port: tc.port,
			})
			require.NoError(t, err, "hint %q excluded every rule", hint)
			require.Equal(t, tc.want, result.Product)
		})
	}
}

// rpcbind is not BIND. The hint on port 111 was masking this: no rule declares
// rpc, so nothing was ever a candidate, and dropping the dead hint would have
// turned a missing answer into a wrong one -- which is worse for a scanner that
// feeds product names into CVE correlation.
func TestRPCBindIsNotIdentifiedAsBIND(t *testing.T) {
	resolver := fingerprint.GetFingerprintResolver()
	banner := "\x80\x00\x00\x64 rpcbind portmapper v2"

	result, err := resolver.Resolve(context.Background(), fingerprint.Input{
		Protocol: ResolverProtocolHint("", "tcp", 111, banner), Banner: banner, Port: 111,
	})
	if err == nil {
		require.NotEqual(t, "BIND", result.Product,
			"the substring bind inside rpcbind must not identify a DNS server")
	}
}
