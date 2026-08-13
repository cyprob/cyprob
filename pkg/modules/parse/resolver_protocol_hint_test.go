package parse

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// ResolverProtocolHint exists so that anything reasoning about what the rules
// would match asks the same question the scan pipeline asks. It had no test,
// which meant the drift it was created to prevent was not actually prevented:
// replacing its body with a constant changed no behavior anyone could observe.
func TestResolverProtocolHint(t *testing.T) {
	const httpResponse = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\n"

	for _, tc := range []struct {
		name                       string
		serviceName, transport     string
		port                       int
		banner                     string
		want                       string
	}{
		{
			name:        "https becomes http when the response is HTTP",
			serviceName: "https", transport: "tcp", port: 443, banner: httpResponse,
			want: "http",
		},
		{
			// Not "https": no rule declares it, so keeping it excluded every
			// rule and the service resolved to nothing. TLS-but-not-HTTP says
			// nothing about the protocol, and an empty hint says that.
			name:        "https becomes unknown when the response is not HTTP",
			serviceName: "https", transport: "tcp", port: 443, banner: "\x16\x03\x01\x00\xa5\x01",
			want: "",
		},
		{
			name:        "SSH answering on 443 is not hidden by the https hint",
			serviceName: "https", transport: "tcp", port: 443,
			banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n",
			want:   "",
		},
		{
			name:        "a named service is kept",
			serviceName: "ssh", transport: "tcp", port: 22, banner: "SSH-2.0-OpenSSH_9.6p1\r\n",
			want: "ssh",
		},
		{
			name:        "the transport says nothing, so the banner decides",
			serviceName: "", transport: "tcp", port: 8080, banner: httpResponse,
			want: "http",
		},
		{
			name:        "udp is a transport, not a protocol",
			serviceName: "udp", transport: "udp", port: 161, banner: "irrelevant",
			want: "snmp",
		},
		{
			name:        "nothing recognizable leaves an empty hint, which tries every rule",
			serviceName: "", transport: "tcp", port: 65000, banner: "\x00\x01\x02\x03",
			want: "",
		},
		{
			name:        "a service name no rule keys on is passed through unchanged",
			serviceName: "rabbitmq", transport: "tcp", port: 5672, banner: "AMQP\x00\x00\x09\x01",
			want: "rabbitmq",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want,
				ResolverProtocolHint(tc.serviceName, tc.transport, tc.port, tc.banner))
		})
	}
}

// The exported wrapper and the chain the pipeline runs must agree, or the
// report describes a scanner nobody runs. Asserting it here rather than
// trusting that both call the same helper is the point: they took different
// arguments once already.
func TestResolverProtocolHint_AgreesWithThePipelineChain(t *testing.T) {
	const banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\n"

	for _, serviceName := range []string{"https", "http", "", "tcp", "rabbitmq"} {
		pipeline := normalizeResolverProtocol(
			protocolHintFor(serviceName, "tcp", 443, banner), banner, "")

		require.Equal(t, pipeline, ResolverProtocolHint(serviceName, "tcp", 443, banner),
			"service %q", serviceName)
	}
}
