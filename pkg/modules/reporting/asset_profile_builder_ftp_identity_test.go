package reporting

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/scan"
)

// cyprob#365 changed what ftp_probe means: it answers "did the probe succeed"
// now, like the other fourteen native probes' flags, rather than "did we reach
// FTP". This is the call site that was reading it for the second meaning, and
// the name of a real FTP server must survive the change on both paths.
func TestApplyFTPDetails_AFailedProbeStillNamesTheService(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		want     string
	}{
		{name: "plain", protocol: "ftp", want: "ftp"},
		{name: "implicit tls", protocol: "ftps", want: "ftps"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			profile := &engine.PortProfile{PortNumber: 21, Protocol: "tcp"}
			applyFTPDetails(profile, scan.FTPServiceInfo{
				Target: "192.0.2.90",
				Port:   21,
				// The shape cyprob#365 creates: greeted, then a later step
				// failed, so the flag is false and the banner is not.
				FTPProbe:    false,
				ProbeError:  "timeout",
				FTPProtocol: tc.protocol,
				Banner:      "220 Welcome to test ftp",
			})
			require.Equal(t, tc.want, profile.Service.Name,
				"a server that greeted and then failed lost its service name")
		})
	}

	// The control. Without it the cases above would pass just as well if the
	// branch named every service it was handed: with nothing saying this is FTP
	// -- no successful probe and no banner -- the name has to stay empty.
	profile := &engine.PortProfile{PortNumber: 21, Protocol: "tcp"}
	applyFTPDetails(profile, scan.FTPServiceInfo{
		Target: "192.0.2.90", Port: 21, ProbeError: "connect_failed",
	})
	require.Empty(t, profile.Service.Name,
		"nothing said this was FTP, so nothing should have named it")

	// And the flag alone still names it, which is the path that has not changed.
	profile = &engine.PortProfile{PortNumber: 21, Protocol: "tcp"}
	applyFTPDetails(profile, scan.FTPServiceInfo{
		Target: "192.0.2.90", Port: 21, FTPProbe: true, FTPProtocol: "ftp",
	})
	require.Equal(t, "ftp", profile.Service.Name)
}
