package scan

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeriveSSHOSIdentity(t *testing.T) {
	cases := []struct {
		name        string
		banner      string
		sshVersion  string
		wantFamily  string
		wantName    string
		wantVersion string
	}{
		{
			name:        "Debian states its release in the banner",
			banner:      "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",
			sshVersion:  "7.4p1",
			wantFamily:  "linux",
			wantName:    "Debian",
			wantVersion: "9",
		},
		{
			name:        "Debian 11 package suffix",
			banner:      "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
			sshVersion:  "8.4p1",
			wantFamily:  "linux",
			wantName:    "Debian",
			wantVersion: "11",
		},
		{
			name:        "Ubuntu LTS inferred from the frozen OpenSSH version",
			banner:      "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
			sshVersion:  "8.9p1",
			wantFamily:  "linux",
			wantName:    "Ubuntu",
			wantVersion: "22.04",
		},
		{
			name:        "Ubuntu with an unmapped OpenSSH version yields no version",
			banner:      "SSH-2.0-OpenSSH_9.2p1 Ubuntu-2",
			sshVersion:  "9.2p1",
			wantFamily:  "linux",
			wantName:    "Ubuntu",
			wantVersion: "",
		},
		{
			// Ubuntu keeps Debian's prefix in its package version, so this real
			// banner names both; the ubuntu revision is what identifies it.
			name:        "Ubuntu banner that also contains Debian",
			banner:      "SSH-2.0-OpenSSH_8.9p1 Debian-1ubuntu1",
			sshVersion:  "8.9p1",
			wantFamily:  "linux",
			wantName:    "Ubuntu",
			wantVersion: "22.04",
		},
		{
			name:        "genuine Debian with no release marker yields no version",
			banner:      "SSH-2.0-OpenSSH_8.9p1 Debian-3",
			sshVersion:  "8.9p1",
			wantFamily:  "linux",
			wantName:    "Debian",
			wantVersion: "",
		},
		{
			name:       "Raspbian is matched before Debian",
			banner:     "SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2",
			sshVersion: "7.9p1",
			wantFamily: "linux", wantName: "Raspbian", wantVersion: "10",
		},
		{
			name:       "FreeBSD",
			banner:     "SSH-2.0-OpenSSH_7.9 FreeBSD-20200214",
			sshVersion: "7.9",
			wantFamily: "freebsd", wantName: "FreeBSD",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hints := deriveSSHOSIdentity(tc.banner, tc.sshVersion)
			require.Equal(t, tc.wantFamily, hints.Family)
			require.Equal(t, tc.wantName, hints.Name)
			require.Equal(t, tc.wantVersion, hints.Version)
		})
	}
}

// A banner with no distribution comment must assert nothing: stock OpenSSH
// builds and most network appliances name no OS.
func TestDeriveSSHOSIdentity_AssertsNothingWithoutADistro(t *testing.T) {
	for _, banner := range []string{
		"SSH-2.0-OpenSSH_9.3",
		"SSH-2.0-OpenSSH_8.0",
		"SSH-2.0-dropbear_2020.81",
		"SSH-2.0-Cisco-1.25",
		"SSH-1.99-OpenSSH_4.3",
		"",
		"not a banner",
	} {
		hints := deriveSSHOSIdentity(banner, "9.3")
		require.Emptyf(t, hints.Family, "%q must not yield an OS", banner)
		require.Empty(t, hints.Name)
		require.Empty(t, hints.Version)
	}
}

func TestSSHBannerComment(t *testing.T) {
	require.Equal(t, "Ubuntu-3ubuntu0.4", sshBannerComment("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"))
	require.Equal(t, "", sshBannerComment("SSH-2.0-OpenSSH_9.3"), "no comment means no OS claim")
	require.Equal(t, "", sshBannerComment("garbage"))
}
