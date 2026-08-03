package scan

import (
	"regexp"
	"strings"
)

// Linux distributions patch OpenSSH and advertise themselves in the SSH banner
// comment, e.g.:
//
//	SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
//	SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7
//
// SSH is reachable on virtually every Linux server, so this is a credential-free
// OS signal for the bulk of an enterprise estate — and an OS version feeds
// version-based CVE correlation, not just the inventory.
var (
	// debianReleasePattern captures the release the package was built for
	// ("+deb11u3" -> 11). This is stated by the banner, not inferred.
	debianReleasePattern = regexp.MustCompile(`(?i)\bdeb(?:ian)?(\d+)`)
	// sshOpenSSHVersionPattern extracts the upstream OpenSSH version.
	sshOpenSSHVersionPattern = regexp.MustCompile(`^(\d+\.\d+)`)
)

// sshDistroMarkers maps a marker in the banner comment to the OS it names.
// Ordered most-specific first (Raspbian before Debian).
var sshDistroMarkers = []struct {
	marker string
	family string
	name   string
}{
	{"raspbian", "linux", "Raspbian"},
	{"ubuntu", "linux", "Ubuntu"},
	{"debian", "linux", "Debian"},
	{"freebsd", "freebsd", "FreeBSD"},
	{"netbsd", "netbsd", "NetBSD"},
	{"openbsd", "openbsd", "OpenBSD"},
}

// ubuntuOpenSSHReleases maps the OpenSSH version Ubuntu ships to its LTS
// release. Ubuntu freezes OpenSSH for the life of a release, so the mapping is
// stable — but it is an INFERENCE, unlike the Debian case where the banner
// states the release outright. Only LTS releases are mapped: interim releases
// are short-lived and rare in the estates this matters for, and a wrong OS
// version would poison CVE correlation. Unknown versions yield no version
// rather than a guess.
var ubuntuOpenSSHReleases = map[string]string{
	"9.6": "24.04",
	"8.9": "22.04",
	"8.2": "20.04",
	"7.6": "18.04",
	"7.2": "16.04",
}

// deriveSSHOSIdentity extracts the operating system from an SSH banner's
// comment field. It returns empty values when the banner names no distribution,
// which is the case for stock OpenSSH builds and most network appliances.
func deriveSSHOSIdentity(banner, sshVersion string) SMBOSHints {
	comment := sshBannerComment(banner)
	if comment == "" {
		return SMBOSHints{}
	}
	lowered := strings.ToLower(comment)

	for _, distro := range sshDistroMarkers {
		if !strings.Contains(lowered, distro.marker) {
			continue
		}
		hints := SMBOSHints{Family: distro.family, Name: distro.name}
		hints.Version = deriveSSHOSVersion(distro.name, lowered, sshVersion)
		return hints
	}
	return SMBOSHints{}
}

func deriveSSHOSVersion(distroName, loweredComment, sshVersion string) string {
	switch distroName {
	case "Debian", "Raspbian":
		// Stated by the banner: "+deb11u3" means the Debian 11 package set.
		if match := debianReleasePattern.FindStringSubmatch(loweredComment); len(match) == 2 {
			return match[1]
		}
	case "Ubuntu":
		// Inferred from the frozen OpenSSH version; unknown versions stay empty.
		if match := sshOpenSSHVersionPattern.FindStringSubmatch(strings.TrimSpace(sshVersion)); len(match) == 2 {
			return ubuntuOpenSSHReleases[match[1]]
		}
	}
	return ""
}

// sshBannerComment returns the free-form comment that follows the version token
// in an SSH identification string. Everything before the first space is the
// software token the probe already parses; the distribution lives after it.
func sshBannerComment(banner string) string {
	banner = strings.TrimSpace(banner)
	if !strings.HasPrefix(banner, "SSH-") {
		return ""
	}
	parts := strings.SplitN(banner, "-", 3)
	if len(parts) < 3 {
		return ""
	}
	_, comment, found := strings.Cut(strings.TrimSpace(parts[2]), " ")
	if !found {
		return ""
	}
	return strings.TrimSpace(comment)
}
