// Package version provides version metadata for the application.
package version

import (
	"fmt"
	"runtime"
)

// These variables are typically injected at build time using -ldflags
// version holds the current version of vulntor. It is set at build time.
// commit holds the current git commit hash of vulntor. It is set at build time.
// buildDate holds the build date of vulntor in RFC3339 format. It is set at build time.
// tag holds the git tag associated with the build. It is set at build time.
var (
	version   = "0.5.1"                // Version holds the current version of vulntor.
	commit    = ""                     // Commit holds the current version commit of vulntor.
	buildDate = "1970-01-01T00:00:00Z" // BuildDate holds the build date of vulntor.
	tag       = ""                     // Tag holds the git tag of the build.
)

// Version holds metadata information about the application build, including
// the semantic version, commit hash, build date, git tag, Go version, compiler,
// and platform details.
type Version struct {
	Version   string
	Commit    string
	BuildDate string
	Tag       string
	GoVersion string
	Compiler  string
	Platform  string
}

// String returns the version as a string.
func (v Version) String() string {
	return v.Version
}

// GetVersion returns version information as a Struct.
func GetVersion() Version {
	var str string

	if commit != "" && tag != "" {
		str = tag
	} else {
		str = "v" + version
		if len(commit) >= 7 {
			str += "+" + commit[:7]
		} else {
			str += "+unknown"
		}
	}

	return Version{
		Version:   str,
		Commit:    commit,
		BuildDate: buildDate,
		Tag:       tag,
		GoVersion: runtime.Version(),
		Compiler:  runtime.Compiler,
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// CheckNewVersion checks if a new version is available.
func CheckNewVersion() bool {
	// TODO: check for new version only if the current version is not "dev"
	// and also not a pre-release
	return false
}
