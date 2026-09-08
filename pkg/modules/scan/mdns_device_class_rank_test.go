package scan

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// cyprob#231: the device class was decided by alphabetical order. Every writer
// of ServiceTypes goes through appendUniqueSorted, so "the first service that
// matches" meant "the alphabetically first one", and a printer that also does
// AirPlay was a media device because "_airplay" sorts before "_ipp".
//
// mdnsServiceTypesAsProduced exists so these tests cannot repeat the mistake the
// old one made: it assigned the slice directly, unsorted, and asserted against a
// shape production never builds.
func mdnsServiceTypesAsProduced(services ...string) []string {
	var out []string
	for _, service := range services {
		out = appendUniqueSorted(out, service)
	}
	return out
}

func TestDeriveMDNSDeviceType_RanksSignalsRatherThanOrder(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		services []string
		model    string
		want     string
		why      string
	}{
		{
			name:     "a printer that also does AirPlay is a printer",
			services: []string{"_ipp._tcp.local.", "_airplay._tcp.local."},
			want:     deviceTypePrinter,
			why:      "IPP is dedicated, AirPlay is a capability — and _airplay sorts first",
		},
		{
			name:     "a Mac that does AirPlay is a workstation",
			services: []string{"_airplay._tcp.local."},
			model:    "Mac16,7",
			want:     deviceTypeWorkstation,
			why:      "the stated model beats a capability every Apple device advertises",
		},
		{
			name:     "a Mac sharing files is still a workstation",
			services: []string{"_smb._tcp.local.", "_afpovertcp._tcp.local."},
			model:    "Mac16,7",
			want:     deviceTypeWorkstation,
			why:      "file sharing is a capability, not a NAS",
		},
		{
			name:     "a host advertising only file sharing is storage",
			services: []string{"_smb._tcp.local.", "_adisk._tcp.local."},
			want:     deviceTypeStorage,
			why:      "nothing stronger competes, so the capability decides",
		},
		{
			name:     "a printer beats a model family",
			services: []string{"_ipp._tcp.local."},
			model:    "Mac16,7",
			want:     deviceTypePrinter,
			why:      "a dedicated service outranks a stated model",
		},
		{
			name:     "a cast device is dedicated, not a capability",
			services: []string{"_googlecast._tcp.local.", "_smb._tcp.local."},
			want:     deviceTypeMediaDevice,
			why:      "no general-purpose computer publishes _googlecast",
		},
		{
			name:     "home automation only when nothing else says anything",
			services: []string{"_hap._tcp.local."},
			want:     deviceTypeIoT,
			why:      "the weakest signal still beats no answer",
		},
		{
			name:     "home automation loses to anything else",
			services: []string{"_hap._tcp.local.", "_airplay._tcp.local."},
			want:     deviceTypeMediaDevice,
			why:      "ambient is the weakest rank, and _airplay sorts first anyway",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			info := &MDNSServiceInfo{
				ServiceTypes: mdnsServiceTypesAsProduced(tc.services...),
				TXTAttrs:     map[string]string{},
			}
			if tc.model != "" {
				info.TXTAttrs["model"] = tc.model
			}
			deriveMDNSIdentity(info)
			require.Equal(t, tc.want, info.DeviceType, tc.why)
		})
	}
}

// The property the issue is actually about: no answer may depend on the order
// the services were discovered in. Asserted over every permutation rather than
// over one pair, because a fix that only reordered the map would pass a single
// case.
func TestDeriveMDNSDeviceType_IsIndependentOfDiscoveryOrder(t *testing.T) {
	t.Parallel()

	services := []string{
		"_airplay._tcp.local.",
		"_ipp._tcp.local.",
		"_smb._tcp.local.",
		"_hap._tcp.local.",
	}

	var want string
	for i, permutation := range permuteStrings(services) {
		info := &MDNSServiceInfo{
			ServiceTypes: mdnsServiceTypesAsProduced(permutation...),
			TXTAttrs:     map[string]string{"model": "Mac16,7"},
		}
		deriveMDNSIdentity(info)
		if i == 0 {
			want = info.DeviceType
			require.NotEmpty(t, want, "the fixture must produce an answer, or this proves nothing")
			continue
		}
		require.Equalf(t, want, info.DeviceType,
			"discovery order %v changed the answer", permutation)
	}
}

// And the answer that property settles on is the right one, so the test above
// cannot be satisfied by returning the same wrong class every time.
func TestDeriveMDNSDeviceType_OrderIndependentAnswerIsTheStrongestSignal(t *testing.T) {
	t.Parallel()

	info := &MDNSServiceInfo{
		ServiceTypes: mdnsServiceTypesAsProduced(
			"_airplay._tcp.local.", "_ipp._tcp.local.", "_smb._tcp.local.", "_hap._tcp.local."),
		TXTAttrs: map[string]string{"model": "Mac16,7"},
	}
	deriveMDNSIdentity(info)
	require.Equal(t, deviceTypePrinter, info.DeviceType,
		"IPP is the only dedicated service present, so it decides")
}

func permuteStrings(values []string) [][]string {
	if len(values) <= 1 {
		return [][]string{append([]string(nil), values...)}
	}
	var out [][]string
	for i := range values {
		rest := make([]string, 0, len(values)-1)
		rest = append(rest, values[:i]...)
		rest = append(rest, values[i+1:]...)
		for _, tail := range permuteStrings(rest) {
			out = append(out, append([]string{values[i]}, tail...))
		}
	}
	return out
}
