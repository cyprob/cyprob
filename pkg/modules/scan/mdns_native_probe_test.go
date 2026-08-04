package scan

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

func mdnsName(t *testing.T, name string) dnsmessage.Name {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	require.NoError(t, err)
	return n
}

// buildMDNSResponse assembles a DNS-SD style answer: PTR records in the answer
// section and SRV/TXT bundled in additionals, which is how real responders reply.
func buildMDNSResponse(t *testing.T, qname string, ptrs []string, srvTarget string, txt []string) []byte {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	builder.EnableCompression()
	require.NoError(t, builder.StartQuestions())
	require.NoError(t, builder.Question(dnsmessage.Question{
		Name: mdnsName(t, qname), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET,
	}))
	require.NoError(t, builder.StartAnswers())
	for _, ptr := range ptrs {
		require.NoError(t, builder.PTRResource(
			dnsmessage.ResourceHeader{Name: mdnsName(t, qname), Class: dnsmessage.ClassINET, TTL: 120},
			dnsmessage.PTRResource{PTR: mdnsName(t, ptr)},
		))
	}
	require.NoError(t, builder.StartAdditionals())
	if srvTarget != "" {
		require.NoError(t, builder.SRVResource(
			dnsmessage.ResourceHeader{Name: mdnsName(t, qname), Class: dnsmessage.ClassINET, TTL: 120},
			dnsmessage.SRVResource{Port: 7000, Target: mdnsName(t, srvTarget)},
		))
	}
	if len(txt) > 0 {
		require.NoError(t, builder.TXTResource(
			dnsmessage.ResourceHeader{Name: mdnsName(t, qname), Class: dnsmessage.ClassINET, TTL: 120},
			dnsmessage.TXTResource{TXT: txt},
		))
	}
	packet, err := builder.Finish()
	require.NoError(t, err)
	return packet
}

func TestProbeMDNSDetails_AppleDevice(t *testing.T) {
	original := mdnsQueryFunc
	t.Cleanup(func() { mdnsQueryFunc = original })

	var asked []string
	mdnsQueryFunc = func(_ context.Context, _ string, _ int, _ MDNSProbeOptions, name string, _ dnsmessage.Type) ([]byte, error) {
		asked = append(asked, name)
		switch name {
		case mdnsServiceEnumeration:
			return buildMDNSResponse(t, name,
				[]string{"_airplay._tcp.local.", "_raop._tcp.local."}, "", nil), nil
		case "_airplay._tcp.local.":
			return buildMDNSResponse(t, name,
				[]string{"Living Room._airplay._tcp.local."},
				"living-room.local.",
				[]string{"model=AppleTV14,1", "osvers=26.5", "srcvers=950.7.1"}), nil
		}
		return nil, errMDNSNoResponse
	}

	result := probeMDNSDetails(context.Background(), "192.0.2.10", mdnsPort, MDNSProbeOptions{
		TotalTimeout: 2 * time.Second, IOTimeout: 200 * time.Millisecond,
	})

	require.True(t, result.MDNSProbe)
	require.Equal(t, "Apple", result.VendorHint)
	require.Equal(t, "AppleTV14,1", result.Model)
	require.Equal(t, "26.5", result.VersionHint, "osvers must win over srcvers")
	require.Equal(t, deviceTypeMediaDevice, result.DeviceType)
	require.Equal(t, "living-room.local", result.Hostname)
	require.Equal(t, "Living Room", result.InstanceName)
	require.Contains(t, result.ServiceTypes, "_airplay._tcp.local.")
	require.Contains(t, asked, mdnsServiceEnumeration)
}

func TestProbeMDNSDetails_NoResponse(t *testing.T) {
	original := mdnsQueryFunc
	t.Cleanup(func() { mdnsQueryFunc = original })
	mdnsQueryFunc = func(_ context.Context, _ string, _ int, _ MDNSProbeOptions, _ string, _ dnsmessage.Type) ([]byte, error) {
		return nil, errMDNSNoResponse
	}

	result := probeMDNSDetails(context.Background(), "192.0.2.11", mdnsPort, MDNSProbeOptions{
		TotalTimeout: time.Second, IOTimeout: 100 * time.Millisecond,
	})
	require.False(t, result.MDNSProbe)
	require.Equal(t, "no_response", result.ProbeError)
	require.Empty(t, result.Model)
}

func TestProbeMDNSDetails_SkipsUnadvertisedServices(t *testing.T) {
	original := mdnsQueryFunc
	t.Cleanup(func() { mdnsQueryFunc = original })

	var asked []string
	mdnsQueryFunc = func(_ context.Context, _ string, _ int, _ MDNSProbeOptions, name string, _ dnsmessage.Type) ([]byte, error) {
		asked = append(asked, name)
		if name == mdnsServiceEnumeration {
			return buildMDNSResponse(t, name, []string{"_airplay._tcp.local."}, "", nil), nil
		}
		return buildMDNSResponse(t, name, nil, "", nil), nil
	}

	probeMDNSDetails(context.Background(), "192.0.2.12", mdnsPort, MDNSProbeOptions{
		TotalTimeout: 2 * time.Second, IOTimeout: 100 * time.Millisecond,
	})

	// _device-info is always tried; other types only when advertised.
	require.Contains(t, asked, "_airplay._tcp.local.")
	require.NotContains(t, asked, "_googlecast._tcp.local.")
	require.NotContains(t, asked, "_printer._tcp.local.")
}

func TestDeriveMDNSIdentity(t *testing.T) {
	t.Run("printer keys and service type", func(t *testing.T) {
		info := &MDNSServiceInfo{
			ServiceTypes: []string{"_ipp._tcp.local."},
			TXTAttrs: map[string]string{
				"usb_mfg": "HP", "usb_mdl": "LaserJet M404dn", "fw": "2.4.1",
			},
		}
		deriveMDNSIdentity(info)
		require.Equal(t, "HP", info.VendorHint)
		require.Equal(t, "LaserJet M404dn", info.Model)
		require.Equal(t, "2.4.1", info.VersionHint)
		require.Equal(t, deviceTypePrinter, info.DeviceType)
		require.Equal(t, "HP LaserJet M404dn", info.ProductHint)
	})

	t.Run("service type outranks model family", func(t *testing.T) {
		info := &MDNSServiceInfo{
			ServiceTypes: []string{"_ipp._tcp.local.", "_airplay._tcp.local."},
			TXTAttrs:     map[string]string{"model": "Mac16,7"},
		}
		deriveMDNSIdentity(info)
		require.Equal(t, deviceTypePrinter, info.DeviceType)
	})

	t.Run("Android TV is classified from its remote-control service", func(t *testing.T) {
		// The cast service carries the model but often answers only multicast,
		// so the remote-control service is the one a unicast probe actually gets.
		info := &MDNSServiceInfo{
			ServiceTypes: []string{"_androidtvremote2._tcp.local."},
			TXTAttrs:     map[string]string{},
		}
		deriveMDNSIdentity(info)
		require.Equal(t, deviceTypeMediaDevice, info.DeviceType)
		require.Empty(t, info.VendorHint, "the service type alone names no vendor")
	})

	t.Run("iot only when nothing more specific", func(t *testing.T) {
		info := &MDNSServiceInfo{ServiceTypes: []string{"_hap._tcp.local."}, TXTAttrs: map[string]string{}}
		deriveMDNSIdentity(info)
		require.Equal(t, deviceTypeIoT, info.DeviceType)
	})

	t.Run("no signals means no guessing", func(t *testing.T) {
		info := &MDNSServiceInfo{TXTAttrs: map[string]string{}}
		deriveMDNSIdentity(info)
		require.Empty(t, info.Model)
		require.Empty(t, info.VendorHint)
		require.Empty(t, info.DeviceType)
		require.Empty(t, info.ProductHint)
	})

	t.Run("non-Apple model does not get an Apple vendor", func(t *testing.T) {
		info := &MDNSServiceInfo{TXTAttrs: map[string]string{"md": "Chromecast Ultra"}}
		deriveMDNSIdentity(info)
		require.Empty(t, info.VendorHint)
		require.Equal(t, "Chromecast Ultra", info.Model)
	})
}

func TestIsAppleModelIdentifier(t *testing.T) {
	for _, model := range []string{"Mac16,7", "AppleTV14,1", "AudioAccessory5,1", "iPhone15,3"} {
		require.Truef(t, isAppleModelIdentifier(model), "%s should be an Apple identifier", model)
	}
	for _, model := range []string{"", "LaserJet M404dn", "Chromecast Ultra", "MacGuffin"} {
		require.Falsef(t, isAppleModelIdentifier(model), "%s should not be an Apple identifier", model)
	}
}

func TestMDNSInstanceLabel(t *testing.T) {
	require.Equal(t, "Living Room", mdnsInstanceLabel("Living Room._airplay._tcp.local."))
	require.Equal(t, "Oyun Odası", mdnsInstanceLabel(`Oyun\032Odası._airplay._tcp.local.`))
	require.Equal(t, "plain", mdnsInstanceLabel("plain."))
}

func TestMDNSCandidatesFromOpenPorts(t *testing.T) {
	candidates := mdnsCandidatesFromOpenPorts(map[string]any{
		"target": "192.0.2.20", "open_ports": []any{53, 5353, 161},
	})
	require.Len(t, candidates, 1, "only 5353 is an mDNS candidate")
	require.Equal(t, mdnsPort, candidates[0].port)
}

func TestClassifyMDNSError(t *testing.T) {
	require.Equal(t, "", classifyMDNSError(nil))
	require.Equal(t, "no_response", classifyMDNSError(errMDNSNoResponse))
	require.Equal(t, "no_response", classifyMDNSError(context.DeadlineExceeded))
	require.Equal(t, "probe_failed", classifyMDNSError(errors.New("boom")))
}
