package scan

import (
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/require"
)

func TestResolveV3Credential_SecurityLevels(t *testing.T) {
	t.Run("no username disables v3", func(t *testing.T) {
		require.Nil(t, SNMPProbeOptions{}.resolveV3Credential())
	})

	t.Run("authPriv from auth+priv passphrases", func(t *testing.T) {
		cred := SNMPProbeOptions{
			V3Username:       "monitor",
			V3AuthProtocol:   "SHA256",
			V3AuthPassphrase: "authpass123",
			V3PrivProtocol:   "AES256",
			V3PrivPassphrase: "privpass123",
		}.resolveV3Credential()
		require.NotNil(t, cred)
		require.Equal(t, "monitor", cred.username)
		require.Equal(t, "authPriv", cred.securityLevel)
		require.Equal(t, gosnmp.AuthPriv, cred.msgFlags)
		require.Equal(t, gosnmp.SHA256, cred.authProtocol)
		require.Equal(t, gosnmp.AES256, cred.privProtocol)
	})

	t.Run("authNoPriv when priv passphrase omitted", func(t *testing.T) {
		cred := SNMPProbeOptions{
			V3Username:       "monitor",
			V3AuthProtocol:   "SHA",
			V3AuthPassphrase: "authpass123",
			V3PrivProtocol:   "AES256", // ignored without a priv passphrase
		}.resolveV3Credential()
		require.NotNil(t, cred)
		require.Equal(t, "authNoPriv", cred.securityLevel)
		require.Equal(t, gosnmp.AuthNoPriv, cred.msgFlags)
		require.Equal(t, gosnmp.NoPriv, cred.privProtocol)
		require.Empty(t, cred.privPassphrase)
	})

	t.Run("noAuthNoPriv when no passphrases", func(t *testing.T) {
		cred := SNMPProbeOptions{V3Username: "monitor"}.resolveV3Credential()
		require.NotNil(t, cred)
		require.Equal(t, "noAuthNoPriv", cred.securityLevel)
		require.Equal(t, gosnmp.NoAuthNoPriv, cred.msgFlags)
		require.Equal(t, gosnmp.NoAuth, cred.authProtocol)
		require.Equal(t, gosnmp.NoPriv, cred.privProtocol)
	})
}

func TestBuildSNMPAttemptPlan_V3FirstWhenConfigured(t *testing.T) {
	t.Run("no v3 -> only community plans", func(t *testing.T) {
		plans := buildSNMPAttemptPlan(SNMPProbeOptions{})
		require.Len(t, plans, 4)
		for _, p := range plans {
			require.Nil(t, p.v3)
			require.NotEqual(t, gosnmp.Version3, p.version)
		}
	})

	t.Run("v3 configured -> tried first", func(t *testing.T) {
		plans := buildSNMPAttemptPlan(SNMPProbeOptions{
			V3Username:       "monitor",
			V3AuthPassphrase: "authpass123",
			V3PrivPassphrase: "privpass123",
		})
		require.Len(t, plans, 5)
		require.Equal(t, gosnmp.Version3, plans[0].version)
		require.NotNil(t, plans[0].v3)
		require.Equal(t, "monitor", plans[0].v3.username)
		// remaining plans stay the v1/v2c community fallbacks
		for _, p := range plans[1:] {
			require.Nil(t, p.v3)
		}
	})
}

func TestMapSNMPAuthProtocol(t *testing.T) {
	cases := map[string]gosnmp.SnmpV3AuthProtocol{
		"MD5":     gosnmp.MD5,
		"SHA":     gosnmp.SHA,
		"sha1":    gosnmp.SHA,
		"SHA224":  gosnmp.SHA224,
		"SHA256":  gosnmp.SHA256,
		"SHA384":  gosnmp.SHA384,
		"SHA512":  gosnmp.SHA512,
		"":        gosnmp.SHA256, // default
		"unknown": gosnmp.SHA256, // default
	}
	for in, want := range cases {
		require.Equalf(t, want, mapSNMPAuthProtocol(in), "auth proto %q", in)
	}
}

func TestMapSNMPPrivProtocol(t *testing.T) {
	cases := map[string]gosnmp.SnmpV3PrivProtocol{
		"DES":     gosnmp.DES,
		"AES":     gosnmp.AES,
		"aes128":  gosnmp.AES,
		"AES192":  gosnmp.AES192,
		"AES256":  gosnmp.AES256,
		"":        gosnmp.AES256, // default
		"unknown": gosnmp.AES256, // default
	}
	for in, want := range cases {
		require.Equalf(t, want, mapSNMPPrivProtocol(in), "priv proto %q", in)
	}
}

func TestSNMPInitParsesV3Config(t *testing.T) {
	m := newSNMPNativeProbeModule()
	require.NoError(t, m.Init("snmp-1", map[string]any{
		"snmpv3_username":      "monitor",
		"snmpv3_auth_protocol": "SHA256",
		"snmpv3_auth_pass":     "authpass123",
		"snmpv3_priv_protocol": "AES256",
		"snmpv3_priv_pass":     "privpass123",
	}))
	require.Equal(t, "monitor", m.options.V3Username)
	require.Equal(t, "SHA256", m.options.V3AuthProtocol)
	require.Equal(t, "authpass123", m.options.V3AuthPassphrase)
	require.Equal(t, "AES256", m.options.V3PrivProtocol)
	require.Equal(t, "privpass123", m.options.V3PrivPassphrase)

	cred := m.options.resolveV3Credential()
	require.NotNil(t, cred)
	require.Equal(t, "authPriv", cred.securityLevel)
}

func TestSNMPVersionStringV3(t *testing.T) {
	require.Equal(t, "SNMPv3", snmpVersionString(gosnmp.Version3))
}
