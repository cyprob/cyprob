package parse

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyprob/cyprob/pkg/engine"
	"github.com/cyprob/cyprob/pkg/modules/scan"
)

func buildSSHParser(t *testing.T) *SSHParserModule {
	t.Helper()
	m := newSSHParserModule()
	require.NoError(t, m.Init("ssh_parser", nil))
	return m
}

func TestSSHParser_Execute_WithValidBanner(t *testing.T) {
	m := buildSSHParser(t)
	inputs := map[string]any{
		"service.banner.tcp": []any{
			scan.BannerGrabResult{IP: "127.0.0.1", Port: 22, Protocol: "tcp", Banner: "SSH-2.0-OpenSSH_9.0"},
		},
	}
	outCh := make(chan engine.ModuleOutput, 4)
	defer close(outCh)
	err := m.Execute(context.Background(), inputs, outCh)
	require.NoError(t, err)
	for len(outCh) > 0 {
		<-outCh
	}
}

func TestSSHParser_Execute_WrongItemType(t *testing.T) {
	m := buildSSHParser(t)
	inputs := map[string]any{
		"service.banner.tcp": []any{[]scan.BannerGrabResult{}},
	}
	outCh := make(chan engine.ModuleOutput, 3)
	defer close(outCh)
	err := m.Execute(context.Background(), inputs, outCh)
	require.NoError(t, err)
}

func TestSSHParser_Metadata_Default(t *testing.T) {
	m := newSSHParserModule()
	md := m.Metadata()

	require.Equal(t, sshParserModuleID, md.ID)
	require.Equal(t, sshParserModuleName, md.Name)
	require.Equal(t, sshParserModuleDescription, md.Description)
	require.Equal(t, sshParserModuleVersion, md.Version)
	require.Equal(t, engine.ParseModuleType, md.Type)

	// Ensure expected consume/produce keys are present
	hasConsume := false
	for _, c := range md.Consumes {
		if c.Key == "service.banner.tcp" {
			hasConsume = true
			break
		}
	}
	require.True(t, hasConsume, "expected consumes to include service.banner.tcp")

	hasProduce := false
	for _, p := range md.Produces {
		if p.Key == "service.ssh.details" {
			hasProduce = true
			break
		}
	}
	require.True(t, hasProduce, "expected producves to include service.ssh.details")
}

func TestSSHParser_Execute_ParsesValidBanners(t *testing.T) {
	testCases := []struct {
		name        string
		banners     []scan.BannerGrabResult
		expectParse bool
		expectErr   bool
	}{
		{
			name: "valid ssh banner",
			banners: []scan.BannerGrabResult{
				{IP: "192.168.1.1", Port: 22, Banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-3ubuntu0.7"},
			},
			expectParse: true,
		},
		{
			name: "non-ssh banner",
			banners: []scan.BannerGrabResult{
				{IP: "192.168.1.1", Port: 80, Banner: "HTTP/1.1 200 OK"},
			},
			expectParse: false,
		},
		{
			name: "empty banner",
			banners: []scan.BannerGrabResult{
				{IP: "192.168.1.1", Port: 22, Banner: ""},
			},
			expectParse: false,
		},
		{
			name: "banner with error",
			banners: []scan.BannerGrabResult{
				{IP: "192.168.1.1", Port: 22, Banner: "", Error: "connection refused"},
			},
			expectParse: false,
		},
		{
			name: "multiple valid banners",
			banners: []scan.BannerGrabResult{
				{IP: "192.168.1.1", Port: 22, Banner: "SSH-2.0-OpenSSH_8.2p1"},
				{IP: "192.168.1.2", Port: 22, Banner: "SSH-2.0-Dropbear_2020.80"},
			},
			expectParse: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := buildSSHParser(t)
			inputs := map[string]any{
				"service.banner.tcp": tc.banners,
			}
			// Each banner produces 3 outputs: service.ssh.details, ssh.banner, ssh.version
			outCh := make(chan engine.ModuleOutput, len(tc.banners)*3)
			defer close(outCh)

			err := m.Execute(context.Background(), inputs, outCh)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			var outputs []engine.ModuleOutput
			for len(outCh) > 0 {
				outputs = append(outputs, <-outCh)
			}

			if tc.expectParse {
				require.NotEmpty(t, outputs)
				// Verify we have the expected output types
				var foundDetails, foundBanner bool
				for _, out := range outputs {
					switch out.DataKey {
					case "service.ssh.details":
						parsed, ok := out.Data.(SSHParsedInfo)
						require.True(t, ok, "service.ssh.details should be SSHParsedInfo")
						require.Equal(t, "SSH", parsed.ProtocolName)
						require.NotEmpty(t, parsed.SSHVersion)
						foundDetails = true
					case "ssh.banner":
						banner, ok := out.Data.(string)
						require.True(t, ok, "ssh.banner should be string")
						require.NotEmpty(t, banner)
						foundBanner = true
					case "ssh.version":
						version, ok := out.Data.(string)
						require.True(t, ok, "ssh.version should be string")
						require.NotEmpty(t, version)
					}
				}
				require.True(t, foundDetails, "should have service.ssh.details output")
				require.True(t, foundBanner, "should have ssh.banner output")
			} else {
				require.Empty(t, outputs)
			}
		})
	}
}

func TestSSHParser_Execute_ContextCancellation(t *testing.T) {
	m := buildSSHParser(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	inputs := map[string]any{
		"service.banner.tcp": []scan.BannerGrabResult{
			{IP: "192.168.1.1", Port: 22, Banner: "SSH-2.0-OpenSSH_8.2p1"},
		},
	}
	outCh := make(chan engine.ModuleOutput, 3)
	defer close(outCh)

	err := m.Execute(ctx, inputs, outCh)
	require.Error(t, err)
	require.Equal(t, context.Canceled, err)
}

func TestSSHParserModuleFactory_CreatesModule(t *testing.T) {
	mod := SSHParserModuleFactory()
	require.NotNil(t, mod)

	md := mod.Metadata()
	require.Equal(t, sshParserModuleName, md.Name)
	require.Equal(t, sshParserModuleID, md.ID)
}

func TestSSHParserModuleFactory_InitSetsInstanceID(t *testing.T) {
	mod := SSHParserModuleFactory()
	require.NoError(t, mod.Init("custom-instance-id", nil))

	md := mod.Metadata()
	require.Equal(t, "custom-instance-id", md.ID)
}

func TestExtractSSHSoftwareAndVersion(t *testing.T) {
	cases := []struct {
		in, wantSoftware, wantVersion string
	}{
		{"OpenSSH_8.9p1", "OpenSSH", "8.9p1"},
		{"dropbear_2020.78", "dropbear", "2020.78"},
		{"OpenSSH 8.2p1", "OpenSSH", "8.2p1"},
		{"OpenSSH-8.2p1", "OpenSSH-8.2p1", ""}, // no space/underscore -> falls back to first token
		{"", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			software, version := extractSSHSoftwareAndVersion(tc.in)
			require.Equal(t, tc.wantSoftware, software)
			require.Equal(t, tc.wantVersion, version)
		})
	}
}

func TestSSHParser_Execute_MissingInputKey(t *testing.T) {
	m := buildSSHParser(t)
	inputs := map[string]any{} // no service.banner.tcp key

	outCh := make(chan engine.ModuleOutput, 3)
	defer close(outCh)

	err := m.Execute(context.Background(), inputs, outCh)
	require.NoError(t, err)
	require.Zero(t, len(outCh), "expected no outputs when input key is missing")
}

func TestSSHParser_Execute_InputWrongType(t *testing.T) {
	m := buildSSHParser(t)
	// Provide a non-list type for the expected key
	inputs := map[string]any{
		"service.banner.tcp": 12345,
	}

	outCh := make(chan engine.ModuleOutput, 3)
	defer close(outCh)

	err := m.Execute(context.Background(), inputs, outCh)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a list")
}

func TestSSHParser_Execute_ParsesSoftwareVersionProperly(t *testing.T) {
	m := buildSSHParser(t)
	inputs := map[string]any{
		"service.banner.tcp": []any{
			scan.BannerGrabResult{IP: "10.0.0.5", Port: 22, Banner: "SSH-2.0-OpenSSH_9.0"},
		},
	}

	// Each banner produces 3 outputs: service.ssh.details, ssh.banner, ssh.version
	outCh := make(chan engine.ModuleOutput, 3)
	defer close(outCh)

	err := m.Execute(context.Background(), inputs, outCh)
	require.NoError(t, err)

	var outputs []engine.ModuleOutput
	for len(outCh) > 0 {
		outputs = append(outputs, <-outCh)
	}

	// Should have 3 outputs: service.ssh.details, ssh.banner, ssh.version
	require.NotEmpty(t, outputs)

	// Find and verify service.ssh.details output
	var parsed SSHParsedInfo
	var found bool
	for _, out := range outputs {
		if out.DataKey == "service.ssh.details" {
			var ok bool
			parsed, ok = out.Data.(SSHParsedInfo)
			require.True(t, ok)
			found = true
			break
		}
	}
	require.True(t, found, "should have service.ssh.details output")

	require.Equal(t, "SSH", parsed.ProtocolName)
	require.Equal(t, "2.0", parsed.SSHVersion)
	require.Equal(t, "OpenSSH_9.0", parsed.VersionInfo)
	require.Equal(t, "OpenSSH", parsed.Software)
	require.Equal(t, "9.0", parsed.SoftwareVersion)
}

func TestSSHParser_Execute_TypedSliceInput(t *testing.T) {
	m := buildSSHParser(t)
	// Provide the typed slice []scan.BannerGrabResult instead of []interface{}
	inputs := map[string]any{
		"service.banner.tcp": []scan.BannerGrabResult{
			{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-Dropbear_2020.78"},
		},
	}

	// Each banner produces 3 outputs: service.ssh.details, ssh.banner, ssh.version
	outCh := make(chan engine.ModuleOutput, 3)
	defer close(outCh)

	err := m.Execute(context.Background(), inputs, outCh)
	require.NoError(t, err)

	var outputs []engine.ModuleOutput
	for len(outCh) > 0 {
		outputs = append(outputs, <-outCh)
	}

	require.NotEmpty(t, outputs)

	// Find and verify service.ssh.details output
	var parsed SSHParsedInfo
	var found bool
	for _, out := range outputs {
		if out.DataKey == "service.ssh.details" {
			var ok bool
			parsed, ok = out.Data.(SSHParsedInfo)
			require.True(t, ok)
			found = true
			break
		}
	}
	require.True(t, found, "should have service.ssh.details output")

	require.Equal(t, "Dropbear", parsed.Software)
	require.Equal(t, "2020.78", parsed.SoftwareVersion)
	require.Equal(t, "2.0", parsed.SSHVersion)
}
