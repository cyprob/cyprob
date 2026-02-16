package parse

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeTechTag_Aliases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{input: "IIS", want: TagMicrosoftIIS},
		{input: "ASP.NET", want: "asp_net"},
		{input: "Node.js", want: "nodejs"},
		{input: "mail_server", want: TagMailService},
		{input: "Roundcube", want: TagRoundcube},
	}

	for _, tc := range tests {
		got, ok := NormalizeTechTag(tc.input)
		require.True(t, ok, "expected %q to normalize", tc.input)
		require.Equal(t, tc.want, got)
	}
}

func TestNormalizeTechTags_ImpliedMailTags(t *testing.T) {
	t.Parallel()

	got := NormalizeTechTags([]string{"roundcube", "smtp", "unknown-tag"})
	require.Contains(t, got, TagRoundcube)
	require.Contains(t, got, TagSMTP)
	require.Contains(t, got, TagWebmail)
	require.Contains(t, got, TagMailService)
	require.NotContains(t, got, "unknown-tag")
}

func TestCanonicalTechTags_MailSetLocked(t *testing.T) {
	t.Parallel()

	required := []string{
		TagMailService,
		TagWebmail,
		TagSMTP,
		TagIMAP,
		TagPOP3,
		TagExchange,
		TagOWA,
		TagSmarterMail,
		TagRoundcube,
		TagZimbra,
		TagSOGo,
		TagRainLoop,
		TagPostfix,
		TagExim,
		TagDovecot,
		TagMicrosoftIIS,
	}
	for _, tag := range required {
		require.True(t, IsCanonicalTechTag(tag), "missing canonical tag %q", tag)
	}
}
