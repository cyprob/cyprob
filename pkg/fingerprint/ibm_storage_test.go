package fingerprint

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The banners below keep the shape captured from live arrays on 2026-08-12:
// the title wraps across lines and is indented, and two of the four models
// serve no Server header at all. Session cookies are dropped because they
// differ per capture and carry no identity.
const (
	ibmStorwizeV3700Banner = "HTTP/1.1 200 OK\r\n" +
		"Cache-Control: no-cache, no-store, must-revalidate\r\n" +
		"X-Content-Type-Options: nosniff\r\n" +
		"Content-Type: text/html;charset=UTF-8\r\n" +
		"Server: SVC GUI\r\n\r\n" +
		"<html><head><title>\n    LS_V3700 - Log in - \n    IBM Storwize V3700\n  </title></head>"

	ibmStorwizeV5000Banner = "HTTP/1.1 200 OK\r\n" +
		"X-Content-Type-Options: nosniff\r\n" +
		"Content-Type: text/html;charset=UTF-8\r\n" +
		"Server: SVC GUI\r\n\r\n" +
		"<html><head><title>\n    LSV5030 - Log in - \n    IBM Storwize V5000\n  </title></head>"

	// No Server header, which is how this one answers.
	ibmFlashSystem5000Banner = "HTTP/1.1 200 \r\n" +
		"Cache-Control: no-cache, no-store, must-revalidate\r\n" +
		"X-Content-Type-Options: nosniff\r\n" +
		"Content-Type: text/html;charset=UTF-8\r\n\r\n" +
		"<html><head><title>\n    LS5030FLASH - Log in - \n    IBM FlashSystem 5000\n  </title></head>"

	// Also no Server header, and it spells the line "IBM Storage FlashSystem".
	ibmFlashSystem5300Banner = "HTTP/1.1 200 \r\n" +
		"Content-Security-Policy: frame-ancestors 'self'\r\n" +
		"X-Content-Type-Options: nosniff\r\n" +
		"Content-Type: text/html;charset=UTF-8\r\n\r\n" +
		"<html><head><title>\n    LS_FS5300 - Log in - \n    IBM Storage FlashSystem 5300\n  </title></head>"

	// A port that redirects and offers no title at all. The header is the only
	// anchor here, which is why the family rule exists.
	ibmSVCRedirectBanner = "HTTP/1.1 302 Found\r\n" +
		"Location: /service/\r\n" +
		"Connection: close\r\n" +
		"Server: SVC GUI\r\n\r\n"
)

// Production hands the resolver "http" for these services: the pipeline maps an
// https hint to http when the response looks like HTTP. Fallback mode is what it
// uses on a port the catalog does not recognize. Both are exercised, because a
// rule that only fires in one of them is dead on half the estate.
func TestIBMStorage_ModelsAreIdentifiedFromTheirOwnBanners(t *testing.T) {
	for _, tc := range []struct {
		name, banner, product string
		port                  int
	}{
		{"Storwize V3700", ibmStorwizeV3700Banner, "Storwize V3700", 443},
		{"Storwize V5000", ibmStorwizeV5000Banner, "Storwize V5000", 8443},
		{"FlashSystem 5000, no Server header", ibmFlashSystem5000Banner, "FlashSystem 5000", 443},
		{"FlashSystem 5300, spelled IBM Storage", ibmFlashSystem5300Banner, "FlashSystem 5300", 80},
	} {
		for _, protocol := range []string{"", "http"} {
			t.Run(tc.name+"/hint="+protocol, func(t *testing.T) {
				result := requireResolved(t, tc.banner, protocol, tc.port)

				require.Equal(t, "IBM", result.Vendor)
				require.Equal(t, tc.product, result.Product)
				require.Empty(t, result.Version,
					"the model belongs in product; version feeds CVE correlation and "+
						"none of these state a firmware without credentials")
			})
		}
	}
}

// The header names the family and not the model, and on a port that answers
// with no title it is the only thing to go on.
func TestIBMStorage_TheHeaderAloneNamesTheFamily(t *testing.T) {
	result := requireResolved(t, ibmSVCRedirectBanner, "http", 8080)

	require.Equal(t, "IBM", result.Vendor)
	require.Equal(t, "SAN Volume Controller", result.Product)
}

// Both rules match an array that serves a title, and the specific one has to
// win — otherwise adding the family rule would cost the model.
func TestIBMStorage_TheModelOutranksTheFamily(t *testing.T) {
	result := requireResolved(t, ibmStorwizeV3700Banner, "http", 443)

	require.Equal(t, "Storwize V3700", result.Product,
		"the title names the model, so the header rule must not win")
}

// Each rule names one model. A pattern loose enough to match a sibling would
// report the wrong hardware, which is worse than reporting the family.
func TestIBMStorage_ModelsDoNotMatchEachOther(t *testing.T) {
	for _, tc := range []struct{ name, banner, mustNotBe string }{
		{"V3700 is not V5000", ibmStorwizeV3700Banner, "Storwize V5000"},
		{"V5000 is not V3700", ibmStorwizeV5000Banner, "Storwize V3700"},
		{"5000 is not 5300", ibmFlashSystem5000Banner, "FlashSystem 5300"},
		{"5300 is not 5000", ibmFlashSystem5300Banner, "FlashSystem 5000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := requireResolved(t, tc.banner, "http", 443)
			require.NotEqual(t, tc.mustNotBe, result.Product)
		})
	}
}

// The rules anchor on a title element, and a title carrying attributes is
// common enough that a literal <title> would miss it.
func TestIBMStorage_MatchesATitleWithAttributes(t *testing.T) {
	banner := "HTTP/1.1 200 OK\r\nServer: SVC GUI\r\n\r\n" +
		`<html><head><title lang="en" dir="ltr">LS_V3700 - Log in - IBM Storwize V3700</title></head>`

	require.Equal(t, "Storwize V3700", requireResolved(t, banner, "http", 443).Product)
}

// Nothing here may claim a host that merely mentions the words.
func TestIBMStorage_DoesNotClaimUnrelatedBanners(t *testing.T) {
	for _, banner := range []string{
		"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n<title>IBM Support Portal</title>",
		"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\n\r\n<title>Storage Overview</title>",
		"SSH-2.0-OpenSSH_7.4\r\n",
	} {
		result, err := NewRuleBasedResolver(loadBuiltinRules()).
			Resolve(context.Background(), Input{Protocol: "", Banner: banner, Port: 443})
		if err == nil {
			require.NotEqual(t, "IBM", result.Vendor, "banner %q", banner)
		}
	}
}

func requireResolved(t *testing.T, banner, protocol string, port int) Result {
	t.Helper()
	result, err := NewRuleBasedResolver(loadBuiltinRules()).
		Resolve(context.Background(), Input{Protocol: protocol, Banner: banner, Port: port})
	require.NoError(t, err, "expected a match for hint %q on port %d", protocol, port)
	return result
}

// ibmRule returns a shipped rule by id.
func ibmRule(t *testing.T, id string) StaticRule {
	t.Helper()
	for _, rule := range loadBuiltinRules() {
		if rule.ID == id {
			return rule
		}
	}
	t.Fatalf("rule %q is not in the shipped database", id)
	return StaticRule{}
}

// Each model pattern must match its own banner and no sibling's. Asserting this
// on the compiled patterns rather than through the resolver is deliberate: when
// two rules match, the winner is decided by confidence and then by the order
// they appear in the file, so a resolver-level assertion can pass because a
// rule happens to be listed first rather than because it is the only one that
// matches.
func TestIBMStorage_EachModelPatternMatchesOnlyItsOwnBanner(t *testing.T) {
	banners := map[string]string{
		"http.ibm_storwize_v3700":   ibmStorwizeV3700Banner,
		"http.ibm_storwize_v5000":   ibmStorwizeV5000Banner,
		"http.ibm_flashsystem_5000": ibmFlashSystem5000Banner,
		"http.ibm_flashsystem_5300": ibmFlashSystem5300Banner,
	}

	for id, own := range banners {
		t.Run(id, func(t *testing.T) {
			pattern := regexp.MustCompile(ibmRule(t, id).Match)

			require.True(t, pattern.MatchString(strings.ToLower(own)),
				"%s does not match the banner it was written from", id)
			for otherID, other := range banners {
				if otherID == id {
					continue
				}
				require.False(t, pattern.MatchString(strings.ToLower(other)),
					"%s also matches the banner of %s", id, otherID)
			}
		})
	}
}

// The family rule has to stay below the model rules by enough that the port
// bonus cannot close the gap. Confidence saturates at 1.0, so two strengths
// near the top become a tie the file order silently resolves -- which would
// make the precedence an accident of listing rather than a decision.
func TestIBMStorage_TheFamilyRuleStaysBelowTheModelRules(t *testing.T) {
	family := ibmRule(t, "http.ibm_svc")

	for _, id := range []string{
		"http.ibm_storwize_v3700",
		"http.ibm_storwize_v5000",
		"http.ibm_flashsystem_5000",
		"http.ibm_flashsystem_5300",
	} {
		model := ibmRule(t, id)
		require.Less(t, family.PatternStrength+0.05, model.PatternStrength,
			"%s must outrank the family rule even with a port bonus applied", id)
	}
}
