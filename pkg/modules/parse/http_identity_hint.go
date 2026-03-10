package parse

import (
	"html"
	"net"
	"regexp"
	"sort"
	"strings"

	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
)

const (
	httpIdentitySkipProxyOnly            = "proxy_only"
	httpIdentitySkipNoSignature          = "no_signature"
	httpIdentitySkipStrongerSource       = "stronger_source_exists"
	bannerResponseClassOrigin            = "origin"
	bannerResponseClassProxy             = "proxy"
	bannerResponseClassProxyOnly         = "proxy_only"
	httpIdentitySignalGitHubHost         = "host:github"
	httpIdentitySignalGitHubTitle        = "title:github"
	httpIdentitySignalGitHubBody         = "body:github"
	httpIdentitySignalGitHubCookie       = "cookie:_octo"
	httpIdentitySignalSmarterMailTitle   = "title:smartermail"
	httpIdentitySignalSmarterMailBody    = "body:smartermail"
	httpIdentitySignalSmarterMailRoute   = "location:/interface/root"
	httpIdentitySignalWordPressBody      = "body:wordpress"
	httpIdentitySignalWordPressContent   = "body:wp-content"
	httpIdentitySignalWordPressTitle     = "title:wordpress"
	httpIdentitySignalDrupalBody         = "body:drupal"
	httpIdentitySignalDrupalSitesAll     = "body:sites/all"
	httpIdentitySignalDrupalSitesDefault = "body:sites/default"
	httpIdentitySignalJoomlaBody         = "body:joomla"
	httpIdentitySignalJoomlaContent      = "body:com_content"
	httpIdentityConfidenceGitHub         = 0.90
	httpIdentityConfidenceSmarterMail    = 0.75
	httpIdentityConfidenceCMS            = 0.80
	httpIdentityConfidenceXPoweredBy     = 0.70
	httpIdentityConfidenceServerHeader   = 0.65
)

var (
	httpIdentityTitleRegex      = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	httpIdentityWhitespaceRegex = regexp.MustCompile(`\s+`)
	httpGenericServerBlacklist  = map[string]struct{}{
		"":                      {},
		"apache":                {},
		"apache httpd":          {},
		"apache traffic server": {},
		"awselb":                {},
		"caddy":                 {},
		"cloudflare":            {},
		"envoy":                 {},
		"haproxy":               {},
		"istio-envoy":           {},
		"nginx":                 {},
		"openresty":             {},
		"squid":                 {},
		"traefik":               {},
		"varnish":               {},
	}
)

type httpIdentitySignal struct {
	Token      string
	Confidence float64
}

type httpIdentityResponse struct {
	StatusLine string
	Headers    map[string]string
	Body       string
	Title      string
}

type httpIdentitySource struct {
	ProbeID  string
	Response string
}

func detectHTTPIdentitySignals(banner scanpkg.BannerGrabResult) ([]httpIdentitySignal, string) {
	host := httpIdentityHost(banner)
	sources, sawProxy := collectHTTPIdentitySources(banner)
	if len(sources) == 0 {
		if sawProxy {
			return nil, httpIdentitySkipProxyOnly
		}
		return nil, httpIdentitySkipNoSignature
	}

	signalSet := make(map[string]httpIdentitySignal)
	for _, source := range sources {
		parsed, ok := parseHTTPIdentityResponse(source.Response)
		if !ok {
			continue
		}
		signals := inferHTTPIdentitySignals(parsed, host)
		for _, signal := range signals {
			if existing, ok := signalSet[signal.Token]; !ok || signal.Confidence > existing.Confidence {
				signalSet[signal.Token] = signal
			}
		}
	}

	if len(signalSet) == 0 {
		return nil, httpIdentitySkipNoSignature
	}

	signals := make([]httpIdentitySignal, 0, len(signalSet))
	for _, signal := range signalSet {
		signals = append(signals, signal)
	}
	sort.SliceStable(signals, func(i, j int) bool {
		if signals[i].Confidence == signals[j].Confidence {
			return signals[i].Token < signals[j].Token
		}
		return signals[i].Confidence > signals[j].Confidence
	})
	return signals, ""
}

func shouldEvaluateHTTPIdentity(entry *ServiceIdentityInfo, banner scanpkg.BannerGrabResult) bool {
	if entry == nil {
		return false
	}
	serviceName := strings.ToLower(strings.TrimSpace(entry.ServiceName))
	if serviceName == "http" || serviceName == "https" {
		return true
	}
	return isHTTPIdentityPort(banner.Port)
}

func isHTTPIdentityPort(port int) bool {
	switch port {
	case 80, 443, 8443, 9443:
		return true
	default:
		return false
	}
}

func collectHTTPIdentitySources(banner scanpkg.BannerGrabResult) ([]httpIdentitySource, bool) {
	sources := make([]httpIdentitySource, 0, len(banner.Evidence)+1)
	seen := map[string]struct{}{}
	sawProxy := false

	add := func(probeID, response string, responseClass string, proxy bool) {
		trimmed := strings.TrimSpace(response)
		if trimmed == "" {
			return
		}
		if proxy || responseClass == bannerResponseClassProxy || responseClass == bannerResponseClassProxyOnly {
			sawProxy = true
			return
		}
		if _, ok := seen[trimmed]; ok {
			return
		}
		if _, ok := parseHTTPIdentityResponse(trimmed); !ok {
			return
		}
		seen[trimmed] = struct{}{}
		sources = append(sources, httpIdentitySource{
			ProbeID:  probeID,
			Response: trimmed,
		})
	}

	add("selected-banner", banner.Banner, banner.ResponseClass, banner.ProxyResponse)
	for _, evidence := range banner.Evidence {
		add(evidence.ProbeID, evidence.Response, evidence.ResponseClass, evidence.ProxyResponse)
	}

	sort.SliceStable(sources, func(i, j int) bool {
		return httpIdentitySourceScore(sources[i].ProbeID) > httpIdentitySourceScore(sources[j].ProbeID)
	})
	return sources, sawProxy
}

func httpIdentitySourceScore(probeID string) int {
	switch {
	case strings.HasPrefix(probeID, "https"):
		return 3
	case strings.HasPrefix(probeID, "http"):
		return 2
	case probeID == "selected-banner":
		return 1
	default:
		return 0
	}
}

func parseHTTPIdentityResponse(raw string) (httpIdentityResponse, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return httpIdentityResponse{}, false
	}

	headerBlock := trimmed
	body := ""
	switch {
	case strings.Contains(trimmed, "\r\n\r\n"):
		parts := strings.SplitN(trimmed, "\r\n\r\n", 2)
		headerBlock, body = parts[0], parts[1]
	case strings.Contains(trimmed, "\n\n"):
		parts := strings.SplitN(trimmed, "\n\n", 2)
		headerBlock, body = parts[0], parts[1]
	}

	lines := strings.Split(headerBlock, "\n")
	if len(lines) == 0 {
		return httpIdentityResponse{}, false
	}

	statusLine := strings.TrimSpace(lines[0])
	if !strings.HasPrefix(strings.ToUpper(statusLine), "HTTP/") {
		return httpIdentityResponse{}, false
	}

	headers := make(map[string]string, len(lines))
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])
		if key == "" || value == "" {
			continue
		}
		if existing, ok := headers[key]; ok {
			headers[key] = existing + "\n" + value
		} else {
			headers[key] = value
		}
	}

	return httpIdentityResponse{
		StatusLine: statusLine,
		Headers:    headers,
		Body:       body,
		Title:      extractHTTPIdentityTitle(body),
	}, true
}

func inferHTTPIdentitySignals(response httpIdentityResponse, host string) []httpIdentitySignal {
	bodyLower := strings.ToLower(response.Body)
	titleLower := strings.ToLower(response.Title)
	hostLower := strings.ToLower(strings.TrimSpace(host))
	server := response.Headers["server"]
	xPoweredBy := response.Headers["x-powered-by"]
	location := strings.ToLower(strings.TrimSpace(response.Headers["location"]))
	setCookie := strings.ToLower(response.Headers["set-cookie"])

	signals := make([]httpIdentitySignal, 0, 12)
	add := func(token string, confidence float64) {
		token = strings.TrimSpace(token)
		if token == "" {
			return
		}
		signals = append(signals, httpIdentitySignal{
			Token:      token,
			Confidence: confidence,
		})
	}

	if strings.Contains(hostLower, "github") {
		add(httpIdentitySignalGitHubHost, httpIdentityConfidenceGitHub)
	}
	if strings.Contains(titleLower, "github") {
		add(httpIdentitySignalGitHubTitle, httpIdentityConfidenceGitHub)
	}
	if strings.Contains(bodyLower, "github") {
		add(httpIdentitySignalGitHubBody, httpIdentityConfidenceGitHub)
	}
	if strings.Contains(setCookie, "_octo") {
		add(httpIdentitySignalGitHubCookie, httpIdentityConfidenceGitHub)
	}

	if strings.HasPrefix(location, "/interface/root") {
		add(httpIdentitySignalSmarterMailRoute, httpIdentityConfidenceSmarterMail)
	}
	if strings.Contains(titleLower, "smartermail") {
		add(httpIdentitySignalSmarterMailTitle, httpIdentityConfidenceSmarterMail)
	}
	if strings.Contains(bodyLower, "smartermail") {
		add(httpIdentitySignalSmarterMailBody, httpIdentityConfidenceSmarterMail)
	}

	if strings.Contains(bodyLower, "wp-content") {
		add(httpIdentitySignalWordPressContent, httpIdentityConfidenceCMS)
	}
	if strings.Contains(bodyLower, "wordpress") {
		add(httpIdentitySignalWordPressBody, httpIdentityConfidenceCMS)
	}
	if strings.Contains(titleLower, "wordpress") {
		add(httpIdentitySignalWordPressTitle, httpIdentityConfidenceCMS)
	}

	if strings.Contains(bodyLower, "drupal") {
		add(httpIdentitySignalDrupalBody, httpIdentityConfidenceCMS)
	}
	if strings.Contains(bodyLower, "sites/default") {
		add(httpIdentitySignalDrupalSitesDefault, httpIdentityConfidenceCMS)
	}
	if strings.Contains(bodyLower, "sites/all") {
		add(httpIdentitySignalDrupalSitesAll, httpIdentityConfidenceCMS)
	}

	if strings.Contains(bodyLower, "joomla") {
		add(httpIdentitySignalJoomlaBody, httpIdentityConfidenceCMS)
	}
	if strings.Contains(bodyLower, "com_content") {
		add(httpIdentitySignalJoomlaContent, httpIdentityConfidenceCMS)
	}

	if token := normalizeHTTPIdentityHeaderToken(xPoweredBy); token != "" {
		add("x-powered-by:"+token, httpIdentityConfidenceXPoweredBy)
	}
	if token := normalizeHTTPIdentityHeaderToken(server); token != "" && !isGenericHTTPServerProduct(token) {
		add("server:"+token, httpIdentityConfidenceServerHeader)
	}

	return signals
}

func normalizeHTTPIdentityHeaderToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, sep := range []string{"\n", ",", ";"} {
		if idx := strings.Index(value, sep); idx >= 0 {
			value = value[:idx]
		}
	}
	value = strings.TrimSpace(value)
	if idx := strings.Index(value, "/"); idx > 0 {
		value = value[:idx]
	}
	if idx := strings.Index(value, "("); idx > 0 {
		value = value[:idx]
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func isGenericHTTPServerProduct(product string) bool {
	normalized := strings.ToLower(strings.TrimSpace(product))
	_, ok := httpGenericServerBlacklist[normalized]
	return ok
}

func extractHTTPIdentityTitle(body string) string {
	if body == "" {
		return ""
	}
	matches := httpIdentityTitleRegex.FindStringSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	title := html.UnescapeString(matches[1])
	title = httpIdentityWhitespaceRegex.ReplaceAllString(title, " ")
	return strings.TrimSpace(title)
}

func httpIdentityHost(banner scanpkg.BannerGrabResult) string {
	for _, candidate := range []string{banner.SNIServerName, banner.ProbeHost} {
		trimmed := strings.TrimSpace(candidate)
		if trimmed == "" || net.ParseIP(trimmed) != nil {
			continue
		}
		return trimmed
	}
	return ""
}
