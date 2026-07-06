package parse

import (
	"html"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	scanpkg "github.com/cyprob/cyprob/pkg/modules/scan"
)

const (
	httpIdentitySkipProxyOnly               = "proxy_only"
	httpIdentitySkipNoSignature             = "no_signature"
	httpIdentitySkipStrongerSource          = "stronger_source_exists"
	bannerResponseClassOrigin               = "origin"
	bannerResponseClassProxy                = "proxy"
	bannerResponseClassProxyOnly            = "proxy_only"
	httpIdentitySignalGitHubHost            = "host:github"
	httpIdentitySignalGitHubTitle           = "title:github"
	httpIdentitySignalGitHubBody            = "body:github"
	httpIdentitySignalGitHubCookie          = "cookie:_octo"
	httpIdentitySignalSmarterMailTitle      = "title:smartermail"
	httpIdentitySignalSmarterMailBody       = "body:smartermail"
	httpIdentitySignalSmarterMailRoute      = "location:/interface/root"
	httpIdentitySignalWordPressBody         = "body:wordpress"
	httpIdentitySignalWordPressContent      = "body:wp-content"
	httpIdentitySignalWordPressTitle        = "title:wordpress"
	httpIdentitySignalDrupalBody            = "body:drupal"
	httpIdentitySignalDrupalSitesAll        = "body:sites/all"
	httpIdentitySignalDrupalSitesDefault    = "body:sites/default"
	httpIdentitySignalJoomlaBody            = "body:joomla"
	httpIdentitySignalJoomlaContent         = "body:com_content"
	httpIdentitySignalCPanelMagic           = "body:cpanel_magic_revision"
	httpIdentitySignalCPanelLoginForm       = "body:cpanel_login_form"
	httpIdentitySignalTomcatBody            = "body:apache_tomcat"
	httpIdentitySignalCPanelCookie          = "cookie:cpanel"
	httpIdentitySignalCPanelTitle           = "title:cpanel"
	httpIdentitySignalCPanelPortRedirect    = "location:cpanel_port"
	httpIdentitySignalWHMCookie             = "cookie:whostmgr"
	httpIdentitySignalWHMTitle              = "title:whm_login"
	httpIdentitySignalWHMPortRedirect       = "location:whm_port"
	httpIdentitySignalCPanelWebmailCookie   = "cookie:cpanel_webmail"
	httpIdentitySignalCPanelWebmailTitle    = "title:cpanel_webmail_login"
	httpIdentitySignalCPanelWebmailRedirect = "location:cpanel_webmail_port"
	httpIdentityConfidenceGitHub            = 0.90
	httpIdentityConfidenceSmarterMail       = 0.75
	httpIdentityConfidenceCMS               = 0.80
	httpIdentityConfidenceCPanel            = 0.88
	httpIdentityConfidenceXPoweredBy        = 0.70
	httpIdentityConfidenceServerHeader      = 0.65
	httpIdentityConfidenceTomcat            = 0.82
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
	// Value optionally carries an extracted payload for the signal, e.g. a
	// version string pulled from the response body/title. Empty for pure
	// presence signals.
	Value string
}

// tomcatBodyVersionPattern extracts the Tomcat version from the default
// error-page/footer marker "Apache Tomcat/9.0.30" (Tomcat sends no Server
// header, so the version only appears in the body/title).
var tomcatBodyVersionPattern = regexp.MustCompile(`(?i)apache tomcat/([0-9][0-9a-z._-]*)`)

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
		signals := inferHTTPIdentitySignals(parsed, host, banner.Port)
		for _, signal := range signals {
			existing, ok := signalSet[signal.Token]
			switch {
			case !ok || signal.Confidence > existing.Confidence:
				signalSet[signal.Token] = signal
			case signal.Confidence == existing.Confidence && existing.Value == "" && signal.Value != "":
				// Same confidence but this occurrence carries an extracted
				// value (e.g. a version) the earlier one lacked.
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
	case 80, 443, 2082, 2083, 2086, 2087, 2095, 2096, 8000, 8080, 8081, 8443, 9443:
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

func inferHTTPIdentitySignals(response httpIdentityResponse, host string, port int) []httpIdentitySignal {
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
	addValue := func(token string, confidence float64, value string) {
		token = strings.TrimSpace(token)
		if token == "" {
			return
		}
		signals = append(signals, httpIdentitySignal{
			Token:      token,
			Confidence: confidence,
			Value:      strings.TrimSpace(value),
		})
	}

	// Apache Tomcat exposes no Server header by default; its version leaks in
	// the default error-page footer ("Apache Tomcat/9.0.30"). Detect the
	// marker in body or title and carry the extracted version on the signal.
	if strings.Contains(bodyLower, "apache tomcat") || strings.Contains(titleLower, "apache tomcat") {
		version := ""
		if m := tomcatBodyVersionPattern.FindStringSubmatch(response.Body); len(m) > 1 {
			version = m[1]
		} else if m := tomcatBodyVersionPattern.FindStringSubmatch(response.Title); len(m) > 1 {
			version = m[1]
		}
		addValue(httpIdentitySignalTomcatBody, httpIdentityConfidenceTomcat, version)
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

	if strings.Contains(bodyLower, "cpanel_magic_revision") {
		add(httpIdentitySignalCPanelMagic, httpIdentityConfidenceCPanel)
	}
	if strings.Contains(bodyLower, `id="login_form"`) && strings.Contains(bodyLower, `action="/login/"`) {
		add(httpIdentitySignalCPanelLoginForm, httpIdentityConfidenceCPanel)
	}
	if strings.Contains(setCookie, "cprelogin=") || strings.Contains(setCookie, "cpsession=") {
		add(httpIdentitySignalCPanelCookie, httpIdentityConfidenceCPanel)
	}
	if strings.Contains(titleLower, "cpanel") {
		add(httpIdentitySignalCPanelTitle, httpIdentityConfidenceCPanel)
	}
	if strings.Contains(setCookie, "whostmgrrelogin=") || strings.Contains(setCookie, "whostmgrsession=") {
		add(httpIdentitySignalWHMCookie, httpIdentityConfidenceCPanel)
	}
	if strings.Contains(titleLower, "whm login") || strings.Contains(bodyLower, "whm login") {
		add(httpIdentitySignalWHMTitle, httpIdentityConfidenceCPanel)
	}
	if strings.Contains(setCookie, "webmailrelogin=") || strings.Contains(setCookie, "webmailsession=") {
		add(httpIdentitySignalCPanelWebmailCookie, httpIdentityConfidenceCPanel)
	}
	if strings.Contains(titleLower, "webmail login") || strings.Contains(bodyLower, "webmail login") {
		add(httpIdentitySignalCPanelWebmailTitle, httpIdentityConfidenceCPanel)
	}
	if signal := cpanelPortRedirectSignal(port, location); signal != "" && !isControlWebPanelResponse(response, bodyLower) {
		add(signal, httpIdentityConfidenceCPanel)
	}

	if token := normalizeHTTPIdentityHeaderToken(xPoweredBy); token != "" {
		add("x-powered-by:"+token, httpIdentityConfidenceXPoweredBy)
	}
	if token := normalizeHTTPIdentityHeaderToken(server); token != "" && !isGenericHTTPServerProduct(token) {
		add("server:"+token, httpIdentityConfidenceServerHeader)
	}

	return signals
}

func isControlWebPanelResponse(response httpIdentityResponse, bodyLower string) bool {
	server := strings.ToLower(strings.TrimSpace(response.Headers["server"]))
	return strings.Contains(server, "cwpsrv") ||
		strings.Contains(bodyLower, "cwp_theme") ||
		strings.Contains(bodyLower, "control webpanel")
}

func cpanelPortRedirectSignal(port int, location string) string {
	location = strings.ToLower(strings.TrimSpace(location))
	if location == "" {
		return ""
	}
	redirectPort := httpIdentityRedirectPort(location)
	switch port {
	case 2082, 2083:
		if redirectPort == "2083" {
			return httpIdentitySignalCPanelPortRedirect
		}
	case 2086, 2087:
		if redirectPort == "2087" {
			return httpIdentitySignalWHMPortRedirect
		}
	case 2095, 2096:
		if redirectPort == "2096" {
			return httpIdentitySignalCPanelWebmailRedirect
		}
	}
	return ""
}

func httpIdentityRedirectPort(location string) string {
	parsed, err := url.Parse(location)
	if err == nil {
		if port := parsed.Port(); port != "" {
			return port
		}
	}
	for _, port := range []string{"2083", "2087", "2096"} {
		if strings.Contains(location, ":"+port+"/") || strings.HasSuffix(location, ":"+port) {
			return port
		}
	}
	return ""
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
