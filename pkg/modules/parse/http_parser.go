// pkg/modules/parse/http_parser.go
// Package parse provides modules for parsing raw data into structured information.
package parse

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/textproto" // For parsing MIME headers efficiently
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/vulntor/vulntor/pkg/engine"
	"github.com/vulntor/vulntor/pkg/modules/scan" // To consume scan.BannerGrabResult
	"github.com/vulntor/vulntor/pkg/output"
)

const (
	httpParserModuleTypeName = "http-parser"
	maxHeaderBytesForTitle   = 4096 // Max bytes of body to scan for title if headers don't give content-length
)

// HTTPParsedInfo holds structured information extracted from an HTTP banner/response.
type HTTPParsedInfo struct {
	Target        string            `json:"target"`
	Port          int               `json:"port"`
	Scheme        string            `json:"scheme"` // "http" or "https" (inferred or from input)
	HTTPVersion   string            `json:"http_version,omitempty"`
	StatusCode    int               `json:"status_code,omitempty"`
	StatusMessage string            `json:"status_message,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"` // Stores first value for each header
	// More specific fields can be extracted from headers if needed:
	ServerProduct   string               `json:"server_product,omitempty"`
	ServerVersion   string               `json:"server_version,omitempty"`
	ContentType     string               `json:"content_type,omitempty"`
	ContentLength   int64                `json:"content_length,omitempty"`
	HTMLTitle       string               `json:"html_title,omitempty"`
	SecurityHeaders *SecurityHeadersInfo `json:"security_headers,omitempty"` // Security header analysis
	RawBanner       string               `json:"-"`                          // Store raw banner for reference, not for marshaling
	ParseError      string               `json:"parse_error,omitempty"`
}

// SecurityHeadersInfo holds security-related HTTP header analysis.
type SecurityHeadersInfo struct {
	HSTS                *HSTSInfo `json:"hsts,omitempty"`
	CSP                 *CSPInfo  `json:"csp,omitempty"`
	XFrameOptions       string    `json:"x_frame_options,omitempty"`
	XContentTypeOptions string    `json:"x_content_type_options,omitempty"`
	XXSSProtection      string    `json:"x_xss_protection,omitempty"`
	ReferrerPolicy      string    `json:"referrer_policy,omitempty"`
	PermissionsPolicy   string    `json:"permissions_policy,omitempty"`

	MissingHeaders  []string `json:"missing_headers"`
	SecurityScore   int      `json:"security_score"` // 0-100
	Recommendations []string `json:"recommendations"`
}

// HSTSInfo holds parsed Strict-Transport-Security header information.
type HSTSInfo struct {
	Present           bool `json:"present"`
	MaxAge            int  `json:"max_age"`
	IncludeSubDomains bool `json:"include_subdomains"`
	Preload           bool `json:"preload"`
}

// CSPInfo holds parsed Content-Security-Policy header information.
type CSPInfo struct {
	Present      bool              `json:"present"`
	Directives   map[string]string `json:"directives"`
	UnsafeInline bool              `json:"unsafe_inline"` // Security risk
	UnsafeEval   bool              `json:"unsafe_eval"`   // Security risk
}

// HTTPParserConfig holds configuration for this module (currently none).
type HTTPParserConfig struct {
	// Future options: e.g., max_header_lines, max_body_for_title_scan
}

// HTTPParserModule implements the engine.Module interface.
type HTTPParserModule struct {
	meta   engine.ModuleMetadata
	config HTTPParserConfig
}

// newHTTPParserModule is the internal constructor.
func newHTTPParserModule() *HTTPParserModule {
	defaultConfig := HTTPParserConfig{}
	return &HTTPParserModule{
		meta: engine.ModuleMetadata{
			ID:          httpParserModuleTypeName + "-default", // Default instance ID, can be overridden in Init
			Name:        httpParserModuleTypeName,
			Version:     "0.1.0",
			Description: "Parses raw HTTP response banners into structured data (status, headers, etc.).",
			Type:        engine.ParseModuleType,
			Author:      "Vulntor Team",
			Tags:        []string{"parser", "http", "banner"},
			Consumes: []engine.DataContractEntry{
				{
					Key: "service.banner.tcp", // Expects output from service-banner-scanner
					// DataTypeName is the type of *each item* within the []interface{} list
					// that DataContext stores for "instance_id_of_banner_scanner.service.banner.tcp".
					DataTypeName: "scan.BannerGrabResult",
					// CardinalityList means this module expects the value for "service.banner.tcp"
					// in its 'inputs' map to be an []interface{} list, where each element
					// can be cast to scan.BannerGrabResult.
					Cardinality: engine.CardinalityList,
					IsOptional:  false, // Requires banner input to do any work
					Description: "List of raw TCP banners, where each item is a scan.BannerGrabResult.",
				},
			},
			Produces: []engine.DataContractEntry{
				{
					Key: "service.http.details",
					// This module will send multiple ModuleOutput messages if it parses multiple HTTP banners.
					// Each ModuleOutput.Data will be a single parse.HTTPParsedInfo struct.
					// DataContext will aggregate these into a list: []interface{}{HTTPParsedInfo1, HTTPParsedInfo2, ...}
					DataTypeName: "parse.HTTPParsedInfo", // The type of the Data field in each ModuleOutput
					Cardinality:  engine.CardinalityList, // Indicates DataContext will store a list for this DataKey.
					Description:  "List of parsed HTTP details, one result per successfully parsed HTTP banner.",
				},
			},
			ConfigSchema: map[string]engine.ParameterDefinition{
				// No specific config parameters for now
			},
			EstimatedCost: 1, // Typically fast, CPU-bound for parsing.
		},
		config: defaultConfig,
	}
}

// Metadata returns the module's metadata.
func (m *HTTPParserModule) Metadata() engine.ModuleMetadata {
	return m.meta
}

// Init initializes the module with its instance ID and configuration.
func (m *HTTPParserModule) Init(instanceID string, configMap map[string]interface{}) error {
	m.meta.ID = instanceID
	// cfg := m.config // Start with defaults
	logger := log.With().Str("module", m.meta.Name).Str("instance_id", m.meta.ID).Logger()
	logger.Debug().Interface("received_config_map", configMap).Msg("Initializing module (no specific config)")
	// No config parameters to parse for now
	// m.config = cfg
	logger.Debug().Msg("Module initialized")
	return nil
}

// titleRegex is a simple regex to find HTML title tags.
var titleRegex = regexp.MustCompile(`(?i)<title.*?>(.*?)</title>`)

// serverRegex attempts to parse common Server header formats.
var serverRegex = regexp.MustCompile(`^([a-zA-Z0-9._-]+)(?:/([0-9a-zA-Z._-]+))?(?:\s*\(([^)]*)\))?`)

// Execute parses HTTP banners.
//
//nolint:gocyclo // Complexity is inherent to HTTP response parsing logic
func (m *HTTPParserModule) Execute(ctx context.Context, inputs map[string]interface{}, outputChan chan<- engine.ModuleOutput) error {
	logger := log.With().Str("module", m.meta.Name).Str("instance_id", m.meta.ID).Logger()
	logger.Debug().Interface("received_inputs", inputs).Msg("Executing module")

	// Extract Output interface for real-time HTTP service detection
	out, _ := ctx.Value(output.OutputKey).(output.Output)

	rawBannerInput, ok := inputs["service.banner.tcp"]
	if !ok {
		logger.Info().Msg("'service.banner.tcp' not found in inputs. Nothing to parse.")
		return nil // Not an error, just no relevant input
	}

	bannerList, listOk := rawBannerInput.([]interface{})
	if !listOk {
		if typed, ok := rawBannerInput.([]scan.BannerGrabResult); ok {
			for _, item := range typed {
				bannerList = append(bannerList, item)
			}
		} else {
			logger.Error().Type("input_type", rawBannerInput).Msg("'service.banner.tcp' input is not a list as expected.")
			return fmt.Errorf("input 'service.banner.tcp' is not a list, type: %T", rawBannerInput)
		}
	}

	logger.Info().Int("banner_count", len(bannerList)).Msg("Processing HTTP banners")

	for i, item := range bannerList {
		select {
		case <-ctx.Done():
			logger.Info().Msg("Context canceled. Aborting further HTTP parsing.")
			return ctx.Err()
		default:
		}

		bannerResult, castOk := item.(scan.BannerGrabResult)
		if !castOk {
			logger.Warn().Int("item_index", i).Type("item_type", item).Msg("Item in 'service.banner.tcp' list is not of expected type scan.BannerGrabResult")
			continue
		}

		if bannerResult.Error != "" || bannerResult.Banner == "" {
			// logger.Debug().Str("target", bannerResult.Target).Int("port", bannerResult.Port).Str("banner_error", bannerResult.Error).Msg("Skipping banner with error or empty content")
			continue // Skip banners that had errors during grabbing or are empty
		}

		// Only parse if it looks like an HTTP response and not TLS handshake data
		if !strings.HasPrefix(bannerResult.Banner, "HTTP/") {
			// logger.Debug().Str("target", bannerResult.Target).Int("port", bannerResult.Port).Msg("Banner does not start with HTTP/, skipping HTTP parse.")
			continue
		}
		// Further check for TLS handshake remnants if banner grabber might mix them
		if bannerResult.IsTLS && (bannerResult.Port == 443 || bannerResult.Port == 8443) { // IsTLS field was in scan.BannerGrabResult
			// logger.Debug().Str("target", bannerResult.Target).Int("port", bannerResult.Port).Msg("Banner marked as TLS, skipping raw HTTP parse for typical HTTPS ports.")
			// A dedicated TLS/HTTPS parser would handle this.
			continue
		}

		parsedInfo := HTTPParsedInfo{
			Target:    bannerResult.IP,
			Port:      bannerResult.Port,
			Scheme:    determineScheme(bannerResult.Port, bannerResult.IsTLS), // Infer scheme
			RawBanner: bannerResult.Banner,                                    // Store for reference if needed
			Headers:   make(map[string]string),
		}

		reader := bufio.NewReader(strings.NewReader(bannerResult.Banner))
		tp := textproto.NewReader(reader)

		// 1. Parse Status Line
		statusLine, err := tp.ReadLine()
		if err != nil {
			parsedInfo.ParseError = fmt.Sprintf("Failed to read status line: %v", err)
			logger.Warn().Str("target", bannerResult.IP).Int("port", bannerResult.Port).Err(err).Msg("HTTP status line parsing error")
			outputChan <- engine.ModuleOutput{FromModuleName: m.meta.ID, DataKey: m.meta.Produces[0].Key, Data: parsedInfo, Timestamp: time.Now(), Target: bannerResult.IP}
			continue
		}

		parts := strings.SplitN(statusLine, " ", 3)
		if len(parts) < 2 { // HTTP version and status code are mandatory
			parsedInfo.ParseError = fmt.Sprintf("Invalid status line format: %s", statusLine)
			logger.Warn().Str("target", bannerResult.IP).Int("port", bannerResult.Port).Str("status_line", statusLine).Msg("Invalid HTTP status line")
			outputChan <- engine.ModuleOutput{FromModuleName: m.meta.ID, DataKey: m.meta.Produces[0].Key, Data: parsedInfo, Timestamp: time.Now(), Target: bannerResult.IP}
			continue
		}
		parsedInfo.HTTPVersion = strings.TrimSpace(parts[0])
		statusCode, err := strconv.Atoi(parts[1])
		if err != nil {
			parsedInfo.ParseError = fmt.Sprintf("Invalid status code '%s': %v", parts[1], err)
			logger.Warn().Str("target", bannerResult.IP).Int("port", bannerResult.Port).Str("status_code_str", parts[1]).Err(err).Msg("Invalid HTTP status code")
			// Continue to parse headers if possible
		} else {
			parsedInfo.StatusCode = statusCode
		}
		if len(parts) > 2 {
			parsedInfo.StatusMessage = strings.TrimSpace(parts[2])
		}

		// 2. Parse Headers
		mimeHeader, err := tp.ReadMIMEHeader()
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF { // EOF is fine if no body
			parsedInfo.ParseError = fmt.Sprintf("Failed to read MIME headers: %v. %s", err, parsedInfo.ParseError)
			logger.Warn().Str("target", bannerResult.IP).Int("port", bannerResult.Port).Err(err).Msg("HTTP MIME header parsing error")
			// Headers might be partially parsed, so continue
		}
		for k, v := range mimeHeader {
			if len(v) > 0 {
				parsedInfo.Headers[http.CanonicalHeaderKey(k)] = v[0] // Store first value, canonical key
			}
		}

		// Extract specific common headers
		if serverStr, ok := parsedInfo.Headers["Server"]; ok {
			matches := serverRegex.FindStringSubmatch(serverStr)
			if len(matches) > 1 {
				parsedInfo.ServerProduct = matches[1]
				if len(matches) > 2 && matches[2] != "" {
					parsedInfo.ServerVersion = matches[2]
				}
			} else {
				parsedInfo.ServerProduct = serverStr // Use raw if regex fails
			}
		}
		if ctStr, ok := parsedInfo.Headers["Content-Type"]; ok {
			parsedInfo.ContentType = strings.Split(ctStr, ";")[0] // Get main type, ignore charset etc.
		}
		if clStr, ok := parsedInfo.Headers["Content-Length"]; ok {
			cl, _ := strconv.ParseInt(clStr, 10, 64)
			parsedInfo.ContentLength = cl
		}

		// 3. Parse security headers
		parsedInfo.SecurityHeaders = parseSecurityHeaders(parsedInfo.Headers)

		// 4. Optionally, try to parse HTML title from the beginning of the body
		if strings.HasPrefix(strings.ToLower(parsedInfo.ContentType), "text/html") {
			// The rest of the reader 'tp.R' contains the body.
			// We need to find where headers ended in the original banner.
			headerEndPos := strings.Index(bannerResult.Banner, "\r\n\r\n")
			if headerEndPos > 0 {
				bodySample := bannerResult.Banner[headerEndPos+4:]
				if len(bodySample) > maxHeaderBytesForTitle { // Limit scan range for title
					bodySample = bodySample[:maxHeaderBytesForTitle]
				}
				titleMatches := titleRegex.FindStringSubmatch(bodySample)
				if len(titleMatches) > 1 {
					parsedInfo.HTMLTitle = strings.TrimSpace(titleMatches[1])
				}
			}
		}

		logger.Debug().
			Str("target", bannerResult.IP).
			Int("port", bannerResult.Port).
			Int("status", parsedInfo.StatusCode).
			Str("server", parsedInfo.ServerProduct).
			Int("security_score", parsedInfo.SecurityHeaders.SecurityScore).
			Msg("HTTP banner parsed")

		// Real-time output: Emit HTTP service detection to user
		if out != nil {
			message := fmt.Sprintf("HTTP service detected: %s:%d - %s %d", bannerResult.IP, bannerResult.Port, parsedInfo.ServerProduct, parsedInfo.StatusCode)
			if parsedInfo.ServerVersion != "" {
				message = fmt.Sprintf("HTTP service detected: %s:%d - %s/%s (Status: %d)", bannerResult.IP, bannerResult.Port, parsedInfo.ServerProduct, parsedInfo.ServerVersion, parsedInfo.StatusCode)
			}
			if parsedInfo.HTMLTitle != "" {
				message += fmt.Sprintf(" - %s", parsedInfo.HTMLTitle)
			}
			// Add security score to output
			if parsedInfo.SecurityHeaders != nil {
				message += fmt.Sprintf(" [Security: %d/100]", parsedInfo.SecurityHeaders.SecurityScore)
			}
			out.Diag(output.LevelNormal, message, nil)
		}

		outputChan <- engine.ModuleOutput{FromModuleName: m.meta.ID, DataKey: m.meta.Produces[0].Key, Data: parsedInfo, Timestamp: time.Now(), Target: bannerResult.IP}
	}

	logger.Info().Msg("HTTP parsing completed for all relevant banners.")
	return nil
}

// determineScheme infers if it's http or https based on port and TLS flag.
func determineScheme(port int, isTLS bool) string {
	if isTLS {
		return "https"
	}
	// Common non-TLS HTTP ports
	switch port {
	case 80, 8000, 8080, 8008: // Add more as needed
		return "http"
	case 443, 8443: // If IsTLS was somehow false for these, still mark as https if common
		return "https" // Or default to http and let a TLS module upgrade it
	default:
		return "http" // Assume http for unknown ports if not TLS
	}
}

// HTTPParserModuleFactory creates a new HTTPParserModule instance.
func HTTPParserModuleFactory() engine.Module {
	return newHTTPParserModule()
}

func init() {
	engine.RegisterModuleFactory(httpParserModuleTypeName, HTTPParserModuleFactory)
}

// parseSecurityHeaders analyzes HTTP security headers and provides recommendations.
func parseSecurityHeaders(headers map[string]string) *SecurityHeadersInfo {
	info := &SecurityHeadersInfo{
		MissingHeaders:  []string{},
		Recommendations: []string{},
		SecurityScore:   100, // Start perfect, deduct points for issues
	}

	// Check critical headers (HSTS, CSP)
	checkCriticalSecurityHeaders(headers, info)

	// Check protection headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection)
	checkProtectionHeaders(headers, info)

	// Check policy headers (Referrer-Policy, Permissions-Policy)
	checkPolicyHeaders(headers, info)

	// Ensure score doesn't go negative
	if info.SecurityScore < 0 {
		info.SecurityScore = 0
	}

	return info
}

// checkCriticalSecurityHeaders checks HSTS and CSP headers.
func checkCriticalSecurityHeaders(headers map[string]string, info *SecurityHeadersInfo) {
	// Check HSTS
	if hstsVal, ok := headers["Strict-Transport-Security"]; ok {
		info.HSTS = parseHSTS(hstsVal)
		if info.HSTS.MaxAge < 31536000 {
			info.SecurityScore -= 5
			info.Recommendations = append(info.Recommendations,
				"HSTS max-age should be at least 31536000 (1 year)")
		}
		if !info.HSTS.IncludeSubDomains {
			info.SecurityScore -= 5
			info.Recommendations = append(info.Recommendations,
				"HSTS should include 'includeSubDomains' directive")
		}
	} else {
		info.MissingHeaders = append(info.MissingHeaders, "Strict-Transport-Security")
		info.SecurityScore -= 20
		info.Recommendations = append(info.Recommendations,
			"Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")
	}

	// Check CSP
	if cspVal, ok := headers["Content-Security-Policy"]; ok {
		info.CSP = parseCSP(cspVal)
		if info.CSP.UnsafeInline {
			info.SecurityScore -= 10
			info.Recommendations = append(info.Recommendations,
				"CSP contains 'unsafe-inline', consider using nonces or hashes")
		}
		if info.CSP.UnsafeEval {
			info.SecurityScore -= 10
			info.Recommendations = append(info.Recommendations,
				"CSP contains 'unsafe-eval', remove if possible for better security")
		}
	} else {
		info.MissingHeaders = append(info.MissingHeaders, "Content-Security-Policy")
		info.SecurityScore -= 15
		info.Recommendations = append(info.Recommendations,
			"Add Content-Security-Policy header to prevent XSS attacks")
	}
}

// checkProtectionHeaders checks X-Frame-Options, X-Content-Type-Options, and X-XSS-Protection.
func checkProtectionHeaders(headers map[string]string, info *SecurityHeadersInfo) {
	// Check X-Frame-Options
	if xfo, ok := headers["X-Frame-Options"]; ok {
		info.XFrameOptions = xfo
		if xfo != "DENY" && xfo != "SAMEORIGIN" {
			info.SecurityScore -= 5
			info.Recommendations = append(info.Recommendations,
				"X-Frame-Options should be DENY or SAMEORIGIN")
		}
	} else {
		info.MissingHeaders = append(info.MissingHeaders, "X-Frame-Options")
		info.SecurityScore -= 15
		info.Recommendations = append(info.Recommendations,
			"Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking")
	}

	// Check X-Content-Type-Options
	if xcto, ok := headers["X-Content-Type-Options"]; ok {
		info.XContentTypeOptions = xcto
		if xcto != "nosniff" {
			info.SecurityScore -= 5
			info.Recommendations = append(info.Recommendations,
				"X-Content-Type-Options should be 'nosniff'")
		}
	} else {
		info.MissingHeaders = append(info.MissingHeaders, "X-Content-Type-Options")
		info.SecurityScore -= 10
		info.Recommendations = append(info.Recommendations,
			"Add X-Content-Type-Options: nosniff to prevent MIME sniffing")
	}

	// Check X-XSS-Protection
	if xxss, ok := headers["X-Xss-Protection"]; ok {
		info.XXSSProtection = xxss
	} else {
		info.MissingHeaders = append(info.MissingHeaders, "X-XSS-Protection")
		info.SecurityScore -= 5
		info.Recommendations = append(info.Recommendations,
			"Add X-XSS-Protection: 1; mode=block (legacy browsers)")
	}
}

// checkPolicyHeaders checks Referrer-Policy and Permissions-Policy.
func checkPolicyHeaders(headers map[string]string, info *SecurityHeadersInfo) {
	// Check Referrer-Policy
	if rp, ok := headers["Referrer-Policy"]; ok {
		info.ReferrerPolicy = rp
	} else {
		info.MissingHeaders = append(info.MissingHeaders, "Referrer-Policy")
		info.SecurityScore -= 5
		info.Recommendations = append(info.Recommendations,
			"Add Referrer-Policy: strict-origin-when-cross-origin")
	}

	// Check Permissions-Policy
	if pp, ok := headers["Permissions-Policy"]; ok {
		info.PermissionsPolicy = pp
	} else {
		info.MissingHeaders = append(info.MissingHeaders, "Permissions-Policy")
		info.SecurityScore -= 5
		info.Recommendations = append(info.Recommendations,
			"Add Permissions-Policy to control browser features")
	}
}

// parseHSTS parses the Strict-Transport-Security header.
func parseHSTS(value string) *HSTSInfo {
	hsts := &HSTSInfo{Present: true}

	// Parse directives: max-age=31536000; includeSubDomains; preload
	parts := strings.Split(value, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			maxAgeStr := strings.TrimPrefix(part, "max-age=")
			if maxAge, err := strconv.Atoi(maxAgeStr); err == nil {
				hsts.MaxAge = maxAge
			}
		} else if part == "includeSubDomains" {
			hsts.IncludeSubDomains = true
		} else if part == "preload" {
			hsts.Preload = true
		}
	}

	return hsts
}

// parseCSP parses the Content-Security-Policy header.
func parseCSP(value string) *CSPInfo {
	csp := &CSPInfo{
		Present:    true,
		Directives: make(map[string]string),
	}

	// Parse directives: default-src 'self'; script-src 'unsafe-inline'; ...
	directives := strings.Split(value, ";")
	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if directive == "" {
			continue
		}

		parts := strings.SplitN(directive, " ", 2)
		if len(parts) == 2 {
			directiveName := strings.TrimSpace(parts[0])
			directiveValue := strings.TrimSpace(parts[1])
			csp.Directives[directiveName] = directiveValue

			// Check for unsafe keywords
			if strings.Contains(directiveValue, "'unsafe-inline'") {
				csp.UnsafeInline = true
			}
			if strings.Contains(directiveValue, "'unsafe-eval'") {
				csp.UnsafeEval = true
			}
		} else if len(parts) == 1 {
			// Directive without value
			csp.Directives[parts[0]] = ""
		}
	}

	return csp
}
