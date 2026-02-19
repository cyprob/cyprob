package parse

import (
	"sort"
	"strings"
)

const (
	TagMailService  = "mail_service"
	TagWebmail      = "webmail"
	TagSMTP         = "smtp"
	TagIMAP         = "imap"
	TagPOP3         = "pop3"
	TagExchange     = "exchange"
	TagOWA          = "owa"
	TagSmarterMail  = "smartermail"
	TagRoundcube    = "roundcube"
	TagZimbra       = "zimbra"
	TagSOGo         = "sogo"
	TagRainLoop     = "rainloop"
	TagPostfix      = "postfix"
	TagExim         = "exim"
	TagDovecot      = "dovecot"
	TagMicrosoftIIS = "microsoft_iis"
)

var canonicalTechTagSet = map[string]struct{}{
	"akamai":         {},
	"amqp":           {},
	"angular":        {},
	"apache":         {},
	"asp_net":        {},
	"backbonejs":     {},
	"bootstrap":      {},
	"cache":          {},
	"caddy":          {},
	"centos":         {},
	"clickhouse":     {},
	"cloudflare":     {},
	"codeigniter":    {},
	"consul":         {},
	"database":       {},
	"debian":         {},
	"dgraph":         {},
	"django":         {},
	"docker":         {},
	"document_store": {},
	"drupal":         {},
	"elasticsearch":  {},
	"express":        {},
	"fedora":         {},
	"flask":          {},
	"freebsd":        {},
	"gitlab":         {},
	"grafana":        {},
	"http_server":    {},
	"imperva":        {},
	"java":           {},
	"jenkins":        {},
	"jetty":          {},
	"joomla":         {},
	"jquery":         {},
	"kafka":          {},
	"kibana":         {},
	"kubernetes":     {},
	"laravel":        {},
	"lighttpd":       {},
	"lodash":         {},
	"magento":        {},
	"message_broker": {},
	"modsecurity":    {},
	"mongodb":        {},
	"momentjs":       {},
	"mysql":          {},
	"netdata":        {},
	"nginx":          {},
	"nodejs":         {},
	"nosql":          {},
	"openssl":        {},
	"openresty":      {},
	"perl":           {},
	"php":            {},
	"postgresql":     {},
	"prometheus":     {},
	"protocol":       {},
	"python":         {},
	"rabbitmq":       {},
	"rdbms":          {},
	"react":          {},
	"redis":          {},
	"rails":          {},
	"reverse_proxy":  {},
	"ruby":           {},
	"search_engine":  {},
	"secure_shell":   {},
	"spring_boot":    {},
	"sql":            {},
	"ssh":            {},
	"streaming":      {},
	"swagger":        {},
	"symfony":        {},
	"tomcat":         {},
	"ubuntu":         {},
	"vuejs":          {},
	"web_server":     {},
	"windows":        {},
	"wordpress":      {},
	"zipkin":         {},

	TagMailService:  {},
	TagWebmail:      {},
	TagSMTP:         {},
	TagIMAP:         {},
	TagPOP3:         {},
	TagExchange:     {},
	TagOWA:          {},
	TagSmarterMail:  {},
	TagRoundcube:    {},
	TagZimbra:       {},
	TagSOGo:         {},
	TagRainLoop:     {},
	TagPostfix:      {},
	TagExim:         {},
	TagDovecot:      {},
	TagMicrosoftIIS: {},
}

var techTagAliases = map[string]string{
	"asp.net":       "asp_net",
	"asp_net":       "asp_net",
	"backbone.js":   "backbonejs",
	"iis":           TagMicrosoftIIS,
	"mail_server":   TagMailService,
	"microsoft_iis": TagMicrosoftIIS,
	"moment.js":     "momentjs",
	"node.js":       "nodejs",
	"spring-boot":   "spring_boot",
	"spring_boot":   "spring_boot",
	"vue.js":        "vuejs",
}

var impliedTechTags = map[string][]string{
	TagSMTP:        {TagMailService},
	TagIMAP:        {TagMailService},
	TagPOP3:        {TagMailService},
	TagPostfix:     {TagSMTP, TagMailService},
	TagExim:        {TagSMTP, TagMailService},
	TagDovecot:     {TagIMAP, TagPOP3, TagMailService},
	TagExchange:    {TagMailService},
	TagOWA:         {TagExchange, TagWebmail, TagMailService},
	TagSmarterMail: {TagWebmail, TagMailService},
	TagRoundcube:   {TagWebmail, TagMailService},
	TagZimbra:      {TagWebmail, TagMailService},
	TagSOGo:        {TagWebmail, TagMailService},
	TagRainLoop:    {TagWebmail, TagMailService},
	TagWebmail:     {TagMailService},
}

// NormalizeTechTag returns a canonical tag value from aliases/rule names.
func NormalizeTechTag(tag string) (string, bool) {
	candidate := strings.ToLower(strings.TrimSpace(tag))
	if candidate == "" {
		return "", false
	}

	if canonical, ok := techTagAliases[candidate]; ok {
		return canonical, true
	}
	if _, ok := canonicalTechTagSet[candidate]; ok {
		return candidate, true
	}
	return "", false
}

// NormalizeTechTags normalizes, deduplicates, and enriches tags with implied canonical tags.
func NormalizeTechTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}

	tagSet := make(map[string]struct{}, len(tags))
	var add func(string)
	add = func(raw string) {
		normalized, ok := NormalizeTechTag(raw)
		if !ok {
			return
		}
		if _, exists := tagSet[normalized]; exists {
			return
		}
		tagSet[normalized] = struct{}{}
		for _, implied := range impliedTechTags[normalized] {
			add(implied)
		}
	}

	for _, tag := range tags {
		add(tag)
	}

	if len(tagSet) == 0 {
		return nil
	}

	result := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		result = append(result, tag)
	}
	sort.Strings(result)
	return result
}

func IsCanonicalTechTag(tag string) bool {
	normalized, ok := NormalizeTechTag(tag)
	if !ok {
		return false
	}
	_, ok = canonicalTechTagSet[normalized]
	return ok
}

func CanonicalTechTags() []string {
	result := make([]string, 0, len(canonicalTechTagSet))
	for tag := range canonicalTechTagSet {
		result = append(result, tag)
	}
	sort.Strings(result)
	return result
}
