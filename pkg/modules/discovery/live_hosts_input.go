package discovery

import "strings"

// ExtractLiveHosts normalizes the several shapes a live-host list arrives in
// from the data context, so modules outside this package can consume it without
// each reimplementing the same coercion.
func ExtractLiveHosts(raw any) []string {
	return extractLiveHostsInput(raw)
}

func extractLiveHostsInput(raw any) []string {
	seen := make(map[string]struct{})
	liveHosts := make([]string, 0)

	appendHosts := func(items []string) {
		for _, host := range items {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}
			if _, exists := seen[host]; exists {
				continue
			}
			seen[host] = struct{}{}
			liveHosts = append(liveHosts, host)
		}
	}

	switch typed := raw.(type) {
	case ICMPPingDiscoveryResult:
		appendHosts(typed.LiveHosts)
	case []ICMPPingDiscoveryResult:
		for _, result := range typed {
			appendHosts(result.LiveHosts)
		}
	case []any:
		for _, item := range typed {
			if result, ok := item.(ICMPPingDiscoveryResult); ok {
				appendHosts(result.LiveHosts)
			}
		}
	}

	return liveHosts
}
