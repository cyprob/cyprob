package discovery

import "strings"

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
