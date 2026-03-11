package discovery

import (
	"reflect"
	"testing"
)

func TestExtractLiveHostsInput(t *testing.T) {
	t.Run("single result", func(t *testing.T) {
		got := extractLiveHostsInput(ICMPPingDiscoveryResult{LiveHosts: []string{"192.0.2.10"}})
		if !reflect.DeepEqual(got, []string{"192.0.2.10"}) {
			t.Fatalf("expected single live host, got %v", got)
		}
	})

	t.Run("list input", func(t *testing.T) {
		got := extractLiveHostsInput([]any{
			ICMPPingDiscoveryResult{LiveHosts: []string{"192.0.2.10", "192.0.2.11"}},
			ICMPPingDiscoveryResult{LiveHosts: []string{"192.0.2.11", "192.0.2.12"}},
		})
		want := []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("expected %v, got %v", want, got)
		}
	})
}
