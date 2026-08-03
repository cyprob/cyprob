//go:build darwin || freebsd || netbsd || openbsd

package netutil

import (
	"net"

	"golang.org/x/net/route"
)

// readARPTable reads neighbor entries from the BSD routing socket. This keeps
// the lookup dependency-free at runtime (no shelling out to `arp`).
func readARPTable() []ARPEntry {
	rib, err := route.FetchRIB(0, route.RIBTypeRoute, 0)
	if err != nil {
		return nil
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil
	}

	entries := make([]ARPEntry, 0, len(messages))
	for _, message := range messages {
		routeMessage, ok := message.(*route.RouteMessage)
		if !ok || len(routeMessage.Addrs) < 2 {
			continue
		}
		destination, ok := routeMessage.Addrs[0].(*route.Inet4Addr)
		if !ok {
			continue
		}
		link, ok := routeMessage.Addrs[1].(*route.LinkAddr)
		if !ok || len(link.Addr) != 6 {
			continue
		}
		entries = append(entries, ARPEntry{
			IP:  net.IP(destination.IP[:]).String(),
			MAC: net.HardwareAddr(link.Addr).String(),
		})
	}
	return entries
}
