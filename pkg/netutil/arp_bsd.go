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

// readDefaultGateways returns the next-hop addresses of the default routes.
//
// A default route carries a gateway address where a neighbor entry carries a
// link address, which is how the two are told apart in the same table.
func readDefaultGateways() []string {
	rib, err := route.FetchRIB(0, route.RIBTypeRoute, 0)
	if err != nil {
		return nil
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil
	}

	var gateways []string
	for _, message := range messages {
		routeMessage, ok := message.(*route.RouteMessage)
		if !ok || len(routeMessage.Addrs) < 2 {
			continue
		}
		destination, ok := routeMessage.Addrs[0].(*route.Inet4Addr)
		if !ok || net.IP(destination.IP[:]).String() != "0.0.0.0" {
			continue
		}
		gateway, ok := routeMessage.Addrs[1].(*route.Inet4Addr)
		if !ok {
			continue
		}
		gateways = append(gateways, net.IP(gateway.IP[:]).String())
	}
	return gateways
}
