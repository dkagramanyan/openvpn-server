package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// The only guest LAN exception is a dedicated Traefik portal-only listener.
// Never send this traffic to the regular HTTPS listener: relay egress has a
// trusted LAN source, so that listener could also grant administrative access.
type guestPortal struct {
	host    string
	target  netip.AddrPort
	aliases map[string]bool
}

type portalFlowKey struct{}

type portalConfig struct {
	Enabled      bool     `json:"enabled"`
	Host         string   `json:"host"`
	Target       string   `json:"target"`
	Destinations []string `json:"destinations"`
}

func parseGuestPortal(host, target, destinations string) (*guestPortal, error) {
	if host == "" && target == "" && destinations == "" {
		return nil, nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || strings.ContainsAny(host, ":/ \\?#@\t\r\n") {
		return nil, fmt.Errorf("GUEST_PORTAL_HOST must be a hostname without scheme or port")
	}
	addr, err := netip.ParseAddrPort(target)
	if err != nil || !addr.Addr().Is4() || !addr.Addr().IsGlobalUnicast() || addr.Addr().IsLoopback() || addr.Port() < 1024 {
		return nil, fmt.Errorf("GUEST_PORTAL_TARGET must be the dedicated portal listener's IPv4:port (port >= 1024)")
	}
	aliases := make(map[string]bool)
	for _, value := range strings.Fields(destinations) {
		ip, err := netip.ParseAddr(value)
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsLoopback() {
			return nil, fmt.Errorf("GUEST_PORTAL_DESTINATIONS must contain individual IPv4 addresses")
		}
		aliases[ip.String()] = true
	}
	return &guestPortal{host: host, target: addr, aliases: aliases}, nil
}

func (s *relayServer) resolveDestination(ctx context.Context, target string, p policy, tcp bool) (context.Context, []netip.AddrPort, error) {
	if !p.compiled {
		if err := p.compile(); err != nil {
			return ctx, nil, errDestinationDenied
		}
	}
	host, port, err := net.SplitHostPort(target)
	if err == nil && p.Guest && p.portal != nil && (strings.EqualFold(strings.TrimSuffix(host, "."), p.portal.host) || p.portal.aliases[host]) {
		// Pin the destination without DNS. HTTPS bytes (including SNI and Host)
		// remain intact; Traefik enforces the hostname and portal path boundary.
		if !tcp || port != "443" {
			return ctx, nil, errDestinationDenied
		}
		ctx = context.WithValue(ctx, portalFlowKey{}, p.portal.target)
		return ctx, []netip.AddrPort{p.portal.target}, nil
	}
	addresses, err := resolveAll(ctx, target, p)
	return ctx, addresses, err
}

func (s *relayServer) portalFlow(ctx context.Context, addr netip.Addr, p policy) bool {
	if !p.compiled {
		if p.compile() != nil {
			return false
		}
	}
	target, ok := ctx.Value(portalFlowKey{}).(netip.AddrPort)
	return ok && p.portal != nil && target == p.portal.target && target.Addr() == addr
}
