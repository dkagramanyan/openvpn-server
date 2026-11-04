package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Guests may reach exactly one destination: the personal portal, through the
// gateway's dedicated portal listener. That listener serves only the portal
// pages of the OpenVPN website, so a guest never reaches the regular HTTPS
// listener, where the relay's LAN source address would count as trusted.
type guestPortal struct {
	host   string
	target netip.AddrPort
}

type portalFlowKey struct{}

// portalConfig is the "portal" object of a guest's policy.
type portalConfig struct {
	Host   string `json:"host"`
	Target string `json:"target"`
}

func parseGuestPortal(c portalConfig) (*guestPortal, error) {
	host := strings.ToLower(strings.TrimSuffix(c.Host, "."))
	if host == "" || strings.ContainsAny(host, ":/ \\?#@\t\r\n") {
		return nil, fmt.Errorf("portal host must be a hostname without scheme or port")
	}
	target, err := netip.ParseAddrPort(c.Target)
	if err != nil || !target.Addr().Is4() || !target.Addr().IsGlobalUnicast() || target.Port() < 1024 {
		return nil, fmt.Errorf("portal target must be the gateway's portal listener IPv4:port (port >= 1024)")
	}
	return &guestPortal{host: host, target: target}, nil
}

// resolveDestination returns the addresses a flow may dial. A guest's only
// destination is the portal host on TCP 443, pinned to the portal listener
// without DNS; the HTTPS bytes (SNI, Host) pass unchanged to the gateway.
func (s *relayServer) resolveDestination(ctx context.Context, target string, p policy, tcp bool) (context.Context, []netip.AddrPort, error) {
	if !p.compiled {
		if err := p.compile(); err != nil {
			return ctx, nil, errDestinationDenied
		}
	}
	if !p.Guest {
		addresses, err := resolveAll(ctx, target, p)
		return ctx, addresses, err
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return ctx, nil, errInvalidTarget
	}
	if p.portal == nil || !tcp || port != "443" || !strings.EqualFold(strings.TrimSuffix(host, "."), p.portal.host) {
		return ctx, nil, errDestinationDenied
	}
	ctx = context.WithValue(ctx, portalFlowKey{}, p.portal.target)
	return ctx, []netip.AddrPort{p.portal.target}, nil
}

// portalFlow reports whether an open flow is a guest's portal flow that the
// current policy still permits.
func (s *relayServer) portalFlow(ctx context.Context, addr netip.Addr, p policy) bool {
	if !p.compiled {
		if p.compile() != nil {
			return false
		}
	}
	target, ok := ctx.Value(portalFlowKey{}).(netip.AddrPort)
	return ok && p.portal != nil && target == p.portal.target && target.Addr() == addr
}
