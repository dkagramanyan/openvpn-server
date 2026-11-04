package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Guests reach the gateway only through its guest portal listener: the
// personal portal plus the guest links the administrator added. That listener
// serves nothing else, so a guest never reaches the regular HTTPS listener,
// where the relay's LAN source address would count as trusted.
type guestPortal struct {
	hosts  map[string]bool // the portal hostname and the guest links' hostnames
	target netip.AddrPort
}

type portalFlowKey struct{}

// portalConfig is the "portal" object of a guest's policy.
type portalConfig struct {
	Host   string   `json:"host"`
	Target string   `json:"target"`
	Hosts  []string `json:"hosts"` // guest links
}

func normalHost(host string) string { return strings.ToLower(strings.TrimSuffix(host, ".")) }

func parseGuestPortal(c portalConfig) (*guestPortal, error) {
	target, err := netip.ParseAddrPort(c.Target)
	if err != nil || !target.Addr().Is4() || !target.Addr().IsGlobalUnicast() || target.Port() < 1024 {
		return nil, fmt.Errorf("portal target must be the gateway's portal listener IPv4:port (port >= 1024)")
	}
	portal := &guestPortal{hosts: map[string]bool{}, target: target}
	for _, value := range append([]string{c.Host}, c.Hosts...) {
		host := normalHost(value)
		if host == "" || strings.ContainsAny(host, ":/ \\?#@\t\r\n") {
			return nil, fmt.Errorf("portal hosts must be hostnames without scheme or port")
		}
		portal.hosts[host] = true
	}
	return portal, nil
}

// resolveDestination returns the addresses a flow may dial. A guest's TCP 443
// flow to the portal or a guest-link hostname is pinned to the portal listener
// without DNS; the HTTPS bytes (SNI, Host) pass unchanged to the gateway, which
// routes only those hostnames (and the links' paths). Anything else a guest
// opens is resolved and checked like a full client's, minus local networks.
func (s *relayServer) resolveDestination(ctx context.Context, target string, p policy, tcp bool) (context.Context, []netip.AddrPort, error) {
	if !p.compiled {
		if err := p.compile(); err != nil {
			return ctx, nil, errDestinationDenied
		}
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return ctx, nil, errInvalidTarget
	}
	if !p.Guest || p.portal == nil || !tcp || port != "443" || !p.portal.hosts[normalHost(host)] {
		addresses, err := resolveAll(ctx, target, p)
		return ctx, addresses, err
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
