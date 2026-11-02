package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"
)

type policy struct {
	CIDRs   []string `json:"allowed_cidrs"`
	URL     string   `json:"url"`
	Guest   bool     `json:"guest"`
	Blocked []string `json:"blocked_cidrs"`
}

func (p policy) allows(addr netip.Addr) bool {
	addr = addr.Unmap()
	// Never expose local control-plane services or special-address traffic.
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return false
	}
	if p.Guest {
		// Match OpenVPN's IPv4-only guest egress; do not expose IPv6 transition
		// mechanisms that can embed or translate private IPv4 destinations.
		if !addr.Is4() || !addr.IsGlobalUnicast() || addr.IsPrivate() {
			return false
		}
		for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"} {
			if netip.MustParsePrefix(cidr).Contains(addr) {
				return false
			}
		}
		// Block directly attached networks even when they use public addresses.
		networks, err := net.InterfaceAddrs()
		if err != nil {
			return false
		}
		for _, network := range networks {
			prefix, err := netip.ParsePrefix(network.String())
			if err == nil && prefix.Contains(addr) {
				return false
			}
		}
	}
	for _, cidr := range p.Blocked {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix.Contains(addr) {
			return false
		}
	}
	for _, cidr := range p.CIDRs {
		if prefix, err := netip.ParsePrefix(cidr); err == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func resolveAll(ctx context.Context, target string, p policy) ([]netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid port")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var allowed []netip.AddrPort
	for _, addr := range addrs {
		if p.allows(addr) {
			allowed = append(allowed, netip.AddrPortFrom(addr.Unmap(), uint16(port)))
			if len(allowed) == 16 {
				break
			}
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("destination denied")
	}
	return allowed, nil
}

// Race only validated numeric destinations. A broken first address must not
// stall connections when the hostname also has a reachable address.
func dialTCP(ctx context.Context, addresses []netip.AddrPort) (net.Conn, netip.AddrPort, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	type result struct {
		conn net.Conn
		addr netip.AddrPort
		err  error
	}
	results := make(chan result)
	for i, addr := range addresses {
		go func() {
			timer := time.NewTimer(time.Duration(i) * 200 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr.String())
			select {
			case results <- result{conn, addr, err}:
			case <-ctx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}()
	}
	var last error = errors.New("no destination")
	for range addresses {
		select {
		case <-ctx.Done():
			return nil, netip.AddrPort{}, ctx.Err()
		case r := <-results:
			if r.err == nil {
				return r.conn, r.addr, nil
			}
			last = r.err
		}
	}
	return nil, netip.AddrPort{}, last
}
