package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// policy is the relay-policy service's answer for one credential. Full-access
// clients may reach CIDRs (internet and LAN); guests reach only the portal.
type policy struct {
	CredentialID    string        `json:"credential_id"`
	Client          string        `json:"client"`
	CIDRs           []string      `json:"allowed_cidrs"`
	URL             string        `json:"url"`
	Guest           bool          `json:"guest"`
	Portal          *portalConfig `json:"portal"`
	portal          *guestPortal
	compiled        bool
	allowedPrefixes []netip.Prefix
}

// compile parses the policy once per authorization; a malformed policy is an error.
func (p *policy) compile() error {
	if p.Guest && p.Portal != nil {
		var err error
		if p.portal, err = parseGuestPortal(*p.Portal); err != nil {
			return err
		}
	}
	for _, value := range p.CIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return err
		}
		p.allowedPrefixes = append(p.allowedPrefixes, prefix.Masked())
	}
	p.compiled = true
	return nil
}

// allows checks a resolved destination address. Guests are never allowed a
// resolved address: their portal flow is pinned in resolveDestination.
func (p policy) allows(addr netip.Addr) bool {
	if !p.compiled {
		if p.compile() != nil {
			return false
		}
	}
	addr = addr.Unmap()
	if p.Guest || addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return false
	}
	for _, prefix := range p.allowedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func resolveAll(ctx context.Context, target string, p policy) ([]netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, errInvalidTarget
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, errInvalidTarget
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errDNSFailed, err)
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
		return nil, errDestinationDenied
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
			conn, err := (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", addr.String())
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
