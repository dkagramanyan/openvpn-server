package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type policy struct {
	Client          string        `json:"client"`
	CIDRs           []string      `json:"allowed_cidrs"`
	URL             string        `json:"url"`
	Guest           bool          `json:"guest"`
	Blocked         []string      `json:"blocked_cidrs"`
	Portal          *portalConfig `json:"portal"`
	portal          *guestPortal
	compiled        bool
	allowedPrefixes []netip.Prefix
	blockedPrefixes []netip.Prefix
	interfaces      []netip.Prefix
}

var guestSpecial = func() []netip.Prefix {
	var values []netip.Prefix
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"} {
		values = append(values, netip.MustParsePrefix(cidr))
	}
	return values
}()

// Compile CIDRs once per fresh policy, including a fresh interface snapshot.
func (p *policy) compile() error {
	if p.Portal != nil && p.Guest && p.Portal.Enabled {
		var err error
		p.portal, err = parseGuestPortal(p.Portal.Host, p.Portal.Target, strings.Join(p.Portal.Destinations, " "))
		if err != nil {
			return err
		}
	}
	for _, group := range []struct {
		source []string
		target *[]netip.Prefix
	}{{p.CIDRs, &p.allowedPrefixes}, {p.Blocked, &p.blockedPrefixes}} {
		for _, value := range group.source {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return err
			}
			*group.target = append(*group.target, prefix.Masked())
		}
	}
	if p.Guest {
		addresses, err := net.InterfaceAddrs()
		if err != nil {
			return err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil {
				p.interfaces = append(p.interfaces, prefix.Masked())
			}
		}
	}
	p.compiled = true
	return nil
}

func (p policy) allows(addr netip.Addr) bool {
	if !p.compiled {
		if p.compile() != nil {
			return false
		}
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return false
	}
	if p.Guest {
		if !addr.Is4() || !addr.IsGlobalUnicast() || addr.IsPrivate() {
			return false
		}
		for _, prefix := range guestSpecial {
			if prefix.Contains(addr) {
				return false
			}
		}
		for _, prefix := range p.interfaces {
			if prefix.Contains(addr) {
				return false
			}
		}
	}
	for _, prefix := range p.blockedPrefixes {
		if prefix.Contains(addr) {
			return false
		}
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
