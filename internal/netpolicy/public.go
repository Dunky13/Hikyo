// Package netpolicy owns the default-deny public-egress address policy shared
// by authenticated outbound integrations.
package netpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// Resolver resolves one hostname immediately before a connection attempt.
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// Dialer opens a connection to an already-resolved, policy-approved address.
type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// PublicDialer resolves and validates every destination address immediately
// before dialing one of those exact addresses. It owns address policy only;
// callers retain protocol, proxy, redirect, TLS, and timeout policy. An opaque
// forward proxy changes the address passed here to the proxy's first hop, so a
// caller must not claim that this dialer validates the proxy's ultimate target.
type PublicDialer struct {
	AllowedCIDRs []netip.Prefix
	Resolver     Resolver
	Dialer       Dialer
}

// NewPublicDialer validates and copies policy inputs before first use.
func NewPublicDialer(allowedCIDRs []netip.Prefix, resolver Resolver, dialer Dialer) (*PublicDialer, error) {
	public := &PublicDialer{
		AllowedCIDRs: append([]netip.Prefix(nil), allowedCIDRs...),
		Resolver:     resolver,
		Dialer:       dialer,
	}
	if err := public.validate(); err != nil {
		return nil, err
	}
	return public, nil
}

func (d *PublicDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("netpolicy: destination address: %w", err)
	}
	addresses, err := d.Resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("netpolicy: resolve destination: %w", err)
	}
	if len(addresses) == 0 {
		return nil, errors.New("netpolicy: destination did not resolve")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	validated := make([]netip.Addr, 0, len(addresses))
	for _, resolved := range addresses {
		resolved = resolved.Unmap()
		if !d.permitted(resolved) {
			return nil, fmt.Errorf("netpolicy: destination resolved to non-public address %s", resolved)
		}
		validated = append(validated, resolved)
	}
	var attempts []error
	for _, resolved := range validated {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pinned := net.JoinHostPort(resolved.String(), port)
		connection, err := d.Dialer.DialContext(ctx, network, pinned)
		if err == nil {
			if err := ctx.Err(); err != nil {
				if connection != nil {
					connection.Close()
				}
				return nil, err
			}
			if connection == nil {
				return nil, errors.New("netpolicy: dialer returned a nil connection")
			}
			return connection, nil
		}
		if connection != nil {
			connection.Close()
		}
		attempts = append(attempts, fmt.Errorf("dial %s: %w", pinned, err))
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	return nil, errors.Join(attempts...)
}

func (d *PublicDialer) validate() error {
	if d == nil || d.Resolver == nil || d.Dialer == nil {
		return errors.New("netpolicy: resolver and dialer are required")
	}
	for index, prefix := range d.AllowedCIDRs {
		if !prefix.IsValid() {
			return fmt.Errorf("netpolicy: invalid allowed CIDR at index %d", index)
		}
	}
	return nil
}

func (d *PublicDialer) permitted(address netip.Addr) bool {
	for _, prefix := range d.AllowedCIDRs {
		if prefix.Contains(address) {
			return true
		}
	}
	return !IsNonPublic(address)
}

var nonPublicIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var (
	publicIPv6Prefix      = netip.MustParsePrefix("2000::/3")
	nonPublicIPv6Prefixes = []netip.Prefix{
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
	}
)

func IsNonPublic(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() ||
		address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return true
	}
	prefixes := nonPublicIPv4Prefixes
	if address.Is6() {
		if !publicIPv6Prefix.Contains(address) {
			return true
		}
		prefixes = nonPublicIPv6Prefixes
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
