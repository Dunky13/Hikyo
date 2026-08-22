package netpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

type staticResolver struct {
	addresses []netip.Addr
	err       error
	calls     int
}

func (r *staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.calls++
	return append([]netip.Addr(nil), r.addresses...), r.err
}

type sequenceResolver struct {
	answers [][]netip.Addr
	calls   int
}

func (r *sequenceResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	answer := r.answers[r.calls]
	r.calls++
	return append([]netip.Addr(nil), answer...), nil
}

type recordingDialer struct {
	attempts  []string
	failures  map[string]error
	onAttempt func(string)
	closed    int
}

func (d *recordingDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.attempts = append(d.attempts, address)
	if d.onAttempt != nil {
		d.onAttempt(address)
	}
	if err := d.failures[address]; err != nil {
		return nil, err
	}
	client, server := net.Pipe()
	server.Close()
	return &recordingConn{Conn: client, onClose: func() { d.closed++ }}, nil
}

type recordingConn struct {
	net.Conn
	onClose func()
}

func (c *recordingConn) Close() error {
	c.onClose()
	return c.Conn.Close()
}

func TestPublicDialerRejectsMixedAnswersBeforeDial(t *testing.T) {
	resolver := &staticResolver{addresses: []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("127.0.0.1"),
	}}
	dialer := &recordingDialer{}
	public := &PublicDialer{Resolver: resolver, Dialer: dialer}

	conn, err := public.DialContext(t.Context(), "tcp", "provider.example:443")
	if conn != nil {
		conn.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("DialContext() error = %v, want non-public-address refusal", err)
	}
	if len(dialer.attempts) != 0 {
		t.Fatalf("dial attempts = %v, want none before every answer passes policy", dialer.attempts)
	}
}

func TestIsNonPublicRejectsSpecialUseAddressFamilies(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1",
		"10.0.0.1",
		"169.254.169.254",
		"100.64.0.1",
		"192.0.2.1",
		"198.51.100.1",
		"203.0.113.1",
		"198.18.0.1",
		"2001:db8::1",
		"fe80::1",
		"fd00::1",
	} {
		address := netip.MustParseAddr(raw)
		if !IsNonPublic(address) {
			t.Errorf("special-use address %s was admitted by default", address)
		}
	}
}

func TestPublicDialerFallsBackAcrossValidatedAddresses(t *testing.T) {
	resolver := &staticResolver{addresses: []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}}
	dialer := &recordingDialer{failures: map[string]error{
		"8.8.8.8:443": errors.New("first address unavailable"),
	}}
	public := &PublicDialer{Resolver: resolver, Dialer: dialer}

	conn, err := public.DialContext(t.Context(), "tcp", "provider.example:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	want := []string{"8.8.8.8:443", "[2606:4700:4700::1111]:443"}
	if !slices.Equal(dialer.attempts, want) {
		t.Fatalf("dial attempts = %v, want exact validated addresses %v", dialer.attempts, want)
	}
}

func TestPublicDialerAllowsExplicitCIDRAndPinsMappedAddress(t *testing.T) {
	resolver := &staticResolver{addresses: []netip.Addr{
		netip.MustParseAddr("::ffff:10.24.3.9"),
	}}
	dialer := &recordingDialer{}
	public := &PublicDialer{
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.24.0.0/16")},
		Resolver:     resolver,
		Dialer:       dialer,
	}

	conn, err := public.DialContext(t.Context(), "tcp", "provider.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if want := []string{"10.24.3.9:8443"}; !slices.Equal(dialer.attempts, want) {
		t.Fatalf("dial attempts = %v, want allowed pinned address %v", dialer.attempts, want)
	}
}

func TestPublicDialerResolvesAndRechecksPolicyForEveryConnection(t *testing.T) {
	resolver := &sequenceResolver{answers: [][]netip.Addr{
		{netip.MustParseAddr("8.8.8.8")},
		{netip.MustParseAddr("127.0.0.1")},
	}}
	dialer := &recordingDialer{}
	public := &PublicDialer{Resolver: resolver, Dialer: dialer}

	conn, err := public.DialContext(t.Context(), "tcp", "provider.example:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if conn, err = public.DialContext(t.Context(), "tcp", "provider.example:443"); err == nil {
		conn.Close()
		t.Fatal("rebinding to loopback unexpectedly succeeded")
	}
	if resolver.calls != 2 {
		t.Fatalf("resolver calls = %d, want one per connection", resolver.calls)
	}
	if want := []string{"8.8.8.8:443"}; !slices.Equal(dialer.attempts, want) {
		t.Fatalf("dial attempts = %v, want only first validated resolution %v", dialer.attempts, want)
	}
}

func TestPublicDialerStopsFallbackWhenContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	dialFailure := errors.New("dial interrupted")
	dialer := &recordingDialer{
		failures: map[string]error{"8.8.8.8:443": dialFailure},
		onAttempt: func(string) {
			cancel()
		},
	}
	public := &PublicDialer{
		Resolver: &staticResolver{addresses: []netip.Addr{
			netip.MustParseAddr("8.8.8.8"),
			netip.MustParseAddr("1.1.1.1"),
		}},
		Dialer: dialer,
	}

	if _, err := public.DialContext(ctx, "tcp", "provider.example:443"); !errors.Is(err, context.Canceled) {
		t.Fatalf("DialContext() error = %v, want context cancellation", err)
	}
	if want := []string{"8.8.8.8:443"}; !slices.Equal(dialer.attempts, want) {
		t.Fatalf("dial attempts after cancellation = %v, want %v", dialer.attempts, want)
	}
}

func TestPublicDialerRefusesConnectionOpenedDuringCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	dialer := &recordingDialer{onAttempt: func(string) { cancel() }}
	public := &PublicDialer{
		Resolver: &staticResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}},
		Dialer:   dialer,
	}

	if conn, err := public.DialContext(ctx, "tcp", "provider.example:443"); !errors.Is(err, context.Canceled) || conn != nil {
		t.Fatalf("DialContext() = %v, %v, want nil connection and cancellation", conn, err)
	}
	if dialer.closed != 1 {
		t.Fatalf("connections closed after cancellation = %d, want 1", dialer.closed)
	}
}

func TestPublicDialerRefusesPreCancelledContextBeforeResolution(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	resolver := &staticResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	public := &PublicDialer{Resolver: resolver, Dialer: &recordingDialer{}}

	if _, err := public.DialContext(ctx, "tcp", "provider.example:443"); !errors.Is(err, context.Canceled) {
		t.Fatalf("DialContext() error = %v, want pre-dial cancellation", err)
	}
	if resolver.calls != 0 {
		t.Fatalf("resolver calls = %d, want none after cancellation", resolver.calls)
	}
}

func TestPublicDialerRejectsInvalidAllowedCIDR(t *testing.T) {
	resolver := &staticResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	public := &PublicDialer{
		AllowedCIDRs: []netip.Prefix{{}},
		Resolver:     resolver,
		Dialer:       &recordingDialer{},
	}

	if _, err := public.DialContext(t.Context(), "tcp", "provider.example:443"); err == nil || !strings.Contains(err.Error(), "invalid allowed CIDR") {
		t.Fatalf("DialContext() error = %v, want invalid-CIDR refusal", err)
	}
	if resolver.calls != 0 {
		t.Fatalf("resolver calls = %d, want config refusal before resolution", resolver.calls)
	}
}

func TestPublicDialerFailsClosedBeforeResolution(t *testing.T) {
	for name, public := range map[string]*PublicDialer{
		"nil":      nil,
		"resolver": {Dialer: &recordingDialer{}},
		"dialer":   {Resolver: &staticResolver{}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := public.DialContext(t.Context(), "tcp", "provider.example:443"); err == nil {
				t.Fatal("incomplete policy unexpectedly dialed")
			}
		})
	}
}

var _ Resolver = (*staticResolver)(nil)
var _ Resolver = (*sequenceResolver)(nil)
var _ Dialer = (*recordingDialer)(nil)
