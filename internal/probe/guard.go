package probe

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/kilo666mj/parallaxd/internal/check"
)

// specialUse contains address space that is not a public-internet vantage even
// though netip does not classify all of it as private. Several of these ranges
// are routed inside carriers, labs and transition networks, which makes them an
// SSRF boundary rather than merely a semantic distinction.
var specialUse = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"),
}

// A prober connects wherever it is told. Requests are signed, so only the
// coordinator can tell it — but that is authentication, not authorisation. A
// coordinator with a bug, or one that has been taken over, could otherwise
// point every prober in the fleet at a cloud metadata endpoint or an internal
// admin panel, and probers sit inside networks precisely where that is worth
// something.
//
// So the address is checked at connect time rather than the hostname being
// checked up front. Resolving a name and then dialling it separately is a
// DNS-rebinding hole: the name resolves to something allowed, and the dial
// resolves it again to something else. Dialer.Control runs with the actual
// address being connected to, after resolution, for every attempt.

// Policy is the operator's statement of where this prober may connect. It
// belongs to the prober rather than to a check: the coordinator says what to
// probe, the host's owner says what is reachable at all, and the second must
// not be overridable by the first.
type Policy struct {
	// Allow, when non-empty, is exhaustive: an address outside every prefix
	// is refused. Empty means "anywhere the built-in rules permit", which is
	// the right default for a prober on a public network and the wrong one
	// for a prober sitting inside something sensitive.
	Allow []netip.Prefix

	// Deny is subtracted from whatever Allow permits. Deny wins, so a narrow
	// exclusion inside a broad allowance does what it looks like.
	Deny []netip.Prefix
}

// blockedTarget explains why an address was refused.
type blockedTarget struct {
	addr   netip.Addr
	reason string
}

func (b *blockedTarget) Error() string {
	return fmt.Sprintf("refusing to probe %s: %s", b.addr, b.reason)
}

// allows reports whether this vantage and policy permit connecting to addr.
//
// The order is deliberate. Built-in refusals and vantage rules come first and
// cannot be re-enabled by an allowlist — an operator who writes 0.0.0.0/0 has
// said "anywhere reasonable", not "including the metadata service". Then deny,
// then allow.
func (p Policy) allows(v check.Vantage, addr netip.Addr) error {
	switch {
	case addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast():
		// 169.254.169.254 and friends. Refused for every vantage and every
		// policy: no availability check legitimately wants a metadata service.
		return &blockedTarget{addr, "link-local addresses are never probed " +
			"(cloud metadata lives there)"}
	case addr.IsMulticast():
		return &blockedTarget{addr, "multicast is not a probe target"}
	case addr.IsUnspecified():
		return &blockedTarget{addr, "the unspecified address is not a probe target"}
	}

	if v == check.VantagePublic {
		switch {
		case addr.IsLoopback():
			return &blockedTarget{addr, "a public-vantage check cannot be satisfied " +
				"by loopback — it claims to test what the internet sees"}
		case addr.IsPrivate() || isULA(addr):
			return &blockedTarget{addr, "a public-vantage check cannot be satisfied " +
				"by a private address"}
		case inPrefixes(specialUse, addr):
			return &blockedTarget{addr, "a public-vantage check cannot use special-use address space"}
		}
	}

	if pfx, ok := match(p.Deny, addr); ok {
		return &blockedTarget{addr, fmt.Sprintf("this prober denies %s", pfx)}
	}
	if len(p.Allow) > 0 {
		if _, ok := match(p.Allow, addr); !ok {
			return &blockedTarget{addr, "outside every network this prober is allowed to probe"}
		}
	}
	return nil
}

func inPrefixes(prefixes []netip.Prefix, addr netip.Addr) bool {
	_, ok := match(prefixes, addr)
	return ok
}

func match(prefixes []netip.Prefix, addr netip.Addr) (netip.Prefix, bool) {
	for _, pfx := range prefixes {
		// Both sides are unmapped so an IPv4-mapped IPv6 address is judged as
		// the IPv4 address it is — otherwise ::ffff:10.0.0.1 slips past a
		// 10.0.0.0/8 rule.
		if pfx.Masked().Contains(addr) {
			return pfx, true
		}
	}
	return netip.Prefix{}, false
}

// isULA reports whether addr is an IPv6 unique local address (fc00::/7),
// which netip.Addr.IsPrivate does not cover.
func isULA(addr netip.Addr) bool {
	if !addr.Is6() || addr.Is4In6() {
		return false
	}
	return addr.As16()[0]&0xfe == 0xfc
}

// guardedDialer returns a dialer that refuses addresses this vantage and
// policy forbid. base may be nil.
func guardedDialer(v check.Vantage, p Policy, base *net.Dialer) *net.Dialer {
	d := &net.Dialer{}
	if base != nil {
		copied := *base
		d = &copied
	}

	inner := d.Control
	d.Control = func(network, address string, c syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("refusing to probe %q: %w", address, err)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			// Control is called with a resolved address; anything else means
			// an assumption here is wrong, so refuse rather than guess.
			return fmt.Errorf("refusing to probe %q: not a resolved address", host)
		}
		if err := p.allows(v, addr.Unmap()); err != nil {
			return err
		}
		if inner != nil {
			return inner(network, address, c)
		}
		return nil
	}
	return d
}

// ParsePrefixes turns config strings into prefixes, accepting a bare address
// as a single-host prefix so an operator can write "192.0.2.10" rather than
// "192.0.2.10/32".
func ParsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		if pfx, err := netip.ParsePrefix(s); err == nil {
			out = append(out, pfx.Masked())
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is neither an address nor a CIDR prefix", s)
		}
		out = append(out, netip.PrefixFrom(addr.Unmap(), addr.BitLen()))
	}
	return out, nil
}
