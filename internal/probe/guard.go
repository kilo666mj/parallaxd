package probe

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/kilo666mj/parallaxd/internal/check"
)

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
//
// The rules follow from the vantage the check already has to declare:
//
//   - Nothing may reach link-local. Cloud metadata services live at
//     169.254.169.254 and fe80::/10, and no legitimate availability check
//     targets them.
//   - A public-vantage check may not reach loopback or private space. Such a
//     check is incoherent: it claims to test what a user on the internet sees,
//     and no user on the internet reaches 10.0.0.1.
//
// An internal-vantage check may reach private space, because that is what it
// is for.

// blockedTarget explains why an address was refused.
type blockedTarget struct {
	addr   netip.Addr
	reason string
}

func (b *blockedTarget) Error() string {
	return fmt.Sprintf("refusing to probe %s: %s", b.addr, b.reason)
}

// checkAddr reports whether this vantage may connect to addr.
func checkAddr(v check.Vantage, addr netip.Addr) error {
	switch {
	case addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast():
		// 169.254.169.254 and friends. Refused for every vantage: there is no
		// availability check that legitimately wants a metadata service.
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
		}
	}
	return nil
}

// isULA reports whether addr is an IPv6 unique local address (fc00::/7),
// which netip.Addr.IsPrivate does not cover.
func isULA(addr netip.Addr) bool {
	if !addr.Is6() || addr.Is4In6() {
		return false
	}
	return addr.As16()[0]&0xfe == 0xfc
}

// guardedDialer returns a dialer that refuses addresses this vantage may not
// reach. base may be nil.
func guardedDialer(v check.Vantage, base *net.Dialer) *net.Dialer {
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
		if err := checkAddr(v, addr.Unmap()); err != nil {
			return err
		}
		if inner != nil {
			return inner(network, address, c)
		}
		return nil
	}
	return d
}
