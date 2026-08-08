package probe

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

// A prober connects wherever it is told, and requests are signed — but that is
// authentication, not authorisation. A coordinator with a bug, or one that has
// been taken over, must not be able to aim the fleet at cloud metadata or at
// private infrastructure a public check has no business reaching.
func TestCheckAddr(t *testing.T) {
	cases := []struct {
		addr    string
		vantage check.Vantage
		blocked bool
		because string
	}{
		// Never, for any vantage: this is where cloud metadata lives.
		{"169.254.169.254", check.VantagePublic, true, "link-local"},
		{"169.254.169.254", check.VantageInternal, true, "link-local"},
		{"fe80::1", check.VantageInternal, true, "link-local"},

		// A public-vantage check claims to test what the internet sees, so it
		// cannot be satisfied from inside.
		{"127.0.0.1", check.VantagePublic, true, "loopback"},
		{"10.0.0.1", check.VantagePublic, true, "private"},
		{"192.168.1.1", check.VantagePublic, true, "private"},
		{"172.16.0.1", check.VantagePublic, true, "private"},
		{"fd00::1", check.VantagePublic, true, "private"},

		// An internal check is for exactly these.
		{"127.0.0.1", check.VantageInternal, false, ""},
		{"10.0.0.1", check.VantageInternal, false, ""},
		{"fd00::1", check.VantageInternal, false, ""},

		// Ordinary public addresses are fine either way.
		{"1.1.1.1", check.VantagePublic, false, ""},
		{"2606:4700:4700::1111", check.VantagePublic, false, ""},

		{"239.1.1.1", check.VantageInternal, true, "multicast"}, // not link-local, so it reaches the multicast rule
		{"0.0.0.0", check.VantagePublic, true, "unspecified"},
	}

	for _, c := range cases {
		t.Run(c.addr+"/"+string(c.vantage), func(t *testing.T) {
			err := Policy{}.allows(c.vantage, netip.MustParseAddr(c.addr))
			if c.blocked && err == nil {
				t.Fatalf("%s was allowed for a %s check", c.addr, c.vantage)
			}
			if !c.blocked && err != nil {
				t.Fatalf("%s was refused for a %s check: %v", c.addr, c.vantage, err)
			}
			if c.blocked && !strings.Contains(err.Error(), c.because) {
				t.Errorf("reason = %q, want it to mention %q", err, c.because)
			}
		})
	}
}

// An IPv4-mapped IPv6 address must be judged as the IPv4 address it is, or
// ::ffff:169.254.169.254 walks straight past the guard.
func TestMappedAddressesAreUnwrapped(t *testing.T) {
	mapped := netip.MustParseAddr("::ffff:169.254.169.254")
	if err := (Policy{}).allows(check.VantageInternal, mapped.Unmap()); err == nil {
		t.Error("an IPv4-mapped link-local address was allowed")
	}
	mappedPrivate := netip.MustParseAddr("::ffff:10.0.0.1")
	if err := (Policy{}).allows(check.VantagePublic, mappedPrivate.Unmap()); err == nil {
		t.Error("an IPv4-mapped private address was allowed for a public check")
	}
}

func TestPublicVantageRejectsSpecialUseNetworks(t *testing.T) {
	p := Policy{}
	for _, raw := range []string{
		"100.64.0.1", "192.0.2.1", "198.18.0.1", "203.0.113.1",
		"64:ff9b:1::1", "2001:db8::1",
	} {
		addr := netip.MustParseAddr(raw)
		if err := p.allows(check.VantagePublic, addr); err == nil {
			t.Errorf("public vantage allowed special-use address %s", addr)
		}
		if err := p.allows(check.VantageInternal, addr); err != nil {
			t.Errorf("internal vantage rejected %s: %v", addr, err)
		}
	}
}

// The guard runs at connect time against the resolved address, so a name that
// resolves to a forbidden address is refused — and no packet is sent.
func TestGuardBlocksAtDialTime(t *testing.T) {
	target := newCounted(t)

	c := check.Check{
		Name: "t", Kind: check.KindTCP, Target: target.addr,
		Vantage:  check.VantagePublic, // loopback is forbidden for this vantage
		Interval: time.Minute, Timeout: time.Second,
		Quorum: check.Quorum{Agree: 1, Of: 1},
	}
	r := Run(t.Context(), TCP{}, c, "probe-a", "")

	if r.Status != check.StatusUnknown {
		t.Fatalf("status = %q (%s), want unknown", r.Status, r.Detail)
	}
	if r.IsEvidence() {
		t.Error("a blocked target must not count as evidence about the target")
	}
	if target.hits.Load() != 0 {
		t.Errorf("target was contacted %d times despite being blocked", target.hits.Load())
	}
	if !strings.Contains(r.Detail, "refusing to probe") {
		t.Errorf("detail = %q", r.Detail)
	}
}

func TestGuardAppliesToHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	c := check.Check{
		Name: "t", Kind: check.KindHTTP, Target: srv.URL,
		Vantage:  check.VantagePublic,
		Interval: time.Minute, Timeout: time.Second,
		Quorum: check.Quorum{Agree: 1, Of: 1},
	}
	r := Run(t.Context(), HTTP{}, c, "probe-a", "")
	if r.Status != check.StatusUnknown {
		t.Fatalf("status = %q (%s), want unknown", r.Status, r.Detail)
	}
	if !strings.Contains(r.Detail, "refusing to probe") {
		t.Errorf("detail = %q", r.Detail)
	}
}

type counted struct {
	addr string
	hits atomic.Int64
}

func newCounted(t *testing.T) *counted {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c := &counted{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.hits.Add(1)
			conn.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return c
}

// The allowlist is the operator's statement of what this host may reach at
// all, independent of what the coordinator asks for. It closes the residual
// exposure the vantage rules leave: an internal-vantage check can otherwise
// reach anything private, which is a pivot if the coordinator is taken over.
func TestAllowlistIsExhaustive(t *testing.T) {
	p := Policy{Allow: mustPrefixes(t, "10.0.0.0/8", "192.0.2.0/24")}

	for _, addr := range []string{"10.1.2.3", "192.0.2.7"} {
		if err := p.allows(check.VantageInternal, netip.MustParseAddr(addr)); err != nil {
			t.Errorf("%s is inside the allowlist but was refused: %v", addr, err)
		}
	}
	for _, addr := range []string{"172.16.0.1", "198.51.100.1"} {
		err := p.allows(check.VantageInternal, netip.MustParseAddr(addr))
		if err == nil {
			t.Errorf("%s is outside the allowlist but was allowed", addr)
			continue
		}
		if !strings.Contains(err.Error(), "outside every network") {
			t.Errorf("reason = %q", err)
		}
	}
}

// Deny wins, so a narrow exclusion inside a broad allowance does what it
// looks like — "everything on our network except the admin subnet".
func TestDenyBeatsAllow(t *testing.T) {
	p := Policy{
		Allow: mustPrefixes(t, "10.0.0.0/8"),
		Deny:  mustPrefixes(t, "10.9.0.0/16"),
	}
	if err := p.allows(check.VantageInternal, netip.MustParseAddr("10.1.0.1")); err != nil {
		t.Errorf("an allowed address was refused: %v", err)
	}
	err := p.allows(check.VantageInternal, netip.MustParseAddr("10.9.0.1"))
	if err == nil {
		t.Fatal("a denied address inside the allowlist was permitted")
	}
	if !strings.Contains(err.Error(), "denies") {
		t.Errorf("reason = %q, want it to name the denial", err)
	}
}

// Deny works without an allowlist too: "anywhere reasonable, except here".
func TestDenyWithoutAllow(t *testing.T) {
	p := Policy{Deny: mustPrefixes(t, "203.0.113.0/24")}
	if err := p.allows(check.VantagePublic, netip.MustParseAddr("1.1.1.1")); err != nil {
		t.Errorf("an ordinary address was refused: %v", err)
	}
	if err := p.allows(check.VantagePublic, netip.MustParseAddr("203.0.113.5")); err == nil {
		t.Error("a denied address was permitted")
	}
}

// An operator writing 0.0.0.0/0 has said "anywhere reasonable", not
// "including the metadata service". The built-in and vantage rules are not
// re-enablable by an allowlist.
func TestAllowlistCannotReEnableBuiltinRefusals(t *testing.T) {
	p := Policy{Allow: mustPrefixes(t, "0.0.0.0/0", "::/0")}

	if err := p.allows(check.VantageInternal, netip.MustParseAddr("169.254.169.254")); err == nil {
		t.Error("an allowlist re-enabled the metadata address")
	}
	if err := p.allows(check.VantagePublic, netip.MustParseAddr("10.0.0.1")); err == nil {
		t.Error("an allowlist overrode the public-vantage private-address rule")
	}
}

// ::ffff:10.0.0.1 must be judged against a 10.0.0.0/8 rule as the IPv4
// address it is, or the allowlist is trivially bypassed.
func TestMappedAddressesMatchIPv4Prefixes(t *testing.T) {
	p := Policy{Allow: mustPrefixes(t, "10.0.0.0/8")}
	mapped := netip.MustParseAddr("::ffff:10.1.2.3").Unmap()
	if err := p.allows(check.VantageInternal, mapped); err != nil {
		t.Errorf("a mapped IPv4 address did not match its IPv4 prefix: %v", err)
	}

	deny := Policy{Deny: mustPrefixes(t, "10.0.0.0/8")}
	if err := deny.allows(check.VantageInternal, mapped); err == nil {
		t.Error("a mapped IPv4 address slipped past an IPv4 deny rule")
	}
}

func TestIPv6Prefixes(t *testing.T) {
	p := Policy{Allow: mustPrefixes(t, "2001:db8::/32")}
	if err := p.allows(check.VantageInternal, netip.MustParseAddr("2001:db8::1")); err != nil {
		t.Errorf("an address inside the v6 allowlist was refused: %v", err)
	}
	if err := p.allows(check.VantageInternal, netip.MustParseAddr("2606:4700::1")); err == nil {
		t.Error("an address outside the v6 allowlist was permitted")
	}
}

// The policy reaches the wire: a probe to a disallowed target sends nothing.
func TestPolicyBlocksAtDialTime(t *testing.T) {
	target := newCounted(t)

	c := check.Check{
		Name: "t", Kind: check.KindTCP, Target: target.addr,
		Vantage:  check.VantageInternal, // loopback is fine for this vantage
		Interval: time.Minute, Timeout: time.Second,
		Quorum: check.Quorum{Agree: 1, Of: 1},
	}
	// …but this prober is only allowed to reach 10.0.0.0/8.
	tcp := TCP{Policy: Policy{Allow: mustPrefixes(t, "10.0.0.0/8")}}

	r := Run(t.Context(), tcp, c, "probe-a", "")
	if r.Status != check.StatusUnknown {
		t.Fatalf("status = %q (%s), want unknown", r.Status, r.Detail)
	}
	if target.hits.Load() != 0 {
		t.Errorf("target was contacted %d times despite the policy", target.hits.Load())
	}

	// Control: with loopback allowed, the same probe succeeds.
	tcp.Policy = Policy{Allow: mustPrefixes(t, "127.0.0.0/8")}
	if r := Run(t.Context(), tcp, c, "probe-a", ""); r.Status != check.StatusUp {
		t.Errorf("status = %q (%s), want up when allowed", r.Status, r.Detail)
	}
}

func TestParsePrefixes(t *testing.T) {
	got, err := ParsePrefixes([]string{"10.0.0.0/8", "192.0.2.10", "2001:db8::/32", "::1"})
	if err != nil {
		t.Fatalf("ParsePrefixes: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d prefixes", len(got))
	}
	// A bare address becomes a single-host prefix, so an operator can write
	// the obvious thing.
	if got[1].String() != "192.0.2.10/32" {
		t.Errorf("bare address became %q, want /32", got[1])
	}
	if got[3].String() != "::1/128" {
		t.Errorf("bare v6 address became %q, want /128", got[3])
	}
	// Host bits in a prefix are masked off, so 10.1.2.3/8 means 10.0.0.0/8
	// rather than silently matching nothing.
	masked, err := ParsePrefixes([]string{"10.1.2.3/8"})
	if err != nil {
		t.Fatalf("ParsePrefixes: %v", err)
	}
	if masked[0].String() != "10.0.0.0/8" {
		t.Errorf("prefix = %q, want host bits masked", masked[0])
	}

	if _, err := ParsePrefixes([]string{"not-an-address"}); err == nil {
		t.Error("garbage was accepted as a prefix")
	}
}

func mustPrefixes(t *testing.T, in ...string) []netip.Prefix {
	t.Helper()
	out, err := ParsePrefixes(in)
	if err != nil {
		t.Fatalf("ParsePrefixes(%v): %v", in, err)
	}
	return out
}
