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
			err := checkAddr(c.vantage, netip.MustParseAddr(c.addr))
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
	if err := checkAddr(check.VantageInternal, mapped.Unmap()); err == nil {
		t.Error("an IPv4-mapped link-local address was allowed")
	}
	mappedPrivate := netip.MustParseAddr("::ffff:10.0.0.1")
	if err := checkAddr(check.VantagePublic, mappedPrivate.Unmap()); err == nil {
		t.Error("an IPv4-mapped private address was allowed for a public check")
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
