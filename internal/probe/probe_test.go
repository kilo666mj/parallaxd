package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

func httpCheck(target string) check.Check {
	return check.Check{
		Name: "test", Kind: check.KindHTTP, Target: target,
		Vantage: check.VantageInternal, Interval: time.Minute, Timeout: 5 * time.Second,
		Quorum: check.Quorum{Agree: 2, Of: 3},
	}
}

func tcpCheck(target string) check.Check {
	c := httpCheck(target)
	c.Kind = check.KindTCP
	return c
}

func TestHTTPUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "all good")
	}))
	defer srv.Close()

	r := Run(t.Context(), HTTP{}, httpCheck(srv.URL), "probe-a", "hetzner")
	if r.Status != check.StatusUp {
		t.Fatalf("status = %q (%s), want up", r.Status, r.Detail)
	}
	if r.Latency <= 0 {
		t.Error("latency not recorded for a successful probe")
	}
	if r.Prober != "probe-a" || r.Provider != "hetzner" || r.Check != "test" {
		t.Errorf("identity not stamped: %+v", r)
	}
	if r.Vantage != check.VantageInternal {
		t.Errorf("vantage = %q, want it carried from the check", r.Vantage)
	}
	if !r.IsEvidence() {
		t.Error("an up result must count as evidence")
	}
}

func TestHTTPBadStatusIsDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := Run(t.Context(), HTTP{}, httpCheck(srv.URL), "probe-a", "")
	if r.Status != check.StatusDown {
		t.Fatalf("status = %q, want down", r.Status)
	}
	if !strings.Contains(r.Detail, "500") {
		t.Errorf("detail = %q, want the status code", r.Detail)
	}
}

func TestHTTPExpectStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	// A 401 is the correct answer from an endpoint that requires auth, so a
	// check must be able to say so.
	c := httpCheck(srv.URL)
	c.ExpectStatus = []int{401}
	if r := Run(t.Context(), HTTP{}, c, "probe-a", ""); r.Status != check.StatusUp {
		t.Errorf("status = %q (%s), want up when 401 is expected", r.Status, r.Detail)
	}

	c.ExpectStatus = []int{200}
	if r := Run(t.Context(), HTTP{}, c, "probe-a", ""); r.Status != check.StatusDown {
		t.Errorf("status = %q, want down when 401 is not expected", r.Status)
	}
}

func TestHTTPMethodHeadersAndBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer test" || string(body) != "ping" {
			http.Error(w, "wrong request", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, "accepted")
	}))
	defer srv.Close()
	c := httpCheck(srv.URL)
	c.HTTPMethod = "POST"
	c.HTTPHeaders = map[string]string{"Authorization": "Bearer test"}
	c.HTTPBody = "ping"
	c.ExpectStatus = []int{http.StatusCreated}
	c.ExpectBody = "accepted"
	status, _, detail := HTTP{}.Probe(t.Context(), c)
	if status != check.StatusUp {
		t.Fatalf("status=%s detail=%s", status, detail)
	}
}

// A service returning 200 with an error page is still down, and body matching
// is the only way a probe can tell.
func TestHTTPBodyMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<h1>Service Temporarily Unavailable</h1>")
	}))
	defer srv.Close()

	c := httpCheck(srv.URL)
	c.ExpectBody = "welcome"
	r := Run(t.Context(), HTTP{}, c, "probe-a", "")
	if r.Status != check.StatusDown {
		t.Fatalf("status = %q, want down when the body is wrong", r.Status)
	}
	if !strings.Contains(r.Detail, "welcome") {
		t.Errorf("detail = %q, want it to name what was missing", r.Detail)
	}
}

// A probe must never be the thing that exhausts memory on the host it runs on.
func TestHTTPBodyReadIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := strings.Repeat("x", 8<<10)
		for range 64 { // 512 KiB, well past the 64 KiB cap
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	c := httpCheck(srv.URL)
	c.ExpectBody = "never-present"
	r := Run(t.Context(), HTTP{}, c, "probe-a", "")
	if r.Status != check.StatusDown {
		t.Errorf("status = %q, want down", r.Status)
	}
}

func TestTCPUpAndDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	if r := Run(t.Context(), TCP{}, tcpCheck(addr), "probe-a", ""); r.Status != check.StatusUp {
		t.Errorf("status = %q (%s), want up against a listener", r.Status, r.Detail)
	}

	ln.Close()
	r := Run(t.Context(), TCP{}, tcpCheck(addr), "probe-a", "")
	if r.Status != check.StatusDown {
		t.Errorf("status = %q, want down once the listener is gone", r.Status)
	}
	if !r.IsEvidence() {
		t.Error("a refused connection is evidence about the target")
	}
}

// The distinction the whole design rests on: a prober whose own resolver is
// broken has learned nothing about the target, and must not vote for down.
func TestUnresolvableNameIsUnknownNotDown(t *testing.T) {
	// .invalid is reserved by RFC 2606 and must never resolve.
	c := tcpCheck("nothing.here.invalid:443")
	r := Run(t.Context(), TCP{}, c, "probe-a", "")
	if r.Status != check.StatusUnknown {
		t.Fatalf("status = %q (%s), want unknown for a DNS failure", r.Status, r.Detail)
	}
	if r.IsEvidence() {
		t.Error("an unknown must not count as evidence — that is how a broken " +
			"resolver becomes a false outage")
	}
	if !strings.Contains(r.Detail, "resolve") {
		t.Errorf("detail = %q, want it to say resolution failed", r.Detail)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want check.Status
	}{
		{"success", nil, check.StatusUp},
		{"cancelled", context.Canceled, check.StatusUnknown},
		{"dns", &net.DNSError{Name: "x.invalid", Err: "no such host"}, check.StatusUnknown},
		{"no route", errors.New("dial tcp 10.0.0.1:80: connect: no route to host"), check.StatusUnknown},
		{"unreachable", errors.New("dial tcp: connect: network is unreachable"), check.StatusUnknown},
		// Evidence about the target: someone declined to answer.
		{"refused", errors.New("dial tcp 127.0.0.1:1: connect: connection refused"), check.StatusDown},
		{"reset", errors.New("read: connection reset by peer"), check.StatusDown},
		// A timeout is treated as evidence on purpose. A genuinely cut-off
		// prober times out on everything, which the fleet-wide view catches;
		// calling every timeout unknown would suppress real outages.
		{"timeout", errors.New("i/o timeout"), check.StatusDown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, detail := classify(tc.err)
			if got != tc.want {
				t.Errorf("classify(%v) = %q, want %q (detail %q)", tc.err, got, tc.want, detail)
			}
			if tc.err != nil && detail == "" {
				t.Error("a non-success classification must explain itself")
			}
		})
	}
}

// A check the prober cannot honour is unknown, not down — every prober would
// report the same thing, and it says nothing about the target.
func TestWrongKindIsUnknown(t *testing.T) {
	r := Run(t.Context(), TCP{}, httpCheck("http://example.invalid"), "probe-a", "")
	if r.Status != check.StatusUnknown {
		t.Fatalf("status = %q, want unknown", r.Status)
	}
	if !strings.Contains(r.Detail, "speaks") {
		t.Errorf("detail = %q, want it to name the mismatch", r.Detail)
	}
}

func TestInvalidCheckIsUnknown(t *testing.T) {
	c := httpCheck("http://example.invalid")
	c.Vantage = "" // the field a check must not omit
	r := Run(t.Context(), HTTP{}, c, "probe-a", "")
	if r.Status != check.StatusUnknown {
		t.Fatalf("status = %q, want unknown for an invalid check", r.Status)
	}
	if !strings.Contains(r.Detail, "vantage") {
		t.Errorf("detail = %q, want it to name the offending field", r.Detail)
	}
}

func TestTimeoutIsBoundedByCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	c := httpCheck(srv.URL)
	c.Timeout = 150 * time.Millisecond

	start := time.Now()
	r := Run(t.Context(), HTTP{}, c, "probe-a", "")
	elapsed := time.Since(start)

	if r.Status != check.StatusDown {
		t.Errorf("status = %q (%s), want down for a target that never answers", r.Status, r.Detail)
	}
	if elapsed > 2*time.Second {
		t.Errorf("probe took %s; the check timeout was not applied", elapsed)
	}
}

// bannerServer answers with greeting, then records anything the client sends
// before hanging up.
func bannerServer(t *testing.T, greeting string) (addr string, sent <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	got := make(chan string, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if greeting != "" {
					conn.Write([]byte(greeting))
				}
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 64)
				n, _ := conn.Read(buf)
				got <- string(buf[:n])
			}()
		}
	}()
	return ln.Addr().String(), got
}

func bannerCheck(target, expect string) check.Check {
	c := tcpCheck(target)
	c.Kind = check.KindBanner
	c.ExpectBody = expect
	return c
}

// The reason this kind exists: a wedged daemon, or a forward to nothing in
// particular, both accept connections. Only the greeting says what is behind
// the port.
func TestBannerMatches(t *testing.T) {
	addr, _ := bannerServer(t, "220 mxs.example.com ESMTP Postfix\r\n")

	r := Run(t.Context(), Banner{}, bannerCheck(addr, "Postfix"), "probe-a", "hetzner")
	if r.Status != check.StatusUp {
		t.Fatalf("status = %q (%s), want up", r.Status, r.Detail)
	}
	if r.Latency <= 0 {
		t.Error("no latency recorded")
	}
}

func TestBannerMismatchIsDown(t *testing.T) {
	addr, _ := bannerServer(t, "220 something-else\r\n")

	r := Run(t.Context(), Banner{}, bannerCheck(addr, "Postfix"), "probe-a", "")
	if r.Status != check.StatusDown {
		t.Fatalf("status = %q, want down", r.Status)
	}
	// The detail has to carry what was actually seen, or an operator cannot
	// tell a changed banner from a dead service.
	if !strings.Contains(r.Detail, "something-else") || !strings.Contains(r.Detail, "Postfix") {
		t.Errorf("detail = %q, want both the greeting and the expectation", r.Detail)
	}
}

// A multi-line greeting is normal SMTP — mx answers with 220- — and matching
// must work against the first line.
func TestBannerMatchesMultilineGreeting(t *testing.T) {
	addr, _ := bannerServer(t, "220-mx.example.com ESMTP Postcow\r\n220 ready\r\n")

	if r := Run(t.Context(), Banner{}, bannerCheck(addr, "Postcow"), "probe-a", ""); r.Status != check.StatusUp {
		t.Fatalf("status = %q (%s), want up", r.Status, r.Detail)
	}
}

// Accepting a connection and then saying nothing is the target misbehaving,
// not this prober failing to ask — so it is evidence.
func TestBannerSilenceIsDown(t *testing.T) {
	addr, _ := bannerServer(t, "")

	c := bannerCheck(addr, "Postfix")
	c.Timeout = 300 * time.Millisecond
	r := Run(t.Context(), Banner{}, c, "probe-a", "")
	if r.Status != check.StatusDown {
		t.Fatalf("status = %q (%s), want down", r.Status, r.Detail)
	}
	if !r.IsEvidence() {
		t.Error("a silent target must count as evidence")
	}
}

// A probe that drops an SMTP session without QUIT logs "lost connection after
// CONNECT" on the far side every interval, and postscreen scores the abrupt
// disconnect — so a monitor could get itself deny-listed by the server it
// watches.
func TestBannerSendsTheGoodbye(t *testing.T) {
	addr, sent := bannerServer(t, "220 mxs.example.com ESMTP Postfix\r\n")

	c := bannerCheck(addr, "Postfix")
	c.Send = "QUIT\r\n"
	if r := Run(t.Context(), Banner{}, c, "probe-a", ""); r.Status != check.StatusUp {
		t.Fatalf("status = %q (%s), want up", r.Status, r.Detail)
	}

	select {
	case got := <-sent:
		if got != "QUIT\r\n" {
			t.Errorf("server received %q, want QUIT", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the probe hung up without saying anything")
	}
}

// Nothing listening is the same evidence as for a TCP check.
func TestBannerRefusedIsDown(t *testing.T) {
	addr, _ := bannerServer(t, "220 x\r\n")
	// Reuse the address after closing so nothing is listening.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	_ = addr

	r := Run(t.Context(), Banner{}, bannerCheck(dead, "Postfix"), "probe-a", "")
	if r.Status != check.StatusDown {
		t.Errorf("status = %q, want down", r.Status)
	}
}

// A banner check with nothing to match is a TCP check that reads a few bytes
// first, and pretending otherwise overstates what it verifies.
func TestBannerWithoutExpectationIsInvalid(t *testing.T) {
	c := bannerCheck("127.0.0.1:25", "")
	if err := c.Validate(); err == nil {
		t.Fatal("Validate accepted a banner check with no expect_body")
	}
	r := Run(t.Context(), Banner{}, c, "probe-a", "")
	if r.Status != check.StatusUnknown {
		t.Errorf("status = %q, want unknown for an invalid check", r.Status)
	}
}
