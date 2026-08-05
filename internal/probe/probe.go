// Package probe runs a single check and reports what happened.
//
// The interesting work is not connecting to things — it is deciding, when a
// connection fails, whether that says something about the target or only
// about this prober. Getting that wrong in the pessimistic direction turns
// every local hiccup into evidence of an outage, which is the failure mode
// parallaxd exists to remove.
//
// # On request forgery
//
// This package makes network requests to addresses it is given, which static
// analysis flags as server-side request forgery — correctly, in the sense that
// the destination comes from outside. It is also the entire purpose: an
// availability monitor that cannot be told what to check is not one.
//
// The exposure is managed rather than eliminated, in two layers:
//
//   - Requests are signed (see internal/wire), so only the coordinator can
//     direct a probe. That establishes who is asking.
//   - The vantage guard in guard.go restricts where a probe may connect, at
//     dial time, against the resolved address. That constrains what may be
//     asked for, including from a coordinator that has been taken over.
//
// A CodeQL go/request-forgery alert on the HTTP prober is expected and has
// been dismissed on that basis. If this package ever gains a probe target that
// is not operator-configured — a redirect followed automatically, a target
// read from a response body — that reasoning no longer holds and the alert
// should be reinstated.
package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

// maxBodyRead bounds how much of a response body is read when a check wants
// to match against it. A monitoring probe must never be the thing that runs a
// host out of memory because a target started streaming.
const maxBodyRead = 64 << 10

// Prober runs checks of one kind.
type Prober interface {
	Kind() check.Kind
	Probe(ctx context.Context, c check.Check) (check.Status, time.Duration, string)
}

// Run executes a check and builds the result, filling in the identity of this
// prober. It never returns an error: a probe that cannot be performed is a
// result with StatusUnknown, because "I could not tell" is information the
// coordinator needs rather than a failure to report.
func Run(ctx context.Context, p Prober, c check.Check, prober, provider string) check.Result {
	r := check.Result{
		Check:    c.Name,
		Prober:   prober,
		Provider: provider,
		Vantage:  c.Vantage,
		At:       time.Now().UTC(),
	}
	if err := c.Validate(); err != nil {
		r.Status = check.StatusUnknown
		r.Detail = fmt.Sprintf("invalid check: %v", err)
		return r
	}
	if p.Kind() != c.Kind {
		r.Status = check.StatusUnknown
		r.Detail = fmt.Sprintf("prober speaks %q, check is %q", p.Kind(), c.Kind)
		return r
	}

	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	status, latency, detail := p.Probe(ctx, c)
	r.Status, r.Latency, r.Detail = status, latency, detail
	return r
}

// classify decides whether a failed attempt is evidence about the target or
// only about this prober.
//
// The rule: a failure that required reaching the target to observe is
// evidence (refused, reset, timed out — someone is not answering). A failure
// that happened before the target was ever contacted is not (the local
// resolver broke, there is no route at all, the attempt was cancelled).
//
// Timeouts are deliberately treated as evidence even though a broken network
// also produces them. A prober that is genuinely cut off times out on
// *everything*, and that is caught by the fleet-wide view rather than by
// second-guessing each probe — which would suppress real outages.
func classify(err error) (check.Status, string) {
	if err == nil {
		return check.StatusUp, ""
	}

	// Cancelled or deadline from the caller's own context, not the target
	// being slow: we stopped asking before learning anything.
	if errors.Is(err, context.Canceled) {
		return check.StatusUnknown, "probe cancelled before completing"
	}

	// Refused by the vantage guard before any packet left. That says the
	// check is misconfigured — or that something is trying to aim this prober
	// somewhere it should not go — and says nothing about the target.
	var blocked *blockedTarget
	if errors.As(err, &blocked) {
		return check.StatusUnknown, blocked.Error()
	}

	// A name that will not resolve is a statement about DNS, which may be
	// this prober's resolver rather than the target. Corroboration from a
	// prober with working DNS settles it.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return check.StatusUnknown, fmt.Sprintf("could not resolve %s: %s", dnsErr.Name, dnsErr.Err)
	}

	// No route at all means this host cannot get onto the network. It has
	// learned nothing about the target.
	if isNoRoute(err) {
		return check.StatusUnknown, fmt.Sprintf("no network path from this prober: %v", unwrapOp(err))
	}

	return check.StatusDown, unwrapOp(err).Error()
}

func isNoRoute(err error) bool {
	// Matched on text because the portable errno constants live in
	// x/sys/unix, and this must build on any platform a prober runs on.
	s := err.Error()
	for _, needle := range []string{
		"network is unreachable",
		"no route to host",
		"host is down",
	} {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

// unwrapOp strips the *net.OpError and *url.Error wrappers, whose Error()
// repeats the address already recorded in the result.
func unwrapOp(err error) error {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		return opErr.Err
	}
	return err
}

// TCP probes by opening a connection and closing it.
type TCP struct {
	// Dialer is used for every connection. Callers override it to bind a
	// source address, which is how a prober offers a specific vantage.
	Dialer *net.Dialer
}

func (TCP) Kind() check.Kind { return check.KindTCP }

func (t TCP) Probe(ctx context.Context, c check.Check) (check.Status, time.Duration, string) {
	d := guardedDialer(c.Vantage, t.Dialer)
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", c.Target)
	latency := time.Since(start)
	if err != nil {
		status, detail := classify(err)
		return status, 0, detail
	}
	conn.Close()
	return check.StatusUp, latency, ""
}

// HTTP probes by making a request and checking the response.
type HTTP struct {
	// Client is used for every request. Callers override it to control the
	// transport — source address, proxy, TLS settings.
	Client *http.Client
}

func (HTTP) Kind() check.Kind { return check.KindHTTP }

func (h HTTP) Probe(ctx context.Context, c check.Check) (check.Status, time.Duration, string) {
	client := h.Client
	if client == nil {
		// No global timeout: the context already carries the check's, and a
		// second one would produce a less specific error.
		client = &http.Client{}
	}
	// Give the client a transport that refuses addresses this vantage may not
	// reach. Done here rather than by validating the URL up front because the
	// check has to happen against the resolved address, at connect time, or a
	// name that resolves differently on the second lookup slips past it.
	if client.Transport == nil {
		client = &http.Client{
			CheckRedirect: client.CheckRedirect,
			Jar:           client.Jar,
			Timeout:       client.Timeout,
			Transport: &http.Transport{
				DialContext:           guardedDialer(c.Vantage, nil).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConnsPerHost:   1,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
			},
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Target, nil)
	if err != nil {
		// A malformed target is a configuration problem, not a target
		// failure, and every prober would report it identically.
		return check.StatusUnknown, 0, fmt.Sprintf("invalid target: %v", err)
	}

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	if err != nil {
		status, detail := classify(err)
		return status, 0, detail
	}
	defer resp.Body.Close()

	if !statusAcceptable(resp.StatusCode, c.ExpectStatus) {
		return check.StatusDown, latency, fmt.Sprintf("HTTP %s", resp.Status)
	}

	if c.ExpectBody != "" {
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
		if err != nil {
			// The response started and then broke, which is the target
			// misbehaving rather than this prober failing to ask.
			return check.StatusDown, latency, fmt.Sprintf("reading body: %v", err)
		}
		if !strings.Contains(string(body), c.ExpectBody) {
			// A service returning 200 with an error page is still down, and
			// this is the only way a probe can tell.
			return check.StatusDown, latency, fmt.Sprintf("body did not contain %q", c.ExpectBody)
		}
	}

	return check.StatusUp, latency, ""
}

func statusAcceptable(code int, expect []int) bool {
	if len(expect) == 0 {
		return code >= 200 && code < 300
	}
	for _, want := range expect {
		if code == want {
			return true
		}
	}
	return false
}
