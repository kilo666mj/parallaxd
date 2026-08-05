// Package check defines what parallaxd probes and what a probe produces.
//
// The types here carry two distinctions that the rest of the system depends
// on, and both are easy to collapse by accident:
//
// A result separates "the target is bad" from "I could not form an opinion".
// A prober whose own resolver is broken has learned nothing about the target,
// and counting that as evidence of failure is how a corroborating monitor
// manufactures the false alerts it exists to prevent.
//
// A check declares which network path it means. On a fleet with a private
// mesh, "reachable" over WireGuard and "reachable" from the internet are
// different claims, and a corroborator that answers the wrong one produces a
// confident all-clear about something nobody asked.
package check

import (
	"fmt"
	"strings"
	"time"
)

// Kind is the protocol a check speaks.
type Kind string

const (
	KindTCP  Kind = "tcp"
	KindHTTP Kind = "http"
)

// Vantage is the network path a probe must take.
//
// There is deliberately no default. A check that does not say which path it
// means is a check whose corroboration cannot be trusted, so an unset vantage
// is a validation error rather than an assumption.
type Vantage string

const (
	// VantagePublic means the probe must traverse the public internet, as a
	// real user would. A prober that can only reach the target over a private
	// mesh must decline rather than answer.
	VantagePublic Vantage = "public"

	// VantageInternal means the probe goes over private infrastructure — a
	// VPN, a mesh, a LAN. Says nothing about whether the world can reach it.
	VantageInternal Vantage = "internal"
)

// Check is one thing to watch.
type Check struct {
	// Name identifies the check everywhere: in assignments, results, alerts
	// and deduplication. It must be stable, because changing it splits the
	// history of one service into two.
	Name string `json:"name"`

	Kind    Kind    `json:"kind"`
	Target  string  `json:"target"`
	Vantage Vantage `json:"vantage"`

	// Interval is how often the assigned prober runs this check. Only one
	// prober runs it in steady state; the others are asked only when it fails.
	Interval time.Duration `json:"interval"`

	// Timeout bounds a single probe attempt.
	Timeout time.Duration `json:"timeout"`

	// Quorum is how many probers must agree before the result is believed.
	Quorum Quorum `json:"quorum"`

	// ExpectStatus, for HTTP, is the acceptable response code range. Empty
	// means any 2xx.
	ExpectStatus []int `json:"expect_status,omitempty"`

	// ExpectBody, for HTTP, is a substring the body must contain. A service
	// that returns 200 with an error page is still down.
	ExpectBody string `json:"expect_body,omitempty"`
}

// Quorum is the agreement rule.
type Quorum struct {
	// Agree is how many probers must independently report the same failure.
	Agree int `json:"agree"`

	// Of is how many are asked. Asking more than Agree leaves room for a
	// prober to be unreachable without stalling the verdict.
	Of int `json:"of"`

	// DistinctProviders requires the agreeing probers to sit behind different
	// providers. Three probers at one host are not three opinions, and a
	// verdict that does not know the difference overstates its confidence.
	DistinctProviders bool `json:"distinct_providers,omitempty"`
}

// Validate reports whether the check is usable.
func (c Check) Validate() error {
	switch {
	case strings.TrimSpace(c.Name) == "":
		return fmt.Errorf("check name is required")
	case c.Kind != KindTCP && c.Kind != KindHTTP:
		return fmt.Errorf("check %q: unknown kind %q", c.Name, c.Kind)
	case strings.TrimSpace(c.Target) == "":
		return fmt.Errorf("check %q: target is required", c.Name)
	case c.Vantage != VantagePublic && c.Vantage != VantageInternal:
		return fmt.Errorf("check %q: vantage must be %q or %q — a check that does "+
			"not say which path it means cannot be corroborated",
			c.Name, VantagePublic, VantageInternal)
	case c.Interval <= 0:
		return fmt.Errorf("check %q: interval must be positive", c.Name)
	case c.Timeout <= 0:
		return fmt.Errorf("check %q: timeout must be positive", c.Name)
	case c.Timeout >= c.Interval:
		// Otherwise a slow probe is still running when the next one starts,
		// and the check quietly stops being periodic.
		return fmt.Errorf("check %q: timeout (%s) must be shorter than interval (%s)",
			c.Name, c.Timeout, c.Interval)
	}
	return c.Quorum.Validate(c.Name)
}

// Validate reports whether the quorum rule is satisfiable.
func (q Quorum) Validate(checkName string) error {
	switch {
	case q.Agree < 1:
		return fmt.Errorf("check %q: quorum agree must be at least 1", checkName)
	case q.Of < q.Agree:
		return fmt.Errorf("check %q: quorum asks %d probers but requires %d to agree",
			checkName, q.Of, q.Agree)
	}
	return nil
}

// Status is what a prober concluded.
type Status string

const (
	// StatusUp means the probe completed and the target behaved.
	StatusUp Status = "up"

	// StatusDown means the probe completed and the target did not: refused,
	// timed out, wrong response. This is evidence about the target.
	StatusDown Status = "down"

	// StatusUnknown means the prober could not form an opinion — its own
	// resolver failed, it has no route at all, the attempt was cancelled, or
	// it was asked for a vantage it cannot offer.
	//
	// This is the distinction the whole design rests on. An Unknown is not a
	// vote for Down. Counting it as one is how a partitioned node, which can
	// reach nothing, reports that everything is broken.
	StatusUnknown Status = "unknown"
)

// Result is one prober's answer about one check.
type Result struct {
	Check   string    `json:"check"`
	Prober  string    `json:"prober"`
	Vantage Vantage   `json:"vantage"`
	Status  Status    `json:"status"`
	At      time.Time `json:"at"`

	// Latency is how long the probe took. Only meaningful when Status is Up.
	Latency time.Duration `json:"latency,omitempty"`

	// Detail explains a Down or Unknown in terms a human can act on.
	Detail string `json:"detail,omitempty"`

	// Provider groups probers that share a network, so a quorum can tell
	// three opinions from one opinion held three times.
	Provider string `json:"provider,omitempty"`
}

// IsEvidence reports whether this result should count toward a verdict. An
// Unknown is a statement about the prober, not about the target.
func (r Result) IsEvidence() bool {
	return r.Status == StatusUp || r.Status == StatusDown
}
