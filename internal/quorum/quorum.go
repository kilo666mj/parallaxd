// Package quorum turns a pile of probe results into a verdict.
//
// This is where corroboration actually happens, and it is deliberately pure:
// results in, verdict out, no clock of its own and no I/O. Every interesting
// decision in parallaxd is a question about counting evidence, and counting is
// much easier to get right — and to test — when nothing else is going on.
//
// The rules, in the order they are applied:
//
//   - A result that answers a different question is discarded, not counted.
//     Wrong check, wrong vantage, or stale.
//   - A prober votes once. Two results from one prober are one opinion.
//   - Unknown is not a vote. It is a statement about the prober.
//   - Down wins if it reaches quorum, even when others report up: a target
//     reachable from two places and not from three is having an outage.
//   - A prober that can reach no peer is not counted at all. Its results are
//     not weak evidence to be outvoted; they are not evidence. See
//     internal/mesh — this is the rule that stops one broken uplink becoming a
//     fleet-wide outage report.
//   - Without enough evidence, the verdict is inconclusive rather than up.
//     Silence is not an all-clear.
package quorum

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

// Options tunes evaluation. Both fields exist so the caller owns time; the
// evaluator never reads the clock.
type Options struct {
	// Now is the reference point for staleness.
	Now time.Time

	// MaxAge discards results older than this. Corroboration is a question
	// about the present, and a result from ten minutes ago answers a
	// different one. Zero disables the check.
	MaxAge time.Duration

	// Isolated names probers that can currently reach no peer. Their results
	// are discarded rather than counted: a prober with no working network path
	// has learned nothing about any target, and its view — that everything is
	// down — is the single most misleading input this system can receive.
	//
	// Passed in rather than looked up, so this package stays pure and the
	// decision to silence a prober lives in one place (internal/mesh) instead
	// of being re-derived here.
	Isolated map[string]bool
}

// Verdict is the conclusion, with enough detail for an alert to explain
// itself. A bare "down" that cannot say who agreed, from where, and who
// dissented is not actionable.
type Verdict struct {
	Check  string
	Status check.Status

	// Down, Up and Unknown count the probers whose results were counted,
	// after discarding and de-duplication.
	Down    int
	Up      int
	Unknown int

	// Counted is the number of probers that produced usable evidence.
	Counted int

	// Discarded counts results thrown out as stale, mismatched or duplicate,
	// so a misconfiguration shows up rather than silently weakening quorum.
	Discarded int

	// Suppressed counts results dropped because their prober could reach no
	// peer. Reported separately from Discarded because it means something
	// different and much more interesting: not "someone is misconfigured" but
	// "part of the fleet cannot see anything, and this verdict was reached
	// without it".
	Suppressed int

	// SuppressedProbers names them, so an alert can say whose opinion is
	// missing rather than quietly reaching a weaker conclusion.
	SuppressedProbers []string

	// Providers lists the distinct providers among the probers that agreed
	// with the verdict. "3 of 5, all one provider" is a far weaker claim than
	// "3 of 5 across three providers", and the reader deserves to know which.
	Providers []string

	// Dissent lists probers that reported the opposite of the verdict.
	Dissent []string

	// Reason explains the verdict in one line.
	Reason string
}

// Actionable reports whether this verdict justifies telling someone. Only a
// confirmed down does; inconclusive means ask again, not raise an alarm.
func (v Verdict) Actionable() bool { return v.Status == check.StatusDown }

// Evaluate applies the check's quorum rule to the results.
func Evaluate(c check.Check, results []check.Result, opts Options) Verdict {
	v := Verdict{Check: c.Name, Status: check.StatusUnknown}

	byProber := map[string]check.Result{}
	seenSuppressed := map[string]bool{}
	for _, r := range results {
		// Before anything else. An isolated prober's result is not weak
		// evidence to be outvoted — it is not evidence at all, and letting it
		// reach the counting stage is how one broken uplink becomes a
		// fleet-wide outage report.
		if opts.Isolated[r.Prober] {
			v.Suppressed++
			if !seenSuppressed[r.Prober] {
				seenSuppressed[r.Prober] = true
				v.SuppressedProbers = append(v.SuppressedProbers, r.Prober)
			}
			continue
		}
		if !usable(c, r, opts) {
			v.Discarded++
			continue
		}
		// One prober, one vote. Without this a single node that retries — or
		// replays — can manufacture a quorum by itself.
		if existing, seen := byProber[r.Prober]; seen {
			v.Discarded++
			// Keep the newer of the two so a retry after a transient failure
			// supersedes the failure rather than being ignored.
			if r.At.After(existing.At) {
				byProber[r.Prober] = r
			}
			continue
		}
		byProber[r.Prober] = r
	}
	sort.Strings(v.SuppressedProbers)

	var down, up []check.Result
	for _, r := range byProber {
		switch r.Status {
		case check.StatusDown:
			down = append(down, r)
		case check.StatusUp:
			up = append(up, r)
		default:
			v.Unknown++
		}
	}
	v.Down, v.Up = len(down), len(up)
	v.Counted = v.Down + v.Up

	// Down first: a target reachable from two vantages and unreachable from
	// three is having an outage, and reporting "up" because somebody could
	// reach it would hide a partial failure.
	if agreed, providers, ok := satisfies(c.Quorum, down); ok {
		v.Status = check.StatusDown
		v.Providers = providers
		v.Dissent = names(up)
		v.Reason = downReason(c, agreed, v, providers)
		return v
	}

	if v.Counted == 0 {
		v.Reason = fmt.Sprintf("no prober could form an opinion (%d unknown, %d discarded)",
			v.Unknown, v.Discarded)
		if v.Suppressed > 0 {
			// Said out loud. "Nobody has an opinion" and "everyone who had an
			// opinion is cut off from the fleet" look the same in the counts
			// and mean completely different things.
			v.Reason += fmt.Sprintf("; %d result(s) not counted because %s could reach no peer",
				v.Suppressed, strings.Join(v.SuppressedProbers, ", "))
		}
		return v
	}

	// Some probers said down but not enough to conclude it. This is the case
	// worth being careful about: reporting up would suppress a real outage
	// that is only visible from a minority of vantages, and reporting down
	// would alert on a single flaky path.
	if v.Down > 0 {
		v.Dissent = names(down)
		v.Reason = fmt.Sprintf("inconclusive: %d of %d reported down, quorum needs %d",
			v.Down, v.Counted, c.Quorum.Agree)
		return v
	}

	v.Status = check.StatusUp
	_, providers, _ := satisfies(check.Quorum{Agree: 1, Of: 1}, up)
	v.Providers = providers
	v.Reason = fmt.Sprintf("%d of %d reported up", v.Up, v.Counted)
	return v
}

// usable reports whether a result answers the question being asked.
func usable(c check.Check, r check.Result, opts Options) bool {
	if r.Check != c.Name {
		return false
	}
	// A prober that answered about a different network path answered a
	// different question. Letting an internal-vantage result corroborate a
	// public-vantage check is how this system would produce a confident
	// all-clear about something nobody asked.
	if r.Vantage != c.Vantage {
		return false
	}
	if opts.MaxAge > 0 && !opts.Now.IsZero() {
		if r.At.Before(opts.Now.Add(-opts.MaxAge)) {
			return false
		}
	}
	return true
}

// satisfies reports whether these agreeing results meet the quorum rule, and
// returns the distinct providers behind them.
func satisfies(q check.Quorum, agreeing []check.Result) (int, []string, bool) {
	providers := distinctProviders(agreeing)
	if len(agreeing) < q.Agree {
		return len(agreeing), providers, false
	}
	if q.DistinctProviders && len(providers) < q.Agree {
		// Three probers behind one provider are one opinion held three times.
		// Note this fails closed: probers with no provider recorded collapse
		// into a single group, so an unlabelled fleet cannot satisfy a rule
		// that asks for diversity.
		return len(agreeing), providers, false
	}
	return len(agreeing), providers, true
}

func distinctProviders(results []check.Result) []string {
	seen := map[string]struct{}{}
	for _, r := range results {
		p := strings.TrimSpace(r.Provider)
		if p == "" {
			p = "unknown"
		}
		seen[p] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func names(results []check.Result) []string {
	out := make([]string, 0, len(results))
	for _, r := range results {
		out = append(out, r.Prober)
	}
	sort.Strings(out)
	return out
}

func downReason(c check.Check, agreed int, v Verdict, providers []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d of %d probers reported down", agreed, v.Counted)

	switch {
	case len(providers) == 1 && providers[0] == "unknown":
		b.WriteString(" (provider not recorded)")
	case len(providers) == 1:
		// Worth saying out loud: agreement from one network is weaker
		// evidence than the count alone suggests.
		fmt.Fprintf(&b, " (all at %s)", providers[0])
	default:
		fmt.Fprintf(&b, " across %d providers: %s", len(providers), strings.Join(providers, ", "))
	}

	if v.Up > 0 {
		fmt.Fprintf(&b, "; %d still reported up", v.Up)
	}
	if v.Unknown > 0 {
		fmt.Fprintf(&b, "; %d could not tell", v.Unknown)
	}
	if c.Quorum.DistinctProviders {
		b.WriteString("; provider diversity required")
	}
	return b.String()
}
