// Package mesh decides which probers can still see the fleet.
//
// This is the phase that justifies parallaxd existing rather than being
// blackbox_exporter with a K-of-N alert rule.
//
// # The problem
//
// A partitioned prober is the worst possible reporter. It cannot reach the
// target, it cannot reach its peers to corroborate, and its local view says
// everything is down. Corroboration that does not know this turns one broken
// uplink into a confident, fleet-wide outage report — which is worse than the
// single false alert it was built to prevent, because it arrives with the
// authority of a system that claims to corroborate.
//
// # The distinction
//
// If probers check each other as well as their targets, a node can tell
//
//	"I cannot reach this"      — evidence about the target
//	"I cannot reach anything"  — evidence about itself
//
// and a node in the second state must stop being counted. That single
// distinction is most of the value of the whole design.
//
// # Why this is pure
//
// Same reason quorum is: reports in, state out, no clock of its own and no
// I/O. Deciding to silence a prober is the most dangerous thing parallaxd
// does — get it wrong in one direction and real outages go unreported — so it
// is the code that most deserves to be trivially testable.
package mesh

import (
	"fmt"
	"sort"
	"time"
)

// defaultMinPeers is how many peers a prober must have reported on before its
// silence can be read as isolation.
//
// With one peer the question is undecidable: "I cannot reach my only peer" and
// "my only peer is down" produce identical evidence, and guessing wrong
// silences a prober that was telling the truth. Two is the smallest number
// where failing to reach *all* of them is more likely to be about the reporter
// than about the peers.
const defaultMinPeers = 2

// PeerView is one prober's opinion of one peer.
type PeerView struct {
	Peer string `json:"peer"`

	// Reachable is whether this prober could open a connection to that peer.
	// It is deliberately not a health check: the question is whether the
	// network path works, not whether the peer is happy.
	Reachable bool `json:"reachable"`

	// Detail explains an unreachable peer.
	Detail string `json:"detail,omitempty"`

	// Latency is how long the connection took, for the map.
	Latency time.Duration `json:"latency,omitempty"`
}

// Report is what one prober says about the rest of the fleet.
type Report struct {
	Prober string     `json:"prober"`
	At     time.Time  `json:"at"`
	Peers  []PeerView `json:"peers"`
}

// Reached counts the peers this prober could reach.
func (r Report) Reached() int {
	var n int
	for _, p := range r.Peers {
		if p.Reachable {
			n++
		}
	}
	return n
}

// Options tunes evaluation. The caller owns time; this package never reads a
// clock.
type Options struct {
	Now time.Time

	// MaxAge ignores reports older than this. A prober that has stopped
	// reporting is the staleness watchdog's problem, not this package's —
	// and an old report must never be the reason a prober stays suppressed
	// after it has recovered.
	MaxAge time.Duration

	// MinPeers is how many peers a report must cover before it can declare
	// isolation. Zero applies defaultMinPeers.
	MinPeers int
}

// State is the fleet's connectivity as last observed.
type State struct {
	// Isolated names the probers that could not reach any peer, sorted. Their
	// results must not be counted: a prober with no working network path has
	// learned nothing about any target.
	Isolated []string

	// Reporting names the probers whose reports were fresh enough to use.
	Reporting []string

	// Partitioned is true when the fleet has split rather than one node having
	// dropped out — several probers isolated at once, or a set that can see
	// each other but not the rest.
	//
	// It changes what an operator should go and look at, so it is worth
	// naming separately even though the suppression is the same.
	Partitioned bool

	// Unreachable maps a peer to the probers that could not reach it. This is
	// the other half of the diagnosis: a target nobody can reach is different
	// from a target one prober cannot reach, and the map says which.
	Unreachable map[string][]string

	// Edges is the visibility map: Edges[from][to] is whether from could
	// reach to at its last report.
	Edges map[string]map[string]bool
}

// IsIsolated reports whether this prober's results should be discarded.
func (s State) IsIsolated(prober string) bool {
	for _, name := range s.Isolated {
		if name == prober {
			return true
		}
	}
	return false
}

// Evaluate turns the latest report from each prober into fleet state.
//
// Isolation is decided from a prober's *own* report rather than from what its
// peers say about it, because that is the fact that actually predicts whether
// its probes mean anything. A prober nobody can reach may still have perfect
// outbound connectivity and be probing correctly; a prober that can reach
// nothing cannot, whatever the rest of the fleet sees. Peer observations feed
// the map and the diagnosis instead.
func Evaluate(reports []Report, opts Options) State {
	minPeers := opts.MinPeers
	if minPeers <= 0 {
		minPeers = defaultMinPeers
	}

	st := State{
		Unreachable: map[string][]string{},
		Edges:       map[string]map[string]bool{},
	}

	// Newest report per prober. A prober that reported twice inside the window
	// gets its latest view, so a recovery is not masked by the failure before
	// it.
	latest := map[string]Report{}
	for _, r := range reports {
		if r.Prober == "" {
			continue
		}
		if opts.MaxAge > 0 && !opts.Now.IsZero() && r.At.Before(opts.Now.Add(-opts.MaxAge)) {
			continue
		}
		if prev, seen := latest[r.Prober]; seen && !r.At.After(prev.At) {
			continue
		}
		latest[r.Prober] = r
	}

	for name, r := range latest {
		st.Reporting = append(st.Reporting, name)
		st.Edges[name] = map[string]bool{}
		for _, p := range r.Peers {
			st.Edges[name][p.Peer] = p.Reachable
			if !p.Reachable {
				st.Unreachable[p.Peer] = append(st.Unreachable[p.Peer], name)
			}
		}

		// The rule: reached nothing, having asked enough peers for that to
		// mean something. Below minPeers this stays silent rather than
		// guessing — suppressing a prober that was telling the truth hides
		// real outages, which is worse than the false alert it would prevent.
		if len(r.Peers) >= minPeers && r.Reached() == 0 {
			st.Isolated = append(st.Isolated, name)
		}
	}

	sort.Strings(st.Isolated)
	sort.Strings(st.Reporting)
	for peer := range st.Unreachable {
		sort.Strings(st.Unreachable[peer])
	}

	// More than one prober isolated at once is not several independent
	// failures; it is the fleet splitting. Worth saying, because it points an
	// operator at the network rather than at the hosts.
	st.Partitioned = len(st.Isolated) > 1

	return st
}

// Summary renders the state as one line for a log or an alert.
func (s State) Summary() string {
	switch {
	case len(s.Isolated) == 0:
		return fmt.Sprintf("%d probers reporting, all can see the fleet", len(s.Reporting))
	case s.Partitioned:
		return fmt.Sprintf("fleet appears partitioned: %d of %d probers can reach no peer (%s)",
			len(s.Isolated), len(s.Reporting), joinNames(s.Isolated))
	default:
		return fmt.Sprintf("%s can reach no peer; its results are not being counted",
			s.Isolated[0])
	}
}

func joinNames(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}
