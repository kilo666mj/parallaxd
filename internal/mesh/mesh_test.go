package mesh

import (
	"testing"
	"time"
)

var now = time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)

// report builds a report where each named peer is reachable or not.
func report(prober string, peers map[string]bool) Report {
	r := Report{Prober: prober, At: now}
	// Sorted insertion is not needed — Evaluate does not depend on order —
	// but a stable map iteration keeps failures readable.
	for _, name := range sortedKeys(peers) {
		r.Peers = append(r.Peers, PeerView{Peer: name, Reachable: peers[name]})
	}
	return r
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func opts() Options { return Options{Now: now, MaxAge: 5 * time.Minute} }

// The distinction the whole phase exists for: a prober that cannot reach one
// peer has learned something about that peer, and a prober that cannot reach
// any peer has learned something about itself.
func TestCannotReachAnythingIsIsolated(t *testing.T) {
	st := Evaluate([]Report{
		report("probe-a", map[string]bool{"probe-b": false, "probe-c": false}),
		report("probe-b", map[string]bool{"probe-a": false, "probe-c": true}),
		report("probe-c", map[string]bool{"probe-a": false, "probe-b": true}),
	}, opts())

	if !st.IsIsolated("probe-a") {
		t.Fatalf("probe-a reached no peer and was not isolated: %+v", st.Isolated)
	}
	if st.IsIsolated("probe-b") || st.IsIsolated("probe-c") {
		t.Errorf("isolated = %v, want only probe-a — the others each reached a peer", st.Isolated)
	}
	if st.Partitioned {
		t.Error("one node dropping out is not a partition")
	}
}

func TestCannotReachOnePeerIsNotIsolation(t *testing.T) {
	st := Evaluate([]Report{
		report("probe-a", map[string]bool{"probe-b": false, "probe-c": true}),
		report("probe-b", map[string]bool{"probe-a": true, "probe-c": true}),
		report("probe-c", map[string]bool{"probe-a": true, "probe-b": false}),
	}, opts())

	if len(st.Isolated) != 0 {
		t.Fatalf("isolated = %v, want none — every prober reached someone", st.Isolated)
	}
	// And the map still records who could not be reached, which is the other
	// half of the diagnosis.
	if got := st.Unreachable["probe-b"]; len(got) != 2 {
		t.Errorf("unreachable[probe-b] = %v, want both a and c", got)
	}
}

// Suppressing a prober that was telling the truth hides real outages, which is
// worse than the false alert it would prevent. With one peer the evidence
// cannot distinguish the two cases, so it must not guess.
func TestOnePeerIsNeverEnoughToIsolate(t *testing.T) {
	st := Evaluate([]Report{
		report("probe-a", map[string]bool{"probe-b": false}),
		report("probe-b", map[string]bool{"probe-a": false}),
	}, opts())

	if len(st.Isolated) != 0 {
		t.Fatalf("isolated = %v, want none: with one peer, 'I cannot reach it' and "+
			"'it is down' are the same evidence", st.Isolated)
	}
}

func TestMinPeersIsConfigurable(t *testing.T) {
	reports := []Report{report("probe-a", map[string]bool{"probe-b": false})}

	o := opts()
	o.MinPeers = 1
	if st := Evaluate(reports, o); !st.IsIsolated("probe-a") {
		t.Error("MinPeers=1 did not allow a single-peer report to isolate")
	}
	o.MinPeers = 3
	if st := Evaluate(reports, o); st.IsIsolated("probe-a") {
		t.Error("MinPeers=3 isolated on a one-peer report")
	}
}

// Several probers cut off at once is the fleet splitting, not several
// independent host failures — which points an operator at the network.
func TestSeveralIsolatedIsAPartition(t *testing.T) {
	st := Evaluate([]Report{
		report("probe-a", map[string]bool{"probe-c": false, "probe-d": false}),
		report("probe-b", map[string]bool{"probe-c": false, "probe-d": false}),
		report("probe-c", map[string]bool{"probe-a": false, "probe-d": true}),
		report("probe-d", map[string]bool{"probe-a": false, "probe-c": true}),
	}, opts())

	if len(st.Isolated) != 2 {
		t.Fatalf("isolated = %v, want probe-a and probe-b", st.Isolated)
	}
	if !st.Partitioned {
		t.Error("two probers isolated at once was not reported as a partition")
	}
	if !contains(st.Summary(), "partitioned") {
		t.Errorf("summary = %q, want it to say the fleet is partitioned", st.Summary())
	}
}

// An old report must never be the reason a prober stays suppressed after it
// has recovered.
func TestStaleReportsAreIgnored(t *testing.T) {
	old := report("probe-a", map[string]bool{"probe-b": false, "probe-c": false})
	old.At = now.Add(-time.Hour)

	st := Evaluate([]Report{old}, opts())
	if st.IsIsolated("probe-a") {
		t.Fatal("a stale report isolated a prober")
	}
	if len(st.Reporting) != 0 {
		t.Errorf("reporting = %v, want none — the only report was stale", st.Reporting)
	}
}

// A recovery must not be masked by the failure that preceded it.
func TestNewestReportWins(t *testing.T) {
	bad := report("probe-a", map[string]bool{"probe-b": false, "probe-c": false})
	bad.At = now.Add(-time.Minute)
	good := report("probe-a", map[string]bool{"probe-b": true, "probe-c": true})
	good.At = now

	if st := Evaluate([]Report{bad, good}, opts()); st.IsIsolated("probe-a") {
		t.Error("the older failing report won over the newer healthy one")
	}
	// And the other way round: order of arrival must not matter.
	if st := Evaluate([]Report{good, bad}, opts()); st.IsIsolated("probe-a") {
		t.Error("evaluation depended on the order reports were listed in")
	}
}

func TestEdgesAreTheVisibilityMap(t *testing.T) {
	st := Evaluate([]Report{
		report("probe-a", map[string]bool{"probe-b": true, "probe-c": false}),
	}, opts())

	if !st.Edges["probe-a"]["probe-b"] {
		t.Error("edge a->b missing")
	}
	if st.Edges["probe-a"]["probe-c"] {
		t.Error("edge a->c should be false")
	}
	// Asymmetry is real and must survive into the map: a link that works one
	// way and not the other is a genuine finding, not a bug to average away.
	if _, ok := st.Edges["probe-b"]; ok {
		t.Error("an edge was invented for a prober that did not report")
	}
}

func TestNoReportsIsNotIsolation(t *testing.T) {
	st := Evaluate(nil, opts())
	if len(st.Isolated) != 0 || st.Partitioned {
		t.Fatalf("empty input produced %+v; silence is the watchdog's problem, not this package's", st)
	}
	if !contains(st.Summary(), "0 probers") {
		t.Errorf("summary = %q", st.Summary())
	}
}

// A prober that reports an empty peer list has not asked anyone anything, so
// it cannot have learned that it is cut off.
func TestEmptyPeerListDoesNotIsolate(t *testing.T) {
	st := Evaluate([]Report{{Prober: "probe-a", At: now}}, opts())
	if st.IsIsolated("probe-a") {
		t.Error("a report covering no peers isolated its prober")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
