package quorum

import (
	"strings"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

var now = time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)

func testCheck() check.Check {
	return check.Check{
		Name: "mx-smtps", Kind: check.KindTCP, Target: "mx.example.com:465",
		Vantage: check.VantagePublic, Interval: time.Minute, Timeout: 10 * time.Second,
		Quorum: check.Quorum{Agree: 3, Of: 5},
	}
}

func result(prober string, status check.Status, provider string) check.Result {
	return check.Result{
		Check: "mx-smtps", Prober: prober, Provider: provider,
		Vantage: check.VantagePublic, Status: status, At: now,
	}
}

func opts() Options { return Options{Now: now, MaxAge: 2 * time.Minute} }

func TestQuorumReachedIsDown(t *testing.T) {
	v := Evaluate(testCheck(), []check.Result{
		result("a", check.StatusDown, "hetzner"),
		result("b", check.StatusDown, "contabo"),
		result("c", check.StatusDown, "netcup"),
		result("d", check.StatusUp, "racknerd"),
		result("e", check.StatusUp, "hetzner"),
	}, opts())

	if v.Status != check.StatusDown {
		t.Fatalf("status = %q (%s), want down", v.Status, v.Reason)
	}
	if !v.Actionable() {
		t.Error("a confirmed down must be actionable")
	}
	if v.Down != 3 || v.Up != 2 || v.Counted != 5 {
		t.Errorf("counts = down %d up %d counted %d", v.Down, v.Up, v.Counted)
	}
	// A partial outage is still an outage: two probers reaching it does not
	// cancel three that cannot.
	if len(v.Dissent) != 2 {
		t.Errorf("dissent = %v, want the two that said up", v.Dissent)
	}
	if len(v.Providers) != 3 {
		t.Errorf("providers = %v, want three distinct", v.Providers)
	}
	if !strings.Contains(v.Reason, "across 3 providers") {
		t.Errorf("reason = %q, want provider diversity stated", v.Reason)
	}
}

// Silence is not an all-clear. Two of five saying down, with the rest unable
// to answer, must not resolve to up.
func TestNotEnoughEvidenceIsInconclusive(t *testing.T) {
	v := Evaluate(testCheck(), []check.Result{
		result("a", check.StatusDown, "hetzner"),
		result("b", check.StatusDown, "contabo"),
		result("c", check.StatusUnknown, "netcup"),
	}, opts())

	if v.Status != check.StatusUnknown {
		t.Fatalf("status = %q (%s), want inconclusive", v.Status, v.Reason)
	}
	if v.Actionable() {
		t.Error("an inconclusive verdict must not raise an alert")
	}
	if !strings.Contains(v.Reason, "quorum needs 3") {
		t.Errorf("reason = %q, want it to say what was missing", v.Reason)
	}
}

// The distinction the whole design rests on: unknown is a statement about the
// prober, never a vote about the target.
func TestUnknownIsNotAVote(t *testing.T) {
	c := testCheck()
	c.Quorum = check.Quorum{Agree: 2, Of: 3}
	v := Evaluate(c, []check.Result{
		result("a", check.StatusDown, "hetzner"),
		result("b", check.StatusUnknown, "contabo"),
		result("c", check.StatusUnknown, "netcup"),
	}, opts())

	if v.Status == check.StatusDown {
		t.Fatal("two unknowns were counted toward a down verdict")
	}
	if v.Unknown != 2 || v.Counted != 1 {
		t.Errorf("unknown = %d counted = %d, want 2 and 1", v.Unknown, v.Counted)
	}
}

// Every prober isolated: the signal of a broken observer, not a broken world.
func TestAllUnknownSaysSo(t *testing.T) {
	v := Evaluate(testCheck(), []check.Result{
		result("a", check.StatusUnknown, "hetzner"),
		result("b", check.StatusUnknown, "contabo"),
	}, opts())

	if v.Status != check.StatusUnknown || v.Actionable() {
		t.Fatalf("status = %q, want a silent inconclusive", v.Status)
	}
	if !strings.Contains(v.Reason, "no prober could form an opinion") {
		t.Errorf("reason = %q", v.Reason)
	}
}

func TestAllUpIsUp(t *testing.T) {
	v := Evaluate(testCheck(), []check.Result{
		result("a", check.StatusUp, "hetzner"),
		result("b", check.StatusUp, "contabo"),
	}, opts())
	if v.Status != check.StatusUp {
		t.Fatalf("status = %q (%s), want up", v.Status, v.Reason)
	}
	if v.Actionable() {
		t.Error("an up verdict must not alert")
	}
}

// One prober, one vote. Otherwise a single node that retries — or replays —
// manufactures a quorum by itself.
func TestOneProberVotesOnce(t *testing.T) {
	v := Evaluate(testCheck(), []check.Result{
		result("a", check.StatusDown, "hetzner"),
		result("a", check.StatusDown, "hetzner"),
		result("a", check.StatusDown, "hetzner"),
		result("a", check.StatusDown, "hetzner"),
	}, opts())

	if v.Status == check.StatusDown {
		t.Fatal("one prober reached quorum on its own")
	}
	if v.Down != 1 {
		t.Errorf("down = %d, want 1 after de-duplication", v.Down)
	}
	if v.Discarded != 3 {
		t.Errorf("discarded = %d, want the 3 duplicates counted", v.Discarded)
	}
}

// A retry that succeeds after a transient failure should supersede it.
func TestNewerResultWinsForTheSameProber(t *testing.T) {
	older := result("a", check.StatusDown, "hetzner")
	newer := result("a", check.StatusUp, "hetzner")
	newer.At = now.Add(time.Second)

	c := testCheck()
	c.Quorum = check.Quorum{Agree: 1, Of: 1}
	v := Evaluate(c, []check.Result{older, newer}, opts())
	if v.Status != check.StatusUp {
		t.Errorf("status = %q, want the newer result to win", v.Status)
	}
}

// A prober answering about a different network path answered a different
// question. This is the trap that produces confident all-clears.
func TestWrongVantageIsDiscarded(t *testing.T) {
	internal := result("b", check.StatusUp, "contabo")
	internal.Vantage = check.VantageInternal

	c := testCheck()
	c.Quorum = check.Quorum{Agree: 2, Of: 3}
	v := Evaluate(c, []check.Result{
		result("a", check.StatusDown, "hetzner"),
		internal,
		result("c", check.StatusDown, "netcup"),
	}, opts())

	if v.Up != 0 {
		t.Errorf("up = %d, want the internal-vantage result discarded", v.Up)
	}
	if v.Discarded != 1 {
		t.Errorf("discarded = %d, want 1", v.Discarded)
	}
	if v.Status != check.StatusDown {
		t.Errorf("status = %q, want the two public-vantage downs to carry", v.Status)
	}
}

func TestWrongCheckIsDiscarded(t *testing.T) {
	other := result("b", check.StatusDown, "contabo")
	other.Check = "something-else"

	v := Evaluate(testCheck(), []check.Result{
		result("a", check.StatusDown, "hetzner"), other,
	}, opts())
	if v.Counted != 1 || v.Discarded != 1 {
		t.Errorf("counted = %d discarded = %d, want 1 and 1", v.Counted, v.Discarded)
	}
}

// Corroboration is a question about now. A result from ten minutes ago
// answers a different one.
func TestStaleResultsAreDiscarded(t *testing.T) {
	stale := result("b", check.StatusDown, "contabo")
	stale.At = now.Add(-10 * time.Minute)

	c := testCheck()
	c.Quorum = check.Quorum{Agree: 2, Of: 3}
	v := Evaluate(c, []check.Result{
		result("a", check.StatusDown, "hetzner"), stale,
	}, opts())

	if v.Status == check.StatusDown {
		t.Fatal("a stale result helped reach quorum")
	}
	if v.Discarded != 1 {
		t.Errorf("discarded = %d, want the stale result counted", v.Discarded)
	}
}

func TestMaxAgeZeroDisablesStaleness(t *testing.T) {
	old := result("b", check.StatusDown, "contabo")
	old.At = now.Add(-24 * time.Hour)

	c := testCheck()
	c.Quorum = check.Quorum{Agree: 2, Of: 3}
	v := Evaluate(c, []check.Result{result("a", check.StatusDown, "hetzner"), old},
		Options{Now: now})
	if v.Status != check.StatusDown {
		t.Errorf("status = %q, want staleness ignored when MaxAge is zero", v.Status)
	}
}

// Three probers behind one provider are one opinion held three times.
func TestDistinctProvidersRequired(t *testing.T) {
	c := testCheck()
	c.Quorum = check.Quorum{Agree: 3, Of: 5, DistinctProviders: true}
	sameProvider := []check.Result{
		result("a", check.StatusDown, "hetzner"),
		result("b", check.StatusDown, "hetzner"),
		result("c", check.StatusDown, "hetzner"),
	}
	if v := Evaluate(c, sameProvider, opts()); v.Status == check.StatusDown {
		t.Error("three probers at one provider satisfied a diversity requirement")
	}

	diverse := []check.Result{
		result("a", check.StatusDown, "hetzner"),
		result("b", check.StatusDown, "contabo"),
		result("c", check.StatusDown, "netcup"),
	}
	v := Evaluate(c, diverse, opts())
	if v.Status != check.StatusDown {
		t.Errorf("status = %q (%s), want down across three providers", v.Status, v.Reason)
	}
	if !strings.Contains(v.Reason, "diversity required") {
		t.Errorf("reason = %q, want the requirement noted", v.Reason)
	}
}

// Fails closed: an unlabelled fleet cannot satisfy a rule asking for
// diversity, rather than silently passing.
func TestDistinctProvidersFailsClosedWhenUnlabelled(t *testing.T) {
	c := testCheck()
	c.Quorum = check.Quorum{Agree: 2, Of: 3, DistinctProviders: true}
	v := Evaluate(c, []check.Result{
		result("a", check.StatusDown, ""),
		result("b", check.StatusDown, ""),
	}, opts())
	if v.Status == check.StatusDown {
		t.Error("unlabelled probers satisfied a provider-diversity requirement")
	}
}

// Agreement from a single network is weaker than the count suggests, and the
// alert has to say so.
func TestReasonNamesSingleProvider(t *testing.T) {
	c := testCheck()
	c.Quorum = check.Quorum{Agree: 2, Of: 3}
	v := Evaluate(c, []check.Result{
		result("a", check.StatusDown, "hetzner"),
		result("b", check.StatusDown, "hetzner"),
	}, opts())
	if v.Status != check.StatusDown {
		t.Fatalf("status = %q", v.Status)
	}
	if !strings.Contains(v.Reason, "all at hetzner") {
		t.Errorf("reason = %q, want the shared provider called out", v.Reason)
	}
}

func TestReasonNotesUnrecordedProvider(t *testing.T) {
	c := testCheck()
	c.Quorum = check.Quorum{Agree: 1, Of: 1}
	v := Evaluate(c, []check.Result{result("a", check.StatusDown, "")}, opts())
	if !strings.Contains(v.Reason, "provider not recorded") {
		t.Errorf("reason = %q", v.Reason)
	}
}

func TestNoResultsAtAll(t *testing.T) {
	v := Evaluate(testCheck(), nil, opts())
	if v.Status != check.StatusUnknown || v.Actionable() {
		t.Errorf("verdict = %+v, want a silent inconclusive", v)
	}
}

// The rule Phase 2 exists for. A partitioned prober sees every target as down;
// counting that is how one broken uplink becomes a fleet-wide outage report.
func TestIsolatedProberIsNotCounted(t *testing.T) {
	c := testCheck()
	c.Quorum = check.Quorum{Agree: 2, Of: 3}

	results := []check.Result{
		result("probe-a", check.StatusDown, "one"),
		result("probe-b", check.StatusDown, "two"),
		result("probe-c", check.StatusUp, "three"),
	}

	// Without suppression the two agreeing downs carry the verdict.
	if v := Evaluate(c, results, Options{Now: now}); v.Status != check.StatusDown {
		t.Fatalf("baseline status = %q, want down", v.Status)
	}

	// probe-a and probe-b are cut off, so their agreement is one broken
	// network reported twice, not two vantages agreeing.
	v := Evaluate(c, results, Options{
		Now:      now,
		Isolated: map[string]bool{"probe-a": true, "probe-b": true},
	})
	if v.Status == check.StatusDown {
		t.Fatalf("isolated probers still reached quorum: %+v", v)
	}
	if v.Suppressed != 2 {
		t.Errorf("suppressed = %d, want 2", v.Suppressed)
	}
	if len(v.SuppressedProbers) != 2 ||
		v.SuppressedProbers[0] != "probe-a" || v.SuppressedProbers[1] != "probe-b" {
		t.Errorf("suppressedProbers = %v, want probe-a and probe-b sorted", v.SuppressedProbers)
	}
	// The one prober that could see the fleet said up, and nothing contradicts
	// it any more.
	if v.Status != check.StatusUp {
		t.Errorf("status = %q, want up — the only prober with a working path said so", v.Status)
	}
}

// Suppression must not be quietly indistinguishable from having no evidence.
func TestSuppressionIsExplainedInTheReason(t *testing.T) {
	c := testCheck()
	v := Evaluate(c, []check.Result{result("probe-a", check.StatusDown, "one")}, Options{
		Now:      now,
		Isolated: map[string]bool{"probe-a": true},
	})

	if v.Status == check.StatusDown {
		t.Fatal("an isolated prober alone produced a down verdict")
	}
	if !strings.Contains(v.Reason, "could reach no peer") {
		t.Errorf("reason = %q, want it to say why the result was not counted", v.Reason)
	}
	if !strings.Contains(v.Reason, "probe-a") {
		t.Errorf("reason = %q, want it to name the suppressed prober", v.Reason)
	}
}

// Suppression is counted separately from discarding because the two mean very
// different things: one is a misconfiguration, the other is the network.
func TestSuppressedIsNotCountedAsDiscarded(t *testing.T) {
	c := testCheck()
	v := Evaluate(c, []check.Result{
		result("probe-a", check.StatusDown, "one"),
		result("probe-b", check.StatusUp, "two"),
	}, Options{Now: now, Isolated: map[string]bool{"probe-a": true}})

	if v.Discarded != 0 {
		t.Errorf("discarded = %d, want 0 — the result was suppressed, not malformed", v.Discarded)
	}
	if v.Suppressed != 1 {
		t.Errorf("suppressed = %d, want 1", v.Suppressed)
	}
}
