package coordinator

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

// A monitoring system's worst failure is no answer rather than a wrong one,
// and these are the tests that hold that line: a check that stops happening
// must be as loud as a check that fails.

// clock is a manually advanced time source, so staleness can be tested by
// moving time rather than by sleeping through a real interval.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type watchHarness struct {
	t        *testing.T
	coord    *Coordinator
	notifier *fakeNotifier
	clk      *clock
}

func newWatchHarness(t *testing.T, cfg Config) *watchHarness {
	t.Helper()

	_, coordPriv, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubA, _, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubB, _, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	clk := newClock()
	h := &watchHarness{t: t, notifier: &fakeNotifier{}, clk: clk}

	cfg.Name = "coordinator"
	cfg.Key = coordPriv
	cfg.Notifier = h.notifier
	cfg.Logger = discardLogger()
	cfg.Now = clk.now
	if cfg.Peers == nil {
		cfg.Peers = []Peer{
			{Name: "probe-a", URL: "http://127.0.0.1:1", Provider: "one", PublicKey: pubA},
			{Name: "probe-b", URL: "http://127.0.0.1:2", Provider: "two", PublicKey: pubB},
		}
	}

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.coord = c
	return h
}

func (h *watchHarness) report(name string, status check.Status) {
	h.t.Helper()
	_, err := h.coord.Process(h.t.Context(), check.Result{
		Check: name, Prober: "probe-a", Provider: "one",
		Vantage: check.VantageInternal, Status: status, At: h.clk.now(),
	})
	if err != nil {
		h.t.Fatalf("Process(%s): %v", name, err)
	}
}

// assignee reports which prober is responsible for a check, so a test can
// assert against the real rendezvous assignment rather than guessing.
func (h *watchHarness) assignee(name string) string {
	p, ok := assign(name, h.coord.peers)
	if !ok {
		h.t.Fatalf("no assignee for %q", name)
	}
	return p.Name
}

// The gap this closes: a prober that dies takes its checks with it, and
// nothing was watching for the resulting silence.
func TestSilentProberAlerts(t *testing.T) {
	h := newWatchHarness(t, Config{Checks: []check.Check{namedCheck("svc")}})

	h.report("svc", check.StatusUp)
	h.coord.CheckStaleness(t.Context())
	if n := h.notifier.count(); n != 0 {
		t.Fatalf("got %d alerts while reporting normally, want none", n)
	}

	// namedCheck runs every minute; the default window is 3 intervals plus 30s.
	h.clk.advance(4 * time.Minute)
	h.coord.CheckStaleness(t.Context())

	alerts := h.notifier.all()
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1: %+v", len(alerts), alerts)
	}
	a := alerts[0]
	if a.Kind != KindSilent {
		t.Fatalf("kind = %q, want %q", a.Kind, KindSilent)
	}
	if a.Prober != h.assignee("svc") {
		t.Errorf("prober = %q, want the check's assignee %q", a.Prober, h.assignee("svc"))
	}
	if !strings.Contains(a.Summary(), "svc") {
		t.Errorf("summary = %q, want it to name the check nobody is running", a.Summary())
	}
}

// The distinction the whole design rests on, applied to its own failure: a
// check nobody is running says nothing about the target. Marking it down would
// mean a prober rebooting pages as an outage of the service it was watching.
func TestSilenceIsUnknownNotDown(t *testing.T) {
	h := newWatchHarness(t, Config{Checks: []check.Check{namedCheck("svc")}})

	h.report("svc", check.StatusUp)
	h.clk.advance(4 * time.Minute)
	h.coord.CheckStaleness(t.Context())

	var got string
	for _, e := range h.coord.Status() {
		if e.Check == "svc" {
			got = e.Status
		}
	}
	if got != string(check.StatusUnknown) {
		t.Fatalf("status = %q, want unknown — nobody probed the target", got)
	}
	for _, a := range h.notifier.all() {
		if a.Kind == KindDown {
			t.Fatalf("a silent prober produced a down alert: %s", a.Summary())
		}
	}
}

// A check that was failing when its prober died stays failing. Silence is not
// evidence the outage ended, and letting it clear a down would turn a dead
// prober into an all-clear.
func TestSilenceDoesNotClearADown(t *testing.T) {
	h := newWatchHarness(t, Config{Checks: []check.Check{namedCheck("svc")}})

	h.report("svc", check.StatusDown)
	if n := h.notifier.count(); n != 1 {
		t.Fatalf("got %d alerts, want the down", n)
	}

	h.clk.advance(4 * time.Minute)
	h.coord.CheckStaleness(t.Context())

	for _, a := range h.notifier.all() {
		if a.Kind == KindRecovered {
			t.Fatal("silence was reported as a recovery")
		}
	}

	// And when it comes back still failing, that is not a new incident.
	h.report("svc", check.StatusDown)
	downs := 0
	for _, a := range h.notifier.all() {
		if a.Kind == KindDown {
			downs++
		}
	}
	if downs != 1 {
		t.Errorf("got %d down alerts for one continuous outage, want 1", downs)
	}
}

// One prober dying must not produce one alert per check it was running — that
// is the noise this project exists to remove, arriving through the mechanism
// meant to catch it.
func TestSilenceIsGroupedByProber(t *testing.T) {
	var checks []check.Check
	for _, n := range []string{"svc", "web", "dns", "mail", "cache", "queue"} {
		checks = append(checks, namedCheck(n))
	}
	h := newWatchHarness(t, Config{Checks: checks})

	h.clk.advance(4 * time.Minute)
	h.coord.CheckStaleness(t.Context())

	alerts := h.notifier.all()
	// Two probers are registered, so at most two alerts however many checks
	// went quiet.
	if len(alerts) > 2 {
		t.Fatalf("got %d alerts for 6 stale checks across 2 probers, want at most 2", len(alerts))
	}
	total := 0
	for _, a := range alerts {
		if a.Prober == "" {
			t.Errorf("alert is not attributed to a prober: %+v", a)
		}
		total += len(a.Members)
	}
	if total != len(checks) {
		t.Errorf("alerts account for %d checks, want all %d", total, len(checks))
	}
}

// Alerting every tick for as long as a prober is down is the same mistake as
// alerting per failing result.
func TestSilenceAlertsOnceThenReportsRecovery(t *testing.T) {
	h := newWatchHarness(t, Config{Checks: []check.Check{namedCheck("svc")}})

	h.report("svc", check.StatusUp)
	h.clk.advance(4 * time.Minute)
	for range 5 {
		h.coord.CheckStaleness(t.Context())
		h.clk.advance(time.Second)
	}
	if n := h.notifier.count(); n != 1 {
		t.Fatalf("got %d alerts for one silent prober, want 1", n)
	}

	// Coming back matters as much as going away: without it an operator is
	// left watching an alert that never closes.
	h.report("svc", check.StatusUp)
	h.coord.CheckStaleness(t.Context())

	alerts := h.notifier.all()
	if len(alerts) != 2 {
		t.Fatalf("got %d alerts, want silent then reporting", len(alerts))
	}
	if alerts[1].Kind != KindReporting {
		t.Fatalf("second alert = %q, want %q", alerts[1].Kind, KindReporting)
	}

	// And it must not re-announce on every subsequent tick.
	h.coord.CheckStaleness(t.Context())
	if n := h.notifier.count(); n != 2 {
		t.Errorf("got %d alerts, want no repeat of the recovery", n)
	}
}

// Everything is unreported the instant a process starts. Alerting on that
// would make this the first thing anyone muted.
func TestRestartDoesNotAlertImmediately(t *testing.T) {
	h := newWatchHarness(t, Config{Checks: []check.Check{namedCheck("svc")}})

	h.coord.CheckStaleness(t.Context())
	if n := h.notifier.count(); n != 0 {
		t.Fatalf("got %d alerts immediately after startup, want none", n)
	}

	// But a check that never reports at all is exactly as invisible as one
	// that stopped, so the grace period does expire.
	h.clk.advance(4 * time.Minute)
	h.coord.CheckStaleness(t.Context())
	if n := h.notifier.count(); n != 1 {
		t.Errorf("got %d alerts for a check that never reported, want 1", n)
	}
}

// A check that runs every 30 seconds and one that runs hourly have very
// different ideas of "late".
func TestStalenessScalesWithInterval(t *testing.T) {
	fast := namedCheck("fast")
	fast.Interval = time.Minute
	fast.Timeout = 5 * time.Second
	slow := namedCheck("slow")
	slow.Interval = time.Hour
	slow.Timeout = 30 * time.Second

	h := newWatchHarness(t, Config{Checks: []check.Check{fast, slow}})
	h.report("fast", check.StatusUp)
	h.report("slow", check.StatusUp)

	h.clk.advance(10 * time.Minute)
	stale := h.coord.staleChecks()
	if _, ok := stale["fast"]; !ok {
		t.Error("a minute-interval check silent for 10 minutes is not stale")
	}
	if _, ok := stale["slow"]; ok {
		t.Error("an hourly check silent for 10 minutes was called stale")
	}
}

// A component whose checks have gone quiet must not keep reading as healthy.
func TestSilenceHoldsComponentAtUnknown(t *testing.T) {
	h := newWatchHarness(t, Config{
		Checks:     []check.Check{namedCheck("a"), namedCheck("b")},
		Components: []check.Component{{Name: "svc", Checks: []string{"a", "b"}}},
	})

	h.report("a", check.StatusUp)
	h.report("b", check.StatusUp)
	if got := componentStatusOf(t, h.coord, "svc"); got != string(check.StatusUp) {
		t.Fatalf("component = %q, want up", got)
	}

	h.clk.advance(4 * time.Minute)
	h.coord.CheckStaleness(t.Context())
	if got := componentStatusOf(t, h.coord, "svc"); got != string(check.StatusUnknown) {
		t.Errorf("component = %q, want unknown once nobody is running its checks", got)
	}
}

func componentStatusOf(t *testing.T, c *Coordinator, name string) string {
	t.Helper()
	for _, e := range c.Components() {
		if e.Component == name {
			return e.Status
		}
	}
	t.Fatalf("no component named %q", name)
	return ""
}

// The outward half. Only a watcher off the fleet can report the fleet being
// unreachable, so this asserts the coordinator actually pings one.
func TestHeartbeatPings(t *testing.T) {
	var (
		mu   sync.Mutex
		hits int
		last []byte
		auth string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		hits++
		last = body
		auth = r.Header.Get("Authorization")
		mu.Unlock()
	}))
	defer srv.Close()

	h := newWatchHarness(t, Config{
		Checks: []check.Check{namedCheck("svc")},
		Heartbeat: Heartbeat{
			URL:      srv.URL,
			Interval: time.Minute,
			Headers:  map[string]string{"Authorization": "Bearer t0ken"},
		},
	})
	h.coord.beat(t.Context())

	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Fatalf("watcher got %d pings, want 1", hits)
	}
	if auth != "Bearer t0ken" {
		t.Errorf("Authorization = %q, want the configured header", auth)
	}

	var got map[string]any
	if err := json.Unmarshal(last, &got); err != nil {
		t.Fatalf("ping body is not JSON: %v", err)
	}
	// The ping carries what the coordinator could see when it sent it, so a
	// watcher that keeps the last body has something to look at afterwards.
	for _, field := range []string{"coordinator", "at", "checks", "probers", "stale_checks"} {
		if _, ok := got[field]; !ok {
			t.Errorf("ping body has no %q: %v", field, got)
		}
	}
}

// The failure that matters is not the process exiting — an external watcher
// would see that anyway — but a coordinator still running and unable to
// decide anything. The ping is gated on reading real state so a wedged one
// stops beating.
func TestHeartbeatStopsWhenCoordinatorIsWedged(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
	}))
	defer srv.Close()

	h := newWatchHarness(t, Config{
		Checks:    []check.Check{namedCheck("svc")},
		Heartbeat: Heartbeat{URL: srv.URL, Interval: 3 * time.Second},
	})

	// Wedge the coordinator the way a real deadlock would: hold the lock every
	// state read has to take.
	h.coord.mu.Lock()
	done := make(chan struct{})
	go func() {
		h.coord.beat(t.Context())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		h.coord.mu.Unlock()
		t.Fatal("beat blocked instead of giving up on a wedged coordinator")
	}
	h.coord.mu.Unlock()

	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Errorf("a wedged coordinator sent %d pings; the external watchdog "+
			"would have seen it as healthy", hits)
	}
}

// An unreachable watcher must not become an alert. A coordinator that alerted
// about its own heartbeat would be claiming to report on its own death, which
// is the thing it cannot do.
func TestFailedHeartbeatDoesNotAlert(t *testing.T) {
	h := newWatchHarness(t, Config{
		Checks:    []check.Check{namedCheck("svc")},
		Heartbeat: Heartbeat{URL: "http://127.0.0.1:1/nothing-here", Interval: time.Minute},
	})
	h.coord.beat(t.Context())

	if n := h.notifier.count(); n != 0 {
		t.Errorf("got %d alerts for a failed heartbeat, want none", n)
	}
}

// The export is what a status page renders, so staleness has to survive into
// it. A check silently reading as unknown, with no way to tell that from a
// genuine disagreement, is how a monitoring system stops monitoring without
// anyone noticing.
func TestExportMarksStaleChecks(t *testing.T) {
	h := newWatchHarness(t, Config{Checks: []check.Check{namedCheck("svc")}})

	h.report("svc", check.StatusUp)
	h.clk.advance(4 * time.Minute)
	h.coord.CheckStaleness(t.Context())

	e := h.coord.Export()
	if len(e.Checks) != 1 {
		t.Fatalf("checks = %d, want 1", len(e.Checks))
	}
	got := e.Checks[0]
	if !got.Stale {
		t.Error("export does not mark the check as stale")
	}
	if got.Status != string(check.StatusUnknown) {
		t.Errorf("status = %q, want unknown", got.Status)
	}
	// The last thing anyone actually observed is still worth showing.
	if got.LastKnown != string(check.StatusUp) {
		t.Errorf("last_known = %q, want up", got.LastKnown)
	}
	if got.AssignedTo == "" {
		t.Error("export does not say who was supposed to be running it")
	}
}
