package coordinator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

// These tests drive the coordinator through Process directly with Agree:1,
// so no fan-out happens and what is under test is the component layer rather
// than corroboration, which coordinator_test.go already covers end to end.

type compHarness struct {
	t        *testing.T
	coord    *Coordinator
	notifier *fakeNotifier
	pub      []byte
}

func namedCheck(name string) check.Check {
	return check.Check{
		Name: name, Kind: check.KindTCP, Target: name + ".example:443",
		Vantage: check.VantageInternal, Interval: time.Minute, Timeout: 2 * time.Second,
		Quorum: check.Quorum{Agree: 1, Of: 1},
	}
}

func newCompHarness(t *testing.T, checks []check.Check, comps []check.Component) *compHarness {
	t.Helper()

	coordPub, coordPriv, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	proberPub, _, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	h := &compHarness{t: t, notifier: &fakeNotifier{}, pub: coordPub}
	c, err := New(Config{
		Name: "coordinator", Key: coordPriv,
		Peers:      []Peer{{Name: "probe-a", URL: "http://127.0.0.1:1", Provider: "one", PublicKey: proberPub}},
		Checks:     checks,
		Components: comps,
		Notifier:   h.notifier,
		Logger:     discardLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.coord = c
	return h
}

// report drives one check to a status through the real Process path.
func (h *compHarness) report(name string, status check.Status) {
	h.t.Helper()
	_, err := h.coord.Process(h.t.Context(), check.Result{
		Check: name, Prober: "probe-a", Provider: "one",
		Vantage: check.VantageInternal, Status: status, At: time.Now().UTC(),
	})
	if err != nil {
		h.t.Fatalf("Process(%s): %v", name, err)
	}
}

func (h *compHarness) componentStatus(name string) string {
	h.t.Helper()
	for _, e := range h.coord.Components() {
		if e.Component == name {
			return e.Status
		}
	}
	h.t.Fatalf("no component named %q", name)
	return ""
}

func emailHarness(t *testing.T) *compHarness {
	return newCompHarness(t,
		[]check.Check{namedCheck("mx-smtps"), namedCheck("mx-imaps"), namedCheck("mx-submission")},
		[]check.Component{{
			Name:        "email",
			Description: "Sending and receiving mail",
			Checks:      []string{"mx-smtps", "mx-imaps", "mx-submission"},
		}},
	)
}

// The reason components exist: an mx host going down must produce one alert
// that says email is down, not one per port.
func TestOneComponentAlertNotOnePerCheck(t *testing.T) {
	h := emailHarness(t)

	h.report("mx-smtps", check.StatusDown)
	h.report("mx-imaps", check.StatusDown)
	h.report("mx-submission", check.StatusDown)

	alerts := h.notifier.all()
	if len(alerts) != 1 {
		var got []string
		for _, a := range alerts {
			got = append(got, a.Summary())
		}
		t.Fatalf("got %d alerts, want 1: %s", len(alerts), strings.Join(got, " | "))
	}
	a := alerts[0]
	if a.Component != "email" || a.Kind != KindDown {
		t.Fatalf("alert = %+v, want a down alert for the email component", a)
	}
	if a.Check != "" {
		t.Errorf("component alert names check %q; the component is the subject", a.Check)
	}
}

// A grouped alert that cannot say which part failed is vaguer than the alerts
// it replaced, which would make the grouping a downgrade.
func TestComponentAlertNamesTheFailingChecks(t *testing.T) {
	h := emailHarness(t)

	h.report("mx-imaps", check.StatusUp)
	h.report("mx-submission", check.StatusUp)
	h.report("mx-smtps", check.StatusDown)

	alerts := h.notifier.all()
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	summary := alerts[0].Summary()
	if !strings.Contains(summary, "mx-smtps") {
		t.Errorf("summary = %q, want it to name the failing check", summary)
	}
	if strings.Contains(summary, "mx-imaps") {
		t.Errorf("summary = %q, want it to name only what failed", summary)
	}

	// And the structured form carries every member, so a receiver can render
	// the healthy ones too.
	if len(alerts[0].Members) != 3 {
		t.Fatalf("members = %d, want all 3", len(alerts[0].Members))
	}
	byName := map[string]string{}
	for _, m := range alerts[0].Members {
		byName[m.Check] = m.Status
	}
	if byName["mx-smtps"] != string(check.StatusDown) || byName["mx-imaps"] != string(check.StatusUp) {
		t.Errorf("members = %+v, want per-check status", alerts[0].Members)
	}
	if alerts[0].Members[0].Target == "" {
		t.Error("members carry no target; a reader cannot tell what was probed")
	}
}

func TestComponentRecoversOnce(t *testing.T) {
	h := emailHarness(t)

	for _, name := range []string{"mx-smtps", "mx-imaps", "mx-submission"} {
		h.report(name, check.StatusDown)
	}
	if got := h.componentStatus("email"); got != string(check.StatusDown) {
		t.Fatalf("component = %q, want down", got)
	}

	// Two of three back is not a recovery under the "any" rollup.
	h.report("mx-smtps", check.StatusUp)
	h.report("mx-imaps", check.StatusUp)
	if n := h.notifier.count(); n != 1 {
		t.Fatalf("got %d alerts after a partial recovery, want just the original down", n)
	}

	h.report("mx-submission", check.StatusUp)
	alerts := h.notifier.all()
	if len(alerts) != 2 {
		t.Fatalf("got %d alerts, want down then recovered", len(alerts))
	}
	if alerts[1].Kind != KindRecovered || alerts[1].Component != "email" {
		t.Fatalf("second alert = %+v, want a component recovery", alerts[1])
	}

	// Further healthy reports must not re-announce it.
	h.report("mx-smtps", check.StatusUp)
	if n := h.notifier.count(); n != 2 {
		t.Errorf("got %d alerts, want no repeat of the recovery", n)
	}
}

// A check outside every component keeps alerting on its own, so adding
// components to part of a config does not silence the rest of it.
func TestUngroupedCheckStillAlerts(t *testing.T) {
	h := newCompHarness(t,
		[]check.Check{namedCheck("mx-smtps"), namedCheck("website")},
		[]check.Component{{Name: "email", Checks: []string{"mx-smtps"}}},
	)

	h.report("website", check.StatusDown)
	alerts := h.notifier.all()
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if alerts[0].Check != "website" || alerts[0].Component != "" {
		t.Fatalf("alert = %+v, want a plain check alert", alerts[0])
	}
	// The check alert keeps its corroboration detail, which is the thing a
	// component alert cannot carry.
	if alerts[0].Verdict.Reason == "" {
		t.Error("check alert lost its verdict")
	}
}

// A check in two components alerts through both. Overlap is allowed on
// purpose — "mx-smtps" is part of email and part of the mx host — and each
// grouping is a separate question.
func TestCheckInTwoComponentsAlertsThroughBoth(t *testing.T) {
	h := newCompHarness(t,
		[]check.Check{namedCheck("mx-smtps")},
		[]check.Component{
			{Name: "email", Checks: []string{"mx-smtps"}},
			{Name: "mx-host", Checks: []string{"mx-smtps"}},
		},
	)

	h.report("mx-smtps", check.StatusDown)
	alerts := h.notifier.all()
	if len(alerts) != 2 {
		t.Fatalf("got %d alerts, want one per component", len(alerts))
	}
	seen := map[string]bool{}
	for _, a := range alerts {
		seen[a.Component] = true
	}
	if !seen["email"] || !seen["mx-host"] {
		t.Errorf("components alerted = %v, want both", seen)
	}
}

// A pool rollup must not report an outage because one member failed.
func TestPoolComponentIsDegradedNotDown(t *testing.T) {
	h := newCompHarness(t,
		[]check.Check{namedCheck("ns1"), namedCheck("ns2")},
		[]check.Component{{Name: "dns", Checks: []string{"ns1", "ns2"}, DownIf: check.RollupAll}},
	)

	h.report("ns1", check.StatusDown)
	h.report("ns2", check.StatusUp)
	if n := h.notifier.count(); n != 0 {
		t.Fatalf("got %d alerts for one failing member of a pool, want none: %+v",
			n, h.notifier.all())
	}
	if got := h.componentStatus("dns"); got != string(check.StatusUp) {
		t.Errorf("component = %q, want up — one member down is degraded, not an outage", got)
	}

	h.report("ns2", check.StatusDown)
	if n := h.notifier.count(); n != 1 {
		t.Fatalf("got %d alerts once every member failed, want 1", n)
	}
}

// Config errors that would otherwise become a component permanently stuck at
// unknown, discovered at 3am rather than at startup.
func TestNewRejectsBadComponents(t *testing.T) {
	cases := []struct {
		name string
		comp []check.Component
		want string
	}{
		{"unknown check", []check.Component{{Name: "email", Checks: []string{"nope"}}}, "no check named"},
		{"duplicate component", []check.Component{
			{Name: "email", Checks: []string{"mx-smtps"}},
			{Name: "email", Checks: []string{"mx-smtps"}},
		}, "duplicate component"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, _ := wire.GenerateKey()
			_, err := New(Config{
				Name: "coordinator", Key: priv,
				Peers:      []Peer{{Name: "probe-a", URL: "http://127.0.0.1:1", PublicKey: pub}},
				Checks:     []check.Check{namedCheck("mx-smtps")},
				Components: tc.comp,
				Logger:     discardLogger(),
			})
			if err == nil {
				t.Fatalf("New() = nil, want an error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("New() = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestExportShape(t *testing.T) {
	h := emailHarness(t)
	h.report("mx-smtps", check.StatusDown)

	e := h.coord.Export()
	if e.Version != exportVersion {
		t.Errorf("version = %d, want %d", e.Version, exportVersion)
	}
	if e.Coordinator != "coordinator" {
		t.Errorf("coordinator = %q", e.Coordinator)
	}
	// Staleness is the failure mode a rendered page cannot otherwise detect.
	if e.GeneratedAt.IsZero() {
		t.Error("export has no generated_at; a renderer cannot tell a live page from a frozen one")
	}
	if len(e.Components) != 1 || e.Components[0].Status != string(check.StatusDown) {
		t.Fatalf("components = %+v, want email down", e.Components)
	}
	if e.Components[0].DownIf != check.RollupAny {
		t.Errorf("down_if = %q, want the effective rule spelled out", e.Components[0].DownIf)
	}
	if e.Components[0].Since.IsZero() {
		t.Error("component has no since; a page cannot say how long it has been down")
	}
	// The detail behind the summary travels with it, because the renderer has
	// no way to ask a follow-up question.
	if len(e.Checks) != 3 {
		t.Errorf("checks = %d, want all 3", len(e.Checks))
	}
	if e.Probers != 1 {
		t.Errorf("probers = %d, want 1", e.Probers)
	}
}

// The export travels off the fleet to something that cannot otherwise tell an
// authentic document from a file someone replaced.
func TestSignedExportVerifies(t *testing.T) {
	h := emailHarness(t)
	h.report("mx-smtps", check.StatusDown)

	env, err := h.coord.SignedExport()
	if err != nil {
		t.Fatalf("SignedExport: %v", err)
	}

	ring := wire.NewKeyring()
	if err := ring.Add("coordinator", h.pub); err != nil {
		t.Fatalf("Add: %v", err)
	}
	raw, err := ring.OpenDocument(env)
	if err != nil {
		t.Fatalf("OpenDocument: %v", err)
	}
	var got Export
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Components) != 1 || got.Components[0].Component != "email" {
		t.Errorf("decoded = %+v, want the email component", got.Components)
	}

	// Tampering must not verify, or signing bought nothing.
	env.Payload = append(env.Payload, ' ')
	if _, err := ring.OpenDocument(env); err == nil {
		t.Error("OpenDocument accepted an altered payload")
	}
}

func TestExportEndpoints(t *testing.T) {
	h := emailHarness(t)
	h.report("mx-smtps", check.StatusDown)
	srv := httptest.NewServer(h.coord.Handler())
	defer srv.Close()

	var plain Export
	getJSON(t, srv.URL+"/v1/export", &plain)
	if len(plain.Components) != 1 {
		t.Fatalf("/v1/export components = %+v", plain.Components)
	}

	var env wire.Envelope
	getJSON(t, srv.URL+"/v1/export?signed=true", &env)
	if len(env.Signature) == 0 {
		t.Fatal("/v1/export?signed=true returned no signature")
	}
	ring := wire.NewKeyring()
	if err := ring.Add("coordinator", h.pub); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := ring.OpenDocument(env); err != nil {
		t.Errorf("served envelope does not verify: %v", err)
	}

	var comps []ComponentEntry
	getJSON(t, srv.URL+"/v1/components", &comps)
	if len(comps) != 1 || comps[0].Component != "email" {
		t.Errorf("/v1/components = %+v", comps)
	}
}

func getJSON(t *testing.T, url string, into any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %s", url, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}

// The rollup reads the state of every sibling check, so it must never run
// while one of those states is held. Two results arriving for sibling checks
// at the same instant would otherwise each wait on the other's lock. This
// fails as a hang rather than an assertion, which is why it has a deadline.
func TestSiblingChecksDoNotDeadlock(t *testing.T) {
	h := newCompHarness(t,
		[]check.Check{namedCheck("a"), namedCheck("b"), namedCheck("c")},
		[]check.Component{
			{Name: "one", Checks: []string{"a", "b", "c"}},
			{Name: "two", Checks: []string{"c", "a"}},
		},
	)

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for range 50 {
			for _, name := range []string{"a", "b", "c"} {
				wg.Add(1)
				go func(name string) {
					defer wg.Done()
					// Process directly rather than through the harness: a
					// helper that calls t.Fatalf must not run off the test
					// goroutine.
					for _, s := range []check.Status{check.StatusDown, check.StatusUp} {
						h.coord.Process(t.Context(), check.Result{
							Check: name, Prober: "probe-a", Provider: "one",
							Vantage: check.VantageInternal, Status: s, At: time.Now().UTC(),
						})
					}
				}(name)
			}
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("sibling checks deadlocked in the component rollup")
	}
}
