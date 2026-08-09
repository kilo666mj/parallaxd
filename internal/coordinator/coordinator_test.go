package coordinator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/prober"
	"github.com/kilo666mj/parallaxd/internal/quorum"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

// The tests below wire real prober.Prober instances to a real Coordinator over
// httptest servers. Mocking the prober would mostly test that the coordinator
// agrees with a fixture of its own making; the interesting failures live in
// the seam between the two — signature verification, nonce echo, the shape of
// a result — so the seam is what gets exercised.

type fakeNotifier struct {
	mu     sync.Mutex
	alerts []Alert
	err    error
}

func (f *fakeNotifier) Notify(_ context.Context, a Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.alerts = append(f.alerts, a)
	return nil
}

func (f *fakeNotifier) all() []Alert {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Alert(nil), f.alerts...)
}

func (f *fakeNotifier) count() int { return len(f.all()) }

// testProber is a real prober behind a server that counts requests, so a test
// can assert who was asked as well as what came back.
type testProber struct {
	name     string
	provider string
	asked    atomic.Int64
	server   *httptest.Server
	peer     Peer
	impl     *prober.Prober

	// key is kept so a test can sign something as this prober — mesh reports
	// in particular, which the prober's own code signs in production.
	key ed25519.PrivateKey
}

type harness struct {
	t        *testing.T
	coord    *Coordinator
	probers  map[string]*testProber
	notifier *fakeNotifier
	target   *toggleTarget
	chk      check.Check
}

// toggleTarget is a listener that can be turned off and on, so a test can make
// a real check fail and recover.
type toggleTarget struct {
	mu   sync.Mutex
	ln   net.Listener
	addr string
}

func newToggleTarget(t *testing.T) *toggleTarget {
	t.Helper()
	tt := &toggleTarget{}
	tt.up(t)
	t.Cleanup(func() { tt.down() })
	return tt
}

func (tt *toggleTarget) up(t *testing.T) {
	t.Helper()
	tt.mu.Lock()
	defer tt.mu.Unlock()
	if tt.ln != nil {
		return
	}
	var (
		ln  net.Listener
		err error
	)
	if tt.addr == "" {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	} else {
		// Rebind the same port so the check's target stays valid.
		ln, err = net.Listen("tcp", tt.addr)
	}
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tt.ln, tt.addr = ln, ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
}

func (tt *toggleTarget) down() {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	if tt.ln != nil {
		tt.ln.Close()
		tt.ln = nil
	}
}

// newHarness builds a coordinator and n probers that genuinely talk to it.
// providers assigns each prober a provider name; nil means all distinct.
func newHarness(t *testing.T, n int, q check.Quorum, providers []string) *harness {
	t.Helper()

	coordPub, coordPriv, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	target := newToggleTarget(t)
	chk := check.Check{
		Name: "svc", Kind: check.KindTCP, Target: target.addr,
		// Internal, because the target is loopback and a public-vantage check
		// is not allowed to be satisfied from inside.
		Vantage:  check.VantageInternal,
		Interval: time.Minute, Timeout: 2 * time.Second,
		Quorum: q,
	}

	h := &harness{t: t, probers: map[string]*testProber{}, notifier: &fakeNotifier{},
		target: target, chk: chk}

	var peers []Peer
	for i := range n {
		name := string(rune('a' + i))
		name = "probe-" + name
		provider := name
		if providers != nil {
			provider = providers[i]
		}

		pub, priv, err := wire.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		ring := wire.NewKeyring()
		if err := ring.Add("coordinator", coordPub); err != nil {
			t.Fatalf("Add: %v", err)
		}
		p, err := prober.New(prober.Config{
			Name: name, Provider: provider, Key: priv, Keyring: ring,
		})
		if err != nil {
			t.Fatalf("prober.New: %v", err)
		}

		tp := &testProber{name: name, provider: provider, impl: p, key: priv}
		inner := p.Handler()
		tp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/probe" {
				tp.asked.Add(1)
			}
			inner.ServeHTTP(w, r)
		}))
		t.Cleanup(tp.server.Close)

		tp.peer = Peer{Name: name, URL: tp.server.URL, Provider: provider, PublicKey: pub}
		peers = append(peers, tp.peer)
		h.probers[name] = tp
	}

	c, err := New(Config{
		Name: "coordinator", Key: coordPriv,
		Peers: peers, Checks: []check.Check{chk},
		Notifier:      h.notifier,
		FanOutTimeout: 3 * time.Second,
		Logger:        discardLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.coord = c
	return h
}

// reportFrom builds the result a prober would submit after running the check
// itself, by actually running it.
func (h *harness) reportFrom(name string, status check.Status) check.Result {
	h.t.Helper()
	tp := h.probers[name]
	return check.Result{
		Check: h.chk.Name, Prober: tp.name, Provider: tp.provider,
		Vantage: h.chk.Vantage, Status: status, At: time.Now().UTC(),
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// probeDirect has a prober run the check for real and sign the result, which
// is exactly what its scheduler would submit.
func (h *harness) probeDirect(t *testing.T, name string) wire.Envelope {
	t.Helper()
	env, err := h.probers[name].impl.Run(t.Context(), h.chk, "")
	if err != nil {
		t.Fatalf("prober Run: %v", err)
	}
	return env
}

// A prober that has already reported has voted. Asking it again spends a
// probe to learn something quorum would de-duplicate anyway.
func TestReportingProberIsNotAsked(t *testing.T) {
	h := newHarness(t, 4, check.Quorum{Agree: 3, Of: 4}, nil)
	h.target.down()

	v, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	if got := h.probers["probe-a"].asked.Load(); got != 0 {
		t.Errorf("the reporting prober was asked %d times", got)
	}
	var others int64
	for name, p := range h.probers {
		if name != "probe-a" {
			others += p.asked.Load()
		}
	}
	// Of-1 corroborators, no more: the fan-out is bounded by the quorum, not
	// by the size of the fleet.
	if others != 3 {
		t.Errorf("corroborators asked %d times, want 3", others)
	}
	if v.Status != check.StatusDown {
		t.Fatalf("status = %q (%s), want down", v.Status, v.Reason)
	}
	if v.Down != 4 {
		t.Errorf("down = %d, want the reporter plus 3 corroborators", v.Down)
	}
}

// An up result answers the question on its own. Corroborating it would spend N
// probes to confirm what one prober can already see.
func TestUpResultDoesNotFanOut(t *testing.T) {
	h := newHarness(t, 4, check.Quorum{Agree: 3, Of: 4}, nil)

	v, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusUp))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	for name, p := range h.probers {
		if got := p.asked.Load(); got != 0 {
			t.Errorf("%s was asked %d times for an up result", name, got)
		}
	}
	if v.Status != check.StatusUp {
		t.Errorf("status = %q, want up", v.Status)
	}
	if h.notifier.count() != 0 {
		t.Errorf("an up result produced %d alerts", h.notifier.count())
	}
}

// Agree: 1 means the operator has said one prober suffices, so there is
// nothing to ask.
func TestSingleProberQuorumSkipsFanOut(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 1, Of: 3}, nil)
	h.target.down()

	v, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	for name, p := range h.probers {
		if got := p.asked.Load(); got != 0 {
			t.Errorf("%s was asked %d times when one report already met quorum", name, got)
		}
	}
	if v.Status != check.StatusDown {
		t.Errorf("status = %q, want down", v.Status)
	}
}

// The behaviour the whole design exists for: a genuine outage produces a
// failing result every interval, and an alert per result is what trains people
// to filter the channel.
func TestOutageAlertsOnceThenRecoversOnce(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	h.target.down()

	for range 4 {
		if _, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown)); err != nil {
			t.Fatalf("Process: %v", err)
		}
	}
	if got := h.notifier.count(); got != 1 {
		t.Fatalf("four failing results produced %d alerts, want 1", got)
	}
	if got := h.notifier.all()[0]; got.Kind != KindDown {
		t.Errorf("alert kind = %q, want down", got.Kind)
	}

	h.target.up(t)
	for range 3 {
		if _, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusUp)); err != nil {
			t.Fatalf("Process: %v", err)
		}
	}
	alerts := h.notifier.all()
	if len(alerts) != 2 {
		t.Fatalf("got %d alerts, want one down and one recovery", len(alerts))
	}
	if alerts[1].Kind != KindRecovered {
		t.Errorf("second alert = %q, want recovered", alerts[1].Kind)
	}
}

// A check that has never produced a usable result has not been declared
// healthy, so its first up is not a recovery. Announcing "recovered" for
// everything at startup is how a monitoring channel gets muted.
func TestFirstUpIsNotARecovery(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	if _, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusUp)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got := h.notifier.count(); got != 0 {
		t.Errorf("a first up produced %d alerts", got)
	}
}

// Not being able to confirm an outage is not evidence it ended. Treating an
// inconclusive verdict as recovery would make a flaky corroborator look like a
// fix.
func TestInconclusiveDoesNotClearADown(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	h.target.down()

	if _, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if h.notifier.count() != 1 {
		t.Fatalf("expected the initial down alert, got %d", h.notifier.count())
	}

	// Every corroborator goes away, so the next failing report cannot reach
	// quorum and the verdict is inconclusive.
	for name, p := range h.probers {
		if name != "probe-a" {
			p.server.Close()
		}
	}
	v, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if v.Status != check.StatusUnknown {
		t.Fatalf("status = %q (%s), want inconclusive", v.Status, v.Reason)
	}
	if got := h.notifier.count(); got != 1 {
		t.Errorf("an inconclusive verdict changed the alert count to %d", got)
	}

	// And the state is still down. A lone up cannot clear it either: recovery is
	// a decision and needs the same corroboration strength as the outage.
	h.target.up(t)
	if _, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusUp)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	alerts := h.notifier.all()
	if len(alerts) != 1 {
		t.Errorf("alerts = %+v, want the uncorroborated recovery suppressed", alerts)
	}
}

// Silence is not a vote. A corroborator that cannot be reached contributes
// nothing rather than counting as agreement.
func TestUnreachableCorroboratorIsNotAVote(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 3, Of: 3}, nil)
	now := time.Now().UTC()
	h.coord.now = func() time.Time { return now }
	// Keep the first observation fresh while the test advances decision time.
	h.coord.cfg.ResultMaxAge = time.Hour
	h.target.down()
	h.probers["probe-c"].server.Close()

	r := h.reportFrom("probe-a", check.StatusDown)
	r.At = now
	v, err := h.coord.Process(t.Context(), r)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	// Two of three agree, quorum needs three: no verdict, no alert.
	if v.Status == check.StatusDown {
		t.Fatalf("an unreachable prober was counted toward quorum: %s", v.Reason)
	}
	if v.Down != 2 {
		t.Errorf("down = %d, want the reporter plus the one reachable corroborator", v.Down)
	}
	if h.notifier.count() != 0 {
		t.Errorf("an unmet quorum produced %d alerts", h.notifier.count())
	}
	diagnostics := h.coord.DiagnosticState().Checks
	if len(diagnostics) != 1 || !diagnostics[0].SuspectedSince.Equal(now) || diagnostics[0].InconclusiveAttempts != 1 {
		t.Fatalf("suspect diagnostics = %+v", diagnostics)
	}
	if diagnostics[0].LastInconclusiveReason == "" {
		t.Error("inconclusive attempt did not retain its reason")
	}
	if len(diagnostics[0].InconclusiveHistory) != 1 || diagnostics[0].InconclusiveHistory[0].Down != 2 {
		t.Fatalf("inconclusive history = %+v", diagnostics[0].InconclusiveHistory)
	}

	// Once the missing vantage returns, the eventual alert retains when the
	// outage was first observed rather than presenting quorum time as onset.
	p := h.probers["probe-c"]
	inner := p.impl.Handler()
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/probe" {
			p.asked.Add(1)
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(p.server.Close)
	p.peer.URL = p.server.URL
	h.coord.byName[p.name] = p.peer
	for i := range h.coord.peers {
		if h.coord.peers[i].Name == p.name {
			h.coord.peers[i] = p.peer
		}
	}
	now = now.Add(2 * time.Second)
	r = h.reportFrom("probe-a", check.StatusDown)
	r.At = now
	if _, err := h.coord.Process(t.Context(), r); err != nil {
		t.Fatalf("Process after corroborator returned: %v", err)
	}
	alerts := h.notifier.all()
	if len(alerts) != 1 || !alerts[0].SuspectedAt.Equal(now.Add(-2*time.Second)) {
		t.Fatalf("alerts = %+v", alerts)
	}
	if summary := alerts[0].Summary(); !strings.Contains(summary, "first suspected 2s earlier") {
		t.Fatalf("summary = %q", summary)
	}

	h.target.up(t)
	now = now.Add(2 * time.Second)
	r = h.reportFrom("probe-a", check.StatusUp)
	r.At = now
	if _, err := h.coord.Process(t.Context(), r); err != nil {
		t.Fatalf("Process recovery: %v", err)
	}
	status := h.coord.Status()[0]
	if !status.SuspectedSince.IsZero() || status.InconclusiveAttempts != 0 || len(status.InconclusiveHistory) != 0 {
		t.Fatalf("recovery retained suspect state: %+v", status)
	}
}

// Three probers behind one provider are one opinion held three times, so the
// fan-out should spend its requests where the rule can actually be satisfied.
func TestDistinctProvidersPrefersFreshProviders(t *testing.T) {
	// probe-a and probe-b share a provider; c and d are distinct.
	h := newHarness(t, 4, check.Quorum{Agree: 3, Of: 3, DistinctProviders: true},
		[]string{"hetzner", "hetzner", "contabo", "netcup"})
	h.target.down()

	v, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	// The reporter is at hetzner, so probe-b adds no diversity and should be
	// passed over in favour of contabo and netcup.
	if got := h.probers["probe-b"].asked.Load(); got != 0 {
		t.Errorf("a same-provider prober was asked %d times while distinct ones were free", got)
	}
	for _, name := range []string{"probe-c", "probe-d"} {
		if got := h.probers[name].asked.Load(); got != 1 {
			t.Errorf("%s asked %d times, want 1", name, got)
		}
	}
	if v.Status != check.StatusDown {
		t.Fatalf("status = %q (%s), want down", v.Status, v.Reason)
	}
	if len(v.Providers) != 3 {
		t.Errorf("providers = %v, want three distinct", v.Providers)
	}
}

func TestUnknownCheckIsRejected(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	r := h.reportFrom("probe-a", check.StatusDown)
	r.Check = "not-a-check"
	if _, err := h.coord.Process(t.Context(), r); err == nil {
		t.Error("a result for an unknown check was processed")
	}
}

// A result counts toward a verdict, so an unauthenticated one could
// manufacture agreement or forge an all-clear.
func TestHandlerRejectsUnverifiedResults(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	srv := httptest.NewServer(h.coord.Handler())
	defer srv.Close()

	_, strangerKey, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	forged, err := wire.SignResult(strangerKey, wire.ResultPayload{
		Result: h.reportFrom("probe-a", check.StatusDown),
	})
	if err != nil {
		t.Fatalf("SignResult: %v", err)
	}

	cases := map[string]wire.Envelope{
		"unsigned":     {Peer: "probe-a", Payload: []byte(`{"result":{}}`), Signature: []byte("no")},
		"wrong key":    forged,
		"unknown peer": {Peer: "nobody", Payload: []byte(`{"result":{}}`), Signature: []byte("no")},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			body, err := json.Marshal(env)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			resp, err := http.Post(srv.URL+"/v1/results", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("status = %d, want 403", resp.StatusCode)
			}
		})
	}
	h.coord.Wait()
	if h.notifier.count() != 0 {
		t.Errorf("forged results produced %d alerts", h.notifier.count())
	}
}

func TestHandlerAuthorizesAssignmentAndRejectsReplay(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	assigned, _ := h.coord.assignedTo(h.chk)
	var other string
	for name := range h.probers {
		if name != assigned {
			other = name
			break
		}
	}
	srv := httptest.NewServer(h.coord.Handler())
	defer srv.Close()
	post := func(env wire.Envelope) int {
		body, _ := json.Marshal(env)
		resp, err := http.Post(srv.URL+"/v1/results", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	forge := func(name string) wire.Envelope {
		env, err := wire.SignResult(h.probers[name].key, wire.ResultPayload{Result: h.reportFrom(name, check.StatusUp)})
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	if code := post(forge(other)); code != http.StatusForbidden {
		t.Fatalf("unassigned result status=%d, want 403", code)
	}
	valid := forge(assigned)
	if code := post(valid); code != http.StatusAccepted {
		t.Fatalf("assigned result status=%d, want 202", code)
	}
	h.coord.Wait()
	if code := post(valid); code != http.StatusConflict {
		t.Fatalf("replayed result status=%d, want 409", code)
	}
}

func TestCoordinatorOwnsProviderMetadata(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3, DistinctProviders: true}, nil)
	r := h.reportFrom("probe-a", check.StatusUp)
	r.Provider = "invented-provider"
	v, err := h.coord.Process(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Providers) != 1 || v.Providers[0] != "probe-a" {
		t.Fatalf("providers=%v, want registered provider", v.Providers)
	}
}

func TestHandlerRejectsMalformedAndOversized(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	srv := httptest.NewServer(h.coord.Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/results", "application/json", strings.NewReader("{nope"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed body: status = %d, want 400", resp.StatusCode)
	}

	resp, err = http.Post(srv.URL+"/v1/results", "application/json",
		bytes.NewReader(make([]byte, maxRequestBytes+1024)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		t.Error("an oversized body was accepted")
	}
}

// The full path: a real prober submits a signed result over HTTP and the
// coordinator corroborates with real probers.
func TestEndToEndThroughTheHandler(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	h.target.down()

	srv := httptest.NewServer(h.coord.Handler())
	defer srv.Close()

	// probe-a runs the check for real and signs what it saw — the same
	// envelope its scheduler would submit.
	env := h.probeDirect(t, "probe-a")

	body, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(srv.URL+"/v1/results", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}

	h.coord.Wait()
	if got := h.notifier.count(); got != 1 {
		t.Fatalf("got %d alerts, want 1", got)
	}
	a := h.notifier.all()[0]
	if a.Kind != KindDown || a.Check != "svc" {
		t.Errorf("alert = %+v", a)
	}
	if !strings.Contains(a.Summary(), "reported down") {
		t.Errorf("summary = %q, want it to state the agreement", a.Summary())
	}

	// And the status endpoint reflects it.
	statusResp, err := http.Get(srv.URL + "/v1/status")
	if err != nil {
		t.Fatalf("get status: %v", err)
	}
	defer statusResp.Body.Close()
	var entries []StatusEntry
	if err := json.NewDecoder(statusResp.Body).Decode(&entries); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if len(entries) != 1 || entries[0].Status != string(check.StatusDown) {
		t.Errorf("status = %+v", entries)
	}
	if entries[0].AssignedTo == "" {
		t.Error("status did not report an assigned prober")
	}
}

func TestAssignmentIsDeterministicAndCovers(t *testing.T) {
	h := newHarness(t, 4, check.Quorum{Agree: 2, Of: 3}, nil)

	first := h.coord.Assignments()
	for range 5 {
		if got := h.coord.Assignments(); !sameAssignments(first, got) {
			t.Fatalf("assignment changed between calls: %v vs %v", first, got)
		}
	}

	// Every prober appears, even with nothing assigned, so an idle prober is
	// visible rather than missing.
	if len(first) != 4 {
		t.Errorf("assignments cover %d probers, want 4", len(first))
	}
	var total int
	for _, checks := range first {
		total += len(checks)
	}
	if total != 1 {
		t.Errorf("%d checks assigned, want exactly 1 (one check, one owner)", total)
	}
}

func sameAssignments(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || len(va) != len(vb) {
			return false
		}
		for i := range va {
			if va[i] != vb[i] {
				return false
			}
		}
	}
	return true
}

func TestNewValidates(t *testing.T) {
	pub, priv, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	peer := Peer{Name: "p", URL: "http://x", PublicKey: pub}
	good := check.Check{
		Name: "c", Kind: check.KindTCP, Target: "x:1", Vantage: check.VantageInternal,
		Interval: time.Minute, Timeout: time.Second, Quorum: check.Quorum{Agree: 1, Of: 1},
	}

	for name, cfg := range map[string]Config{
		"no name":  {Key: priv, Peers: []Peer{peer}},
		"no key":   {Name: "c", Peers: []Peer{peer}},
		"no peers": {Name: "c", Key: priv},
		"duplicate peer": {Name: "c", Key: priv,
			Peers: []Peer{peer, {Name: "p", URL: "http://y", PublicKey: pub}}},
		"invalid check": {Name: "c", Key: priv, Peers: []Peer{peer},
			Checks: []check.Check{{Name: "bad"}}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}

	// A quorum larger than the fleet can never be met, and would leave the
	// check permanently inconclusive with nothing ever alerting.
	tooBig := good
	tooBig.Quorum = check.Quorum{Agree: 2, Of: 3}
	if _, err := New(Config{Name: "c", Key: priv, Peers: []Peer{peer},
		Checks: []check.Check{tooBig}}); err == nil {
		t.Error("a quorum larger than the registered fleet was accepted")
	}

	if _, err := New(Config{Name: "c", Key: priv, Peers: []Peer{peer},
		Checks: []check.Check{good}}); err != nil {
		t.Errorf("a valid config was rejected: %v", err)
	}

	// A hard-down target commonly consumes the entire probe timeout. The
	// coordinator still needs enough time afterward to receive and verify the
	// signed result; otherwise every real timeout becomes an absent vote.
	pub2, _, err := wire.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	peer2 := Peer{Name: "q", URL: "http://y", PublicKey: pub2}
	slow := good
	slow.Timeout = 15 * time.Second
	slow.Quorum = check.Quorum{Agree: 2, Of: 2}
	_, err = New(Config{
		Name: "c", Key: priv, Peers: []Peer{peer, peer2}, Checks: []check.Check{slow},
		FanOutTimeout: 10 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "leaves no response budget") {
		t.Fatalf("short fan-out timeout error = %v, want response-budget error", err)
	}

	providerBound := good
	providerBound.Quorum = check.Quorum{Agree: 2, Of: 2, DistinctProviders: true}
	_, err = New(Config{
		Name: "c", Key: priv,
		Peers:  []Peer{{Name: "p", URL: "http://x", Provider: "same", PublicKey: pub}, {Name: "q", URL: "http://y", Provider: "same", PublicKey: pub2}},
		Checks: []check.Check{providerBound},
	})
	if err == nil || !strings.Contains(err.Error(), "requires 2 distinct providers") {
		t.Fatalf("provider diversity error = %v, want impossible-provider error", err)
	}

	_, err = New(Config{
		Name: "c", Key: priv,
		Peers:  []Peer{{Name: "p", URL: "http://x", PublicKey: pub}, {Name: "q", URL: "http://y", PublicKey: pub}},
		Checks: []check.Check{providerBound},
	})
	if err == nil || !strings.Contains(err.Error(), "share a public key") {
		t.Fatalf("shared-key error = %v, want duplicate-key error", err)
	}
}

func TestCorroborationCanUseTheFullCheckTimeout(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)

	// Keep the HTTP exchange open until the check's own deadline. This is what
	// a black-holed host did in production: it is down evidence, but only after
	// consuming the complete probe timeout.
	target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(target.Close)

	h.chk.Kind = check.KindHTTP
	h.chk.Target = target.URL
	h.chk.Timeout = 50 * time.Millisecond
	h.coord.checks[h.chk.Name] = h.chk
	h.coord.cfg.FanOutTimeout = 500 * time.Millisecond

	v, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if v.Status != check.StatusDown || v.Down != 3 {
		t.Fatalf("verdict = %+v, want three down votes after full probe timeouts", v)
	}
	if got := h.notifier.count(); got != 1 {
		t.Fatalf("notifications = %d, want one immediate down alert", got)
	}
}

// A failing notifier must not cause the same outage to alert repeatedly: the
// state has already moved, and re-announcing on every subsequent result is the
// noise this design removes.
func TestNotifierFailureDoesNotCauseRepeats(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	h.notifier.err = errBoom
	h.target.down()

	for range 3 {
		if _, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown)); err != nil {
			t.Fatalf("Process: %v", err)
		}
	}
	h.notifier.mu.Lock()
	h.notifier.err = nil
	h.notifier.mu.Unlock()

	// Still down, so still no new alert — the transition already happened.
	if _, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got := h.notifier.count(); got != 0 {
		t.Errorf("alerts recorded = %d; a failed delivery should not be retried as a new transition", got)
	}
}

var errBoom = &net.OpError{Op: "dial", Err: errRefused{}}

type errRefused struct{}

func (errRefused) Error() string { return "connection refused" }

func TestQuorumVerdictIsNotReimplemented(t *testing.T) {
	// A guard against drift: the coordinator must delegate counting. If this
	// ever disagrees with quorum.Evaluate, the coordinator has grown its own
	// opinion about what agreement means.
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	results := []check.Result{
		h.reportFrom("probe-a", check.StatusDown),
		h.reportFrom("probe-b", check.StatusDown),
	}
	want := quorum.Evaluate(h.chk, results, quorum.Options{Now: time.Now(), MaxAge: time.Minute})
	got := h.coord.evaluate(h.chk, results)
	if got.Status != want.Status || got.Down != want.Down || got.Up != want.Up {
		t.Errorf("coordinator verdict %+v disagrees with quorum %+v", got, want)
	}
}

// An explicit preferred owner overrides the rendezvous choice while healthy.
func TestExplicitProberWinsOverTheHash(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)

	computed, ok := assign("svc", h.coord.peers)
	if !ok {
		t.Fatal("no computed assignment")
	}

	// Pick a prober the hash did not choose.
	var other string
	for _, p := range h.coord.peers {
		if p.Name != computed.Name {
			other = p.Name
			break
		}
	}

	chk := h.chk
	chk.Prober = other
	h.coord.checks["svc"] = chk

	if got := h.coord.Assignments()[other]; len(got) != 1 || got[0] != "svc" {
		t.Errorf("assignments[%s] = %v, want the check it was given explicitly", other, got)
	}
	if got := h.coord.Assignments()[computed.Name]; len(got) != 0 {
		t.Errorf("assignments[%s] = %v, want none — the hash was overridden", computed.Name, got)
	}
	for _, e := range h.coord.Status() {
		if e.Check == "svc" && e.AssignedTo != other {
			t.Errorf("status assigned_to = %q, want %q", e.AssignedTo, other)
		}
	}
}

// Naming a prober that is not registered means nobody the coordinator knows is
// running the check, which is worth discovering at startup rather than during
// an incident.
func TestUnknownExplicitProberIsRejected(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)

	chk := h.chk
	chk.Prober = "probe-nowhere"
	if _, err := New(Config{
		Name: "coordinator", Key: h.coord.cfg.Key,
		Peers: h.coord.peers, Checks: []check.Check{chk},
		Logger: discardLogger(),
	}); err == nil {
		t.Fatal("New accepted a check assigned to an unregistered prober")
	}
}

func TestEligibleProberPoolScopesOwnershipAndCorroboration(t *testing.T) {
	h := newHarness(t, 4, check.Quorum{Agree: 2, Of: 2}, nil)
	chk := h.chk
	chk.Prober = "probe-b"
	chk.Probers = []string{"probe-b", "probe-d"}

	if got, ok := h.coord.baseAssignedTo(chk); !ok || got != "probe-b" {
		t.Fatalf("owner = %q, %v; want probe-b", got, ok)
	}
	peers := h.coord.corroborators(chk, check.Result{Prober: "probe-b", Provider: "probe-b"})
	if len(peers) != 1 || peers[0].Name != "probe-d" {
		t.Fatalf("corroborators = %+v, want only probe-d", peers)
	}
}

func TestEligibleProberPoolIsValidatedAgainstFleet(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	chk := h.chk
	chk.Probers = []string{"probe-a", "probe-nowhere"}
	if _, err := New(Config{Name: "coordinator", Key: h.coord.cfg.Key, Peers: h.coord.peers,
		Checks: []check.Check{chk}, Logger: discardLogger()}); err == nil || !strings.Contains(err.Error(), "unregistered eligible prober") {
		t.Fatalf("unknown eligible prober error = %v", err)
	}

	chk.Probers = []string{"probe-a", "probe-b"}
	if _, err := New(Config{Name: "coordinator", Key: h.coord.cfg.Key, Peers: h.coord.peers,
		Checks: []check.Check{chk}, Logger: discardLogger()}); err == nil || !strings.Contains(err.Error(), "asks 3 probers") {
		t.Fatalf("undersized eligible pool error = %v", err)
	}
}
