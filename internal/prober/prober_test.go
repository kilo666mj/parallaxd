package prober

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

// countingListener accepts connections and counts them, so a test can assert
// that a target was — or crucially was not — contacted.
type countingListener struct {
	ln    net.Listener
	count atomic.Int64
}

func newCountingListener(t *testing.T) *countingListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c := &countingListener{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.count.Add(1)
			conn.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return c
}

func (c *countingListener) addr() string { return c.ln.Addr().String() }
func (c *countingListener) hits() int64  { return c.count.Load() }

type collector struct {
	mu   sync.Mutex
	envs []wire.Envelope
	err  error
}

func (c *collector) Submit(_ context.Context, env wire.Envelope) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.envs = append(c.envs, env)
	return nil
}

func (c *collector) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.envs)
}

type fixture struct {
	prober    *Prober
	proberPub ed25519.PublicKey
	coordKey  ed25519.PrivateKey
	coordRing *wire.Keyring // verifies results, as the coordinator would
	server    *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	proberPub, proberPriv, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	coordPub, coordPriv, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// What the prober trusts: the coordinator's key, and nothing else.
	proberRing := wire.NewKeyring()
	if err := proberRing.Add("coordinator", coordPub); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// What the coordinator trusts: this prober's key.
	coordRing := wire.NewKeyring()
	if err := coordRing.Add("probe-a", proberPub); err != nil {
		t.Fatalf("Add: %v", err)
	}

	p, err := New(Config{
		Name: "probe-a", Provider: "hetzner",
		Key: proberPriv, Keyring: proberRing, CoordinatorName: "coordinator",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)

	return &fixture{prober: p, proberPub: proberPub, coordKey: coordPriv,
		coordRing: coordRing, server: srv}
}

func tcpCheck(target string) check.Check {
	return check.Check{
		Name: "target-tcp", Kind: check.KindTCP, Target: target,
		Vantage: check.VantageInternal, Interval: time.Minute, Timeout: 3 * time.Second,
		Quorum: check.Quorum{Agree: 2, Of: 3},
	}
}

func (f *fixture) post(t *testing.T, env wire.Envelope) *http.Response {
	t.Helper()
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(f.server.URL+"/v1/probe", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (f *fixture) signedRequest(t *testing.T, c check.Check) wire.Envelope {
	t.Helper()
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatalf("NewRequestID: %v", err)
	}
	env, err := wire.SignRequest(f.coordKey, "coordinator", wire.Request{
		ID: id, Prober: "probe-a", Check: c, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	return env
}

// The property this package exists to hold. A prober will open a socket to an
// arbitrary address when asked, so an unverifiable request must produce no
// traffic whatsoever — not a refused probe reported as down, not a connection
// that is then discarded. Nothing.
func TestUnverifiedRequestCausesNoTraffic(t *testing.T) {
	f := newFixture(t)
	target := newCountingListener(t)
	c := tcpCheck(target.addr())

	_, strangerKey, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cases := map[string]wire.Envelope{
		"unsigned": {Peer: "coordinator", Payload: []byte(`{"id":"x"}`), Signature: []byte("nope")},
		"signed by a stranger": func() wire.Envelope {
			env, err := wire.SignRequest(strangerKey, "coordinator", wire.Request{
				ID: "x", Prober: "probe-a", Check: c, ExpiresAt: time.Now().Add(time.Minute),
			})
			if err != nil {
				t.Fatalf("SignRequest: %v", err)
			}
			return env
		}(),
		"unknown peer": func() wire.Envelope {
			env, err := wire.SignRequest(strangerKey, "somebody-else", wire.Request{
				ID: "x", Prober: "probe-a", Check: c, ExpiresAt: time.Now().Add(time.Minute),
			})
			if err != nil {
				t.Fatalf("SignRequest: %v", err)
			}
			return env
		}(),
		"expired": func() wire.Envelope {
			env, err := wire.SignRequest(f.coordKey, "coordinator", wire.Request{
				ID: "x", Prober: "probe-a", Check: c,
				IssuedAt:  time.Now().Add(-time.Hour),
				ExpiresAt: time.Now().Add(-30 * time.Minute),
			})
			if err != nil {
				t.Fatalf("SignRequest: %v", err)
			}
			return env
		}(),
	}

	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			before := target.hits()
			resp := f.post(t, env)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("status = %d, want 403", resp.StatusCode)
			}
			if got := target.hits() - before; got != 0 {
				t.Errorf("target was contacted %d times by an unverified request", got)
			}
		})
	}

	// And the control: a properly signed request does reach the target, so
	// the test above is not passing because nothing works.
	before := target.hits()
	if resp := f.post(t, f.signedRequest(t, c)); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d for a valid request, want 200", resp.StatusCode)
	}
	if got := target.hits() - before; got != 1 {
		t.Errorf("target contacted %d times by a valid request, want 1", got)
	}
}

func TestSignedRequestReturnsAVerifiableResult(t *testing.T) {
	f := newFixture(t)
	target := newCountingListener(t)
	c := tcpCheck(target.addr())

	req := f.signedRequest(t, c)
	var wanted wire.Request
	if err := json.Unmarshal(req.Payload, &wanted); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}

	resp := f.post(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var env wire.Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Verified exactly as the coordinator would.
	got, err := f.coordRing.OpenResult(env, time.Now())
	if err != nil {
		t.Fatalf("the coordinator could not verify the result: %v", err)
	}
	if got.Result.Status != check.StatusUp {
		t.Errorf("status = %q (%s), want up", got.Result.Status, got.Result.Detail)
	}
	if got.Result.Prober != "probe-a" || got.Result.Provider != "hetzner" {
		t.Errorf("identity = %+v", got.Result)
	}
	// The nonce must come back, so the coordinator can tell a fresh answer
	// from a result that happened to be lying around.
	if got.RequestID != wanted.ID {
		t.Errorf("request id = %q, want %q echoed", got.RequestID, wanted.ID)
	}
}

func TestRequestAudienceAndReplayAreEnforced(t *testing.T) {
	f := newFixture(t)
	target := newCountingListener(t)
	c := tcpCheck(target.addr())
	env := f.signedRequest(t, c)
	resp := f.post(t, env)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first status=%d", resp.StatusCode)
	}
	resp = f.post(t, env)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("replay status=%d, want 409", resp.StatusCode)
	}
	requestID, _ := wire.NewRequestID()
	wrong, err := wire.SignRequest(f.coordKey, "coordinator", wire.Request{ID: requestID, Prober: "probe-b", Check: c, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	resp = f.post(t, wrong)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong audience status=%d, want 403", resp.StatusCode)
	}
}

func TestDownTargetIsReportedNotErrored(t *testing.T) {
	f := newFixture(t)
	target := newCountingListener(t)
	addr := target.addr()
	target.ln.Close()

	resp := f.post(t, f.signedRequest(t, tcpCheck(addr)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; a down target is a result, not an HTTP error", resp.StatusCode)
	}
	var env wire.Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, err := f.coordRing.OpenResult(env, time.Now())
	if err != nil {
		t.Fatalf("OpenResult: %v", err)
	}
	if got.Result.Status != check.StatusDown {
		t.Errorf("status = %q, want down", got.Result.Status)
	}
}

// "I cannot speak this protocol" is an observation, and it must not count as
// evidence the target is down.
func TestUnsupportedKindIsUnknown(t *testing.T) {
	f := newFixture(t)
	c := tcpCheck("127.0.0.1:1")
	c.Kind = "gopher"

	env, err := f.prober.Run(t.Context(), c, "req-1")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got, err := f.coordRing.OpenResult(env, time.Now())
	if err != nil {
		t.Fatalf("OpenResult: %v", err)
	}
	if got.Result.Status != check.StatusUnknown {
		t.Fatalf("status = %q, want unknown", got.Result.Status)
	}
	if got.Result.IsEvidence() {
		t.Error("an unsupported kind must not count as evidence")
	}
}

func TestMalformedBodyIsRejected(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Post(f.server.URL+"/v1/probe", "application/json",
		strings.NewReader("{not json"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// The body is bounded before decoding, so an unauthenticated sender cannot
// make the prober allocate on demand.
func TestOversizedBodyIsRejected(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Post(f.server.URL+"/v1/probe", "application/json",
		bytes.NewReader(make([]byte, maxRequestBytes+1024)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("status = %d, want an oversized body refused", resp.StatusCode)
	}
}

func TestScheduleSubmitsResults(t *testing.T) {
	f := newFixture(t)
	target := newCountingListener(t)

	c := tcpCheck(target.addr())
	c.Interval = 20 * time.Millisecond
	c.Timeout = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()

	out := &collector{}
	f.prober.Schedule(ctx, []check.Check{c}, out)

	if out.len() == 0 {
		t.Fatal("no results submitted by the scheduler")
	}
	got, err := f.coordRing.OpenResult(out.envs[0], time.Now())
	if err != nil {
		t.Fatalf("OpenResult: %v", err)
	}
	// A scheduled probe answers no request, so the nonce is empty.
	if got.RequestID != "" {
		t.Errorf("request id = %q, want empty for a scheduled probe", got.RequestID)
	}
	if got.Result.Check != "target-tcp" {
		t.Errorf("check = %q", got.Result.Check)
	}
}

// A result the coordinator never receives is a gap, but the prober cannot fix
// it and must not stop probing over it.
func TestScheduleKeepsGoingWhenSubmitFails(t *testing.T) {
	f := newFixture(t)
	target := newCountingListener(t)

	c := tcpCheck(target.addr())
	c.Interval = 20 * time.Millisecond
	c.Timeout = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	f.prober.Schedule(ctx, []check.Check{c}, &collector{err: errNoCoordinator})

	if target.hits() < 2 {
		t.Errorf("target probed %d times; the scheduler stopped after a submit failure",
			target.hits())
	}
}

var errNoCoordinator = &net.OpError{Op: "dial", Err: errClosed{}}

type errClosed struct{}

func (errClosed) Error() string { return "connection refused" }

func TestScheduleSkipsInvalidChecks(t *testing.T) {
	f := newFixture(t)
	bad := tcpCheck("127.0.0.1:1")
	bad.Vantage = ""
	bad.Interval = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	out := &collector{}
	f.prober.Schedule(ctx, []check.Check{bad}, out)
	if out.len() != 0 {
		t.Errorf("submitted %d results for an invalid check", out.len())
	}
}

func TestNewValidatesConfig(t *testing.T) {
	_, priv, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ring := wire.NewKeyring()

	for name, cfg := range map[string]Config{
		"no name":    {Key: priv, Keyring: ring},
		"no key":     {Name: "p", Keyring: ring},
		"short key":  {Name: "p", Key: ed25519.PrivateKey("short"), Keyring: ring},
		"no keyring": {Name: "p", Key: priv},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestHealthEndpoint(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Get(f.server.URL + "/v1/health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["prober"] != "probe-a" {
		t.Errorf("body = %v", body)
	}
}
