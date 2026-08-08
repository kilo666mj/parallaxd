package coordinator

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/mesh"
	"github.com/kilo666mj/parallaxd/internal/prober"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

// Phase 2 end to end.
//
// These run on the real-prober harness rather than a stub one, because the
// property under test is that suppression changes a verdict that corroboration
// would otherwise have reached. With unreachable peers the fan-out fails and
// nothing alerts anyway — a test built that way passes whether or not the mesh
// works at all, which is worse than no test. (Written that way first.)

// submitMesh posts a signed report through the real handler, so the signature
// and identity checks are exercised rather than bypassed.
func (h *harness) submitMesh(t *testing.T, srv *httptest.Server, from string, peers map[string]bool) int {
	t.Helper()
	r := mesh.Report{Prober: from, At: time.Now().UTC()}
	for name, ok := range peers {
		r.Peers = append(r.Peers, mesh.PeerView{Peer: name, Reachable: ok})
	}
	env, err := wire.SignMeshReport(h.probers[from].key, r)
	if err != nil {
		t.Fatalf("SignMeshReport: %v", err)
	}
	body, _ := json.Marshal(env)
	resp, err := http.Post(srv.URL+"/v1/mesh", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/mesh: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func (h *harness) downAlerts() int {
	var n int
	for _, a := range h.notifier.all() {
		if a.Kind == KindDown {
			n++
		}
	}
	return n
}

// The control. Three probers that can all see the fleet, a target that is
// genuinely down: corroboration works and the outage is reported.
//
// Without this, the suppression test below proves nothing.
func TestOutageIsReportedWhenTheFleetIsHealthy(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	srv := httptest.NewServer(h.coord.Handler())
	defer srv.Close()

	for _, name := range []string{"probe-a", "probe-b", "probe-c"} {
		others := map[string]bool{}
		for _, other := range []string{"probe-a", "probe-b", "probe-c"} {
			if other != name {
				others[other] = true
			}
		}
		h.submitMesh(t, srv, name, others)
	}
	if got := h.coord.Mesh().Isolated; len(got) != 0 {
		t.Fatalf("isolated = %v, want none", got)
	}

	h.target.down()
	if _, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if h.downAlerts() != 1 {
		t.Fatalf("got %d down alerts, want 1: %+v", h.downAlerts(), h.notifier.all())
	}
}

// The same outage, the same corroboration — but the probers that agree can
// reach nothing, so their agreement is one broken network reported twice
// rather than two independent vantages.
func TestIsolatedProbersDoNotCarryAVerdict(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	srv := httptest.NewServer(h.coord.Handler())
	defer srv.Close()

	// a and b are cut off. c can still see b.
	h.submitMesh(t, srv, "probe-a", map[string]bool{"probe-b": false, "probe-c": false})
	h.submitMesh(t, srv, "probe-b", map[string]bool{"probe-a": false, "probe-c": false})
	h.submitMesh(t, srv, "probe-c", map[string]bool{"probe-a": false, "probe-b": true})

	st := h.coord.Mesh()
	if len(st.Isolated) != 2 {
		t.Fatalf("isolated = %v, want probe-a and probe-b", st.Isolated)
	}
	if !st.Partitioned {
		t.Error("two isolated probers were not reported as a partition")
	}

	h.target.down()
	v, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	if h.downAlerts() != 0 {
		t.Fatalf("isolated probers produced an outage alert: %+v", h.notifier.all())
	}
	if v.Suppressed != 1 || v.Status == check.StatusDown {
		t.Errorf("verdict = %+v, want the result suppressed", v)
	}

	// And it did not spend the corroboration budget asking anyone about it.
	// During a partition every cut-off prober reports everything down, and
	// fanning out on each would starve the triggers that mean something.
	for name, tp := range h.probers {
		if n := tp.asked.Load(); n != 0 {
			t.Errorf("%s was asked %d times to corroborate an isolated prober's report", name, n)
		}
	}
}

// Suppression must be temporary in the right way: once the prober can see the
// fleet again, its opinion counts again immediately.
func TestRejoinedProberCountsAgain(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	srv := httptest.NewServer(h.coord.Handler())
	defer srv.Close()

	h.submitMesh(t, srv, "probe-a", map[string]bool{"probe-b": false, "probe-c": false})
	h.target.down()
	if _, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if h.downAlerts() != 0 {
		t.Fatalf("suppression did not apply: %+v", h.notifier.all())
	}

	h.submitMesh(t, srv, "probe-a", map[string]bool{"probe-b": true, "probe-c": true})
	if _, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if h.downAlerts() != 1 {
		t.Fatalf("got %d down alerts after the prober rejoined, want 1", h.downAlerts())
	}
}

// Silencing a prober is a monitoring gap. If it happens quietly, Phase 2 has
// traded loud false alerts for a quiet blind spot — the worse failure.
func TestIsolationIsAlertedOnceAndSoIsTheRejoin(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	srv := httptest.NewServer(h.coord.Handler())
	defer srv.Close()

	h.submitMesh(t, srv, "probe-a", map[string]bool{"probe-b": false, "probe-c": false})
	alerts := h.notifier.all()
	if len(alerts) != 1 || alerts[0].Kind != KindIsolated || alerts[0].Prober != "probe-a" {
		t.Fatalf("alerts = %+v, want one isolation alert for probe-a", alerts)
	}

	h.submitMesh(t, srv, "probe-a", map[string]bool{"probe-b": false, "probe-c": false})
	if n := h.notifier.count(); n != 1 {
		t.Fatalf("got %d alerts, want no repeat while it stays isolated", n)
	}

	h.submitMesh(t, srv, "probe-a", map[string]bool{"probe-b": true, "probe-c": true})
	alerts = h.notifier.all()
	if len(alerts) != 2 || alerts[1].Kind != KindRejoined {
		t.Fatalf("alerts = %+v, want a rejoin — otherwise the alert never closes", alerts)
	}
}

// A report that silences a prober is an instruction with consequences.
func TestUnsignedMeshReportIsRefused(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	srv := httptest.NewServer(h.coord.Handler())
	defer srv.Close()

	body, _ := json.Marshal(wire.Envelope{Peer: "probe-a", Payload: []byte(`{"prober":"probe-a"}`)})
	resp, err := http.Post(srv.URL+"/v1/mesh", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %s, want 403", resp.Status)
	}
	if len(h.coord.Mesh().Reporting) != 0 {
		t.Error("an unsigned report was recorded")
	}
}

// One prober must not be able to have another silenced — that would be a way
// to suppress an opinion, which is how a real outage goes unreported.
func TestMeshReportCannotSpeakForAnotherProber(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	srv := httptest.NewServer(h.coord.Handler())
	defer srv.Close()

	r := mesh.Report{Prober: "probe-b", At: time.Now().UTC(), Peers: []mesh.PeerView{
		{Peer: "probe-a", Reachable: false}, {Peer: "probe-c", Reachable: false},
	}}
	env, err := wire.SignMeshReport(h.probers["probe-a"].key, r)
	if err != nil {
		t.Fatalf("SignMeshReport: %v", err)
	}
	body, _ := json.Marshal(env)
	resp, err := http.Post(srv.URL+"/v1/mesh", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %s, want 403 — probe-a signed a report claiming to be probe-b", resp.Status)
	}
	if h.coord.Mesh().IsIsolated("probe-b") {
		t.Error("probe-b was silenced by a report it did not sign")
	}
}

// credentialFor mints the signed proof a prober sends on a read request.
func (h *harness) credentialFor(t *testing.T, name string, at time.Time) string {
	t.Helper()
	env, err := wire.SignDocument(h.probers[name].key, name, struct {
		Prober string    `json:"prober"`
		At     time.Time `json:"at"`
	}{Prober: name, At: at})
	if err != nil {
		t.Fatalf("SignDocument: %v", err)
	}
	raw, _ := json.Marshal(env)
	return base64.StdEncoding.EncodeToString(raw)
}

func (h *harness) getPeers(t *testing.T, srv *httptest.Server, cred string) (int, []prober.MeshPeer) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/peers", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if cred != "" {
		req.Header.Set(wire.ProberAuthHeader, cred)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/peers: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	var peers []prober.MeshPeer
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.StatusCode, peers
}

// Probers fetch the peer list rather than carrying a copy, so there is one
// authoritative list to keep correct.
func TestPeerListIsServedToProbers(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	srv := httptest.NewServer(h.coord.Handler())
	defer srv.Close()

	code, peers := h.getPeers(t, srv, h.credentialFor(t, "probe-a", time.Now()))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a registered prober", code)
	}
	if len(peers) != 3 {
		t.Fatalf("peers = %+v, want 3", peers)
	}
	for _, p := range peers {
		if p.Address == "" {
			t.Errorf("peer %q has no dialable address", p.Name)
		}
	}
}

// The response maps the whole monitoring fleet, which is the most useful thing
// here for someone deciding what to attack.
func TestPeerListRequiresACredential(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	srv := httptest.NewServer(h.coord.Handler())
	defer srv.Close()

	if code, _ := h.getPeers(t, srv, ""); code != http.StatusForbidden {
		t.Errorf("no credential: status = %d, want 403", code)
	}
	if code, _ := h.getPeers(t, srv, "not-base64!!"); code != http.StatusForbidden {
		t.Errorf("garbage credential: status = %d, want 403", code)
	}

	// Signed by a key the coordinator does not know.
	_, strangerPriv, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	env, err := wire.SignDocument(strangerPriv, "probe-a", struct {
		Prober string    `json:"prober"`
		At     time.Time `json:"at"`
	}{Prober: "probe-a", At: time.Now()})
	if err != nil {
		t.Fatalf("SignDocument: %v", err)
	}
	raw, _ := json.Marshal(env)
	forged := base64.StdEncoding.EncodeToString(raw)
	if code, _ := h.getPeers(t, srv, forged); code != http.StatusForbidden {
		t.Errorf("forged credential: status = %d, want 403", code)
	}
}

// A captured credential must not be useful indefinitely.
func TestPeerListCredentialExpires(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	srv := httptest.NewServer(h.coord.Handler())
	defer srv.Close()

	old := h.credentialFor(t, "probe-a", time.Now().Add(-time.Hour))
	if code, _ := h.getPeers(t, srv, old); code != http.StatusForbidden {
		t.Errorf("stale credential: status = %d, want 403", code)
	}

	// And one from a badly wrong clock is an error, not a token that outlives
	// every check applied to it.
	future := h.credentialFor(t, "probe-a", time.Now().Add(time.Hour))
	if code, _ := h.getPeers(t, srv, future); code != http.StatusForbidden {
		t.Errorf("future credential: status = %d, want 403", code)
	}
}

func TestAssignmentFeedRequiresIdentityAndFailsOverIsolation(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	base := "probe-a"
	chk := h.coord.checks[h.chk.Name]
	chk.Prober = base
	h.coord.checks[h.chk.Name] = chk
	srv := httptest.NewServer(h.coord.Handler())
	defer srv.Close()
	fetch := func(name, cred string) (int, []check.Check) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/checks", nil)
		if cred != "" {
			req.Header.Set(wire.ProberAuthHeader, cred)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var got []check.Check
		if resp.StatusCode == http.StatusOK {
			json.NewDecoder(resp.Body).Decode(&got)
		}
		return resp.StatusCode, got
	}
	if code, _ := fetch(base, ""); code != http.StatusForbidden {
		t.Fatalf("anonymous status=%d", code)
	}
	code, got := fetch(base, h.credentialFor(t, base, time.Now()))
	if code != http.StatusOK || len(got) != 1 {
		t.Fatalf("base feed status=%d checks=%v", code, got)
	}
	peers := map[string]bool{"probe-b": false, "probe-c": false}
	if code := h.submitMesh(t, srv, base, peers); code != http.StatusAccepted {
		t.Fatalf("mesh status=%d", code)
	}
	_, got = fetch(base, h.credentialFor(t, base, time.Now()))
	if len(got) != 0 {
		t.Fatalf("isolated owner retained checks: %v", got)
	}
	assigned, _ := h.coord.assignedTo(chk)
	if assigned == base {
		t.Fatal("check did not fail over")
	}
	_, got = fetch(assigned, h.credentialFor(t, assigned, time.Now()))
	if len(got) != 1 {
		t.Fatalf("fallback %s checks=%v", assigned, got)
	}
}

func TestMeshEndpointReportsTheMap(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	srv := httptest.NewServer(h.coord.Handler())
	defer srv.Close()

	h.submitMesh(t, srv, "probe-a", map[string]bool{"probe-b": true, "probe-c": false})

	var got struct {
		mesh.State
		Summary string `json:"summary"`
	}
	getJSON(t, srv.URL+"/v1/mesh", &got)
	if !got.Edges["probe-a"]["probe-b"] {
		t.Error("edge a->b missing from the served map")
	}
	if got.Unreachable["probe-c"] == nil {
		t.Error("the map does not record who could not reach probe-c")
	}
	if got.Summary == "" {
		t.Error("no summary served")
	}
}

func TestHostPort(t *testing.T) {
	cases := map[string]string{
		"http://10.0.1.7:8973":  "10.0.1.7:8973",
		"https://probe.example": "probe.example:443",
		"http://probe.example":  "probe.example:80",
		"[::1]:8973":            "", // not a URL
		"ftp://probe.example":   "",
	}
	for in, want := range cases {
		if got := hostPort(in); got != want {
			t.Errorf("hostPort(%q) = %q, want %q", in, got, want)
		}
	}
}
