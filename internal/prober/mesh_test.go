package prober

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/mesh"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

// fakeCoordinator serves a peer list and records the mesh reports it receives,
// verifying their signatures the way the real one does.
type fakeCoordinator struct {
	mu      sync.Mutex
	peers   []MeshPeer
	got     []mesh.Report
	ring    *wire.Keyring
	server  *httptest.Server
	peersOK bool
	key     []byte
}

func newFakeCoordinator(t *testing.T, p *Prober, proberName string, pub []byte) *fakeCoordinator {
	t.Helper()
	ring := wire.NewKeyring()
	if err := ring.Add(proberName, pub); err != nil {
		t.Fatalf("Add: %v", err)
	}
	coordPub, coordPriv, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	f := &fakeCoordinator{ring: ring, peersOK: true, key: coordPriv}
	trusted := wire.NewKeyring()
	if err := trusted.Add("coordinator", coordPub); err != nil {
		t.Fatalf("Add coordinator: %v", err)
	}
	p.cfg.Keyring = trusted

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/peers", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		ok, peers := f.peersOK, f.peers
		f.mu.Unlock()
		if !ok {
			http.Error(w, "nope", http.StatusInternalServerError)
			return
		}
		env, err := wire.SignPublishedDocument(f.key, "coordinator", proberName, "peers", time.Now(), peers)
		if err != nil {
			http.Error(w, "sign", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(env)
	})
	mux.HandleFunc("POST /v1/mesh", func(w http.ResponseWriter, r *http.Request) {
		var env wire.Envelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		report, err := f.ring.OpenMeshReport(env, time.Now())
		if err != nil {
			http.Error(w, "rejected", http.StatusForbidden)
			return
		}
		f.mu.Lock()
		f.got = append(f.got, report)
		f.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	})

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeCoordinator) reports() []mesh.Report {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]mesh.Report(nil), f.got...)
}

func (f *fakeCoordinator) setPeers(peers []MeshPeer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peers = peers
}

// listener returns a live address and a closer, so a test can make a peer
// genuinely reachable or genuinely not.
func listener(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	addr := ln.Addr().String()
	closed := false
	return addr, func() {
		if !closed {
			closed = true
			ln.Close()
		}
	}
}

// deadAddress returns an address nothing is listening on.
func deadAddress(t *testing.T) string {
	t.Helper()
	addr, stop := listener(t)
	stop()
	return addr
}

func meshProber(t *testing.T, name string) (*Prober, []byte) {
	t.Helper()
	pub, priv, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ring := wire.NewKeyring()
	coordPub, _, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := ring.Add("coordinator", coordPub); err != nil {
		t.Fatalf("Add: %v", err)
	}
	p, err := New(Config{Name: name, Provider: "one", Key: priv, Keyring: ring,
		CoordinatorName: "coordinator", Logger: discardLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p, pub
}

func TestMeshRoundReportsReachability(t *testing.T) {
	p, pub := meshProber(t, "probe-a")
	f := newFakeCoordinator(t, p, "probe-a", pub)

	liveAddr, stopLive := listener(t)
	defer stopLive()
	f.setPeers([]MeshPeer{
		{Name: "probe-b", Address: liveAddr},
		{Name: "probe-c", Address: deadAddress(t)},
	})

	p.meshRound(t.Context(), MeshConfig{CoordinatorURL: f.server.URL, Timeout: time.Second})

	reports := f.reports()
	if len(reports) != 1 {
		t.Fatalf("coordinator got %d reports, want 1", len(reports))
	}
	r := reports[0]
	if r.Prober != "probe-a" {
		t.Errorf("prober = %q", r.Prober)
	}
	if len(r.Peers) != 2 {
		t.Fatalf("peers = %+v, want 2", r.Peers)
	}

	byName := map[string]mesh.PeerView{}
	for _, v := range r.Peers {
		byName[v.Peer] = v
	}
	if !byName["probe-b"].Reachable {
		t.Errorf("probe-b was listening but reported unreachable: %q", byName["probe-b"].Detail)
	}
	if byName["probe-c"].Reachable {
		t.Error("probe-c had nothing listening but was reported reachable")
	}
	if byName["probe-c"].Detail == "" {
		t.Error("an unreachable peer carries no explanation")
	}
	if r.Reached() != 1 {
		t.Errorf("Reached = %d, want 1", r.Reached())
	}
}

// The signal Phase 2 is built on: a prober that can reach nothing says so.
func TestMeshRoundReportsTotalIsolation(t *testing.T) {
	p, pub := meshProber(t, "probe-a")
	f := newFakeCoordinator(t, p, "probe-a", pub)
	f.setPeers([]MeshPeer{
		{Name: "probe-b", Address: deadAddress(t)},
		{Name: "probe-c", Address: deadAddress(t)},
	})

	p.meshRound(t.Context(), MeshConfig{CoordinatorURL: f.server.URL, Timeout: time.Second})

	reports := f.reports()
	if len(reports) != 1 {
		t.Fatalf("got %d reports, want 1", len(reports))
	}
	if reports[0].Reached() != 0 {
		t.Fatalf("Reached = %d, want 0", reports[0].Reached())
	}
	// The report still has to be delivered — an isolated prober that stays
	// quiet is indistinguishable from one that is fine.
	if len(reports[0].Peers) != 2 {
		t.Errorf("peers = %+v, want both reported", reports[0].Peers)
	}
}

// Reaching yourself proves nothing about the network, and counting it would
// mean a prober is never isolated.
func TestMeshRoundSkipsItself(t *testing.T) {
	p, pub := meshProber(t, "probe-a")
	f := newFakeCoordinator(t, p, "probe-a", pub)

	liveAddr, stopLive := listener(t)
	defer stopLive()
	f.setPeers([]MeshPeer{
		{Name: "probe-a", Address: liveAddr},
		{Name: "probe-b", Address: deadAddress(t)},
	})

	p.meshRound(t.Context(), MeshConfig{CoordinatorURL: f.server.URL, Timeout: time.Second})

	r := f.reports()[0]
	for _, v := range r.Peers {
		if v.Peer == "probe-a" {
			t.Fatal("a prober reported on itself; it could then never be isolated")
		}
	}
	if r.Reached() != 0 {
		t.Errorf("Reached = %d, want 0 — the only real peer was unreachable", r.Reached())
	}
}

// A report that can silence a prober must be authenticated, so the fake
// coordinator verifying it is the assertion.
func TestMeshReportIsSigned(t *testing.T) {
	p, pub := meshProber(t, "probe-a")
	f := newFakeCoordinator(t, p, "probe-a", pub)
	f.setPeers([]MeshPeer{{Name: "probe-b", Address: deadAddress(t)}})

	p.meshRound(t.Context(), MeshConfig{CoordinatorURL: f.server.URL, Timeout: time.Second})
	if len(f.reports()) != 1 {
		t.Fatal("the report did not verify against the prober's key")
	}

	// A different key must not pass.
	otherPub, _, err := wire.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	f2 := newFakeCoordinator(t, p, "probe-a", otherPub)
	f2.setPeers([]MeshPeer{{Name: "probe-b", Address: deadAddress(t)}})
	p.meshRound(t.Context(), MeshConfig{CoordinatorURL: f2.server.URL, Timeout: time.Second})
	if len(f2.reports()) != 0 {
		t.Error("a report verified against the wrong key")
	}
}

// Cannot reach the coordinator: reporting "I reached nobody" on that basis
// would be guessing, and the report could not be delivered anyway. The
// coordinator's staleness watchdog covers this case instead.
func TestMeshRoundSaysNothingWhenThePeerListIsUnavailable(t *testing.T) {
	p, pub := meshProber(t, "probe-a")
	f := newFakeCoordinator(t, p, "probe-a", pub)
	f.mu.Lock()
	f.peersOK = false
	f.mu.Unlock()

	p.meshRound(t.Context(), MeshConfig{CoordinatorURL: f.server.URL, Timeout: time.Second})
	if n := len(f.reports()); n != 0 {
		t.Errorf("got %d reports, want none when the peer list could not be fetched", n)
	}
}

func TestMeshRoundWithNoPeersReportsNothing(t *testing.T) {
	p, pub := meshProber(t, "probe-a")
	f := newFakeCoordinator(t, p, "probe-a", pub)
	f.setPeers(nil)

	p.meshRound(t.Context(), MeshConfig{CoordinatorURL: f.server.URL, Timeout: time.Second})
	if n := len(f.reports()); n != 0 {
		t.Errorf("got %d reports, want none — there was nobody to ask", n)
	}
}

// A prober with no coordinator configured cannot participate, and must say so
// rather than looking healthy by omission.
func TestWatchMeshReturnsWithoutACoordinator(t *testing.T) {
	p, _ := meshProber(t, "probe-a")
	done := make(chan struct{})
	go func() {
		p.WatchMesh(t.Context(), MeshConfig{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("WatchMesh blocked with no coordinator url")
	}
}

func TestWatchMeshStopsOnCancel(t *testing.T) {
	p, pub := meshProber(t, "probe-a")
	f := newFakeCoordinator(t, p, "probe-a", pub)
	f.setPeers([]MeshPeer{{Name: "probe-b", Address: deadAddress(t)}})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		p.WatchMesh(ctx, MeshConfig{
			CoordinatorURL: f.server.URL, Interval: time.Hour, Timeout: time.Second,
		})
		close(done)
	}()

	// The first round runs immediately, so a partition is visible without
	// waiting an interval.
	deadline := time.After(5 * time.Second)
	for len(f.reports()) == 0 {
		select {
		case <-deadline:
			t.Fatal("no report before the first tick")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("WatchMesh ignored cancellation")
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
