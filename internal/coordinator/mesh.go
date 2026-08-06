package coordinator

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/kilo666mj/parallaxd/internal/mesh"
	"github.com/kilo666mj/parallaxd/internal/prober"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

// The coordinator half of Phase 2.
//
// Probers report which peers they can reach; this decides what that means.
// The decision is the dangerous one in the whole system — silencing a prober
// wrongly means real outages go unreported — so it lives here, in the one
// component allowed to conclude anything, and the arithmetic behind it lives
// in internal/mesh where it is pure and testable.

// defaultMeshMaxAge is how old a mesh report may be and still influence
// evaluation. It has to comfortably exceed the probers' mesh interval, and
// stay short enough that a recovered prober starts counting again quickly:
// suppression that outlives the partition is indistinguishable from the
// outage it was meant to avoid inventing.
const defaultMeshMaxAge = 3 * time.Minute

// meshState holds the latest report from each prober.
type meshState struct {
	mu      sync.Mutex
	reports map[string]mesh.Report

	// isolated is the last evaluated set, so a transition can be alerted on
	// once rather than on every report.
	isolated map[string]bool
}

func newMeshState() *meshState {
	return &meshState{reports: map[string]mesh.Report{}, isolated: map[string]bool{}}
}

func (m *meshState) put(r mesh.Report) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Newest wins. An out-of-order delivery must not resurrect a partition
	// that has already cleared.
	if prev, ok := m.reports[r.Prober]; ok && !r.At.After(prev.At) {
		return
	}
	m.reports[r.Prober] = r
}

func (m *meshState) all() []mesh.Report {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]mesh.Report, 0, len(m.reports))
	for _, r := range m.reports {
		out = append(out, r)
	}
	return out
}

// Mesh returns the current fleet connectivity.
func (c *Coordinator) Mesh() mesh.State {
	maxAge := c.cfg.MeshMaxAge
	if maxAge <= 0 {
		maxAge = defaultMeshMaxAge
	}
	return mesh.Evaluate(c.meshState.all(), mesh.Options{
		Now:      c.now(),
		MaxAge:   maxAge,
		MinPeers: c.cfg.MeshMinPeers,
	})
}

// isolatedProbers is what quorum is given. Nil when the mesh is not in use, so
// a fleet that has not deployed Phase 2 behaves exactly as it did before.
func (c *Coordinator) isolatedProbers() map[string]bool {
	st := c.Mesh()
	if len(st.Isolated) == 0 {
		return nil
	}
	out := make(map[string]bool, len(st.Isolated))
	for _, name := range st.Isolated {
		out[name] = true
	}
	return out
}

// handleMesh ingests a signed report.
func (c *Coordinator) handleMesh(w http.ResponseWriter, r *http.Request) {
	var env wire.Envelope
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes)).Decode(&env); err != nil {
		http.Error(w, "malformed envelope", http.StatusBadRequest)
		return
	}

	report, err := c.ring.OpenMeshReport(env, c.now())
	if err != nil {
		// A mesh report can silence a prober, so an unauthenticated one is a
		// way to suppress somebody's opinion — which is how a real outage goes
		// unreported. Refused before it is looked at.
		c.log.Warn("refused a mesh report", "peer", env.Peer, "err", err)
		http.Error(w, "report rejected", http.StatusForbidden)
		return
	}
	if _, known := c.byName[report.Prober]; !known {
		c.log.Warn("mesh report from an unregistered prober", "prober", report.Prober)
		http.Error(w, "unknown prober", http.StatusBadRequest)
		return
	}

	c.meshState.put(report)
	c.reportMeshTransitions(r.Context())
	w.WriteHeader(http.StatusAccepted)
}

// reportMeshTransitions alerts when a prober becomes isolated or recovers.
//
// A silenced prober is a monitoring gap: everything it was the assigned
// reporter for is now being judged on fewer opinions, or none. That has to be
// visible, or Phase 2 trades loud false alerts for quiet blind spots — which
// is the worse failure of the two.
func (c *Coordinator) reportMeshTransitions(ctx context.Context) {
	st := c.Mesh()

	nowIsolated := make(map[string]bool, len(st.Isolated))
	for _, name := range st.Isolated {
		nowIsolated[name] = true
	}

	c.meshState.mu.Lock()
	was := c.meshState.isolated
	c.meshState.isolated = nowIsolated
	c.meshState.mu.Unlock()

	var alerts []Alert
	for _, name := range st.Isolated {
		if !was[name] {
			alerts = append(alerts, Alert{
				Prober: name, Kind: KindIsolated, At: c.now(),
				Detail: st.Summary(),
			})
		}
	}
	for name := range was {
		if !nowIsolated[name] {
			alerts = append(alerts, Alert{
				Prober: name, Kind: KindRejoined, At: c.now(),
				Detail: "can reach the fleet again; its results are being counted",
			})
		}
	}

	for _, a := range alerts {
		if err := c.cfg.Notifier.Notify(ctx, a); err != nil {
			c.log.Error("could not deliver alert",
				"prober", a.Prober, "kind", string(a.Kind), "err", err)
		}
	}
}

// handlePeers serves the list probers use for their mesh checks.
//
// Served by the coordinator rather than configured on each prober so there is
// one authoritative list. Two copies kept in step by hand is how a prober ends
// up probing a peer decommissioned last month and concluding it is isolated.
//
// Unauthenticated on purpose: it is the same host:port information every
// prober already has to connect to, and requiring a signature to fetch it
// would mean a prober that cannot verify cannot participate in the mesh —
// failing exactly when the mesh matters.
func (c *Coordinator) handlePeers(w http.ResponseWriter, _ *http.Request) {
	out := make([]prober.MeshPeer, 0, len(c.peers))
	for _, p := range c.peers {
		addr := hostPort(p.URL)
		if addr == "" {
			c.log.Warn("prober url has no usable host:port for mesh checks",
				"prober", p.Name, "url", p.URL)
			continue
		}
		out = append(out, prober.MeshPeer{Name: p.Name, Address: addr})
	}
	writeJSON(w, out)
}

// hostPort extracts a dialable address from a prober's base URL.
func hostPort(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Port() != "" {
		return u.Host
	}
	// A URL without an explicit port still has a dialable one implied by its
	// scheme, and a mesh check is a TCP connect rather than a request.
	switch u.Scheme {
	case "https":
		return net.JoinHostPort(u.Hostname(), "443")
	case "http":
		return net.JoinHostPort(u.Hostname(), "80")
	default:
		return ""
	}
}

func (c *Coordinator) handleMeshView(w http.ResponseWriter, _ *http.Request) {
	st := c.Mesh()
	writeJSON(w, struct {
		mesh.State
		Summary string `json:"summary"`
	}{State: st, Summary: st.Summary()})
}
