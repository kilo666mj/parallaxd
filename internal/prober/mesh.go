package prober

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kilo666mj/parallaxd/internal/mesh"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

// The prober half of Phase 2: each prober checks whether it can reach its
// peers, and reports what it found.
//
// It still decides nothing. Whether "I reached none of them" means this prober
// is cut off — and whether its results should therefore stop counting — is the
// coordinator's call, via internal/mesh. A prober that could silence itself
// could also decline to, which is exactly the authority this design keeps out
// of the probers.
//
// The check is a TCP connect, deliberately not a health check. The question is
// whether the network path works, not whether the peer is happy: a peer whose
// store is broken but whose socket answers still proves this prober has
// working connectivity, and that is all this is asking.

const (
	defaultMeshInterval = 30 * time.Second
	defaultMeshTimeout  = 5 * time.Second

	// meshFanOut bounds simultaneous peer probes. The mesh is N-squared per
	// interval across the fleet, which is fine at thirteen hosts and worth
	// bounding anyway so a large fleet does not open every socket at once.
	meshFanOut = 8
)

// MeshConfig describes how this prober watches the rest of the fleet.
type MeshConfig struct {
	// CoordinatorURL is where the peer list is fetched and reports are sent.
	// The peer list is fetched rather than configured so there is one
	// authoritative list — keeping a copy on every prober in step by hand is
	// how a prober ends up probing a peer that was decommissioned last month
	// and calling itself isolated.
	CoordinatorURL string

	// Interval is how often the fleet is checked. Zero applies the default.
	Interval time.Duration

	// Timeout bounds a single peer connection. Zero applies the default.
	//
	// It has to stay well under Interval: a prober that cannot reach anyone
	// spends Timeout on every peer, and if that exceeds the interval the
	// reports fall behind exactly when they matter most.
	Timeout time.Duration

	// Client is used for fetching peers and submitting reports.
	Client *http.Client
}

// MeshPeer is one entry in the coordinator's peer list.
type MeshPeer struct {
	Name string `json:"name"`

	// Address is host:port for a plain TCP connect. Derived by the
	// coordinator from the peer's URL, so probers never parse URLs.
	Address string `json:"address"`
}

// WatchMesh checks the fleet on an interval and reports what it saw, until
// ctx is cancelled.
func (p *Prober) WatchMesh(ctx context.Context, cfg MeshConfig) {
	if cfg.CoordinatorURL == "" {
		// Said out loud. A prober that does not participate in the mesh cannot
		// be told apart from one that can reach everything, so its results
		// keep counting during a partition — the exact failure Phase 2 exists
		// to remove.
		p.log.Warn("no coordinator url for mesh reporting; this prober will " +
			"keep being counted even when it can reach nothing")
		return
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = defaultMeshInterval
	}

	p.meshRound(ctx, cfg)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.meshRound(ctx, cfg)
		}
	}
}

func (p *Prober) meshRound(ctx context.Context, cfg MeshConfig) {
	peers, err := p.fetchPeers(ctx, cfg)
	if err != nil {
		// Cannot reach the coordinator. That is itself a connectivity problem,
		// but reporting "I reached nobody" on the strength of it would be
		// guessing — and the report could not be delivered anyway. The
		// coordinator's staleness watchdog covers this case.
		p.log.Warn("could not fetch the peer list", "err", err)
		return
	}
	if len(peers) == 0 {
		return
	}

	report := mesh.Report{Prober: p.cfg.Name, At: p.nowFunc().UTC()}
	report.Peers = p.probePeers(ctx, peers, cfg)
	sort.Slice(report.Peers, func(i, j int) bool { return report.Peers[i].Peer < report.Peers[j].Peer })

	if report.Reached() == 0 {
		// Logged locally as well as reported, because this is the one message
		// worth having on the host itself: if the report cannot be delivered,
		// the journal is the only place the evidence exists.
		p.log.Warn("cannot reach any peer; this prober's results should not be counted",
			"peers", len(report.Peers))
	}

	if err := p.submitMesh(ctx, cfg, report); err != nil {
		p.log.Error("could not submit the mesh report", "err", err)
	}
}

func (p *Prober) probePeers(ctx context.Context, peers []MeshPeer, cfg MeshConfig) []mesh.PeerView {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultMeshTimeout
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		out  []mesh.PeerView
		slot = make(chan struct{}, meshFanOut)
	)
	for _, peer := range peers {
		if peer.Name == p.cfg.Name || peer.Address == "" {
			// Reaching yourself proves nothing about the network.
			continue
		}
		wg.Add(1)
		go func(peer MeshPeer) {
			defer wg.Done()
			select {
			case slot <- struct{}{}:
				defer func() { <-slot }()
			case <-ctx.Done():
				return
			}

			view := mesh.PeerView{Peer: peer.Name}
			dialCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			start := p.nowFunc()
			conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", peer.Address)
			if err != nil {
				view.Detail = err.Error()
			} else {
				view.Reachable = true
				view.Latency = p.nowFunc().Sub(start)
				conn.Close()
			}

			mu.Lock()
			out = append(out, view)
			mu.Unlock()
		}(peer)
	}
	wg.Wait()
	return out
}

func (p *Prober) fetchPeers(ctx context.Context, cfg MeshConfig) ([]MeshPeer, error) {
	url := strings.TrimRight(cfg.CoordinatorURL, "/") + "/v1/peers"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// The peer list is a map of the whole monitoring fleet, so the coordinator
	// only serves it to a prober that can prove it is itself. Minted per
	// request rather than cached: it carries a timestamp and expires, and a
	// long-lived one would be worth capturing.
	cred, err := p.credential()
	if err != nil {
		return nil, err
	}
	req.Header.Set(wire.ProberAuthHeader, cred)

	resp, err := p.meshClient(cfg).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("coordinator returned %s", resp.Status)
	}

	var peers []MeshPeer
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, maxRequestBytes)).Decode(&peers); err != nil {
		return nil, fmt.Errorf("decode peer list: %w", err)
	}
	return peers, nil
}

func (p *Prober) submitMesh(ctx context.Context, cfg MeshConfig, r mesh.Report) error {
	env, err := wire.SignMeshReport(p.cfg.Key, r)
	if err != nil {
		return err
	}
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}

	url := strings.TrimRight(cfg.CoordinatorURL, "/") + "/v1/mesh"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.meshClient(cfg).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("coordinator returned %s", resp.Status)
	}
	return nil
}

// credential returns a signed proof that this prober is who it says, for read
// requests that have no body to sign.
func (p *Prober) credential() (string, error) {
	env, err := wire.SignDocument(p.cfg.Key, p.cfg.Name, struct {
		Prober string    `json:"prober"`
		At     time.Time `json:"at"`
	}{Prober: p.cfg.Name, At: p.nowFunc().UTC()})
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func (p *Prober) meshClient(cfg MeshConfig) *http.Client {
	if cfg.Client != nil {
		return cfg.Client
	}
	return &http.Client{Timeout: 15 * time.Second}
}
