// Package prober is the agent that actually connects to things.
//
// It holds no policy. It runs the checks it is assigned, answers signed
// requests for corroboration, signs what it saw, and sends that to the
// coordinator. Every judgement — is this down, is that enough agreement, does
// anyone need telling — belongs to the coordinator, so a compromised or
// confused prober can misreport what it observed but cannot decide anything.
//
// The security property this package exists to hold: **a request is verified
// before any connection is attempted.** A prober is a machine that will open
// a socket to an arbitrary address when asked, which is a useful thing to own
// if you are not its owner. Signature first, traffic second, no exceptions.
package prober

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/probe"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

// maxRequestBytes bounds a request body before anything is decoded. The wire
// package caps the signed payload, but that check happens after JSON decoding
// has already allocated; this stops an unauthenticated sender from getting
// that far.
const maxRequestBytes = 128 << 10

// defaultMaxConcurrent bounds probes in flight. Requests are signed, so this
// is not about strangers — it is about a coordinator with a bug, or a genuine
// fleet-wide incident where every check fails at once and asks everyone.
const defaultMaxConcurrent = 32

// Submitter delivers a signed result to the coordinator.
type Submitter interface {
	Submit(ctx context.Context, env wire.Envelope) error
}

// Config describes this prober.
type Config struct {
	// Name identifies this prober. It appears in every result, selects the
	// public key the coordinator verifies against, and is what quorum counts
	// one vote per — so it must be stable and unique in the fleet.
	Name string

	// CoordinatorName identifies the peer allowed to publish assignments and
	// fleet topology. It must match the key registered in Keyring.
	CoordinatorName string

	// Provider groups probers that share a network. Quorum uses it to tell
	// three opinions from one opinion held three times, so getting it wrong
	// overstates the independence of an agreement.
	Provider string

	// Key signs results.
	Key ed25519.PrivateKey

	// Keyring holds the coordinator's public key. Requests that do not verify
	// against it never become traffic.
	Keyring *wire.Keyring

	// Policy constrains where this prober may connect, independently of what
	// the coordinator asks for. The host's owner decides what is reachable;
	// the coordinator only decides what is worth checking.
	Policy probe.Policy

	// MaxConcurrent bounds simultaneous probes. Zero applies the default.
	MaxConcurrent int

	// Now is injectable for tests. Zero means time.Now.
	Now func() time.Time

	Logger *slog.Logger
}

// Prober runs checks and signs the results.
type Prober struct {
	cfg          Config
	kinds        map[check.Kind]probe.Prober
	slots        chan struct{}
	log          *slog.Logger
	nowFunc      func() time.Time
	requestMu    sync.Mutex
	seenRequests map[string]time.Time
}

// New builds a prober.
func New(cfg Config) (*Prober, error) {
	switch {
	case cfg.Name == "":
		return nil, errors.New("prober name is required")
	case len(cfg.Key) != ed25519.PrivateKeySize:
		return nil, fmt.Errorf("prober %q: signing key is %d bytes, want %d",
			cfg.Name, len(cfg.Key), ed25519.PrivateKeySize)
	case cfg.Keyring == nil:
		// Without a keyring nothing can be verified, and a prober that cannot
		// verify must not run: it would probe on anyone's say-so.
		return nil, fmt.Errorf("prober %q: a keyring is required to verify requests", cfg.Name)
	case cfg.CoordinatorName == "":
		return nil, fmt.Errorf("prober %q: coordinator name is required", cfg.Name)
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = defaultMaxConcurrent
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Prober{
		cfg: cfg,
		kinds: map[check.Kind]probe.Prober{
			check.KindTCP:     probe.TCP{Policy: cfg.Policy},
			check.KindHTTP:    probe.HTTP{Policy: cfg.Policy},
			check.KindBanner:  probe.Banner{Policy: cfg.Policy},
			check.KindDNS:     probe.DNS{Policy: cfg.Policy},
			check.KindTLS:     probe.TLS{Policy: cfg.Policy},
			check.KindSMTP:    probe.SMTP{Policy: cfg.Policy},
			check.KindICMP:    probe.ICMP{Policy: cfg.Policy},
			check.KindRequest: probe.Request{Policy: cfg.Policy},
			check.KindNTP:     probe.NTP{Policy: cfg.Policy},
			check.KindGRPC:    probe.GRPC{Policy: cfg.Policy},
		},
		slots:        make(chan struct{}, cfg.MaxConcurrent),
		log:          cfg.Logger.With("prober", cfg.Name),
		nowFunc:      now,
		seenRequests: map[string]time.Time{},
	}, nil
}

// Name returns this prober's identity.
func (p *Prober) Name() string { return p.cfg.Name }

// Run executes a check and returns a signed result.
//
// requestID is empty for a scheduled probe and set when answering a
// corroboration request, so the coordinator can tell a fresh answer from a
// result that happens to be lying around.
func (p *Prober) Run(ctx context.Context, c check.Check, requestID string) (wire.Envelope, error) {
	impl, ok := p.kinds[c.Kind]
	if !ok {
		// Reported as a result rather than an error: "I cannot speak this
		// protocol" is an observation the coordinator should see, and it must
		// not count as evidence the target is down.
		return p.sign(check.Result{
			Check: c.Name, Prober: p.cfg.Name, Provider: p.cfg.Provider,
			Vantage: c.Vantage, Status: check.StatusUnknown, At: p.nowFunc().UTC(),
			Detail: fmt.Sprintf("this prober cannot run %q checks", c.Kind),
		}, requestID)
	}

	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	case <-ctx.Done():
		return wire.Envelope{}, ctx.Err()
	}

	r := probe.Run(ctx, impl, c, p.cfg.Name, p.cfg.Provider)
	return p.sign(r, requestID)
}

func (p *Prober) sign(r check.Result, requestID string) (wire.Envelope, error) {
	return wire.SignResult(p.cfg.Key, wire.ResultPayload{Result: r, RequestID: requestID})
}

// Handler serves corroboration requests.
//
// The order of operations is the point: read a bounded body, verify the
// signature, and only then connect to anything.
func (p *Prober) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/probe", p.handleProbe)
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"prober": p.cfg.Name, "status": "ok"})
	})
	return mux
}

func (p *Prober) handleProbe(w http.ResponseWriter, r *http.Request) {
	var env wire.Envelope
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	if err := dec.Decode(&env); err != nil {
		http.Error(w, "malformed envelope", http.StatusBadRequest)
		return
	}

	// Nothing below this line has happened yet: no name resolved, no socket
	// opened, no packet sent. An unverifiable request is refused here.
	req, err := p.cfg.Keyring.OpenRequest(env, p.nowFunc())
	if err != nil {
		// Logged at warn because a rejected request is either a
		// misconfiguration or someone trying to use the fleet as a probe
		// amplifier, and both are worth seeing.
		p.log.Warn("refused a probe request", "peer", env.Peer, "err", err)
		http.Error(w, "request rejected", http.StatusForbidden)
		return
	}
	if req.Prober != p.cfg.Name {
		p.log.Warn("refused a probe request intended for another prober",
			"intended", req.Prober)
		http.Error(w, "request is for another prober", http.StatusForbidden)
		return
	}
	if !p.acceptRequest(req.ID, req.ExpiresAt) {
		p.log.Warn("refused a replayed probe request", "request_id", req.ID)
		http.Error(w, "request already used", http.StatusConflict)
		return
	}

	out, err := p.Run(r.Context(), req.Check, req.ID)
	if err != nil {
		p.log.Error("probe failed to produce a result", "check", req.Check.Name, "err", err)
		http.Error(w, "probe failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		p.log.Error("writing result", "err", err)
	}
}

func (p *Prober) acceptRequest(id string, expires time.Time) bool {
	p.requestMu.Lock()
	defer p.requestMu.Unlock()
	now := p.nowFunc()
	for seen, until := range p.seenRequests {
		if now.After(until) {
			delete(p.seenRequests, seen)
		}
	}
	if _, exists := p.seenRequests[id]; exists {
		return false
	}
	p.seenRequests[id] = expires
	return true
}

// Schedule runs the assigned checks on their own intervals until ctx is
// cancelled, submitting each result.
//
// Only the checks assigned to this prober run here. Everything else it does is
// on request, which is what keeps the steady-state cost proportional to the
// number of checks rather than to checks times probers.
func (p *Prober) Schedule(ctx context.Context, checks []check.Check, out Submitter) {
	var wg sync.WaitGroup
	for _, c := range checks {
		if err := c.Validate(); err != nil {
			p.log.Error("skipping invalid check", "err", err)
			continue
		}
		wg.Add(1)
		go func(c check.Check) {
			defer wg.Done()
			p.runLoop(ctx, c, out)
		}(c)
	}
	wg.Wait()
}

func (p *Prober) runLoop(ctx context.Context, c check.Check, out Submitter) {
	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			env, err := p.Run(ctx, c, "")
			if err != nil {
				if ctx.Err() == nil {
					p.log.Error("scheduled probe failed", "check", c.Name, "err", err)
				}
				continue
			}
			if err := out.Submit(ctx, env); err != nil {
				// A result the coordinator never receives is a gap, but the
				// prober cannot fix it and must not stop probing over it.
				p.log.Error("could not submit result", "check", c.Name, "err", err)
			}
		}
	}
}
