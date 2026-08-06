// Package coordinator is the only component that decides anything.
//
// Probers observe and report. The coordinator assigns checks, asks for
// corroboration when a report says something is down, applies the quorum rule,
// remembers what it has already said, and tells someone. Keeping all of that
// in one place is what lets a prober be dumb enough to be safe: a compromised
// one can misreport what it saw, but it cannot conclude anything, cannot
// suppress an alert, and cannot cause one on its own.
//
// The shape of an incident:
//
//	prober reports down  ->  ask Of-1 others, concurrently, with a deadline
//	                     ->  quorum.Evaluate over everything that came back
//	                     ->  state machine: alert only on a transition
//
// Corroboration happens only on suspicion. That is the cost argument: M probes
// in steady state, N during an incident, which is what makes checks expensive
// enough to be worth having — a real SMTP conversation, a TLS handshake —
// affordable at all.
package coordinator

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/quorum"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

const (
	// maxRequestBytes bounds a submitted body before anything is decoded.
	// wire caps the signed payload, but that check happens after JSON has
	// already allocated; this stops an unauthenticated sender getting there.
	maxRequestBytes = 128 << 10

	defaultFanOutTimeout = 10 * time.Second
	defaultRequestTTL    = 30 * time.Second

	// defaultResultMaxAge is how old a result may be and still count. It has
	// to cover the whole fan-out plus clock skew between probers, and stay
	// far below any realistic check interval so a verdict is never assembled
	// from two different rounds of the same check.
	defaultResultMaxAge = 2 * time.Minute

	// defaultMaxFanOuts bounds corroboration rounds in flight. During a
	// fleet-wide incident every check fails at once and each one wants to ask
	// everybody; without a ceiling the coordinator answers an outage by
	// opening a few thousand connections.
	defaultMaxFanOuts = 16
)

// Peer is a prober the coordinator knows about.
type Peer struct {
	Name string

	// URL is the prober's base address, e.g. "http://10.0.1.7:8973".
	URL string

	// Provider groups peers sharing a network. Quorum uses it to tell three
	// opinions from one opinion held three times, and corroborator selection
	// uses it to go looking for genuinely independent vantages.
	Provider string

	PublicKey ed25519.PublicKey
}

// Config describes the coordinator.
type Config struct {
	// Name is what this coordinator signs requests as. Probers verify against
	// it, so it must match what they have configured.
	Name string

	// Key signs corroboration requests. Probers refuse unsigned instructions,
	// which is what stops the fleet being usable as a probe amplifier.
	Key ed25519.PrivateKey

	Peers  []Peer
	Checks []check.Check

	// Components group checks into the services a person recognises. A check
	// that belongs to one alerts through it rather than on its own, which is
	// the difference between four alerts and one that says "email is down".
	Components []check.Component

	// Notifier receives alerts. Nil means log only.
	Notifier Notifier

	// Heartbeat is the outward dead-man's switch: something off the fleet that
	// alerts when this coordinator stops pinging it. Without one, a
	// coordinator that dies takes the alerting with it and the silence is
	// indistinguishable from everything being fine.
	Heartbeat Heartbeat

	// StaleMultiplier and StaleGrace decide how late a check may be before
	// nobody is considered to be watching it: interval*multiplier + grace.
	StaleMultiplier int
	StaleGrace      time.Duration

	// WatchInterval is how often staleness is evaluated.
	WatchInterval time.Duration

	// MeshMaxAge is how old a mesh report may be and still suppress a prober.
	// Suppression that outlives the partition is indistinguishable from the
	// outage it was meant to avoid inventing.
	MeshMaxAge time.Duration

	// MeshMinPeers is how many peers a report must cover before reaching none
	// of them counts as isolation. Zero applies the mesh package's default.
	MeshMinPeers int

	FanOutTimeout time.Duration
	RequestTTL    time.Duration
	ResultMaxAge  time.Duration
	MaxFanOuts    int

	HTTPClient *http.Client
	Logger     *slog.Logger

	// Now is injectable so tests own time. Nil means time.Now.
	Now func() time.Time
}

// Coordinator receives results, corroborates failures, and alerts.
type Coordinator struct {
	cfg    Config
	peers  []Peer
	byName map[string]Peer
	checks map[string]check.Check
	ring   *wire.Keyring

	log    *slog.Logger
	client *http.Client
	now    func() time.Time

	// componentsFor maps a check name to the components containing it, so a
	// result only re-evaluates the groupings it can actually affect.
	componentsFor map[string][]check.Component

	// meshState holds what each prober can currently see of the fleet.
	meshState *meshState

	// slots bounds concurrent fan-outs.
	slots chan struct{}

	// startedAt is the baseline for staleness on a check that has never
	// reported. Without it every check is stale the instant the process
	// starts, which is how a useful signal becomes one people mute.
	startedAt time.Time

	mu              sync.Mutex
	states          map[string]*entityState
	componentStates map[string]*entityState

	// silent tracks which probers have already been reported as not reporting,
	// so a dead one produces one alert rather than one per watch tick.
	silent map[string]bool

	// inflight tracks background processing so shutdown can wait for a
	// verdict to finish rather than abandoning it half-delivered.
	inflight sync.WaitGroup
}

// entityState is what the coordinator remembers about one thing it reports on
// — a check, or a component built from several.
//
// Its own mutex, held across evaluation, so two results for the same check
// cannot both decide it is newly down and alert twice. Different checks do
// not contend.
type entityState struct {
	mu sync.Mutex

	// status is the last decided verdict: up or down. Unknown means nothing
	// has been decided yet, which is not the same as up — a check that has
	// never produced a usable result has not been declared healthy.
	status check.Status

	// stale means nobody is reporting on this any more. Kept separate from
	// status rather than overwriting it, because they are different facts:
	// what was last decided, and whether anyone is still looking. Collapsing
	// them loses the last verdict, and a prober restarting during an outage
	// would then read as a second, new outage.
	stale bool

	since       time.Time
	lastVerdict time.Time
}

// reported returns what to show a reader. A stale check is unknown however
// healthy it looked when it went quiet — a verdict nobody is refreshing is not
// evidence about anything now.
func (s *entityState) reported() check.Status {
	if s.stale {
		return check.StatusUnknown
	}
	return s.status
}

// New builds a coordinator.
func New(cfg Config) (*Coordinator, error) {
	switch {
	case strings.TrimSpace(cfg.Name) == "":
		return nil, errors.New("coordinator name is required")
	case len(cfg.Key) != ed25519.PrivateKeySize:
		return nil, fmt.Errorf("signing key is %d bytes, want %d",
			len(cfg.Key), ed25519.PrivateKeySize)
	case len(cfg.Peers) == 0:
		return nil, errors.New("at least one prober is required")
	}

	if cfg.FanOutTimeout <= 0 {
		cfg.FanOutTimeout = defaultFanOutTimeout
	}
	if cfg.RequestTTL <= 0 {
		cfg.RequestTTL = defaultRequestTTL
	}
	if cfg.ResultMaxAge <= 0 {
		cfg.ResultMaxAge = defaultResultMaxAge
	}
	if cfg.MaxFanOuts <= 0 {
		cfg.MaxFanOuts = defaultMaxFanOuts
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.FanOutTimeout}
	}
	if cfg.Notifier == nil {
		cfg.Notifier = LogNotifier{Logger: cfg.Logger}
	}

	ring := wire.NewKeyring()
	byName := make(map[string]Peer, len(cfg.Peers))
	peers := make([]Peer, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		if _, dup := byName[p.Name]; dup {
			// Quorum counts one vote per prober name. Two peers sharing one
			// would either vote as one or let one vote twice, depending on
			// which way the mistake ran.
			return nil, fmt.Errorf("duplicate prober name %q", p.Name)
		}
		if err := ring.Add(p.Name, p.PublicKey); err != nil {
			return nil, err
		}
		byName[p.Name] = p
		peers = append(peers, p)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].Name < peers[j].Name })

	checks := make(map[string]check.Check, len(cfg.Checks))
	for _, c := range cfg.Checks {
		if err := c.Validate(); err != nil {
			return nil, err
		}
		if _, dup := checks[c.Name]; dup {
			return nil, fmt.Errorf("duplicate check name %q", c.Name)
		}
		if c.Quorum.Of > len(peers) {
			// Caught here rather than discovered during an incident, when the
			// verdict would be permanently inconclusive and nothing would
			// alert.
			return nil, fmt.Errorf("check %q asks %d probers but only %d are registered",
				c.Name, c.Quorum.Of, len(peers))
		}
		checks[c.Name] = c
	}

	known := make(map[string]bool, len(checks))
	for name := range checks {
		known[name] = true
	}
	componentsFor := map[string][]check.Component{}
	seenComponent := map[string]bool{}
	for _, comp := range cfg.Components {
		if err := comp.Validate(known); err != nil {
			return nil, err
		}
		if seenComponent[comp.Name] {
			return nil, fmt.Errorf("duplicate component name %q", comp.Name)
		}
		seenComponent[comp.Name] = true
		for _, name := range comp.Checks {
			componentsFor[name] = append(componentsFor[name], comp)
		}
	}

	return &Coordinator{
		cfg: cfg, peers: peers, byName: byName, checks: checks, ring: ring,
		componentsFor:   componentsFor,
		log:             cfg.Logger,
		client:          cfg.HTTPClient,
		now:             cfg.Now,
		slots:           make(chan struct{}, cfg.MaxFanOuts),
		startedAt:       cfg.Now(),
		meshState:       newMeshState(),
		states:          map[string]*entityState{},
		componentStates: map[string]*entityState{},
		silent:          map[string]bool{},
	}, nil
}

// Process handles one authenticated result: corroborates if needed, decides,
// and alerts on a transition. Exported because it is the whole of the
// coordinator's behaviour, and testing it directly is better than testing it
// through a handler and a sleep.
func (c *Coordinator) Process(ctx context.Context, r check.Result) (quorum.Verdict, error) {
	chk, ok := c.checks[r.Check]
	if !ok {
		return quorum.Verdict{}, fmt.Errorf("unknown check %q", r.Check)
	}

	// An isolated prober's result is not evidence, so it is not a trigger
	// either. Fanning out on it would spend the corroboration budget on
	// reports carrying no information — and during a partition, when every
	// cut-off prober sees every target as down, that is the entire budget,
	// starving the triggers that do mean something.
	//
	// The cost is that a check whose assigned prober is isolated stops being
	// evaluated until it rejoins. That is a real gap, and it is why isolation
	// alerts rather than silently suppressing: the operator is told the
	// prober's checks are no longer being run. Reassigning them to a healthy
	// prober needs pushed assignments, which is future work.
	if c.isolatedProbers()[r.Prober] {
		c.log.Debug("ignoring a result from an isolated prober",
			"check", chk.Name, "prober", r.Prober)
		return quorum.Verdict{
			Check: chk.Name, Status: check.StatusUnknown,
			Suppressed: 1, SuppressedProbers: []string{r.Prober},
			Reason: fmt.Sprintf("%s can reach no peer; its result was not counted", r.Prober),
		}, nil
	}

	v, alert, kind := c.decide(ctx, chk, r)

	// A check inside a component alerts through the component, so an mx host
	// going down produces one alert naming the failing ports rather than one
	// per port. A check in no component is still its own alert.
	if alert && len(c.componentsFor[chk.Name]) == 0 {
		a := Alert{Check: chk.Name, Target: chk.Target, Kind: kind, At: c.now(), Verdict: v}
		if err := c.cfg.Notifier.Notify(ctx, a); err != nil {
			// The state has already moved. Re-alerting on the next result would
			// mean a flaky webhook produces a stream of duplicates for one
			// outage, which is the noise this whole design is trying to remove.
			c.log.Error("could not deliver alert", "check", chk.Name, "kind", string(kind), "err", err)
		}
	}

	// Deliberately outside the check's lock, and unconditional. A rollup reads
	// the state of every sibling check, so holding this one while doing it
	// would let two results for sibling checks deadlock each other. And it runs
	// even when nothing alerted, because a check moving from undecided to up is
	// not an alert but does change what its component can conclude.
	c.rollUp(ctx, chk.Name)
	return v, nil
}

// decide runs the check's own state machine and reports whether the transition
// is worth telling someone about. The state lock is confined here so callers
// can safely take other locks afterwards.
func (c *Coordinator) decide(ctx context.Context, chk check.Check, r check.Result) (quorum.Verdict, bool, Kind) {
	st := c.stateFor(chk.Name)
	st.mu.Lock()
	defer st.mu.Unlock()

	results := []check.Result{r}

	// Only a failure is worth asking about. An up result already answers the
	// question, and corroborating it would spend N probes to confirm what one
	// prober can see — which is the cost model this design exists to avoid.
	//
	// The exception is a check whose quorum a single report already satisfies
	// (Agree: 1): the operator has said one prober suffices, so asking others
	// would change nothing.
	if r.Status == check.StatusDown && !c.evaluate(chk, results).Actionable() {
		results = append(results, c.corroborate(ctx, chk, r)...)
	}

	v := c.evaluate(chk, results)
	st.lastVerdict = c.now()
	// It just reported, so whatever the watchdog last concluded about its
	// silence is out of date. Cleared here rather than waiting for the next
	// watch tick, so a returning prober is visible immediately.
	st.stale = false

	alert, kind := st.apply(v.Status, c.now())
	if !alert {
		c.log.Debug("verdict", "check", chk.Name, "status", string(v.Status), "reason", v.Reason)
	}
	return v, alert, kind
}

func (c *Coordinator) evaluate(chk check.Check, results []check.Result) quorum.Verdict {
	return quorum.Evaluate(chk, results, quorum.Options{
		Now:    c.now(),
		MaxAge: c.cfg.ResultMaxAge,
		// The Phase 2 rule. A prober that can reach no peer sees every target
		// as down, and counting that is how one broken uplink becomes a
		// fleet-wide outage report.
		Isolated: c.isolatedProbers(),
	})
}

// apply moves the state machine and reports whether this is a transition
// worth telling someone about.
//
// Alerts fire on transitions, never on results. A genuine outage produces a
// failing result every interval for as long as it lasts, and an alert per
// result is the behaviour that trains people to filter the channel.
func (s *entityState) apply(status check.Status, now time.Time) (bool, Kind) {
	switch status {
	case check.StatusDown:
		if s.status == check.StatusDown {
			return false, ""
		}
		s.status, s.since = check.StatusDown, now
		return true, KindDown

	case check.StatusUp:
		wasDown := s.status == check.StatusDown
		if s.status != check.StatusUp {
			s.since = now
		}
		s.status = check.StatusUp
		// A first-ever up is not a recovery. Announcing "recovered" for
		// everything at startup is how a monitoring system gets muted.
		return wasDown, KindRecovered

	default:
		// Inconclusive. It must not clear a down: not being able to confirm
		// an outage is not evidence it ended, and treating it as recovery
		// would make a flaky corroborator look like a fix.
		return false, ""
	}
}

func (c *Coordinator) stateFor(name string) *entityState {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.states[name]
	if !ok {
		st = &entityState{status: check.StatusUnknown}
		c.states[name] = st
	}
	return st
}

// corroborate asks other probers to run the check now and returns whatever
// comes back inside the deadline.
func (c *Coordinator) corroborate(ctx context.Context, chk check.Check, reported check.Result) []check.Result {
	peers := c.corroborators(chk, reported)
	if len(peers) == 0 {
		c.log.Warn("nothing to corroborate with",
			"check", chk.Name, "reported_by", reported.Prober)
		return nil
	}

	// Wait for a slot, but not past the deadline: during a fleet-wide
	// incident it is better to reach an inconclusive verdict — which stays
	// quiet — than to queue behind every other check and alert late.
	slotCtx, cancelSlot := context.WithTimeout(ctx, c.cfg.FanOutTimeout)
	defer cancelSlot()
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-slotCtx.Done():
		c.log.Warn("fan-out capacity exhausted; deciding without corroboration",
			"check", chk.Name)
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.FanOutTimeout)
	defer cancel()

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		out []check.Result
	)
	for _, p := range peers {
		wg.Add(1)
		go func(p Peer) {
			defer wg.Done()
			r, err := c.ask(ctx, p, chk)
			if err != nil {
				// Silence is not a vote. A prober that cannot be reached
				// contributes nothing rather than counting as agreement or
				// dissent, and the quorum simply goes unmet if too many are
				// missing.
				c.log.Warn("corroborator did not answer",
					"check", chk.Name, "prober", p.Name, "err", err)
				return
			}
			mu.Lock()
			out = append(out, r)
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	sort.Slice(out, func(i, j int) bool { return out[i].Prober < out[j].Prober })
	return out
}

// corroborators picks who to ask.
func (c *Coordinator) corroborators(chk check.Check, reported check.Result) []Peer {
	// The reporting prober has already voted. Asking it again would be one
	// prober counted twice, which quorum de-duplicates anyway — so it would
	// spend a probe to learn nothing.
	var candidates []Peer
	for _, p := range c.peers {
		if p.Name != reported.Prober {
			candidates = append(candidates, p)
		}
	}

	want := chk.Quorum.Of - 1
	if want < 1 {
		return nil
	}
	if want > len(candidates) {
		want = len(candidates)
	}

	if !chk.Quorum.DistinctProviders {
		return candidates[:want]
	}

	// Prefer providers not already represented. Three probers behind one
	// provider are one opinion held three times, and a quorum that demanded
	// diversity would fail with such a sample — so spend the requests where
	// they can actually satisfy the rule.
	seen := map[string]bool{reported.Provider: true}
	var fresh, rest []Peer
	for _, p := range candidates {
		if seen[p.Provider] {
			rest = append(rest, p)
			continue
		}
		seen[p.Provider] = true
		fresh = append(fresh, p)
	}

	out := append(fresh, rest...)
	return out[:want]
}

// ask sends one signed corroboration request and verifies the answer.
func (c *Coordinator) ask(ctx context.Context, p Peer, chk check.Check) (check.Result, error) {
	id, err := wire.NewRequestID()
	if err != nil {
		return check.Result{}, err
	}
	now := c.now()
	env, err := wire.SignRequest(c.cfg.Key, c.cfg.Name, wire.Request{
		ID: id, Check: chk, IssuedAt: now, ExpiresAt: now.Add(c.cfg.RequestTTL),
	})
	if err != nil {
		return check.Result{}, err
	}
	body, err := json.Marshal(env)
	if err != nil {
		return check.Result{}, err
	}

	url := strings.TrimRight(p.URL, "/") + "/v1/probe"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return check.Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return check.Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return check.Result{}, fmt.Errorf("prober returned %s", resp.Status)
	}

	var answer wire.Envelope
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, maxRequestBytes)).Decode(&answer); err != nil {
		return check.Result{}, fmt.Errorf("decode answer: %w", err)
	}
	payload, err := c.ring.OpenResult(answer, c.now())
	if err != nil {
		return check.Result{}, err
	}

	// The nonce must come back. Without this a captured result could be
	// replayed to satisfy a later request, which is exactly what giving
	// requests an id was for.
	if payload.RequestID != id {
		return check.Result{}, fmt.Errorf("answer quotes request %q, expected %q",
			payload.RequestID, id)
	}
	// And it must be from the prober that was asked. wire binds the result to
	// whoever signed it, so this catches a misrouted or misconfigured peer
	// rather than a forgery.
	if payload.Result.Prober != p.Name {
		return check.Result{}, fmt.Errorf("asked %q, answered by %q", p.Name, payload.Result.Prober)
	}
	if payload.Result.Check != chk.Name {
		return check.Result{}, fmt.Errorf("asked about %q, answered about %q",
			chk.Name, payload.Result.Check)
	}
	return payload.Result, nil
}

// Handler serves the coordinator's HTTP surface.
func (c *Coordinator) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/results", c.handleResult)
	mux.HandleFunc("GET /v1/health", c.handleHealth)
	mux.HandleFunc("GET /v1/status", c.handleStatus)
	mux.HandleFunc("POST /v1/mesh", c.handleMesh)
	mux.HandleFunc("GET /v1/mesh", c.handleMeshView)
	mux.HandleFunc("GET /v1/peers", c.handlePeers)
	mux.HandleFunc("GET /v1/components", c.handleComponents)
	mux.HandleFunc("GET /v1/export", c.handleExport)
	mux.HandleFunc("GET /v1/assignments", c.handleAssignments)
	return mux
}

func (c *Coordinator) handleResult(w http.ResponseWriter, r *http.Request) {
	var env wire.Envelope
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes)).Decode(&env); err != nil {
		http.Error(w, "malformed envelope", http.StatusBadRequest)
		return
	}

	payload, err := c.ring.OpenResult(env, c.now())
	if err != nil {
		// A result counts toward a verdict, so an unauthenticated one could
		// manufacture agreement or forge an all-clear. Refused before it is
		// looked at.
		c.log.Warn("refused a result", "peer", env.Peer, "err", err)
		http.Error(w, "result rejected", http.StatusForbidden)
		return
	}
	if _, known := c.checks[payload.Result.Check]; !known {
		// A registered prober reporting a check the coordinator does not have
		// is a configuration drift, not an attack — but acting on it would
		// mean alerting about something nobody defined.
		c.log.Warn("result for an unknown check",
			"prober", payload.Result.Prober, "check", payload.Result.Check)
		http.Error(w, "unknown check", http.StatusBadRequest)
		return
	}

	// Accepted, then processed in the background. Corroboration takes seconds
	// and the prober submitting this is single-threaded per check: holding it
	// open would delay that check's next probe by the length of the fan-out.
	c.inflight.Add(1)
	go func(res check.Result) {
		defer c.inflight.Done()
		ctx, cancel := context.WithTimeout(
			context.WithoutCancel(r.Context()), c.cfg.FanOutTimeout*2)
		defer cancel()
		if _, err := c.Process(ctx, res); err != nil {
			c.log.Error("processing result", "check", res.Check, "err", err)
		}
	}(payload.Result)

	w.WriteHeader(http.StatusAccepted)
}

func (c *Coordinator) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"coordinator": c.cfg.Name,
		"status":      "ok",
		"probers":     len(c.peers),
		"checks":      len(c.checks),
	})
}

// StatusEntry is the coordinator's current view of one check.
type StatusEntry struct {
	Check       string    `json:"check"`
	Target      string    `json:"target"`
	Status      string    `json:"status"`
	Since       time.Time `json:"since,omitempty"`
	LastVerdict time.Time `json:"last_verdict,omitempty"`
	AssignedTo  string    `json:"assigned_to,omitempty"`

	// Stale means nobody is reporting on this check any more, so Status is
	// unknown regardless of how it last looked. A status page must render this
	// visibly: a check silently dropping to unknown is how a monitoring system
	// stops monitoring without anyone noticing.
	Stale bool `json:"stale,omitempty"`

	// LastKnown is the verdict before it went quiet, kept because it is still
	// the most recent thing anyone actually observed.
	LastKnown string `json:"last_known,omitempty"`
}

// Status reports the current state of every check.
func (c *Coordinator) Status() []StatusEntry {
	out := make([]StatusEntry, 0, len(c.checks))
	for _, chk := range c.checks {
		e := StatusEntry{Check: chk.Name, Target: chk.Target, Status: string(check.StatusUnknown)}
		if p, ok := assign(chk.Name, c.peers); ok {
			e.AssignedTo = p.Name
		}
		c.mu.Lock()
		st := c.states[chk.Name]
		c.mu.Unlock()
		if st != nil {
			st.mu.Lock()
			e.Status = string(st.reported())
			e.Since, e.LastVerdict = st.since, st.lastVerdict
			if st.stale {
				// Named separately so a reader can tell "nobody is watching
				// this" from "the probers disagreed", which are very different
				// problems with the same status.
				e.Stale = true
				e.LastKnown = string(st.status)
			}
			st.mu.Unlock()
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Check < out[j].Check })
	return out
}

func (c *Coordinator) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, c.Status())
}

func (c *Coordinator) handleComponents(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, c.Components())
}

func (c *Coordinator) handleAssignments(w http.ResponseWriter, r *http.Request) {
	all := c.Assignments()
	if who := r.URL.Query().Get("prober"); who != "" {
		writeJSON(w, map[string][]string{who: all[who]})
		return
	}
	writeJSON(w, all)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Default().Error("writing response", "err", err)
	}
}

// Wait blocks until background processing has finished. Called during
// shutdown so a verdict in flight is delivered rather than abandoned.
func (c *Coordinator) Wait() { c.inflight.Wait() }
