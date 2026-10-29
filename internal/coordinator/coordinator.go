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
	"sync/atomic"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/quorum"
	"github.com/kilo666mj/parallaxd/internal/wire"
	"go.michaelspost.com/oidcrp"
)

const (
	// maxRequestBytes bounds a submitted body before anything is decoded.
	// wire caps the signed payload, but that check happens after JSON has
	// already allocated; this stops an unauthenticated sender getting there.
	maxRequestBytes = 128 << 10

	defaultFanOutTimeout = 20 * time.Second
	defaultRequestTTL    = 30 * time.Second

	// A corroborator needs time to finish the probe and return its signed
	// result. Giving the outer request the same deadline as the probe races the
	// result against cancellation; giving it less time guarantees that a
	// target which consumes its whole timeout can never contribute a vote.
	minimumFanOutOverhead = time.Second

	// defaultResultMaxAge is how old a result may be and still count. It has
	// to cover the whole fan-out plus clock skew between probers, and stay
	// far below any realistic check interval so a verdict is never assembled
	// from two different rounds of the same check.
	defaultResultMaxAge = 2 * time.Minute

	// defaultMaxFanOuts bounds corroboration rounds in flight. During a
	// fleet-wide incident every check fails at once and each one wants to ask
	// everybody; without a ceiling the coordinator answers an outage by
	// opening a few thousand connections.
	defaultMaxFanOuts        = 16
	defaultMaxPendingResults = 128
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

	// ProxyProfiles maps supported profile names to coordinator-owned exit identities.
	ProxyProfiles map[string]string

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
	Components  []check.Component
	Maintenance []Maintenance
	StateFile   string

	// OperatorToken is the legacy administrator and break-glass credential.
	// Local users, OIDC sessions, and scoped API tokens are preferred.
	OperatorToken string

	// SessionTTL controls browser login lifetime. InsecureSessionCookies is
	// intended only for local HTTP development; production cookies are Secure.
	SessionTTL             time.Duration
	InsecureSessionCookies bool
	BootstrapAdminUsername string
	BootstrapAdminPassword string
	OIDC                   OIDCConfig

	// Notifier receives alerts. Nil means log only.
	Notifier Notifier

	// Destinations are independently delivered and retried. Notifier remains
	// the always-on default destination for backwards compatibility.
	Destinations []NotificationDestination
	Routes       []NotificationRoute
	Escalations  []EscalationPolicy

	NotificationRetryInitial  time.Duration
	NotificationRetryMax      time.Duration
	NotificationRetryInterval time.Duration

	// HistoryFile is an append-only observation journal. Retention bounds the
	// queryable window and HistoryMaxPerCheck bounds memory and compaction size.
	HistoryFile        string
	HistoryRetention   time.Duration
	HistoryMaxPerCheck int
	Prometheus         []PrometheusSource
	HA                 HAConfig
	SkipRestore        bool

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

	FanOutTimeout     time.Duration
	RequestTTL        time.Duration
	ResultMaxAge      time.Duration
	MaxFanOuts        int
	MaxPendingResults int

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
	mcp    http.Handler
	// checks and monitors are a copy-on-write live catalogue. checks contains
	// only enabled monitors; monitors also retains disabled definitions.
	checksMu sync.RWMutex
	monitors map[string]MonitorSpec
	ring     *wire.Keyring

	log    *slog.Logger
	client *http.Client
	now    func() time.Time

	// prometheus is an optional read-only metrics plane. It is deliberately
	// separate from checks, verdicts, incidents, persistence, and replication:
	// losing metrics context must never change an availability decision.
	prometheus []prometheusRuntime

	// componentsFor maps a check name to the components containing it, so a
	// result only re-evaluates the groupings it can actually affect.
	componentsFor map[string][]check.Component

	// meshState holds what each prober can currently see of the fleet.
	meshState *meshState

	// slots bounds concurrent fan-outs.
	slots chan struct{}

	// resultSlots bounds authenticated results waiting to be processed. Fan-out
	// slots only cap active network work; without this second bound a registered
	// peer can create an unlimited number of goroutines queued on check locks.
	resultSlots chan struct{}

	// startedAt is the baseline for staleness on a check that has never
	// reported. Without it every check is stale the instant the process
	// starts, which is how a useful signal becomes one people mute.
	startedAt time.Time

	// Corroboration counters for /metrics, for this process lifetime.
	corroborations             atomic.Uint64
	inconclusiveCorroborations atomic.Uint64
	corroborationNanos         atomic.Int64

	mu sync.Mutex
	// overruled counts, per prober and check, scheduled failures that
	// corroboration decided were up. A prober wrong about one zone otherwise
	// looks exactly like a healthy one. Guarded by mu.
	overruled           map[[2]string]uint64
	states              map[string]*entityState
	componentStates     map[string]*entityState
	lastScheduled       map[string]time.Time
	incidents           []Incident
	nextIncidentID      uint64
	silences            []Silence
	maintenance         []Maintenance
	notices             []Notice
	nextNoticeID        uint64
	nextSilenceID       uint64
	diagnostics         Diagnostics
	destinations        map[string]Notifier
	outbox              []Delivery
	nextDeliveryID      uint64
	escalated           map[string]time.Time
	history             map[string][]Observation
	historyAppends      int
	promoted            atomic.Bool
	promoteCh           chan struct{}
	promoteOnce         sync.Once
	promotedAt          time.Time
	promotedBy          string
	lastReplicaSync     time.Time
	primaryStateAt      time.Time
	lastReplicaErr      string
	monitorRevisions    []MonitorRevision
	nextMonitorRevision uint64

	authMu        sync.Mutex
	users         map[string]User
	apiTokens     map[string]APIToken
	sessions      map[string]Session
	loginFailures map[string][]time.Time
	oidc          *oidcrp.Service

	// silent tracks which probers have already been reported as not reporting,
	// so a dead one produces one alert rather than one per watch tick.
	silent map[string]bool

	// recoveryStarted gives a prober restored by an authenticated mesh report
	// one normal staleness window to fetch its preferred assignments and produce
	// a scheduled result. Without this grace, the watchdog can silence it again
	// before the assignment refresh loop runs, causing an endless
	// NOT REPORTING/REPORTING oscillation.
	recoveryStarted map[string]time.Time

	// beatFailures counts consecutive failed heartbeats, so a sustained
	// failure is reported once rather than a dropped packet being reported at
	// all.
	beatFailures int

	// inflight tracks background processing so shutdown can wait for a
	// verdict to finish rather than abandoning it half-delivered.
	inflight   sync.WaitGroup
	persistMu  sync.Mutex
	deliveryMu sync.Mutex
	historyMu  sync.Mutex
	haMu       sync.Mutex
	catalogMu  sync.Mutex
}

// SetMCPHandler mounts an application-supplied MCP handler at /mcp. The
// coordinator still authenticates every request before handing it to MCP, and
// individual tool calls continue through the normal operator API permission
// checks. Call this before serving Handler.
func (c *Coordinator) SetMCPHandler(handler http.Handler) {
	c.mcp = handler
}

// entityState is what the coordinator remembers about one thing it reports on
// — a check, or a component built from several.
//
// Its own mutex, held across evaluation, so two results for the same check
// cannot both decide it is newly down and alert twice. Different checks do
// not contend.
type entityState struct {
	mu sync.Mutex

	// status is the last decided verdict: up, warning or down. Unknown means nothing
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

	// Suspicion is deliberately separate from the decided status. A failed
	// probe that cannot yet reach quorum is operationally important even
	// though it is not enough evidence to declare the service down.
	suspectedSince       time.Time
	lastAttempt          time.Time
	lastCorroboration    time.Duration
	inconclusiveAttempts uint64
	lastInconclusive     string
	inconclusiveHistory  []CorroborationAttempt
}

const maxInconclusiveHistory = 32

// CorroborationAttempt is one failed attempt to turn suspicion into a verdict.
// The bounded history explains repeated delays without allowing state to grow
// forever during a long partition.
type CorroborationAttempt struct {
	At         time.Time `json:"at"`
	DurationMS int64     `json:"duration_ms,omitempty"`
	Reason     string    `json:"reason"`
	Counted    int       `json:"counted,omitempty"`
	Down       int       `json:"down,omitempty"`
	Up         int       `json:"up,omitempty"`
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

func validateEligibleProbers(chk check.Check, peers []Peer, byName map[string]Peer) ([]Peer, error) {
	candidates := peers
	if len(chk.Probers) > 0 {
		candidates = nil
		for _, name := range chk.Probers {
			peer, ok := byName[name]
			if !ok {
				return nil, fmt.Errorf("check %q names unregistered eligible prober %q", chk.Name, name)
			}
			candidates = append(candidates, peer)
		}
	}
	eligible := make([]Peer, 0, len(candidates))
	for _, peer := range candidates {
		if chk.ProxyProfile != "" && peer.ProxyProfiles[chk.ProxyProfile] == "" {
			if len(chk.Probers) > 0 || chk.Prober == peer.Name {
				return nil, fmt.Errorf("check %q: prober %q has no registered proxy profile %q", chk.Name, peer.Name, chk.ProxyProfile)
			}
			continue
		}
		eligible = append(eligible, peer)
	}
	return eligible, nil
}

func routeResult(chk check.Check, peer Peer) check.Result {
	return check.Result{Prober: peer.Name, Provider: peer.Provider, ProxyProfile: chk.ProxyProfile, Egress: peer.ProxyProfiles[chk.ProxyProfile]}
}

func validateRouteQuorum(chk check.Check, peers []Peer) error {
	if chk.ProxyProfile == "" {
		return nil
	}
	results := make([]check.Result, 0, len(peers))
	for _, peer := range peers {
		results = append(results, routeResult(chk, peer))
	}
	if quorum.IndependentCount(results, chk.Quorum.DistinctProviders) < chk.Quorum.Agree {
		return fmt.Errorf("check %q: insufficient independent proxy exits/providers for quorum", chk.Name)
	}
	return nil
}

// A signed result from an older agent may have silently ignored proxy_profile.
// Fail closed before it can trigger or clear an incident. Topology comes from
// registration, not a prober's claim of an independent exit.
func normalizeRoute(chk check.Check, peer Peer, r check.Result) check.Result {
	expected := routeResult(chk, peer)
	if r.ProxyProfile != expected.ProxyProfile || r.Egress != expected.Egress || (chk.ProxyProfile != "" && expected.Egress == "") {
		r.Status = check.StatusUnknown
		r.Detail = "result route does not match the registered proxy profile/exit"
	}
	r.Provider = peer.Provider
	r.ProxyProfile = expected.ProxyProfile
	r.Egress = expected.Egress
	return r
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
	if cfg.MaxPendingResults <= 0 {
		cfg.MaxPendingResults = defaultMaxPendingResults
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
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
	if err := validateNotificationConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.HistoryRetention < 0 || cfg.HistoryMaxPerCheck < 0 {
		return nil, errors.New("history retention and max_per_check cannot be negative")
	}
	if err := validateHAConfig(cfg); err != nil {
		return nil, err
	}
	if err := validateOIDCConfig(cfg.OIDC); err != nil {
		return nil, err
	}
	prometheus, err := preparePrometheusSources(cfg.Prometheus)
	if err != nil {
		return nil, err
	}

	ring := wire.NewKeyring()
	byName := make(map[string]Peer, len(cfg.Peers))
	byKey := make(map[string]string, len(cfg.Peers))
	peers := make([]Peer, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		p.ProxyProfiles = cloneStrings(p.ProxyProfiles)
		for name, egress := range p.ProxyProfiles {
			if !check.ValidRouteID(name) || !check.ValidRouteID(egress) {
				return nil, fmt.Errorf("prober %q has an invalid proxy profile/exit identifier", p.Name)
			}
		}
		if _, dup := byName[p.Name]; dup {
			// Quorum counts one vote per prober name. Two peers sharing one
			// would either vote as one or let one vote twice, depending on
			// which way the mistake ran.
			return nil, fmt.Errorf("duplicate prober name %q", p.Name)
		}
		keyID := string(p.PublicKey)
		if other, dup := byKey[keyID]; dup {
			return nil, fmt.Errorf("probers %q and %q share a public key", other, p.Name)
		}
		if err := ring.Add(p.Name, p.PublicKey); err != nil {
			return nil, err
		}
		byName[p.Name] = p
		byKey[keyID] = p.Name
		peers = append(peers, p)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].Name < peers[j].Name })

	checks := make(map[string]check.Check, len(cfg.Checks))
	for _, c := range cfg.Checks {
		if err := c.Validate(); err != nil {
			return nil, err
		}
		if c.Quorum.Agree > 1 && cfg.FanOutTimeout < c.Timeout+minimumFanOutOverhead {
			return nil, fmt.Errorf("check %q timeout %s leaves no response budget inside fan-out timeout %s; need at least %s",
				c.Name, c.Timeout, cfg.FanOutTimeout, c.Timeout+minimumFanOutOverhead)
		}
		if _, dup := checks[c.Name]; dup {
			return nil, fmt.Errorf("duplicate check name %q", c.Name)
		}
		eligiblePeers, err := validateEligibleProbers(c, peers, byName)
		if err != nil {
			return nil, err
		}
		if c.Quorum.Of > len(eligiblePeers) {
			// Caught here rather than discovered during an incident, when the
			// verdict would be permanently inconclusive and nothing would
			// alert.
			return nil, fmt.Errorf("check %q asks %d probers but only %d are registered",
				c.Name, c.Quorum.Of, len(eligiblePeers))
		}
		if err := validateRouteQuorum(c, eligiblePeers); err != nil {
			return nil, err
		}
		if c.Quorum.DistinctProviders {
			providers := make(map[string]bool)
			for _, p := range eligiblePeers {
				if strings.TrimSpace(p.Provider) != "" {
					providers[p.Provider] = true
				}
			}
			if len(providers) < c.Quorum.Agree {
				return nil, fmt.Errorf("check %q requires %d distinct providers but only %d are configured",
					c.Name, c.Quorum.Agree, len(providers))
			}
		}
		if c.Prober != "" {
			if _, ok := byName[c.Prober]; !ok {
				return nil, fmt.Errorf("check %q names unregistered prober %q", c.Name, c.Prober)
			}
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
	for _, m := range cfg.Maintenance {
		if err := m.Validate(); err != nil {
			return nil, err
		}
	}

	coord := &Coordinator{
		cfg: cfg, peers: peers, byName: byName, checks: checks, ring: ring,
		componentsFor:   componentsFor,
		log:             cfg.Logger,
		client:          cfg.HTTPClient,
		now:             cfg.Now,
		prometheus:      prometheus,
		slots:           make(chan struct{}, cfg.MaxFanOuts),
		resultSlots:     make(chan struct{}, cfg.MaxPendingResults),
		startedAt:       cfg.Now(),
		meshState:       newMeshState(),
		states:          map[string]*entityState{},
		componentStates: map[string]*entityState{},
		lastScheduled:   map[string]time.Time{},
		silent:          map[string]bool{},
		recoveryStarted: map[string]time.Time{},
		diagnostics: Diagnostics{
			RejectedResults: map[string]uint64{},
		},
		destinations:  map[string]Notifier{"default": cfg.Notifier},
		escalated:     map[string]time.Time{},
		history:       map[string][]Observation{},
		promoteCh:     make(chan struct{}),
		monitors:      map[string]MonitorSpec{},
		users:         map[string]User{},
		apiTokens:     map[string]APIToken{},
		sessions:      map[string]Session{},
		loginFailures: map[string][]time.Time{},
	}
	coord.oidc = coord.newOIDC()
	for _, chk := range cfg.Checks {
		monitor := monitorFromCheck(chk)
		coord.monitors[monitor.Name] = monitor
	}
	coord.nextMonitorRevision = 1
	coord.monitorRevisions = []MonitorRevision{{ID: 1, At: coord.startedAt.UTC(), Actor: "configuration", Action: "baseline", Catalog: coord.monitorList()}}
	for _, destination := range cfg.Destinations {
		coord.destinations[destination.Name] = destination.Notifier
	}
	if !cfg.SkipRestore {
		if err := coord.restore(); err != nil {
			return nil, err
		}
		if err := coord.loadHistory(); err != nil {
			return nil, err
		}
	}
	if err := coord.ensureBootstrapAdmin(); err != nil {
		return nil, err
	}
	return coord, nil
}

// Process handles one authenticated result: corroborates if needed, decides,
// and alerts on a transition. Exported because it is the whole of the
// coordinator's behaviour, and testing it directly is better than testing it
// through a handler and a sleep.
func (c *Coordinator) Process(ctx context.Context, r check.Result) (quorum.Verdict, error) {
	chk, ok := c.checkByName(r.Check)
	if !ok {
		return quorum.Verdict{}, fmt.Errorf("unknown check %q", r.Check)
	}
	peer, ok := c.byName[r.Prober]
	if !ok {
		return quorum.Verdict{}, fmt.Errorf("unknown prober %q", r.Prober)
	}
	// Provider diversity is coordinator policy, not a claim a prober gets to
	// make about itself. Always replace the signed value with the registered one.
	r = normalizeRoute(chk, peer, r)
	// An isolated prober's result is not evidence, so it is not a trigger
	// either. Fanning out on it would spend the corroboration budget on
	// reports carrying no information — and during a partition, when every
	// cut-off prober sees every target as down, that is the entire budget,
	// starving the triggers that do mean something.
	//
	// Dynamic assignment moves an isolated owner's scheduled checks to a healthy
	// peer. Results already in flight from the isolated peer remain non-evidence.
	isolated := c.isolatedProbers()[r.Prober]
	if isolated {
		c.recordObservation(chk, r, "scheduled", true, check.StatusUnknown)
		c.log.Debug("ignoring a result from an isolated prober",
			"check", chk.Name, "prober", r.Prober)
		return quorum.Verdict{
			Check: chk.Name, Status: check.StatusUnknown,
			Suppressed: 1, SuppressedProbers: []string{r.Prober},
			Reason: fmt.Sprintf("%s can reach no peer; its result was not counted", r.Prober),
		}, nil
	}
	if c.markResultReporting(r.Prober) {
		c.emit(ctx, Alert{Prober: r.Prober, Kind: KindReporting, At: c.now(), Detail: "reporting again; preferred assignments restored"})
	}

	v, alert, kind, suspectedAt := c.decide(ctx, chk, r)
	c.recordObservation(chk, r, "scheduled", r.Vantage != chk.Vantage, v.Status)
	// A minority down verdict is "inconclusive", not up, so overruled means
	// enough peers answered to satisfy quorum without this prober.
	if (r.Status == check.StatusDown || r.Status == check.StatusWarning) &&
		v.Status != check.StatusDown && v.Status != r.Status && v.IndependentUp >= chk.Quorum.Agree {
		c.mu.Lock()
		if c.overruled == nil {
			c.overruled = map[[2]string]uint64{}
		}
		c.overruled[[2]string{r.Prober, chk.Name}]++
		c.mu.Unlock()
	}

	// A check inside a component alerts through the component, so an mx host
	// going down produces one alert naming the failing ports rather than one
	// per port. A check in no component is still its own alert.
	if alert && len(c.componentsFor[chk.Name]) == 0 {
		a := Alert{Check: chk.Name, Target: chk.Target, Kind: kind, At: c.now(), SuspectedAt: suspectedAt, Verdict: v}
		c.emit(ctx, a)
	}

	// Deliberately outside the check's lock, and unconditional. A rollup reads
	// the state of every sibling check, so holding this one while doing it
	// would let two results for sibling checks deadlock each other. And it runs
	// even when nothing alerted, because a check moving from undecided to up is
	// not an alert but does change what its component can conclude.
	c.rollUp(ctx, chk.Name)
	c.persist()
	return v, nil
}

// decide runs the check's own state machine and reports whether the transition
// is worth telling someone about. The state lock is confined here so callers
// can safely take other locks afterwards.
func (c *Coordinator) decide(ctx context.Context, chk check.Check, r check.Result) (quorum.Verdict, bool, Kind, time.Time) {
	st := c.stateFor(chk.Name)
	st.mu.Lock()
	defer st.mu.Unlock()

	results := []check.Result{r}
	attemptAt := c.now()
	var corroborationStarted time.Time

	// Only a failure is worth asking about. An up result already answers the
	// question, and corroborating it would spend N probes to confirm what one
	// prober can see — which is the cost model this design exists to avoid.
	//
	// The exception is a check whose quorum a single report already satisfies
	// (Agree: 1): the operator has said one prober suffices, so asking others
	// would change nothing.
	//
	// A warning is corroborated like a failure, so one prober cannot raise it,
	// but only when it is news: re-confirming a decided warning every interval
	// would spend N probes per check for as long as a certificate is near
	// expiry.
	single := c.evaluate(chk, results)
	if (r.Status == check.StatusDown && !single.Actionable()) ||
		(r.Status == check.StatusWarning && single.Status != check.StatusWarning && st.status != check.StatusWarning) {
		corroborationStarted = time.Now()
		corroborated := c.corroborate(ctx, chk, r)
		for _, result := range corroborated {
			c.recordObservation(chk, result, "corroboration", result.Vantage != chk.Vantage, "")
		}
		results = append(results, corroborated...)
	} else if r.Status == check.StatusUp && (st.status == check.StatusDown || st.status == check.StatusWarning) && chk.Quorum.Agree > 1 {
		// A recovery is a decision too. Requiring corroboration here prevents one
		// compromised assigned prober from clearing an incident by itself, while
		// keeping the steady-state cost at one probe when the check is healthy.
		corroborated := c.corroborate(ctx, chk, r)
		for _, result := range corroborated {
			c.recordObservation(chk, result, "corroboration", result.Vantage != chk.Vantage, "")
		}
		results = append(results, corroborated...)
	}

	v := c.evaluate(chk, results)
	if st.status == check.StatusWarning && r.Status == check.StatusWarning && v.Status == check.StatusUp {
		// The assigned prober agrees with the decided warning; nothing changed.
		v.Status = check.StatusWarning
		v.Reason = fmt.Sprintf("%s still reports the decided warning", r.Prober)
	}
	if (st.status == check.StatusDown || st.status == check.StatusWarning) &&
		v.Status == check.StatusUp && !recoveryConfirmed(chk, v) {
		v.Status = check.StatusUnknown
		v.Reason = fmt.Sprintf("recovery unconfirmed: %d of %d reported up, quorum needs %d",
			v.Up+v.Warning, v.Counted, chk.Quorum.Agree)
		if chk.ProxyProfile != "" {
			v.Reason += fmt.Sprintf("; %d independent up votes", v.IndependentUp)
		}
	}
	now := c.now()
	st.lastVerdict = now
	// It just reported, so whatever the watchdog last concluded about its
	// silence is out of date. Cleared here rather than waiting for the next
	// watch tick, so a returning prober is visible immediately.
	st.stale = false
	if !corroborationStarted.IsZero() {
		c.corroborations.Add(1)
		c.corroborationNanos.Add(int64(time.Since(corroborationStarted)))
		if v.Status == check.StatusUnknown {
			c.inconclusiveCorroborations.Add(1)
		}
	}

	if r.Status == check.StatusDown {
		if st.suspectedSince.IsZero() {
			st.suspectedSince = attemptAt
		}
		st.lastAttempt = attemptAt
		if !corroborationStarted.IsZero() {
			st.lastCorroboration = time.Since(corroborationStarted)
		}
		if v.Status == check.StatusUnknown {
			st.inconclusiveAttempts++
			st.lastInconclusive = v.Reason
			st.inconclusiveHistory = append(st.inconclusiveHistory, CorroborationAttempt{
				At: attemptAt, DurationMS: st.lastCorroboration.Milliseconds(),
				Reason: v.Reason, Counted: v.Counted, Down: v.Down, Up: v.Up,
			})
			if len(st.inconclusiveHistory) > maxInconclusiveHistory {
				st.inconclusiveHistory = append([]CorroborationAttempt(nil), st.inconclusiveHistory[len(st.inconclusiveHistory)-maxInconclusiveHistory:]...)
			}
		}
	} else if v.Status == check.StatusUp || v.Status == check.StatusWarning {
		st.clearSuspicion()
	}

	suspectedAt := st.suspectedSince
	alert, kind := st.apply(v.Status, now)
	if !alert {
		c.log.Debug("verdict", "check", chk.Name, "status", string(v.Status), "reason", v.Reason)
	}
	return v, alert, kind, suspectedAt
}

func (s *entityState) clearSuspicion() {
	s.suspectedSince = time.Time{}
	s.lastAttempt = time.Time{}
	s.lastCorroboration = 0
	s.inconclusiveAttempts = 0
	s.lastInconclusive = ""
	s.inconclusiveHistory = nil
}

func recoveryConfirmed(chk check.Check, v quorum.Verdict) bool {
	return v.IndependentUp >= chk.Quorum.Agree
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

	case check.StatusWarning:
		switch s.status {
		case check.StatusWarning:
			return false, ""
		case check.StatusDown:
			// The outage is over even though a warning remains, and the
			// recovery is what closes the outage incident.
			s.status, s.since = check.StatusWarning, now
			return true, KindRecovered
		}
		// Unlike recovery, a first-ever warning is news: a certificate that
		// is already close to expiry when monitoring starts still needs action.
		s.status, s.since = check.StatusWarning, now
		return true, KindWarning

	case check.StatusUp:
		previous := s.status
		if previous != check.StatusUp {
			s.since = now
		}
		s.status = check.StatusUp
		switch previous {
		case check.StatusDown:
			return true, KindRecovered
		case check.StatusWarning:
			return true, KindWarningCleared
		}
		// A first-ever up is not a recovery. Announcing "recovered" for
		// everything at startup is how a monitoring system gets muted.
		return false, ""

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
	for _, p := range c.eligiblePeers(chk) {
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
	if chk.ProxyProfile != "" {
		// First select a maximum independent set compatible with the reporter.
		// Fill any spare budget with other routes so partial failures can still
		// be observed. Quorum independently checks the resulting evidence.
		seed := routeResult(chk, c.byName[reported.Prober])
		var routes []check.Result
		for _, p := range candidates {
			r := routeResult(chk, p)
			if r.Egress == seed.Egress || (chk.Quorum.DistinctProviders && r.Provider == seed.Provider) {
				continue
			}
			routes = append(routes, r)
		}
		chosen := map[string]bool{}
		var out []Peer
		for _, r := range quorum.IndependentResults(routes, chk.Quorum.DistinctProviders) {
			chosen[r.Prober] = true
			out = append(out, c.byName[r.Prober])
		}
		for _, p := range candidates {
			if !chosen[p.Name] {
				out = append(out, p)
			}
		}
		return out[:want]
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
func (c *Coordinator) ask(ctx context.Context, p Peer, chk check.Check) (_ check.Result, err error) {
	id, err := wire.NewRequestID()
	if err != nil {
		return check.Result{}, err
	}
	now := c.now()
	env, err := wire.SignRequest(c.cfg.Key, c.cfg.Name, wire.Request{
		ID: id, Prober: p.Name, Check: chk, IssuedAt: now, ExpiresAt: now.Add(c.cfg.RequestTTL),
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
	defer closeWithError(&err, "close response body", resp.Body.Close)
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
	// The coordinator owns provider topology. A prober may be misconfigured or
	// compromised, but neither may redefine the independence of its vote.
	payload.Result = normalizeRoute(chk, p, payload.Result)
	return payload.Result, nil
}

// StatusEntry is the coordinator's current view of one check.
type StatusEntry struct {
	Check                string                 `json:"check"`
	Target               string                 `json:"target"`
	Status               string                 `json:"status"`
	Since                time.Time              `json:"since,omitempty"`
	LastVerdict          time.Time              `json:"last_verdict,omitempty"`
	AssignedTo           string                 `json:"assigned_to,omitempty"`
	SuspectedSince       time.Time              `json:"suspected_since,omitempty"`
	LastAttempt          time.Time              `json:"last_attempt,omitempty"`
	LastCorroborationMS  int64                  `json:"last_corroboration_ms,omitempty"`
	InconclusiveAttempts uint64                 `json:"inconclusive_attempts,omitempty"`
	LastInconclusive     string                 `json:"last_inconclusive_reason,omitempty"`
	InconclusiveHistory  []CorroborationAttempt `json:"inconclusive_history,omitempty"`

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
	checks := c.allChecks()
	out := make([]StatusEntry, 0, len(checks))
	for _, chk := range checks {
		e := StatusEntry{Check: chk.Name, Target: chk.Target, Status: string(check.StatusUnknown)}
		if name, ok := c.assignedTo(chk); ok {
			e.AssignedTo = name
		}
		c.mu.Lock()
		st := c.states[chk.Name]
		c.mu.Unlock()
		if st != nil {
			st.mu.Lock()
			e.Status = string(st.reported())
			e.Since, e.LastVerdict = st.since, st.lastVerdict
			e.SuspectedSince = st.suspectedSince
			e.LastAttempt = st.lastAttempt
			e.LastCorroborationMS = st.lastCorroboration.Milliseconds()
			e.InconclusiveAttempts = st.inconclusiveAttempts
			e.LastInconclusive = st.lastInconclusive
			e.InconclusiveHistory = append([]CorroborationAttempt(nil), st.inconclusiveHistory...)
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

// Wait blocks until background processing has finished. Called during
// shutdown so a verdict in flight is delivered rather than abandoned.
func (c *Coordinator) Wait() { c.inflight.Wait() }
