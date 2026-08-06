// Package watch is the other half of the dead-man's switch: the thing that
// notices when the coordinator stops saying it is alive.
//
// # Why this is in the project
//
// The usual answer is a hosted cron-ping service, and for a system whose
// premise is not depending on anyone else's infrastructure that is the wrong
// answer. What the receiver actually has to be is in a **different failure
// domain** — different host, different provider, different uplink — not a
// different company. A watcher one provider over catches a dead host, a
// crashed or wedged process, a bad deploy, and a provider-wide outage, which
// between them are essentially every way a coordinator fails.
//
// # The regress
//
// "Who watches the watcher" is the real problem, and it is solved by watching
// back rather than by buying. The coordinator reports a watcher it can no
// longer deliver to; the watcher reports a coordinator that has gone quiet.
// Either dying alone is reported by the other.
//
// Both dying at once is not covered, and nothing here pretends otherwise. That
// is also true of a hosted service when the alerting path is self-hosted, so
// it is a property of the topology rather than a cost of building it yourself.
package watch

import (
	"fmt"
	"sync"
	"time"

	"github.com/kilo666mj/parallaxd/internal/wire"
)

// Beat is what the coordinator sends. It mirrors the payload the coordinator
// already produces, so the watcher stores what it was told rather than a
// reduction of it: when an operator goes looking after an outage, the last
// thing the coordinator managed to say is the most useful record there is.
type Beat = wire.Heartbeat

// State is what the watcher currently believes about the coordinator.
type State struct {
	// Alive is false once the grace period has elapsed with no beat.
	Alive bool `json:"alive"`

	// Last is the most recent beat received, zero if none ever has been.
	Last Beat `json:"last,omitzero"`

	// Silence is how long it has been since the last beat.
	Silence time.Duration `json:"silence"`

	// Since is when the current Alive value took effect.
	Since time.Time `json:"since,omitzero"`
}

// Watcher tracks heartbeats and reports transitions.
//
// Deliberately tiny and free of I/O beyond what the caller drives, for the
// same reason quorum and mesh are: this is the component that has to keep
// working when everything it watches has stopped, so there is very little of
// it to go wrong.
type Watcher struct {
	// Grace is how long the coordinator may go quiet before it is declared
	// dead. It should be a small multiple of the coordinator's heartbeat
	// interval: too tight and a single lost packet pages someone, too loose
	// and a dead coordinator goes unnoticed for longer than an outage lasts.
	Grace time.Duration

	// Now is injectable so tests own time.
	Now func() time.Time

	mu sync.Mutex

	// started is the baseline before any beat has arrived. Without it the
	// watcher declares the coordinator dead the instant it starts, which is
	// how a useful signal becomes one people mute.
	started    time.Time
	last       Beat
	receivedAt time.Time
	haveOne    bool
	alive      bool
	since      time.Time
}

// New builds a watcher. started is the moment it came up, used as the
// staleness baseline until the first beat arrives.
func New(grace time.Duration, now func() time.Time) *Watcher {
	if now == nil {
		now = time.Now
	}
	t := now()
	return &Watcher{Grace: grace, Now: now, started: t, alive: true, since: t}
}

// Record stores a beat and reports whether this was a recovery.
func (w *Watcher) Record(b Beat) (recovered bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Out-of-order delivery must not resurrect an older view.
	if w.haveOne && !b.At.After(w.last.At) {
		return false
	}
	w.last, w.receivedAt, w.haveOne = b, w.Now(), true

	if !w.alive {
		w.alive, w.since = true, w.Now()
		return true
	}
	return false
}

// Check evaluates the grace period and reports whether the coordinator has
// just been declared dead. Called on a timer by the caller.
func (w *Watcher) Check() (died bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.silence() <= w.Grace {
		return false
	}
	if !w.alive {
		// Already reported. Alerting every tick for as long as it is down is
		// the same mistake as alerting per failing result.
		return false
	}
	w.alive, w.since = false, w.Now()
	return true
}

// State returns the current view.
func (w *Watcher) State() State {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := State{Alive: w.alive, Silence: w.silence(), Since: w.since}
	if w.haveOne {
		s.Last = w.last
	}
	return s
}

// silence is how long since the last beat, or since startup if none has
// arrived. Caller holds the lock.
func (w *Watcher) silence() time.Duration {
	from := w.started
	if w.haveOne && w.receivedAt.After(from) {
		from = w.receivedAt
	}
	d := w.Now().Sub(from)
	if d < 0 {
		return 0
	}
	return d
}

// Summary renders the state as one line.
func (s State) Summary() string {
	if s.Alive {
		return fmt.Sprintf("coordinator %s alive; %d checks, %d probers, %d stale",
			s.Last.Coordinator, s.Last.Checks, s.Last.Probers, s.Last.Stale)
	}
	who := s.Last.Coordinator
	if who == "" {
		who = "coordinator"
	}
	return fmt.Sprintf("%s has not checked in for %s — nothing is deciding, "+
		"and no outage will be reported until it returns",
		who, s.Silence.Round(time.Second))
}
