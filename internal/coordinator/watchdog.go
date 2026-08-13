package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

// A monitoring system's worst failure is not a wrong answer, it is no answer.
// Everything else here alerts when a check fails; nothing yet alerts when a
// check stops happening, and silence is indistinguishable from health.
//
// Two mechanisms, deliberately separate because they answer different
// questions and conflating them makes both diagnoses ambiguous:
//
//   - **Outward heartbeat.** The coordinator proves to something off-fleet
//     that it is alive and not wedged. Only an external watcher survives the
//     fleet being unreachable, which is exactly when this matters.
//   - **Inward staleness.** The coordinator notices probers that have stopped
//     reporting, and says so. This catches a prober that died quietly, whose
//     checks would otherwise simply stop being evaluated.
//
// Neither substitutes for the other. The heartbeat cannot see a dead prober
// because the coordinator is fine; the staleness watch cannot report a dead
// coordinator because it dies with it.

const (
	defaultHeartbeatInterval = time.Minute
	defaultStaleMultiplier   = 3
	defaultStaleGrace        = 30 * time.Second
	defaultWatchInterval     = 30 * time.Second
)

// Heartbeat is the outward dead-man's switch.
type Heartbeat struct {
	// URL is pinged on every interval while the coordinator is healthy. It
	// must point somewhere off the fleet — a hosted cron-ping service, or
	// anything that alerts when a expected ping does not arrive. A watcher
	// inside the fleet cannot report the fleet being unreachable.
	URL string

	// Interval is how often to ping. The external service's own grace period
	// should be a small multiple of this: too tight and a single lost packet
	// pages someone, too loose and a dead coordinator goes unnoticed for
	// longer than an outage lasts.
	Interval time.Duration

	// Headers are sent with every ping, which is where a token goes.
	Headers map[string]string
}

// Run starts the watchdog loops and blocks until ctx is cancelled. It is
// separate from Handler so a coordinator can be driven directly in tests
// without background goroutines deciding things underneath the test.
func (c *Coordinator) Run(ctx context.Context) {
	if c.isStandby() && !c.runStandby(ctx) {
		return
	}
	c.runActive(ctx)
}

func (c *Coordinator) runActive(ctx context.Context) {
	done := make(chan struct{}, 3)
	go func() { c.watchStaleness(ctx); done <- struct{}{} }()
	go func() { c.runHeartbeat(ctx); done <- struct{}{} }()
	go func() { c.runDeliveries(ctx); done <- struct{}{} }()
	<-done
	<-done
	<-done
}

// ---------------------------------------------------------------------------
// Outward: prove the coordinator is alive

func (c *Coordinator) runHeartbeat(ctx context.Context) {
	hb := c.cfg.Heartbeat
	if hb.URL == "" {
		// Said out loud rather than defaulted quietly. A coordinator with no
		// external watcher is the single-point-of-failure this design has
		// always named, and an operator should know they are running that way.
		c.log.Warn("no heartbeat url configured; nothing outside the fleet " +
			"will notice if this coordinator dies")
		return
	}
	interval := hb.Interval
	if interval <= 0 {
		interval = defaultHeartbeatInterval
	}

	c.beat(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.beat(ctx)
		}
	}
}

// beat pings the external watcher, but only if the coordinator can still do
// its job.
//
// The gate matters. A goroutine that pings on a timer proves the process has
// not exited, which is the least interesting way a coordinator fails — a
// wedged one still has a running scheduler. Building the export first means
// the ping traverses the same locks every verdict traverses, so a coordinator
// deadlocked in evaluation stops beating and the external watcher notices.
func (c *Coordinator) beat(ctx context.Context) {
	ready := make(chan wire.Heartbeat, 1)
	go func() {
		e := c.Export()
		ready <- wire.Heartbeat{
			Coordinator: e.Coordinator, At: e.GeneratedAt,
			Checks: len(e.Checks), Probers: e.Probers, Stale: len(c.staleChecks()),
		}
	}()

	// A wedged coordinator must fail to beat rather than block this loop
	// forever, so the ping is skipped rather than waited on.
	var body wire.Heartbeat
	select {
	case body = <-ready:
	case <-time.After(c.cfg.Heartbeat.timeout()):
		c.log.Error("skipping heartbeat: could not read own state in time — " +
			"the external watchdog should now fire")
		return
	case <-ctx.Done():
		return
	}

	env, err := wire.SignHeartbeat(c.cfg.Key, body)
	if err != nil {
		c.log.Error("signing heartbeat", "err", err)
		return
	}
	payload, err := json.Marshal(env)
	if err != nil {
		c.log.Error("encoding heartbeat", "err", err)
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx, c.cfg.Heartbeat.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		c.cfg.Heartbeat.URL, bytes.NewReader(payload))
	if err != nil {
		c.log.Error("building heartbeat request", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.cfg.Heartbeat.Headers {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		c.beatFailed(ctx, err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		c.beatFailed(ctx, "watcher returned "+resp.Status)
		return
	}
	c.beatSucceeded(ctx)
	c.log.Debug("heartbeat sent", "stale_checks", body.Stale)
}

// unwatchedAfter is how many consecutive failed beats before the coordinator
// says nothing is watching it. More than one, because a single dropped packet
// is not a dead watcher and this alert should mean something when it arrives.
const unwatchedAfter = 3

// beatFailed records a failed heartbeat and alerts once the failures are
// sustained.
//
// A coordinator must not claim to report its own death — that is precisely
// what it cannot do, and why the watcher exists. But **"nothing is watching
// me" is a different fact**, and the coordinator is the only component
// positioned to know it. Left unreported, a watcher that died silently means
// the dead-man's switch is gone and nothing says so, which is the failure the
// whole mechanism was built to remove, one level up.
func (c *Coordinator) beatFailed(ctx context.Context, detail string) {
	c.mu.Lock()
	c.beatFailures++
	n := c.beatFailures
	first := n == unwatchedAfter
	c.mu.Unlock()

	c.log.Warn("heartbeat failed", "consecutive", n, "detail", detail)
	if !first {
		return
	}
	a := Alert{
		Kind: KindUnwatched, At: c.now(),
		Detail: fmt.Sprintf("%d heartbeats in a row did not reach the watcher (%s); "+
			"nothing outside this coordinator would notice if it died", n, detail),
	}
	c.emit(ctx, a)
}

func (c *Coordinator) beatSucceeded(ctx context.Context) {
	c.mu.Lock()
	wasUnwatched := c.beatFailures >= unwatchedAfter
	c.beatFailures = 0
	c.mu.Unlock()

	if !wasUnwatched {
		return
	}
	a := Alert{Kind: KindWatched, At: c.now(), Detail: "heartbeats are reaching the watcher again"}
	c.emit(ctx, a)
}

func (h Heartbeat) timeout() time.Duration {
	interval := h.Interval
	if interval <= 0 {
		interval = defaultHeartbeatInterval
	}
	// Bounded well inside the interval so a slow ping cannot overlap the next
	// one and turn the heartbeat into a queue.
	if t := interval / 3; t < 10*time.Second {
		return t
	}
	return 10 * time.Second
}

// ---------------------------------------------------------------------------
// Inward: notice probers that stopped reporting

// staleAfter is how long a check may go unreported before nobody is watching
// it any more.
//
// A multiple of the interval rather than a fixed duration: a check that runs
// every 30 seconds and one that runs hourly have very different ideas of
// "late", and a single threshold would either page constantly on the slow one
// or take an hour to notice the fast one has stopped.
func (c *Coordinator) staleAfter(chk check.Check) time.Duration {
	mult := c.cfg.StaleMultiplier
	if mult <= 0 {
		mult = defaultStaleMultiplier
	}
	grace := c.cfg.StaleGrace
	if grace <= 0 {
		grace = defaultStaleGrace
	}
	return chk.Interval*time.Duration(mult) + grace
}

// staleChecks returns the checks that have not been reported on recently
// enough, and how long each has been silent.
//
// A check that has never reported counts from when the coordinator started,
// not from the zero time — otherwise everything is stale for the first
// interval after a restart, which would make the whole mechanism something
// people mute.
func (c *Coordinator) staleChecks() map[string]time.Duration {
	now := c.now()
	out := map[string]time.Duration{}
	for _, chk := range c.allChecks() {
		name := chk.Name
		last := c.startedAt

		c.mu.Lock()
		st := c.states[name]
		c.mu.Unlock()
		if st != nil {
			st.mu.Lock()
			if !st.lastVerdict.IsZero() {
				last = st.lastVerdict
			}
			st.mu.Unlock()
		}
		// A mesh report proves the process has returned, but not yet that it is
		// running checks. Use the recovery time only as a bounded scheduling
		// grace. It is not written into lastVerdict, which remains the timestamp
		// of actual monitoring evidence.
		if owner, ok := c.baseAssignedTo(chk); ok {
			c.mu.Lock()
			recovered := c.recoveryStarted[owner]
			c.mu.Unlock()
			if recovered.After(last) {
				last = recovered
			}
		}

		if silent := now.Sub(last); silent > c.staleAfter(chk) {
			out[name] = silent
		}
	}
	return out
}

func (c *Coordinator) watchStaleness(ctx context.Context) {
	interval := c.cfg.WatchInterval
	if interval <= 0 {
		interval = defaultWatchInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.CheckStaleness(ctx)
		}
	}
}

// CheckStaleness evaluates which checks have gone quiet and alerts on the
// transitions. Exported so a test can drive it without a ticker.
func (c *Coordinator) CheckStaleness(ctx context.Context) {
	c.releaseSuppressions(ctx)
	stale := c.staleChecks()
	now := c.now()

	// Flagged rather than forced to Down. Nobody is running the check, so there
	// is no evidence about the target, and calling it down would mean a prober
	// rebooting pages as an outage of the service it was watching.
	//
	// Flagged rather than forced to Unknown, too. The last verdict is still
	// worth keeping: overwrite it and a check that was already failing when
	// its prober died would announce itself as a brand new outage the moment
	// the prober came back. Readers see unknown either way — see
	// entityState.reported — but the dedup state underneath survives.
	for _, chk := range c.allChecks() {
		name := chk.Name
		st := c.stateFor(name)
		_, isStale := stale[name]
		st.mu.Lock()
		st.stale = isStale
		st.mu.Unlock()
	}

	// Grouped by the prober responsible, because the common cause is one
	// prober dying and taking all of its checks with it. Ungrouped, that is a
	// dozen alerts saying the same thing — the noise this project exists to
	// remove, arriving through the mechanism meant to catch it.
	byProber := map[string][]string{}
	for name := range stale {
		who := "(unassigned)"
		if chk, exists := c.checkByName(name); exists {
			if assigned, ok := c.baseAssignedTo(chk); ok {
				who = assigned
			}
		}
		byProber[who] = append(byProber[who], name)
	}

	for _, alert := range c.applySilence(byProber, stale, now) {
		c.emit(ctx, alert)
	}

	// A stale check can change what its components can conclude, so they are
	// re-rolled — outside every check lock, as always.
	for name := range stale {
		c.rollUp(ctx, name)
	}
	c.persist()
}

// applySilence moves the per-prober silence state machine and returns the
// alerts worth sending. Separated so the transition logic is testable without
// a notifier.
func (c *Coordinator) applySilence(
	byProber map[string][]string, silentFor map[string]time.Duration, now time.Time,
) []Alert {
	c.mu.Lock()
	defer c.mu.Unlock()

	var out []Alert

	for who, checks := range byProber {
		sort.Strings(checks)
		if c.silent[who] {
			// Already reported. Alerting every tick for as long as a prober is
			// down is the same mistake as alerting per failing result.
			continue
		}
		c.silent[who] = true

		members := make([]Member, 0, len(checks))
		var longest time.Duration
		for _, name := range checks {
			m := Member{Check: name, Status: string(check.StatusUnknown)}
			if chk, ok := c.checkByName(name); ok {
				m.Target = chk.Target
			}
			members = append(members, m)
			if silentFor[name] > longest {
				longest = silentFor[name]
			}
		}
		out = append(out, Alert{
			Prober:  who,
			Kind:    KindSilent,
			At:      now,
			Members: members,
			Detail: fmt.Sprintf("no results for %s; these checks are not being run",
				longest.Round(time.Second)),
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Prober < out[j].Prober })
	return out
}

func (c *Coordinator) markResultReporting(prober string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.recoveryStarted, prober)
	if !c.silent[prober] {
		return false
	}
	c.silent[prober] = false
	return true
}

func (c *Coordinator) markMeshReporting(prober string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.silent[prober] {
		return false
	}
	c.silent[prober] = false
	c.recoveryStarted[prober] = c.now()
	return true
}

func (c *Coordinator) isSilent(prober string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.silent[prober]
}
