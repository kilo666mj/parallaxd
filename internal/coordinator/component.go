package coordinator

import (
	"context"
	"sort"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

// Components are the user-facing layer over checks, and they change who
// alerts.
//
// **A check that belongs to a component does not alert on its own.** The
// component does, once, naming the members that failed. Otherwise an mx host
// going down produces one alert per port plus one for the component, which is
// the noise the grouping exists to remove. A check in no component is its own
// alert, exactly as before — components are opt-in and nothing is lost by not
// using them.
//
// Locking. A component's status is read from the states of several checks, so
// the rollup must never run while a check state is held: two results arriving
// for sibling checks at the same instant would each want the other's lock.
// Process therefore finishes with the check state and releases it *before*
// calling rollUp, and rollUp takes each check's lock one at a time. The order
// is always component-then-check, never the reverse.

// rollUp re-evaluates every component containing changed, alerting on a
// transition. Called after the check's own state has been released.
func (c *Coordinator) rollUp(ctx context.Context, changed string) {
	for _, comp := range c.componentsFor[changed] {
		st := c.componentState(comp.Name)
		status := comp.Roll(c.checkStatuses(comp.Checks))

		st.mu.Lock()
		st.lastVerdict = c.now()
		alert, kind := st.apply(status, c.now())
		st.mu.Unlock()

		if !alert {
			continue
		}
		a := Alert{
			Component: comp.Name,
			Detail:    comp.Description,
			Kind:      kind,
			At:        c.now(),
			Members:   c.members(comp),
		}
		if err := c.cfg.Notifier.Notify(ctx, a); err != nil {
			c.log.Error("could not deliver alert",
				"component", comp.Name, "kind", string(kind), "err", err)
		}
	}
}

// checkStatuses reads the current decided status of the named checks. A check
// with no state yet is absent from the map, which Roll reads as undecided.
func (c *Coordinator) checkStatuses(names []string) map[string]check.Status {
	out := make(map[string]check.Status, len(names))
	for _, name := range names {
		c.mu.Lock()
		st := c.states[name]
		c.mu.Unlock()
		if st == nil {
			continue
		}
		st.mu.Lock()
		out[name] = st.status
		st.mu.Unlock()
	}
	return out
}

// members renders the per-check detail carried on a component alert.
//
// A component alert without this would say "email is down" and leave the
// reader to go and find out which part — losing exactly the specificity that
// made the check-level alerts worth having.
func (c *Coordinator) members(comp check.Component) []Member {
	status := c.checkStatuses(comp.Checks)
	out := make([]Member, 0, len(comp.Checks))
	for _, name := range comp.Checks {
		m := Member{Check: name, Status: string(check.StatusUnknown)}
		if s, ok := status[name]; ok {
			m.Status = string(s)
		}
		if chk, ok := c.checks[name]; ok {
			m.Target = chk.Target
		}
		out = append(out, m)
	}
	return out
}

func (c *Coordinator) componentState(name string) *entityState {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.componentStates[name]
	if !ok {
		st = &entityState{status: check.StatusUnknown}
		c.componentStates[name] = st
	}
	return st
}

// ComponentEntry is the coordinator's current view of one component.
type ComponentEntry struct {
	Component   string `json:"component"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status"`

	// Since is when the component entered this status, which is what a page
	// renders as "down for 14 minutes".
	Since time.Time `json:"since,omitempty"`

	// Checks names the members, so a reader can follow a component down to the
	// entries in the checks list without a second request.
	Checks []string `json:"checks"`

	// DownIf records the rollup rule in force. A component sitting at up with
	// one member down is not a contradiction, and this is the field that
	// explains why.
	DownIf check.Rollup `json:"down_if"`
}

// Components reports the current state of every component.
func (c *Coordinator) Components() []ComponentEntry {
	out := make([]ComponentEntry, 0, len(c.cfg.Components))
	for _, comp := range c.cfg.Components {
		rule := comp.DownIf
		if rule == "" {
			rule = check.RollupAny
		}
		e := ComponentEntry{
			Component:   comp.Name,
			Description: comp.Description,
			Status:      string(comp.Roll(c.checkStatuses(comp.Checks))),
			Checks:      append([]string(nil), comp.Checks...),
			DownIf:      rule,
		}

		// Since comes from the state machine rather than being recomputed:
		// Roll gives the status now, but how long it has held that status is
		// only known to the thing that watched it change.
		c.mu.Lock()
		st := c.componentStates[comp.Name]
		c.mu.Unlock()
		if st != nil {
			st.mu.Lock()
			if string(st.status) == e.Status {
				e.Since = st.since
			}
			st.mu.Unlock()
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Component < out[j].Component })
	return out
}
