package check

import (
	"fmt"
	"strings"
)

// A component is what a person cares about; a check is how the system finds
// out. Nobody outside the fleet wants to know whether mx-smtps answered TCP
// 465 from three vantages — they want to know whether email works.
//
// The distinction is not only presentational. It is the difference between
// four alerts and one that says "email is down", and getting the rollup wrong
// is how a monitoring system reports a degraded service as an outage or the
// reverse.

// Rollup is how a component's checks combine into its status.
type Rollup string

const (
	// RollupAny means one failing check takes the component down. The right
	// default: if any part of a service is broken, the service is broken.
	RollupAny Rollup = "any"

	// RollupAll means the component is down only when every check is. For a
	// pool of equivalent members — three mirrors, two resolvers — one failing
	// is degraded, not an outage.
	RollupAll Rollup = "all"

	// RollupQuorum means the component is down when DownAt or more checks are.
	// The middle ground for a pool that needs a majority to be useful.
	RollupQuorum Rollup = "quorum"
)

// Component is a named group of checks presented as one thing.
type Component struct {
	// Name is what appears in alerts and on any page built from the export, so
	// it should read as the service a person recognises rather than as
	// infrastructure: "email", not "mx01-smtp".
	Name string `json:"name"`

	// Description is a sentence for a reader who does not know the fleet.
	Description string `json:"description,omitempty"`

	// Checks names the checks that make up this component. A check may belong
	// to several components — "mx-smtps" is part of both "email" and "the mx
	// host" — and each rolls up independently.
	Checks []string `json:"checks"`

	// DownIf is the rollup rule. Empty means RollupAny.
	DownIf Rollup `json:"down_if,omitempty"`

	// DownAt is how many failing checks take the component down under
	// RollupQuorum. Ignored otherwise.
	DownAt int `json:"down_at,omitempty"`
}

// Validate reports whether the component is usable. known, when non-nil, is
// the set of defined check names: a component naming a check that does not
// exist is a config error that would otherwise show up as a component
// permanently stuck at unknown.
func (c Component) Validate(known map[string]bool) error {
	switch {
	case strings.TrimSpace(c.Name) == "":
		return fmt.Errorf("component name is required")
	case len(c.Checks) == 0:
		return fmt.Errorf("component %q: at least one check is required", c.Name)
	}

	seen := map[string]bool{}
	for _, name := range c.Checks {
		if seen[name] {
			// Under a quorum rollup a duplicate would let one check vote twice,
			// which is the same mistake quorum de-duplicates probers to avoid.
			return fmt.Errorf("component %q: check %q listed twice", c.Name, name)
		}
		seen[name] = true
		if known != nil && !known[name] {
			return fmt.Errorf("component %q: no check named %q", c.Name, name)
		}
	}

	switch c.DownIf {
	case "", RollupAny, RollupAll:
	case RollupQuorum:
		if c.DownAt < 1 || c.DownAt > len(c.Checks) {
			return fmt.Errorf("component %q: down_at is %d, must be between 1 and the "+
				"%d checks it contains", c.Name, c.DownAt, len(c.Checks))
		}
	default:
		return fmt.Errorf("component %q: unknown down_if %q, want %q, %q or %q",
			c.Name, c.DownIf, RollupAny, RollupAll, RollupQuorum)
	}
	return nil
}

// Roll combines the current status of each member check into the component's.
//
// The same rule the rest of the system runs on: an undecided check is not
// evidence. It cannot make a component down, and — crucially — it cannot make
// one up either. A component is up only when every check it contains has been
// decided and none of them is failing, so a check that has gone quiet holds the
// component at unknown rather than being silently read as healthy.
//
// The exception is a rollup that is already satisfied. If one failing check is
// enough to take the component down, it is down whether or not the others have
// reported.
func (c Component) Roll(status map[string]Status) Status {
	var down, up, undecided int
	for _, name := range c.Checks {
		switch status[name] {
		case StatusDown:
			down++
		case StatusUp:
			up++
		default:
			undecided++
		}
	}

	if c.isDown(down, len(c.Checks)) {
		return StatusDown
	}
	if undecided > 0 || up == 0 {
		return StatusUnknown
	}
	return StatusUp
}

func (c Component) isDown(down, total int) bool {
	switch c.DownIf {
	case RollupAll:
		// No undecided guard needed: reaching total means every check reported.
		return down == total
	case RollupQuorum:
		return c.DownAt > 0 && down >= c.DownAt
	default:
		return down > 0
	}
}
