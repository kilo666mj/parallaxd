package coordinator

import (
	"hash/fnv"
	"sort"

	"github.com/kilo666mj/parallaxd/internal/check"
)

// assign picks the prober responsible for running a check in steady state.
//
// One prober per check is the whole cost argument: M probes in steady state
// and N only during an incident. Everything else a prober does is on request.
//
// Rendezvous hashing rather than name-hash-modulo-count. Modulo reshuffles
// almost every assignment when the peer list changes by one, which on a fleet
// this size means a single prober being added silently moves every check to a
// different vantage — and a check's history is only comparable while it is
// being run from the same place. Rendezvous moves only the checks that
// belonged to the peer that left.
//
// The check catalogue lives in one place. Probers fetch their effective set
// from /v1/checks, and owners that are silent or isolated are excluded until
// they report or rejoin.
func assign(checkName string, peers []Peer) (Peer, bool) {
	var (
		best  Peer
		score uint64
		found bool
	)
	for _, p := range peers {
		s := weight(checkName, p.Name)
		// Ties break on name so the result does not depend on the order peers
		// happened to be listed in.
		if !found || s > score || (s == score && p.Name < best.Name) {
			best, score, found = p, s, true
		}
	}
	return best, found
}

func weight(checkName, peerName string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(checkName))
	// A separator, so ("ab", "c") and ("a", "bc") do not collide.
	h.Write([]byte{0})
	h.Write([]byte(peerName))
	return h.Sum64()
}

// assignedTo reports which prober runs a check in steady state.
//
// An explicit Prober is the preferred owner; otherwise rendezvous hashing
// chooses one. unavailable owners are temporarily removed below.
func (c *Coordinator) assignedTo(chk check.Check) (string, bool) {
	preferred, ok := c.baseAssignedTo(chk)
	if !ok {
		return "", false
	}
	unavailable := c.unavailableProbers()
	if !unavailable[preferred] {
		return preferred, true
	}
	// An isolated owner cannot produce evidence. Move the check using the same
	// stable hash over the healthy subset; when it rejoins, the preferred owner
	// automatically resumes without reshuffling unrelated checks.
	healthy := make([]Peer, 0, len(c.peers))
	for _, p := range c.peers {
		if !unavailable[p.Name] {
			healthy = append(healthy, p)
		}
	}
	p, ok := assign(chk.Name, healthy)
	return p.Name, ok
}

func (c *Coordinator) unavailableProbers() map[string]bool {
	out := c.isolatedProbers()
	if out == nil {
		out = map[string]bool{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for name, silent := range c.silent {
		if silent {
			out[name] = true
		}
	}
	return out
}

func (c *Coordinator) baseAssignedTo(chk check.Check) (string, bool) {
	if chk.Prober != "" {
		return chk.Prober, true
	}
	p, ok := assign(chk.Name, c.peers)
	return p.Name, ok
}

func (c *Coordinator) checksFor(prober string) []check.Check {
	out := []check.Check{}
	for _, chk := range c.checks {
		if assigned, ok := c.assignedTo(chk); ok && assigned == prober {
			out = append(out, chk)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Assignments returns which prober is responsible for each check, keyed by
// prober name. Probers with nothing assigned are present with an empty list,
// so a fleet-wide view shows an idle prober rather than omitting it.
func (c *Coordinator) Assignments() map[string][]string {
	out := make(map[string][]string, len(c.peers))
	for _, p := range c.peers {
		out[p.Name] = nil
	}
	for _, chk := range c.checks {
		if name, ok := c.assignedTo(chk); ok {
			out[name] = append(out[name], chk.Name)
		}
	}
	for name := range out {
		sort.Strings(out[name])
	}
	return out
}
