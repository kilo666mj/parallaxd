package coordinator

import (
	"hash/fnv"
	"sort"
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
// Assignment is computed, not configured, so the check catalogue lives in one
// place. Probers currently self-schedule from their own config; pushing
// assignments to them, and reassigning when one goes silent, is future work.
// Until then this is what /v1/assignments exposes so an operator can generate
// or verify those configs rather than keeping two lists in step by hand.
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

// Assignments returns which prober is responsible for each check, keyed by
// prober name. Probers with nothing assigned are present with an empty list,
// so a fleet-wide view shows an idle prober rather than omitting it.
func (c *Coordinator) Assignments() map[string][]string {
	out := make(map[string][]string, len(c.peers))
	for _, p := range c.peers {
		out[p.Name] = nil
	}
	for _, chk := range c.checks {
		if p, ok := assign(chk.Name, c.peers); ok {
			out[p.Name] = append(out[p.Name], chk.Name)
		}
	}
	for name := range out {
		sort.Strings(out[name])
	}
	return out
}
