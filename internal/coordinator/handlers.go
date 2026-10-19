package coordinator

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

func (c *Coordinator) handleResult(w http.ResponseWriter, r *http.Request) {
	var env wire.Envelope
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes)).Decode(&env); err != nil {
		c.recordRejectedResult("malformed_envelope")
		http.Error(w, "malformed envelope", http.StatusBadRequest)
		return
	}

	payload, err := c.ring.OpenResult(env, c.now())
	if err != nil {
		c.recordRejectedResult("authentication")
		// A result counts toward a verdict, so an unauthenticated one could
		// manufacture agreement or forge an all-clear. Refused before it is
		// looked at.
		c.log.Warn("refused a result", "peer", env.Peer, "err", err)
		http.Error(w, "result rejected", http.StatusForbidden)
		return
	}
	chk, known := c.checkByName(payload.Result.Check)
	if !known {
		c.recordRejectedResult("unknown_check")
		// A registered prober reporting a check the coordinator does not have
		// is a configuration drift, not an attack — but acting on it would
		// mean alerting about something nobody defined.
		c.log.Warn("result for an unknown check",
			"prober", payload.Result.Prober, "check", payload.Result.Check)
		http.Error(w, "unknown check", http.StatusBadRequest)
		return
	}
	if payload.RequestID != "" {
		c.recordRejectedResult("request_bound_result")
		http.Error(w, "request-bound result is not a scheduled result", http.StatusBadRequest)
		return
	}
	assigned, ok := c.assignedTo(chk)
	preferred, _ := c.baseAssignedTo(chk)
	returning := preferred == payload.Result.Prober && c.isSilent(payload.Result.Prober)
	if (!ok || assigned != payload.Result.Prober) && !returning {
		c.recordRejectedResult("not_assigned")
		c.log.Warn("result from a prober not assigned to the check",
			"check", chk.Name, "prober", payload.Result.Prober, "assigned", assigned)
		http.Error(w, "prober is not assigned to this check", http.StatusForbidden)
		return
	}
	payload.Result.Provider = c.byName[payload.Result.Prober].Provider

	select {
	case c.resultSlots <- struct{}{}:
	case <-r.Context().Done():
		return
	default:
		c.recordRejectedResult("queue_full")
		http.Error(w, "result queue is full", http.StatusServiceUnavailable)
		return
	}

	// Scheduled results must move forward. This rejects retries, replays and
	// delayed packets that would otherwise let an old all-clear undo a newer
	// outage decision.
	key := payload.Result.Prober + "\x00" + payload.Result.Check
	c.mu.Lock()
	last := c.lastScheduled[key]
	if !payload.Result.At.After(last) {
		c.mu.Unlock()
		<-c.resultSlots
		c.recordRejectedResult("replay_or_out_of_order")
		http.Error(w, "result is not newer than the last accepted result", http.StatusConflict)
		return
	}
	c.lastScheduled[key] = payload.Result.At
	c.mu.Unlock()
	// Accepted, then processed in the background. Corroboration takes seconds
	// and the prober submitting this is single-threaded per check: holding it
	// open would delay that check's next probe by the length of the fan-out.
	c.inflight.Add(1)
	go func(res check.Result) {
		defer c.inflight.Done()
		defer func() { <-c.resultSlots }()
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
	status := "ok"
	if c.isStandby() {
		status = "standby"
	}
	writeJSON(w, map[string]any{
		"coordinator": c.cfg.Name,
		"status":      status,
		"probers":     len(c.peers),
		"checks":      len(c.allChecks()),
	})
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

func (c *Coordinator) handleChecks(w http.ResponseWriter, r *http.Request) {
	prober, ok := c.proberCaller(r)
	if !ok {
		http.Error(w, "not a registered prober", http.StatusForbidden)
		return
	}
	env, err := wire.SignPublishedDocument(c.cfg.Key, c.cfg.Name, prober, "assignments", c.now(), c.checksFor(prober))
	if err != nil {
		http.Error(w, "could not sign assignments", http.StatusInternalServerError)
		return
	}
	writeJSON(w, env)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Default().Error("writing response", "err", err)
	}
}
