package coordinator

import (
	"context"
	"net/http"
	"sort"
	"time"
)

// Diagnostics is the coordinator's explainability surface. Counters describe
// this process lifetime; durable incident state is exposed separately.
type Diagnostics struct {
	GeneratedAt     time.Time               `json:"generated_at"`
	ResultQueue     QueueDiagnostics        `json:"result_queue"`
	RejectedResults map[string]uint64       `json:"rejected_results"`
	Notifications   NotificationDiagnostics `json:"notifications"`
	Assignments     []AssignmentDiagnostic  `json:"assignments"`
	Checks          []CheckDiagnostic       `json:"checks"`
	History         HistoryDiagnostics      `json:"history"`
	HA              HAStatus                `json:"ha"`
}

type QueueDiagnostics struct {
	Depth    int `json:"depth"`
	Capacity int `json:"capacity"`
}

type NotificationDiagnostics struct {
	Attempts      uint64                            `json:"attempts"`
	Failures      uint64                            `json:"failures"`
	Pending       int                               `json:"pending"`
	OldestPending time.Time                         `json:"oldest_pending,omitempty"`
	LastAttempt   time.Time                         `json:"last_attempt,omitempty"`
	LastSuccess   time.Time                         `json:"last_success,omitempty"`
	LastError     string                            `json:"last_error,omitempty"`
	Destinations  map[string]DestinationDiagnostics `json:"destinations,omitempty"`
}

type DestinationDiagnostics struct {
	Attempts    uint64    `json:"attempts"`
	Failures    uint64    `json:"failures"`
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
}

type HistoryDiagnostics struct {
	Retained      int       `json:"retained"`
	WriteFailures uint64    `json:"write_failures"`
	LastWrite     time.Time `json:"last_write,omitzero"`
	LastError     string    `json:"last_error,omitempty"`
}

type AssignmentDiagnostic struct {
	Check          string `json:"check"`
	PreferredOwner string `json:"preferred_owner,omitempty"`
	EffectiveOwner string `json:"effective_owner,omitempty"`
	Reason         string `json:"reason"`
}

type CheckDiagnostic struct {
	Check                  string                 `json:"check"`
	SuspectedSince         time.Time              `json:"suspected_since,omitempty"`
	LastAttempt            time.Time              `json:"last_attempt,omitempty"`
	LastCorroborationMS    int64                  `json:"last_corroboration_ms,omitempty"`
	InconclusiveAttempts   uint64                 `json:"inconclusive_attempts,omitempty"`
	LastInconclusiveReason string                 `json:"last_inconclusive_reason,omitempty"`
	InconclusiveHistory    []CorroborationAttempt `json:"inconclusive_history,omitempty"`
}

func (c *Coordinator) recordRejectedResult(reason string) {
	c.mu.Lock()
	c.diagnostics.RejectedResults[reason]++
	c.mu.Unlock()
}

func (c *Coordinator) recordDeliveryAttempt(ctx context.Context, destination string, notifier Notifier, a Alert) error {
	now := c.now().UTC()
	c.mu.Lock()
	c.diagnostics.Notifications.Attempts++
	c.diagnostics.Notifications.LastAttempt = now
	if c.diagnostics.Notifications.Destinations == nil {
		c.diagnostics.Notifications.Destinations = map[string]DestinationDiagnostics{}
	}
	diagnostic := c.diagnostics.Notifications.Destinations[destination]
	diagnostic.Attempts++
	diagnostic.LastAttempt = now
	c.diagnostics.Notifications.Destinations[destination] = diagnostic
	c.mu.Unlock()

	err := notifier.Notify(ctx, a)
	c.mu.Lock()
	if err != nil {
		c.diagnostics.Notifications.Failures++
		diagnostic.Failures++
		diagnostic.LastError = err.Error()
	} else {
		c.diagnostics.Notifications.LastSuccess = now
		diagnostic.LastSuccess = now
		diagnostic.LastError = ""
	}
	c.diagnostics.Notifications.Destinations[destination] = diagnostic
	c.diagnostics.Notifications.LastError = ""
	for _, state := range c.diagnostics.Notifications.Destinations {
		if state.LastError != "" {
			c.diagnostics.Notifications.LastError = state.LastError
			break
		}
	}
	c.mu.Unlock()
	return err
}

func (c *Coordinator) DiagnosticState() Diagnostics {
	c.mu.Lock()
	out := c.diagnostics
	out.Notifications.Destinations = make(map[string]DestinationDiagnostics, len(c.diagnostics.Notifications.Destinations))
	for destination, diagnostic := range c.diagnostics.Notifications.Destinations {
		out.Notifications.Destinations[destination] = diagnostic
	}
	out.RejectedResults = make(map[string]uint64, len(c.diagnostics.RejectedResults))
	for reason, count := range c.diagnostics.RejectedResults {
		out.RejectedResults[reason] = count
	}
	c.mu.Unlock()

	out.GeneratedAt = c.now().UTC()
	out.HA = c.HAStatus()
	out.ResultQueue = QueueDiagnostics{Depth: len(c.resultSlots), Capacity: cap(c.resultSlots)}
	c.historyMu.Lock()
	cutoff := c.now().UTC().Add(-c.historyRetention())
	for _, observations := range c.history {
		for _, observation := range observations {
			if !observation.ReceivedAt.Before(cutoff) {
				out.History.Retained++
			}
		}
	}
	c.historyMu.Unlock()
	c.mu.Lock()
	out.Notifications.Pending = len(c.outbox)
	for _, delivery := range c.outbox {
		if out.Notifications.OldestPending.IsZero() || delivery.CreatedAt.Before(out.Notifications.OldestPending) {
			out.Notifications.OldestPending = delivery.CreatedAt
		}
	}
	c.mu.Unlock()
	unavailable := c.unavailableProbers()
	for _, chk := range c.allChecks() {
		preferred, _ := c.baseAssignedTo(chk)
		effective, _ := c.assignedTo(chk)
		reason := "preferred owner active"
		if preferred == "" {
			reason = "no eligible owner"
		} else if effective == "" {
			reason = "all owners unavailable"
		} else if preferred != effective {
			reason = "preferred owner unavailable"
			if unavailable[preferred] {
				reason += "; failed over"
			}
		} else if chk.Prober == "" {
			reason = "rendezvous hash owner"
		}
		out.Assignments = append(out.Assignments, AssignmentDiagnostic{
			Check: chk.Name, PreferredOwner: preferred, EffectiveOwner: effective, Reason: reason,
		})
		c.mu.Lock()
		st := c.states[chk.Name]
		c.mu.Unlock()
		if st != nil {
			st.mu.Lock()
			if !st.lastAttempt.IsZero() {
				out.Checks = append(out.Checks, CheckDiagnostic{
					Check: chk.Name, SuspectedSince: st.suspectedSince,
					LastAttempt: st.lastAttempt, LastCorroborationMS: st.lastCorroboration.Milliseconds(),
					InconclusiveAttempts: st.inconclusiveAttempts, LastInconclusiveReason: st.lastInconclusive,
					InconclusiveHistory: append([]CorroborationAttempt(nil), st.inconclusiveHistory...),
				})
			}
			st.mu.Unlock()
		}
	}
	sort.Slice(out.Assignments, func(i, j int) bool { return out.Assignments[i].Check < out.Assignments[j].Check })
	sort.Slice(out.Checks, func(i, j int) bool { return out.Checks[i].Check < out.Checks[j].Check })
	return out
}

func (c *Coordinator) handleDiagnostics(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, c.DiagnosticState())
}
