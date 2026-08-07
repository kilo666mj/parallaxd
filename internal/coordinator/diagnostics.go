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
}

type QueueDiagnostics struct {
	Depth    int `json:"depth"`
	Capacity int `json:"capacity"`
}

type NotificationDiagnostics struct {
	Attempts    uint64    `json:"attempts"`
	Failures    uint64    `json:"failures"`
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
}

type AssignmentDiagnostic struct {
	Check          string `json:"check"`
	PreferredOwner string `json:"preferred_owner,omitempty"`
	EffectiveOwner string `json:"effective_owner,omitempty"`
	Reason         string `json:"reason"`
}

func (c *Coordinator) recordRejectedResult(reason string) {
	c.mu.Lock()
	c.diagnostics.RejectedResults[reason]++
	c.mu.Unlock()
}

func (c *Coordinator) deliver(ctx context.Context, a Alert) error {
	now := c.now().UTC()
	c.mu.Lock()
	c.diagnostics.Notifications.Attempts++
	c.diagnostics.Notifications.LastAttempt = now
	c.mu.Unlock()

	err := c.cfg.Notifier.Notify(ctx, a)
	c.mu.Lock()
	if err != nil {
		c.diagnostics.Notifications.Failures++
		c.diagnostics.Notifications.LastError = err.Error()
	} else {
		c.diagnostics.Notifications.LastSuccess = now
		c.diagnostics.Notifications.LastError = ""
	}
	c.mu.Unlock()
	return err
}

func (c *Coordinator) DiagnosticState() Diagnostics {
	c.mu.Lock()
	out := c.diagnostics
	out.RejectedResults = make(map[string]uint64, len(c.diagnostics.RejectedResults))
	for reason, count := range c.diagnostics.RejectedResults {
		out.RejectedResults[reason] = count
	}
	c.mu.Unlock()

	out.GeneratedAt = c.now().UTC()
	out.ResultQueue = QueueDiagnostics{Depth: len(c.resultSlots), Capacity: cap(c.resultSlots)}
	unavailable := c.unavailableProbers()
	for _, chk := range c.checks {
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
	}
	sort.Slice(out.Assignments, func(i, j int) bool { return out.Assignments[i].Check < out.Assignments[j].Check })
	return out
}

func (c *Coordinator) handleDiagnostics(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, c.DiagnosticState())
}
