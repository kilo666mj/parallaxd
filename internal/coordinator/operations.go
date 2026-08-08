package coordinator

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Maintenance is a configured interval during which matching alerts are
// recorded but not delivered. Empty Checks and Components means fleet-wide.
type Maintenance struct {
	Name       string    `json:"name"`
	StartsAt   time.Time `json:"starts_at"`
	EndsAt     time.Time `json:"ends_at"`
	Checks     []string  `json:"checks,omitempty"`
	Components []string  `json:"components,omitempty"`
}

type Incident struct {
	ID               uint64     `json:"id"`
	Subject          string     `json:"subject"`
	Kind             Kind       `json:"kind"`
	OpenedAt         time.Time  `json:"opened_at"`
	ResolvedAt       time.Time  `json:"resolved_at,omitempty"`
	Active           bool       `json:"active"`
	Suppressed       bool       `json:"suppressed,omitempty"`
	Maintenance      string     `json:"maintenance,omitempty"`
	SilenceID        uint64     `json:"silence_id,omitempty"`
	Silence          string     `json:"silence,omitempty"`
	AcknowledgedAt   *time.Time `json:"acknowledged_at,omitempty"`
	AcknowledgedBy   string     `json:"acknowledged_by,omitempty"`
	Acknowledgement  string     `json:"acknowledgement,omitempty"`
	ResolvedBy       string     `json:"resolved_by,omitempty"`
	Resolution       string     `json:"resolution,omitempty"`
	ManualResolution bool       `json:"manual_resolution,omitempty"`
	Alert            Alert      `json:"alert"`
}

func (c *Coordinator) emit(ctx context.Context, a Alert) {
	maintenance := c.activeMaintenance(a, c.now())
	silenceID, silence := c.activeSilence(a, c.now())
	c.recordIncident(a, maintenance, silenceID, silence)
	c.persist()
	if maintenance != "" || silenceID != 0 {
		c.log.Info("alert suppressed", "subject", a.Subject(), "maintenance", maintenance, "silence", silence)
		return
	}
	if err := c.deliver(ctx, a); err != nil {
		c.log.Error("could not deliver alert", "subject", a.Subject(), "kind", string(a.Kind), "err", err)
	}
}

func (c *Coordinator) activeMaintenance(a Alert, now time.Time) string {
	for _, m := range c.cfg.Maintenance {
		if now.Before(m.StartsAt) || !now.Before(m.EndsAt) {
			continue
		}
		if len(m.Checks) == 0 && len(m.Components) == 0 {
			return m.Name
		}
		for _, name := range m.Checks {
			if name == a.Check {
				return m.Name
			}
			for _, member := range a.Members {
				if name == member.Check {
					return m.Name
				}
			}
		}
		for _, name := range m.Components {
			if name == a.Component {
				return m.Name
			}
		}
	}
	return ""
}

func (c *Coordinator) recordIncident(a Alert, maintenance string, silenceID uint64, silence string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	subject := a.Subject()
	switch a.Kind {
	case KindRecovered, KindReporting, KindRejoined, KindWatched, KindWatchRecovered:
		for i := len(c.incidents) - 1; i >= 0; i-- {
			if c.incidents[i].Subject == subject && c.incidents[i].Active {
				c.incidents[i].Active = false
				c.incidents[i].ResolvedAt = a.At
				return
			}
		}
		return
	}
	c.nextIncidentID++
	c.incidents = append(c.incidents, Incident{
		ID: c.nextIncidentID, Subject: subject, Kind: a.Kind, OpenedAt: a.At,
		Active: true, Suppressed: maintenance != "" || silenceID != 0,
		Maintenance: maintenance, SilenceID: silenceID, Silence: silence, Alert: a,
	})
}

func (c *Coordinator) Incidents() []Incident {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A JSON API should represent an empty collection as [] rather than null.
	// The dashboard and other clients can then iterate without special-casing
	// the coordinator's initial no-incident state.
	out := append([]Incident{}, c.incidents...)
	sort.Slice(out, func(i, j int) bool { return out[i].OpenedAt.After(out[j].OpenedAt) })
	return out
}

func (c *Coordinator) handleIncidents(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, c.Incidents())
}
func (c *Coordinator) handleMaintenance(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, c.cfg.Maintenance)
}

func (m Maintenance) Validate() error {
	if m.Name == "" {
		return fmt.Errorf("maintenance name is required")
	}
	if m.StartsAt.IsZero() || !m.EndsAt.After(m.StartsAt) {
		return fmt.Errorf("maintenance %q has an invalid interval", m.Name)
	}
	return nil
}

// releaseSuppressions delivers an incident that began under maintenance or an
// operator silence if it is still active when suppression ends. Otherwise a
// long outage would remain silent forever because no new transition occurs.
func (c *Coordinator) releaseSuppressions(ctx context.Context) {
	now := c.now()
	var alerts []Alert
	c.mu.Lock()
	for i := range c.incidents {
		incident := &c.incidents[i]
		if !incident.Active || !incident.Suppressed {
			continue
		}
		stillActive := c.suppressionActiveLocked(*incident, now)
		if stillActive {
			continue
		}
		incident.Suppressed = false
		incident.Maintenance = ""
		incident.SilenceID = 0
		incident.Silence = ""
		a := incident.Alert
		a.At = now
		a.Detail = strings.TrimSpace(a.Detail + "; suppression ended and the incident is still active")
		alerts = append(alerts, a)
	}
	c.mu.Unlock()
	for _, a := range alerts {
		if err := c.deliver(ctx, a); err != nil {
			c.log.Error("could not deliver post-suppression alert", "subject", a.Subject(), "err", err)
		}
	}
	if len(alerts) > 0 {
		c.persist()
	}
}
