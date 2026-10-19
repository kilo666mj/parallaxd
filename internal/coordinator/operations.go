package coordinator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

var (
	errMaintenanceNotFound   = errors.New("maintenance window not found")
	errMaintenanceExists     = errors.New("maintenance window already exists")
	errMaintenanceConfigured = errors.New("maintenance window is defined in the coordinator configuration")
)

// Maintenance is an interval during which matching alerts are recorded but
// not delivered. Empty Checks, Components and Probers means fleet-wide.
// Windows come from the configuration (read-only) or from the operator API,
// which persists and replicates them.
type Maintenance struct {
	Name     string    `json:"name"`
	StartsAt time.Time `json:"starts_at"`
	EndsAt   time.Time `json:"ends_at"`
	// Every repeats the window at a fixed period after StartsAt, such as
	// "24h" or "168h".
	Every      string    `json:"every,omitempty"`
	Checks     []string  `json:"checks,omitempty"`
	Components []string  `json:"components,omitempty"`
	Probers    []string  `json:"probers,omitempty"`
	Comment    string    `json:"comment,omitempty"`
	Source     string    `json:"source,omitempty"`
	CreatedAt  time.Time `json:"created_at,omitzero"`
	CreatedBy  string    `json:"created_by,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitzero"`
	UpdatedBy  string    `json:"updated_by,omitempty"`
}

const (
	maintenanceFromConfig = "config"
	maintenanceFromAPI    = "api"
)

func (m Maintenance) active(now time.Time) bool {
	if now.Before(m.StartsAt) {
		return false
	}
	if every, err := time.ParseDuration(m.Every); err == nil && every > 0 {
		// shortcut: a fixed period ignores DST, so a weekly window moves by an hour
		// in local time twice a year; add a time zone if that starts to matter.
		now = now.Add(-now.Sub(m.StartsAt) / every * every)
	}
	return now.Before(m.EndsAt)
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
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.maintenanceLocked() {
		if m.active(now) && alertMatches(a, m.Checks, m.Components, m.Probers) {
			return m.Name
		}
	}
	return ""
}

// maintenanceLocked returns configured windows followed by managed ones. It is
// called while c.mu is held.
func (c *Coordinator) maintenanceLocked() []Maintenance {
	out := make([]Maintenance, 0, len(c.cfg.Maintenance)+len(c.maintenance))
	for _, m := range c.cfg.Maintenance {
		m.Source = maintenanceFromConfig
		out = append(out, m)
	}
	return append(out, c.maintenance...)
}

// MaintenanceWindows returns every configured and managed maintenance window.
func (c *Coordinator) MaintenanceWindows() []Maintenance {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maintenanceLocked()
}

// PutMaintenance creates or replaces a managed maintenance window.
func (c *Coordinator) PutMaintenance(m Maintenance, actor string, create bool) (Maintenance, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return Maintenance{}, errors.New("actor is required")
	}
	now := c.now().UTC()
	m.Name = strings.TrimSpace(m.Name)
	m.StartsAt, m.EndsAt = m.StartsAt.UTC(), m.EndsAt.UTC()
	if m.StartsAt.IsZero() && create {
		m.StartsAt = now
	}
	m.Source, m.UpdatedAt, m.UpdatedBy = maintenanceFromAPI, now, actor
	if err := m.Validate(); err != nil {
		return Maintenance{}, err
	}
	if err := c.validateScope(m.Checks, m.Components, m.Probers); err != nil {
		return Maintenance{}, err
	}
	c.mu.Lock()
	for _, configured := range c.cfg.Maintenance {
		if configured.Name == m.Name {
			c.mu.Unlock()
			return Maintenance{}, errMaintenanceConfigured
		}
	}
	index := -1
	for i, existing := range c.maintenance {
		if existing.Name == m.Name {
			index = i
		}
	}
	switch {
	case create && index >= 0:
		c.mu.Unlock()
		return Maintenance{}, errMaintenanceExists
	case !create && index < 0:
		c.mu.Unlock()
		return Maintenance{}, errMaintenanceNotFound
	case create:
		m.CreatedAt, m.CreatedBy = now, actor
		c.maintenance = append(c.maintenance, m)
	default:
		m.CreatedAt, m.CreatedBy = c.maintenance[index].CreatedAt, c.maintenance[index].CreatedBy
		c.maintenance[index] = m
	}
	c.mu.Unlock()
	c.persist()
	c.log.Info("maintenance window saved", "name", m.Name, "actor", actor, "created", create)
	return m, nil
}

// DeleteMaintenance removes a managed maintenance window.
func (c *Coordinator) DeleteMaintenance(name, actor, note string) error {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return errors.New("actor is required")
	}
	c.mu.Lock()
	for _, configured := range c.cfg.Maintenance {
		if configured.Name == name {
			c.mu.Unlock()
			return errMaintenanceConfigured
		}
	}
	for i, existing := range c.maintenance {
		if existing.Name == name {
			c.maintenance = append(c.maintenance[:i:i], c.maintenance[i+1:]...)
			c.mu.Unlock()
			c.persist()
			c.log.Info("maintenance window deleted", "name", name, "actor", actor, "note", strings.TrimSpace(note))
			return nil
		}
	}
	c.mu.Unlock()
	return errMaintenanceNotFound
}

func (c *Coordinator) recordIncident(a Alert, maintenance string, silenceID uint64, silence string) {
	c.deliveryMu.Lock()
	defer c.deliveryMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	subject := a.Subject()
	switch a.Kind {
	case KindRecovered, KindWarningCleared, KindReporting, KindRejoined, KindWatched, KindWatchRecovered:
		for i := len(c.incidents) - 1; i >= 0; i-- {
			if c.incidents[i].Subject == subject && c.incidents[i].Active {
				c.incidents[i].Active = false
				c.incidents[i].ResolvedAt = a.At
				c.cancelEscalationsLocked(c.incidents[i].ID)
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
	writeJSON(w, c.MaintenanceWindows())
}

type maintenanceRequest struct {
	Name       string    `json:"name,omitempty"`
	StartsAt   time.Time `json:"starts_at,omitzero"`
	EndsAt     time.Time `json:"ends_at"`
	Every      string    `json:"every,omitempty"`
	Checks     []string  `json:"checks,omitempty"`
	Components []string  `json:"components,omitempty"`
	Probers    []string  `json:"probers,omitempty"`
	Comment    string    `json:"comment,omitempty"`
	Actor      string    `json:"actor,omitempty"`
}

func (c *Coordinator) handlePutMaintenance(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionOperate)
	if !ok {
		return
	}
	var body maintenanceRequest
	if err := decodeOperatorJSON(w, r, &body); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	create := r.Method == http.MethodPost
	if !create {
		if body.Name != "" && body.Name != r.PathValue("name") {
			http.Error(w, "name in the body must match the path", http.StatusBadRequest)
			return
		}
		body.Name = r.PathValue("name")
	}
	m, err := c.PutMaintenance(Maintenance{
		Name: body.Name, StartsAt: body.StartsAt, EndsAt: body.EndsAt, Every: body.Every,
		Checks: body.Checks, Components: body.Components, Probers: body.Probers, Comment: body.Comment,
	}, mutationActor(principal, body.Actor), create)
	if err != nil {
		writeMutationError(w, err)
		return
	}
	// A shortened or narrowed window may end suppression of an active incident.
	c.releaseSuppressions(r.Context())
	w.Header().Set("Content-Type", "application/json")
	if create {
		w.WriteHeader(http.StatusCreated)
	}
	writeJSON(w, m)
}

func (c *Coordinator) handleDeleteMaintenance(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionOperate)
	if !ok {
		return
	}
	var body incidentMutation
	if err := decodeOperatorJSON(w, r, &body); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	if err := c.DeleteMaintenance(r.PathValue("name"), mutationActor(principal, body.Actor), body.Note); err != nil {
		writeMutationError(w, err)
		return
	}
	c.releaseSuppressions(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (m Maintenance) Validate() error {
	if m.Name == "" {
		return fmt.Errorf("maintenance name is required")
	}
	if m.StartsAt.IsZero() || !m.EndsAt.After(m.StartsAt) {
		return fmt.Errorf("maintenance %q has an invalid interval", m.Name)
	}
	if m.Every != "" {
		every, err := time.ParseDuration(m.Every)
		if err != nil || every <= 0 {
			return fmt.Errorf("maintenance %q has an invalid every %q", m.Name, m.Every)
		}
		if m.EndsAt.Sub(m.StartsAt) >= every {
			return fmt.Errorf("maintenance %q lasts at least as long as its repeat period", m.Name)
		}
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
