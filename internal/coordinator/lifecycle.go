package coordinator

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	errIncidentNotFound = errors.New("incident not found")
	errIncidentInactive = errors.New("incident is not active")
	errSilenceNotFound  = errors.New("silence not found")
)

// Silence is an operator-created, durable notification suppression. Unlike a
// configured maintenance window it records who created or cancelled it.
type Silence struct {
	ID           uint64     `json:"id"`
	Name         string     `json:"name"`
	StartsAt     time.Time  `json:"starts_at"`
	EndsAt       time.Time  `json:"ends_at"`
	Checks       []string   `json:"checks,omitempty"`
	Components   []string   `json:"components,omitempty"`
	Probers      []string   `json:"probers,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	CreatedBy    string     `json:"created_by"`
	Comment      string     `json:"comment,omitempty"`
	CancelledAt  *time.Time `json:"cancelled_at,omitempty"`
	CancelledBy  string     `json:"cancelled_by,omitempty"`
	Cancellation string     `json:"cancellation,omitempty"`
}

func (s Silence) active(now time.Time) bool {
	return s.CancelledAt == nil && !now.Before(s.StartsAt) && now.Before(s.EndsAt)
}

func (c *Coordinator) validateSilence(s Silence) error {
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("silence name is required")
	}
	if s.StartsAt.IsZero() || !s.EndsAt.After(s.StartsAt) {
		return errors.New("silence has an invalid interval")
	}
	for _, name := range s.Checks {
		if _, ok := c.checkByName(name); !ok {
			return fmt.Errorf("unknown check %q", name)
		}
	}
	knownComponents := make(map[string]bool, len(c.cfg.Components))
	for _, component := range c.cfg.Components {
		knownComponents[component.Name] = true
	}
	for _, name := range s.Components {
		if !knownComponents[name] {
			return fmt.Errorf("unknown component %q", name)
		}
	}
	for _, name := range s.Probers {
		if _, ok := c.byName[name]; !ok {
			return fmt.Errorf("unknown prober %q", name)
		}
	}
	return nil
}

func alertMatches(a Alert, checks, components, probers []string) bool {
	if len(checks) == 0 && len(components) == 0 && len(probers) == 0 {
		return true
	}
	for _, name := range checks {
		if name == a.Check {
			return true
		}
		for _, member := range a.Members {
			if name == member.Check {
				return true
			}
		}
	}
	for _, name := range components {
		if name == a.Component {
			return true
		}
	}
	for _, name := range probers {
		if name == a.Prober {
			return true
		}
	}
	return false
}

func (c *Coordinator) activeSilence(a Alert, now time.Time) (uint64, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, silence := range c.silences {
		if silence.active(now) && alertMatches(a, silence.Checks, silence.Components, silence.Probers) {
			return silence.ID, silence.Name
		}
	}
	return 0, ""
}

// suppressionActiveLocked is called while c.mu is held.
func (c *Coordinator) suppressionActiveLocked(incident Incident, now time.Time) bool {
	if incident.Maintenance != "" {
		for _, maintenance := range c.cfg.Maintenance {
			if maintenance.Name == incident.Maintenance &&
				!now.Before(maintenance.StartsAt) && now.Before(maintenance.EndsAt) {
				return true
			}
		}
	}
	if incident.SilenceID != 0 {
		for _, silence := range c.silences {
			if silence.ID == incident.SilenceID && silence.active(now) {
				return true
			}
		}
	}
	return false
}

func (c *Coordinator) AcknowledgeIncident(id uint64, actor, note string) error {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return errors.New("actor is required")
	}
	now := c.now().UTC()
	c.deliveryMu.Lock()
	defer c.deliveryMu.Unlock()
	c.mu.Lock()
	for i := range c.incidents {
		incident := &c.incidents[i]
		if incident.ID != id {
			continue
		}
		if !incident.Active {
			c.mu.Unlock()
			return errIncidentInactive
		}
		incident.AcknowledgedAt = &now
		incident.AcknowledgedBy = actor
		incident.Acknowledgement = strings.TrimSpace(note)
		c.cancelEscalationsLocked(incident.ID)
		c.mu.Unlock()
		c.persist()
		return nil
	}
	c.mu.Unlock()
	return errIncidentNotFound
}

func (c *Coordinator) ResolveIncident(id uint64, actor, note string) error {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return errors.New("actor is required")
	}
	now := c.now().UTC()
	c.deliveryMu.Lock()
	defer c.deliveryMu.Unlock()
	c.mu.Lock()
	for i := range c.incidents {
		incident := &c.incidents[i]
		if incident.ID != id {
			continue
		}
		if !incident.Active {
			c.mu.Unlock()
			return errIncidentInactive
		}
		incident.Active = false
		incident.ResolvedAt = now
		incident.ResolvedBy = actor
		incident.Resolution = strings.TrimSpace(note)
		incident.ManualResolution = true
		c.cancelEscalationsLocked(incident.ID)
		c.mu.Unlock()
		c.persist()
		return nil
	}
	c.mu.Unlock()
	return errIncidentNotFound
}

func (c *Coordinator) Silences() []Silence {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Collection endpoints consistently encode an empty result as [] rather
	// than null so clients can iterate without special cases.
	out := append([]Silence{}, c.silences...)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (c *Coordinator) CreateSilence(s Silence) (Silence, error) {
	now := c.now().UTC()
	if s.StartsAt.IsZero() {
		s.StartsAt = now
	}
	s.StartsAt = s.StartsAt.UTC()
	s.EndsAt = s.EndsAt.UTC()
	s.CreatedAt = now
	s.CreatedBy = strings.TrimSpace(s.CreatedBy)
	if s.CreatedBy == "" {
		return Silence{}, errors.New("actor is required")
	}
	if err := c.validateSilence(s); err != nil {
		return Silence{}, err
	}
	c.mu.Lock()
	c.nextSilenceID++
	s.ID = c.nextSilenceID
	c.silences = append(c.silences, s)
	c.mu.Unlock()
	c.persist()
	return s, nil
}

func (c *Coordinator) CancelSilence(id uint64, actor, note string) error {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return errors.New("actor is required")
	}
	now := c.now().UTC()
	c.mu.Lock()
	for i := range c.silences {
		silence := &c.silences[i]
		if silence.ID != id {
			continue
		}
		if silence.CancelledAt != nil {
			c.mu.Unlock()
			return nil
		}
		silence.CancelledAt = &now
		silence.CancelledBy = actor
		silence.Cancellation = strings.TrimSpace(note)
		c.mu.Unlock()
		c.persist()
		return nil
	}
	c.mu.Unlock()
	return errSilenceNotFound
}

func decodeOperatorJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request must contain one JSON object")
		}
		return err
	}
	return nil
}

type incidentMutation struct {
	Actor string `json:"actor"`
	Note  string `json:"note,omitempty"`
}

func incidentID(r *http.Request) (uint64, error) {
	return strconv.ParseUint(r.PathValue("id"), 10, 64)
}

func writeMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errIncidentNotFound), errors.Is(err, errSilenceNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, errIncidentInactive):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (c *Coordinator) handleAcknowledgeIncident(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionOperate)
	if !ok {
		return
	}
	id, err := incidentID(r)
	if err != nil {
		http.Error(w, "invalid incident id", http.StatusBadRequest)
		return
	}
	var body incidentMutation
	if err := decodeOperatorJSON(w, r, &body); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	if err := c.AcknowledgeIncident(id, mutationActor(principal, body.Actor), body.Note); err != nil {
		writeMutationError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) handleResolveIncident(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionOperate)
	if !ok {
		return
	}
	id, err := incidentID(r)
	if err != nil {
		http.Error(w, "invalid incident id", http.StatusBadRequest)
		return
	}
	var body incidentMutation
	if err := decodeOperatorJSON(w, r, &body); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	if err := c.ResolveIncident(id, mutationActor(principal, body.Actor), body.Note); err != nil {
		writeMutationError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *Coordinator) handleSilences(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, c.Silences())
}

type createSilenceRequest struct {
	Name       string    `json:"name"`
	StartsAt   time.Time `json:"starts_at,omitempty"`
	EndsAt     time.Time `json:"ends_at"`
	Checks     []string  `json:"checks,omitempty"`
	Components []string  `json:"components,omitempty"`
	Probers    []string  `json:"probers,omitempty"`
	Actor      string    `json:"actor"`
	Comment    string    `json:"comment,omitempty"`
}

func (c *Coordinator) handleCreateSilence(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionOperate)
	if !ok {
		return
	}
	var body createSilenceRequest
	if err := decodeOperatorJSON(w, r, &body); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	silence, err := c.CreateSilence(Silence{Name: body.Name, StartsAt: body.StartsAt, EndsAt: body.EndsAt, Checks: body.Checks, Components: body.Components, Probers: body.Probers, CreatedBy: mutationActor(principal, body.Actor), Comment: body.Comment})
	if err != nil {
		writeMutationError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, silence)
}

func (c *Coordinator) handleDeleteSilence(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionOperate)
	if !ok {
		return
	}
	id, err := incidentID(r)
	if err != nil {
		http.Error(w, "invalid silence id", http.StatusBadRequest)
		return
	}
	var body incidentMutation
	if err := decodeOperatorJSON(w, r, &body); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	if err := c.CancelSilence(id, mutationActor(principal, body.Actor), body.Note); err != nil {
		writeMutationError(w, err)
		return
	}
	c.releaseSuppressions(r.Context())
	w.WriteHeader(http.StatusNoContent)
}
