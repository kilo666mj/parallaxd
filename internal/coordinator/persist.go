package coordinator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

type persistedState struct {
	Version             int                        `json:"version"`
	Checks              map[string]persistedEntity `json:"checks"`
	Components          map[string]persistedEntity `json:"components"`
	LastScheduled       map[string]time.Time       `json:"last_scheduled"`
	Silent              map[string]bool            `json:"silent"`
	Incidents           []Incident                 `json:"incidents"`
	NextIncidentID      uint64                     `json:"next_incident_id"`
	Silences            []Silence                  `json:"silences,omitempty"`
	NextSilenceID       uint64                     `json:"next_silence_id,omitempty"`
	Outbox              []Delivery                 `json:"outbox,omitempty"`
	NextDeliveryID      uint64                     `json:"next_delivery_id,omitempty"`
	Escalated           map[string]time.Time       `json:"escalated,omitempty"`
	Promoted            bool                       `json:"promoted,omitempty"`
	PromotedAt          time.Time                  `json:"promoted_at,omitempty"`
	PromotedBy          string                     `json:"promoted_by,omitempty"`
	Monitors            []MonitorSpec              `json:"monitors,omitempty"`
	MonitorRevisions    []MonitorRevision          `json:"monitor_revisions,omitempty"`
	NextMonitorRevision uint64                     `json:"next_monitor_revision,omitempty"`
}
type persistedEntity struct {
	Status               check.Status           `json:"status"`
	Stale                bool                   `json:"stale"`
	Since                time.Time              `json:"since"`
	LastVerdict          time.Time              `json:"last_verdict"`
	SuspectedSince       time.Time              `json:"suspected_since,omitempty"`
	LastAttempt          time.Time              `json:"last_attempt,omitempty"`
	LastCorroboration    time.Duration          `json:"last_corroboration,omitempty"`
	InconclusiveAttempts uint64                 `json:"inconclusive_attempts,omitempty"`
	LastInconclusive     string                 `json:"last_inconclusive_reason,omitempty"`
	InconclusiveHistory  []CorroborationAttempt `json:"inconclusive_history,omitempty"`
}

func (c *Coordinator) persist() {
	if err := c.persistState(); err != nil {
		c.log.Error("persisting state", "err", err)
	}
}

func (c *Coordinator) persistState() error {
	if c.cfg.StateFile == "" {
		return nil
	}
	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	s := c.snapshot()
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	dir := filepath.Dir(c.cfg.StateFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".parallaxd-state-*")
	if err != nil {
		return fmt.Errorf("create state file: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(raw)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, c.cfg.StateFile)
	}
	if err == nil {
		err = syncDirectory(dir)
	}
	return err
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	err = dir.Sync()
	if closeErr := dir.Close(); err == nil {
		err = closeErr
	}
	return err
}

func (c *Coordinator) snapshot() persistedState {
	c.mu.Lock()
	checks := make(map[string]*entityState, len(c.states))
	for k, v := range c.states {
		checks[k] = v
	}
	components := make(map[string]*entityState, len(c.componentStates))
	for k, v := range c.componentStates {
		components[k] = v
	}
	s := persistedState{Version: 5, Checks: map[string]persistedEntity{}, Components: map[string]persistedEntity{}, LastScheduled: map[string]time.Time{}, Silent: map[string]bool{}, Incidents: append([]Incident(nil), c.incidents...), NextIncidentID: c.nextIncidentID, Silences: append([]Silence(nil), c.silences...), NextSilenceID: c.nextSilenceID, Outbox: append([]Delivery(nil), c.outbox...), NextDeliveryID: c.nextDeliveryID, Escalated: map[string]time.Time{}, Promoted: c.promoted.Load(), PromotedAt: c.promotedAt, PromotedBy: c.promotedBy, Monitors: c.monitorList(), MonitorRevisions: append([]MonitorRevision(nil), c.monitorRevisions...), NextMonitorRevision: c.nextMonitorRevision}
	for k, v := range c.lastScheduled {
		s.LastScheduled[k] = v
	}
	for k, v := range c.silent {
		s.Silent[k] = v
	}
	for k, v := range c.escalated {
		s.Escalated[k] = v
	}
	c.mu.Unlock()
	copyEntity := func(dst map[string]persistedEntity, src map[string]*entityState) {
		for k, v := range src {
			v.mu.Lock()
			dst[k] = persistedEntity{
				Status: v.status, Stale: v.stale, Since: v.since, LastVerdict: v.lastVerdict,
				SuspectedSince: v.suspectedSince, LastAttempt: v.lastAttempt,
				LastCorroboration: v.lastCorroboration, InconclusiveAttempts: v.inconclusiveAttempts,
				LastInconclusive:    v.lastInconclusive,
				InconclusiveHistory: append([]CorroborationAttempt(nil), v.inconclusiveHistory...),
			}
			v.mu.Unlock()
		}
	}
	copyEntity(s.Checks, checks)
	copyEntity(s.Components, components)
	return s
}

func (c *Coordinator) restore() error {
	if c.cfg.StateFile == "" {
		return nil
	}
	raw, err := os.ReadFile(c.cfg.StateFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read state file: %w", err)
	}
	var s persistedState
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("parse state file: %w", err)
	}
	if s.Version < 1 || s.Version > 5 {
		return fmt.Errorf("unsupported state version %d", s.Version)
	}
	return c.applyPersistedState(s, false)
}

func (c *Coordinator) applyPersistedState(s persistedState, replicated bool) error {
	if s.Version >= 5 {
		if err := c.replaceMonitorCatalog(s.Monitors); err != nil {
			return fmt.Errorf("restore monitor catalogue: %w", err)
		}
	}
	states := map[string]*entityState{}
	for k, v := range s.Checks {
		if _, ok := c.checkByName(k); ok {
			states[k] = &entityState{status: v.Status, stale: v.Stale, since: v.Since, lastVerdict: v.LastVerdict,
				suspectedSince: v.SuspectedSince, lastAttempt: v.LastAttempt, lastCorroboration: v.LastCorroboration,
				inconclusiveAttempts: v.InconclusiveAttempts, lastInconclusive: v.LastInconclusive}
			states[k].inconclusiveHistory = append([]CorroborationAttempt(nil), v.InconclusiveHistory...)
		}
	}
	componentStates := map[string]*entityState{}
	for k, v := range s.Components {
		componentStates[k] = &entityState{status: v.Status, stale: v.Stale, since: v.Since, lastVerdict: v.LastVerdict}
	}
	lastScheduled := map[string]time.Time{}
	for k, v := range s.LastScheduled {
		lastScheduled[k] = v
	}
	silent := map[string]bool{}
	for k, v := range s.Silent {
		silent[k] = v
	}
	outbox := append([]Delivery(nil), s.Outbox...)
	for _, delivery := range outbox {
		if c.destinations[delivery.Destination] == nil {
			return fmt.Errorf("pending delivery %d names unavailable notification destination %q", delivery.ID, delivery.Destination)
		}
	}
	escalated := map[string]time.Time{}
	for k, v := range s.Escalated {
		escalated[k] = v
	}
	c.mu.Lock()
	c.states, c.componentStates = states, componentStates
	c.lastScheduled, c.silent = lastScheduled, silent
	c.incidents, c.nextIncidentID = append([]Incident(nil), s.Incidents...), s.NextIncidentID
	c.silences, c.nextSilenceID = append([]Silence(nil), s.Silences...), s.NextSilenceID
	c.outbox, c.nextDeliveryID, c.escalated = outbox, s.NextDeliveryID, escalated
	if s.Version >= 5 {
		c.monitorRevisions = append([]MonitorRevision(nil), s.MonitorRevisions...)
		c.nextMonitorRevision = s.NextMonitorRevision
	}
	c.mu.Unlock()
	if !replicated && s.Promoted {
		c.promoted.Store(true)
		c.mu.Lock()
		c.promotedAt, c.promotedBy = s.PromotedAt, s.PromotedBy
		c.mu.Unlock()
	}
	return nil
}
