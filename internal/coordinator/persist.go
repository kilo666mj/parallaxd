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
	Version        int                        `json:"version"`
	Checks         map[string]persistedEntity `json:"checks"`
	Components     map[string]persistedEntity `json:"components"`
	LastScheduled  map[string]time.Time       `json:"last_scheduled"`
	Silent         map[string]bool            `json:"silent"`
	Incidents      []Incident                 `json:"incidents"`
	NextIncidentID uint64                     `json:"next_incident_id"`
	Silences       []Silence                  `json:"silences,omitempty"`
	NextSilenceID  uint64                     `json:"next_silence_id,omitempty"`
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
	if c.cfg.StateFile == "" {
		return
	}
	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	s := c.snapshot()
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		c.log.Error("encoding state", "err", err)
		return
	}
	dir := filepath.Dir(c.cfg.StateFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		c.log.Error("creating state directory", "err", err)
		return
	}
	tmp, err := os.CreateTemp(dir, ".parallaxd-state-*")
	if err != nil {
		c.log.Error("creating state file", "err", err)
		return
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err == nil {
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
	if err != nil {
		c.log.Error("persisting state", "err", err)
	}
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
	s := persistedState{Version: 2, Checks: map[string]persistedEntity{}, Components: map[string]persistedEntity{}, LastScheduled: map[string]time.Time{}, Silent: map[string]bool{}, Incidents: append([]Incident(nil), c.incidents...), NextIncidentID: c.nextIncidentID, Silences: append([]Silence(nil), c.silences...), NextSilenceID: c.nextSilenceID}
	for k, v := range c.lastScheduled {
		s.LastScheduled[k] = v
	}
	for k, v := range c.silent {
		s.Silent[k] = v
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
	if s.Version != 1 && s.Version != 2 {
		return fmt.Errorf("unsupported state version %d", s.Version)
	}
	for k, v := range s.Checks {
		if _, ok := c.checks[k]; ok {
			c.states[k] = &entityState{status: v.Status, stale: v.Stale, since: v.Since, lastVerdict: v.LastVerdict,
				suspectedSince: v.SuspectedSince, lastAttempt: v.LastAttempt, lastCorroboration: v.LastCorroboration,
				inconclusiveAttempts: v.InconclusiveAttempts, lastInconclusive: v.LastInconclusive}
			c.states[k].inconclusiveHistory = append([]CorroborationAttempt(nil), v.InconclusiveHistory...)
		}
	}
	for k, v := range s.Components {
		c.componentStates[k] = &entityState{status: v.Status, stale: v.Stale, since: v.Since, lastVerdict: v.LastVerdict}
	}
	for k, v := range s.LastScheduled {
		c.lastScheduled[k] = v
	}
	for k, v := range s.Silent {
		c.silent[k] = v
	}
	c.incidents = s.Incidents
	c.nextIncidentID = s.NextIncidentID
	c.silences = s.Silences
	c.nextSilenceID = s.NextSilenceID
	return nil
}
