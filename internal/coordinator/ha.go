package coordinator

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	HARolePrimary          = "primary"
	HARoleStandby          = "standby"
	defaultReplicaInterval = 30 * time.Second
	defaultReplicaTimeout  = 2 * time.Minute
	maxReplicaDocument     = 256 << 20
)

type HAConfig struct {
	Role       string
	PrimaryURL string
	Token      string
	Interval   time.Duration
	Timeout    time.Duration
	Client     *http.Client
}

type HAStatus struct {
	Role                 string    `json:"role"`
	Active               bool      `json:"active"`
	Promoted             bool      `json:"promoted"`
	PromotedAt           time.Time `json:"promoted_at,omitzero"`
	PromotedBy           string    `json:"promoted_by,omitempty"`
	LastReplicaSync      time.Time `json:"last_replica_sync,omitzero"`
	PrimaryStateAt       time.Time `json:"primary_state_at,omitzero"`
	ReplicationLagMS     int64     `json:"replication_lag_ms,omitempty"`
	LastReplicationError string    `json:"last_replication_error,omitempty"`
}

type replicaDocument struct {
	Version     int            `json:"version"`
	GeneratedAt time.Time      `json:"generated_at"`
	State       persistedState `json:"state"`
	History     []Observation  `json:"history,omitempty"`
}

func validateHAConfig(cfg Config) error {
	role := cfg.HA.Role
	if role == "" {
		role = HARolePrimary
	}
	if role != HARolePrimary && role != HARoleStandby {
		return fmt.Errorf("ha role must be %q or %q", HARolePrimary, HARoleStandby)
	}
	if cfg.HA.Interval < 0 || cfg.HA.Timeout < 0 {
		return errors.New("ha interval and timeout cannot be negative")
	}
	if role == HARoleStandby {
		if cfg.StateFile == "" {
			return errors.New("standby coordinator requires a state_file")
		}
		if cfg.HistoryFile == "" {
			return errors.New("standby coordinator requires a history_file")
		}
		if strings.TrimSpace(cfg.HA.Token) == "" {
			return errors.New("standby coordinator requires a replication token")
		}
		u, err := url.ParseRequestURI(cfg.HA.PrimaryURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("standby primary_url must be an absolute http or https URL")
		}
	}
	return nil
}

func (c *Coordinator) isStandby() bool {
	return c.cfg.HA.Role == HARoleStandby && !c.promoted.Load()
}

func (c *Coordinator) HAStatus() HAStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	role := c.cfg.HA.Role
	if role == "" {
		role = HARolePrimary
	}
	status := HAStatus{Role: role, Active: !c.isStandby(), Promoted: c.promoted.Load(),
		PromotedAt: c.promotedAt, PromotedBy: c.promotedBy,
		LastReplicaSync: c.lastReplicaSync, PrimaryStateAt: c.primaryStateAt,
		LastReplicationError: c.lastReplicaErr}
	if !status.LastReplicaSync.IsZero() && !status.PrimaryStateAt.IsZero() {
		status.ReplicationLagMS = status.LastReplicaSync.Sub(status.PrimaryStateAt).Milliseconds()
		if status.ReplicationLagMS < 0 {
			status.ReplicationLagMS = 0
		}
	}
	return status
}

func (c *Coordinator) runStandby(ctx context.Context) bool {
	replicaCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-c.promoteCh:
			cancel()
		case <-replicaCtx.Done():
		}
	}()
	c.syncReplica(replicaCtx)
	if c.promoted.Load() {
		return true
	}
	interval := c.cfg.HA.Interval
	if interval <= 0 {
		interval = defaultReplicaInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-c.promoteCh:
			return true
		case <-ticker.C:
			c.syncReplica(replicaCtx)
		}
	}
}

func (c *Coordinator) syncReplica(ctx context.Context) {
	since := c.latestHistoryTime()
	endpoint := strings.TrimRight(c.cfg.HA.PrimaryURL, "/") + "/v1/replica"
	if !since.IsZero() {
		endpoint += "?history_since=" + url.QueryEscape(since.Format(time.RFC3339Nano))
	}
	timeout := c.cfg.HA.Timeout
	if timeout <= 0 {
		timeout = defaultReplicaTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err == nil {
		req.Header.Set("Authorization", "Bearer "+c.cfg.HA.Token)
	}
	var document replicaDocument
	if err == nil {
		var response *http.Response
		client := c.cfg.HA.Client
		if client == nil {
			client = &http.Client{}
		}
		response, err = client.Do(req)
		if err == nil {
			defer response.Body.Close()
			if response.StatusCode/100 != 2 {
				err = fmt.Errorf("primary returned %s", response.Status)
			} else {
				err = json.NewDecoder(io.LimitReader(response.Body, maxReplicaDocument)).Decode(&document)
			}
		}
	}
	if err == nil && document.Version != 1 {
		err = fmt.Errorf("unsupported replica document version %d", document.Version)
	}
	if err == nil {
		err = c.applyReplica(document)
	}
	if err != nil && c.promoted.Load() && errors.Is(err, context.Canceled) {
		return
	}
	c.mu.Lock()
	if err != nil {
		c.lastReplicaErr = err.Error()
		c.log.Error("standby replication failed", "err", err)
	} else {
		c.lastReplicaSync = c.now().UTC()
		c.primaryStateAt = document.GeneratedAt
		c.lastReplicaErr = ""
	}
	c.mu.Unlock()
}

func (c *Coordinator) applyReplica(document replicaDocument) error {
	c.haMu.Lock()
	defer c.haMu.Unlock()
	if document.State.Version < 1 || document.State.Version > 4 {
		return fmt.Errorf("unsupported replicated state version %d", document.State.Version)
	}
	if err := c.applyPersistedState(document.State, true); err != nil {
		return err
	}
	c.historyMu.Lock()
	seen := map[string]bool{}
	for _, items := range c.history {
		for _, observation := range items {
			seen[observation.ID] = true
		}
	}
	var fresh []Observation
	for _, observation := range document.History {
		observation.ensureID()
		if !seen[observation.ID] {
			seen[observation.ID] = true
			fresh = append(fresh, observation)
		}
	}
	if len(fresh) > 0 && c.cfg.HistoryFile != "" {
		if err := appendObservations(c.cfg.HistoryFile, fresh); err != nil {
			c.historyMu.Unlock()
			return fmt.Errorf("replicate history: %w", err)
		}
	}
	for _, observation := range fresh {
		c.appendHistoryLocked(observation)
	}
	c.historyMu.Unlock()
	if err := c.persistState(); err != nil {
		return fmt.Errorf("persist replicated state: %w", err)
	}
	return nil
}

func (c *Coordinator) latestHistoryTime() time.Time {
	c.historyMu.Lock()
	defer c.historyMu.Unlock()
	var latest time.Time
	for _, items := range c.history {
		if len(items) > 0 && items[len(items)-1].ReceivedAt.After(latest) {
			latest = items[len(items)-1].ReceivedAt
		}
	}
	return latest
}

func (c *Coordinator) promote(actor string, confirmed bool) error {
	c.haMu.Lock()
	defer c.haMu.Unlock()
	if !confirmed {
		return errors.New("confirm_primary_fenced must be true")
	}
	if c.cfg.HA.Role != HARoleStandby {
		return errors.New("only a configured standby can be promoted")
	}
	if c.promoted.Swap(true) {
		return nil
	}
	now := c.now().UTC()
	c.mu.Lock()
	c.promotedAt, c.promotedBy = now, strings.TrimSpace(actor)
	c.mu.Unlock()
	if err := c.persistState(); err != nil {
		c.promoted.Store(false)
		c.mu.Lock()
		c.promotedAt, c.promotedBy = time.Time{}, ""
		c.mu.Unlock()
		return fmt.Errorf("persist promotion: %w", err)
	}
	c.promoteOnce.Do(func() { close(c.promoteCh) })
	return nil
}

func (c *Coordinator) requireReplica(w http.ResponseWriter, r *http.Request) bool {
	if c.cfg.HA.Token == "" {
		http.Error(w, "replication API is disabled", http.StatusServiceUnavailable)
		return false
	}
	provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if len(provided) != len(c.cfg.HA.Token) || subtle.ConstantTimeCompare([]byte(provided), []byte(c.cfg.HA.Token)) != 1 {
		http.Error(w, "replication authorization required", http.StatusUnauthorized)
		return false
	}
	return true
}

func (c *Coordinator) handleReplica(w http.ResponseWriter, r *http.Request) {
	if !c.requireReplica(w, r) {
		return
	}
	var since time.Time
	if raw := r.URL.Query().Get("history_since"); raw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			http.Error(w, "history_since must be RFC3339", http.StatusBadRequest)
			return
		}
		since = parsed
	}
	writeJSON(w, replicaDocument{Version: 1, GeneratedAt: c.now().UTC(), State: c.snapshot(), History: c.History("", since, 0)})
}

func (c *Coordinator) handlePromote(w http.ResponseWriter, r *http.Request) {
	if !c.requireOperator(w, r) {
		return
	}
	var request struct {
		Actor   string `json:"actor"`
		Confirm bool   `json:"confirm_primary_fenced"`
	}
	if err := decodeOperatorJSON(w, r, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(request.Actor) == "" {
		http.Error(w, "actor is required", http.StatusBadRequest)
		return
	}
	if err := c.promote(request.Actor, request.Confirm); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, c.HAStatus())
}

func (c *Coordinator) handleHAStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, c.HAStatus())
}

func standbyBlocks(r *http.Request) bool {
	if r.Method == http.MethodPost || r.Method == http.MethodDelete {
		return r.URL.Path != "/v1/ha/promote"
	}
	return r.URL.Path == "/v1/assignments" || r.URL.Path == "/v1/checks"
}
