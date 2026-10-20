package coordinator

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Notices are operator-written status page posts: an incident with a timeline
// of human updates, or announced maintenance. They are presentation only. They
// never change a corroborated status or suppress an alert; maintenance windows
// and silences do that. Keeping the two apart means a forgotten notice cannot
// hide an outage, and an announcement does not need a matching window.

var (
	errNoticeNotFound = errors.New("notice not found")
	errNoticeFull     = errors.New("too many notices; delete or resolve old ones first")
)

const (
	NoticeIncident    = "incident"
	NoticeMaintenance = "maintenance"

	maxNoticeTitle   = 200
	maxNoticeMessage = 2000
	maxNoticeUpdates = 100
	maxNotices       = 500
	// Resolved notices are kept this long, then dropped when a new one is
	// created, so state does not grow without bound.
	noticeRetention = 90 * 24 * time.Hour
)

// noticeStates lists the valid states per kind; the last one closes the notice.
var noticeStates = map[string][]string{
	NoticeIncident:    {"investigating", "identified", "monitoring", "resolved"},
	NoticeMaintenance: {"scheduled", "in_progress", "completed"},
}

type NoticeUpdate struct {
	At      time.Time `json:"at"`
	State   string    `json:"state"`
	Message string    `json:"message"`
	By      string    `json:"by,omitempty"`
}

type Notice struct {
	ID    uint64 `json:"id"`
	Kind  string `json:"kind"`
	Title string `json:"title"`
	State string `json:"state"`
	// Public notices appear in the export and so on status pages.
	Public     bool     `json:"public"`
	Checks     []string `json:"checks,omitempty"`
	Components []string `json:"components,omitempty"`
	// StartsAt and EndsAt are the announced schedule of maintenance.
	StartsAt   time.Time      `json:"starts_at,omitzero"`
	EndsAt     time.Time      `json:"ends_at,omitzero"`
	Updates    []NoticeUpdate `json:"updates"`
	CreatedAt  time.Time      `json:"created_at"`
	CreatedBy  string         `json:"created_by"`
	UpdatedAt  time.Time      `json:"updated_at"`
	UpdatedBy  string         `json:"updated_by"`
	ResolvedAt time.Time      `json:"resolved_at,omitzero"`
}

// Open reports whether the notice has not reached its closing state.
func (n Notice) Open() bool { return n.ResolvedAt.IsZero() }

func validNoticeState(kind, state string) bool {
	return slices.Contains(noticeStates[kind], state)
}

func closingState(kind, state string) bool {
	states := noticeStates[kind]
	return len(states) > 0 && states[len(states)-1] == state
}

func validateNoticeText(title, message string) error {
	if title != "" && utf8.RuneCountInString(title) > maxNoticeTitle {
		return fmt.Errorf("title is longer than %d characters", maxNoticeTitle)
	}
	if utf8.RuneCountInString(message) > maxNoticeMessage {
		return fmt.Errorf("message is longer than %d characters", maxNoticeMessage)
	}
	return nil
}

// validateNotice checks the fields an operator can edit.
func (c *Coordinator) validateNotice(n Notice) error {
	if n.Title == "" {
		return errors.New("title is required")
	}
	if err := validateNoticeText(n.Title, ""); err != nil {
		return err
	}
	if _, ok := noticeStates[n.Kind]; !ok {
		return fmt.Errorf("kind must be %q or %q", NoticeIncident, NoticeMaintenance)
	}
	if n.Kind == NoticeMaintenance && (n.StartsAt.IsZero() || !n.EndsAt.After(n.StartsAt)) {
		return errors.New("maintenance needs starts_at before ends_at")
	}
	if n.Kind == NoticeIncident && (!n.StartsAt.IsZero() || !n.EndsAt.IsZero()) {
		return errors.New("only maintenance has starts_at and ends_at")
	}
	return c.validateScope(n.Checks, n.Components, nil)
}

// Notices returns every stored notice, newest first.
func (c *Coordinator) Notices() []Notice {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Notice, 0, len(c.notices))
	for i := len(c.notices) - 1; i >= 0; i-- {
		out = append(out, cloneNotice(c.notices[i]))
	}
	return out
}

// noticesCopyLocked deep-copies notices for persistence; updates append to
// the stored slices in place. It is called while c.mu is held.
func (c *Coordinator) noticesCopyLocked() []Notice {
	if len(c.notices) == 0 {
		return nil
	}
	out := make([]Notice, len(c.notices))
	for i, n := range c.notices {
		out[i] = cloneNotice(n)
	}
	return out
}

func cloneNotice(n Notice) Notice {
	n.Checks = slices.Clone(n.Checks)
	n.Components = slices.Clone(n.Components)
	n.Updates = slices.Clone(n.Updates)
	return n
}

// CreateNotice stores a notice with its first update.
func (c *Coordinator) CreateNotice(n Notice, message, actor string) (Notice, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return Notice{}, errors.New("actor is required")
	}
	n.Title, message = strings.TrimSpace(n.Title), strings.TrimSpace(message)
	n.StartsAt, n.EndsAt = n.StartsAt.UTC(), n.EndsAt.UTC()
	if states := noticeStates[n.Kind]; n.State == "" && len(states) > 0 {
		n.State = states[0]
	}
	if err := c.validateNotice(n); err != nil {
		return Notice{}, err
	}
	if !validNoticeState(n.Kind, n.State) {
		return Notice{}, fmt.Errorf("state for %s must be one of %s", n.Kind, strings.Join(noticeStates[n.Kind], ", "))
	}
	if message == "" {
		return Notice{}, errors.New("message is required")
	}
	if err := validateNoticeText("", message); err != nil {
		return Notice{}, err
	}
	now := c.now().UTC()
	n.Updates = []NoticeUpdate{{At: now, State: n.State, Message: message, By: actor}}
	n.CreatedAt, n.CreatedBy, n.UpdatedAt, n.UpdatedBy, n.ResolvedAt = now, actor, now, actor, time.Time{}
	if closingState(n.Kind, n.State) {
		n.ResolvedAt = now
	}
	c.mu.Lock()
	c.notices = slices.DeleteFunc(c.notices, func(old Notice) bool {
		return !old.Open() && now.Sub(old.ResolvedAt) > noticeRetention
	})
	if len(c.notices) >= maxNotices {
		c.mu.Unlock()
		return Notice{}, errNoticeFull
	}
	c.nextNoticeID++
	n.ID = c.nextNoticeID
	c.notices = append(c.notices, n)
	c.mu.Unlock()
	c.persist()
	c.log.Info("notice created", "id", n.ID, "kind", n.Kind, "state", n.State, "public", n.Public, "actor", actor)
	return cloneNotice(n), nil
}

// PostNoticeUpdate appends a timeline entry and moves the notice to its state.
// Reaching the closing state resolves it; any other state reopens it.
func (c *Coordinator) PostNoticeUpdate(id uint64, state, message, actor string) (Notice, error) {
	actor, message = strings.TrimSpace(actor), strings.TrimSpace(message)
	if actor == "" {
		return Notice{}, errors.New("actor is required")
	}
	if message == "" {
		return Notice{}, errors.New("message is required")
	}
	if err := validateNoticeText("", message); err != nil {
		return Notice{}, err
	}
	now := c.now().UTC()
	c.mu.Lock()
	i := c.noticeIndexLocked(id)
	if i < 0 {
		c.mu.Unlock()
		return Notice{}, errNoticeNotFound
	}
	n := &c.notices[i]
	if state == "" {
		state = n.State
	}
	if !validNoticeState(n.Kind, state) {
		c.mu.Unlock()
		return Notice{}, fmt.Errorf("state for %s must be one of %s", n.Kind, strings.Join(noticeStates[n.Kind], ", "))
	}
	if len(n.Updates) >= maxNoticeUpdates {
		c.mu.Unlock()
		return Notice{}, fmt.Errorf("notice already has %d updates", maxNoticeUpdates)
	}
	n.Updates = append(n.Updates, NoticeUpdate{At: now, State: state, Message: message, By: actor})
	n.State, n.UpdatedAt, n.UpdatedBy = state, now, actor
	switch {
	case !closingState(n.Kind, state):
		n.ResolvedAt = time.Time{}
	case n.ResolvedAt.IsZero():
		n.ResolvedAt = now
	}
	out := cloneNotice(*n)
	c.mu.Unlock()
	c.persist()
	c.log.Info("notice updated", "id", id, "state", state, "actor", actor)
	return out, nil
}

// EditNotice replaces a notice's title, visibility, affected items and
// schedule. Its kind, state and timeline are left alone.
func (c *Coordinator) EditNotice(id uint64, edit Notice, actor string) (Notice, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return Notice{}, errors.New("actor is required")
	}
	c.mu.Lock()
	i := c.noticeIndexLocked(id)
	if i < 0 {
		c.mu.Unlock()
		return Notice{}, errNoticeNotFound
	}
	n := cloneNotice(c.notices[i])
	c.mu.Unlock()
	n.Title, n.Public = strings.TrimSpace(edit.Title), edit.Public
	n.Checks, n.Components = edit.Checks, edit.Components
	n.StartsAt, n.EndsAt = edit.StartsAt.UTC(), edit.EndsAt.UTC()
	if err := c.validateNotice(n); err != nil {
		return Notice{}, err
	}
	n.UpdatedAt, n.UpdatedBy = c.now().UTC(), actor
	c.mu.Lock()
	if i = c.noticeIndexLocked(id); i < 0 {
		c.mu.Unlock()
		return Notice{}, errNoticeNotFound
	}
	// Keep updates posted while this edit was being validated.
	n.Updates, n.State, n.ResolvedAt = c.notices[i].Updates, c.notices[i].State, c.notices[i].ResolvedAt
	c.notices[i] = n
	c.mu.Unlock()
	c.persist()
	c.log.Info("notice edited", "id", id, "public", n.Public, "actor", actor)
	return cloneNotice(n), nil
}

// DeleteNotice removes a notice, for example one posted by mistake.
func (c *Coordinator) DeleteNotice(id uint64, actor, note string) error {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return errors.New("actor is required")
	}
	c.mu.Lock()
	i := c.noticeIndexLocked(id)
	if i < 0 {
		c.mu.Unlock()
		return errNoticeNotFound
	}
	c.notices = slices.Delete(c.notices, i, i+1)
	c.mu.Unlock()
	c.persist()
	c.log.Info("notice deleted", "id", id, "actor", actor, "note", strings.TrimSpace(note))
	return nil
}

// noticeIndexLocked is called while c.mu is held.
func (c *Coordinator) noticeIndexLocked(id uint64) int {
	return slices.IndexFunc(c.notices, func(n Notice) bool { return n.ID == id })
}

type noticeRequest struct {
	Kind       string    `json:"kind,omitempty"`
	Title      string    `json:"title,omitempty"`
	State      string    `json:"state,omitempty"`
	Message    string    `json:"message,omitempty"`
	Public     bool      `json:"public,omitempty"`
	Checks     []string  `json:"checks,omitempty"`
	Components []string  `json:"components,omitempty"`
	StartsAt   time.Time `json:"starts_at,omitzero"`
	EndsAt     time.Time `json:"ends_at,omitzero"`
	Actor      string    `json:"actor,omitempty"`
}

func (c *Coordinator) handleNotices(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, c.Notices())
}

func (c *Coordinator) handleCreateNotice(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionOperate)
	if !ok {
		return
	}
	var body noticeRequest
	if err := decodeOperatorJSON(w, r, &body); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	n, err := c.CreateNotice(Notice{
		Kind: body.Kind, Title: body.Title, State: body.State, Public: body.Public,
		Checks: body.Checks, Components: body.Components, StartsAt: body.StartsAt, EndsAt: body.EndsAt,
	}, body.Message, mutationActor(principal, body.Actor))
	if err != nil {
		writeMutationError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, n)
}

func (c *Coordinator) handlePostNoticeUpdate(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionOperate)
	if !ok {
		return
	}
	id, err := incidentID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var body struct {
		State   string `json:"state,omitempty"`
		Message string `json:"message"`
		Actor   string `json:"actor,omitempty"`
	}
	if err := decodeOperatorJSON(w, r, &body); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	n, err := c.PostNoticeUpdate(id, body.State, body.Message, mutationActor(principal, body.Actor))
	if err != nil {
		writeMutationError(w, err)
		return
	}
	writeJSON(w, n)
}

func (c *Coordinator) handleEditNotice(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionOperate)
	if !ok {
		return
	}
	id, err := incidentID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var body noticeRequest
	if err := decodeOperatorJSON(w, r, &body); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	if body.Kind != "" || body.State != "" || body.Message != "" {
		http.Error(w, "kind, state and message cannot be edited; post an update instead", http.StatusBadRequest)
		return
	}
	n, err := c.EditNotice(id, Notice{
		Title: body.Title, Public: body.Public, Checks: body.Checks, Components: body.Components,
		StartsAt: body.StartsAt, EndsAt: body.EndsAt,
	}, mutationActor(principal, body.Actor))
	if err != nil {
		writeMutationError(w, err)
		return
	}
	writeJSON(w, n)
}

func (c *Coordinator) handleDeleteNotice(w http.ResponseWriter, r *http.Request) {
	principal, ok := c.requirePermission(w, r, PermissionOperate)
	if !ok {
		return
	}
	id, err := incidentID(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var body incidentMutation
	if err := decodeOperatorJSON(w, r, &body); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	if err := c.DeleteNotice(id, mutationActor(principal, body.Actor), body.Note); err != nil {
		writeMutationError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
