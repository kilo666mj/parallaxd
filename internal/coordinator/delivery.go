package coordinator

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	defaultNotificationRetryInitial  = 15 * time.Second
	defaultNotificationRetryMax      = 15 * time.Minute
	defaultNotificationRetryInterval = 5 * time.Second
)

// NotificationDestination is an independently retried alert sink.
type NotificationDestination struct {
	Name     string
	Notifier Notifier
}

// NotificationRoute limits a named destination to matching alerts. A
// destination with no routes receives every alert.
type NotificationRoute struct {
	Name        string   `json:"name"`
	Destination string   `json:"destination"`
	Checks      []string `json:"checks,omitempty"`
	Components  []string `json:"components,omitempty"`
	Probers     []string `json:"probers,omitempty"`
	Kinds       []Kind   `json:"kinds,omitempty"`
}

// EscalationPolicy sends an active, unacknowledged incident to another
// destination after a delay. Each policy fires at most once per incident.
type EscalationPolicy struct {
	Name        string        `json:"name"`
	Destination string        `json:"destination"`
	After       time.Duration `json:"after"`
	Checks      []string      `json:"checks,omitempty"`
	Components  []string      `json:"components,omitempty"`
	Probers     []string      `json:"probers,omitempty"`
	Kinds       []Kind        `json:"kinds,omitempty"`
}

// Delivery is a durable failed or scheduled notification attempt.
type Delivery struct {
	ID          uint64    `json:"id"`
	Destination string    `json:"destination"`
	Alert       Alert     `json:"alert"`
	CreatedAt   time.Time `json:"created_at"`
	NextAttempt time.Time `json:"next_attempt"`
	Attempts    uint64    `json:"attempts"`
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	Escalation  string    `json:"escalation,omitempty"`
	IncidentID  uint64    `json:"incident_id,omitempty"`
}

func validateNotificationConfig(cfg Config) error {
	if cfg.NotificationRetryInitial < 0 || cfg.NotificationRetryMax < 0 || cfg.NotificationRetryInterval < 0 {
		return errors.New("notification retry durations cannot be negative")
	}
	initial, maximum := cfg.NotificationRetryInitial, cfg.NotificationRetryMax
	if initial == 0 {
		initial = defaultNotificationRetryInitial
	}
	if maximum == 0 {
		maximum = defaultNotificationRetryMax
	}
	if maximum < initial {
		return errors.New("notification_retry_max cannot be shorter than notification_retry_initial")
	}
	knownDestinations := map[string]bool{"default": true}
	for _, destination := range cfg.Destinations {
		name := strings.TrimSpace(destination.Name)
		if name == "" || name != destination.Name || destination.Notifier == nil {
			return errors.New("every notification destination needs a name and notifier")
		}
		if knownDestinations[name] {
			return fmt.Errorf("duplicate notification destination %q", name)
		}
		knownDestinations[name] = true
	}
	seenRoutes := map[string]bool{}
	for _, route := range cfg.Routes {
		if strings.TrimSpace(route.Name) == "" || strings.TrimSpace(route.Name) != route.Name {
			return errors.New("every notification route needs a name")
		}
		if route.Destination == "default" {
			return fmt.Errorf("notification route %q cannot restrict the always-on default destination", route.Name)
		}
		if seenRoutes[route.Name] {
			return fmt.Errorf("duplicate notification route %q", route.Name)
		}
		seenRoutes[route.Name] = true
		if !knownDestinations[route.Destination] {
			return fmt.Errorf("notification route %q names unknown destination %q", route.Name, route.Destination)
		}
		if err := validateAlertSelector(cfg, route.Checks, route.Components, route.Probers, route.Kinds); err != nil {
			return fmt.Errorf("notification route %q: %w", route.Name, err)
		}
	}
	seenEscalations := map[string]bool{}
	for _, policy := range cfg.Escalations {
		if strings.TrimSpace(policy.Name) == "" || strings.TrimSpace(policy.Name) != policy.Name || policy.After <= 0 {
			return errors.New("every escalation needs a name and positive after duration")
		}
		if seenEscalations[policy.Name] {
			return fmt.Errorf("duplicate escalation %q", policy.Name)
		}
		seenEscalations[policy.Name] = true
		if !knownDestinations[policy.Destination] {
			return fmt.Errorf("escalation %q names unknown destination %q", policy.Name, policy.Destination)
		}
		if err := validateAlertSelector(cfg, policy.Checks, policy.Components, policy.Probers, policy.Kinds); err != nil {
			return fmt.Errorf("escalation %q: %w", policy.Name, err)
		}
	}
	return nil
}

func validateAlertSelector(cfg Config, checks, components, probers []string, kinds []Kind) error {
	knownChecks := make(map[string]bool, len(cfg.Checks))
	for _, chk := range cfg.Checks {
		knownChecks[chk.Name] = true
	}
	knownComponents := make(map[string]bool, len(cfg.Components))
	for _, component := range cfg.Components {
		knownComponents[component.Name] = true
	}
	knownProbers := make(map[string]bool, len(cfg.Peers))
	for _, peer := range cfg.Peers {
		knownProbers[peer.Name] = true
	}
	for _, name := range checks {
		if !knownChecks[name] {
			return fmt.Errorf("unknown check %q", name)
		}
	}
	for _, name := range components {
		if !knownComponents[name] {
			return fmt.Errorf("unknown component %q", name)
		}
	}
	for _, name := range probers {
		if !knownProbers[name] {
			return fmt.Errorf("unknown prober %q", name)
		}
	}
	for _, kind := range kinds {
		if !validKind(kind) {
			return fmt.Errorf("unknown alert kind %q", kind)
		}
	}
	return nil
}

func validKind(kind Kind) bool {
	switch kind {
	case KindDown, KindRecovered, KindSilent, KindReporting, KindIsolated, KindRejoined,
		KindUnwatched, KindWatched, KindWatchLost, KindWatchRecovered:
		return true
	}
	return false
}

func selectorMatches(a Alert, checks, components, probers []string, kinds []Kind) bool {
	if len(kinds) > 0 {
		matched := false
		for _, kind := range kinds {
			if a.Kind == kind {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return alertMatches(a, checks, components, probers)
}

func (c *Coordinator) deliveryTargets(a Alert) []string {
	out := []string{"default"}
	for _, destination := range c.cfg.Destinations {
		hasRoutes, matched := false, false
		for _, route := range c.cfg.Routes {
			if route.Destination != destination.Name {
				continue
			}
			hasRoutes = true
			if selectorMatches(a, route.Checks, route.Components, route.Probers, route.Kinds) {
				matched = true
			}
		}
		if !hasRoutes || matched {
			out = append(out, destination.Name)
		}
	}
	return out
}

func (c *Coordinator) deliver(ctx context.Context, a Alert) error {
	c.deliveryMu.Lock()
	defer c.deliveryMu.Unlock()
	var errs []string
	for _, destination := range c.deliveryTargets(a) {
		if c.destinationPending(destination) {
			c.enqueueDelivery(Delivery{Destination: destination, Alert: a, NextAttempt: c.now().UTC()})
			continue
		}
		if err := c.deliverTo(ctx, destination, a); err != nil {
			c.enqueueFailedDelivery(destination, a, err)
			errs = append(errs, destination+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (c *Coordinator) destinationPending(destination string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, delivery := range c.outbox {
		if delivery.Destination == destination {
			return true
		}
	}
	return false
}

func (c *Coordinator) deliverTo(ctx context.Context, destination string, a Alert) error {
	notifier := c.destinations[destination]
	if notifier == nil {
		return fmt.Errorf("notification destination %q is unavailable", destination)
	}
	return c.recordDeliveryAttempt(ctx, destination, notifier, a)
}

func (c *Coordinator) enqueueFailedDelivery(destination string, a Alert, deliveryErr error) {
	now := c.now().UTC()
	c.enqueueDelivery(Delivery{Destination: destination, Alert: a,
		NextAttempt: now.Add(c.retryInitial()), Attempts: 1,
		LastAttempt: now, LastError: deliveryErr.Error()})
}

func (c *Coordinator) enqueueDelivery(delivery Delivery) {
	now := c.now().UTC()
	c.mu.Lock()
	c.nextDeliveryID++
	delivery.ID = c.nextDeliveryID
	delivery.CreatedAt = now
	if delivery.NextAttempt.IsZero() {
		delivery.NextAttempt = now
	}
	c.outbox = append(c.outbox, delivery)
	c.mu.Unlock()
	c.persist()
}

func (c *Coordinator) retryInitial() time.Duration {
	if c.cfg.NotificationRetryInitial > 0 {
		return c.cfg.NotificationRetryInitial
	}
	return defaultNotificationRetryInitial
}

func (c *Coordinator) retryMax() time.Duration {
	if c.cfg.NotificationRetryMax > 0 {
		return c.cfg.NotificationRetryMax
	}
	return defaultNotificationRetryMax
}

func (c *Coordinator) retryDelay(attempts uint64) time.Duration {
	delay := c.retryInitial()
	for i := uint64(1); i < attempts && delay < c.retryMax(); i++ {
		if delay > c.retryMax()/2 {
			return c.retryMax()
		}
		delay *= 2
	}
	if delay > c.retryMax() {
		return c.retryMax()
	}
	return delay
}

func (c *Coordinator) processDeliveries(ctx context.Context) {
	c.deliveryMu.Lock()
	defer c.deliveryMu.Unlock()
	now := c.now().UTC()
	c.scheduleEscalations(now)
	c.persist()

	c.mu.Lock()
	items := append([]Delivery(nil), c.outbox...)
	c.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	blocked := map[string]bool{}
	for _, item := range items {
		if blocked[item.Destination] {
			continue
		}
		if item.NextAttempt.After(now) {
			blocked[item.Destination] = true
			continue
		}
		if item.Escalation != "" && !c.escalationRelevant(item) {
			c.removeDelivery(item.ID)
			c.persist()
			continue
		}
		err := c.deliverTo(ctx, item.Destination, item.Alert)
		attemptedAt := c.now().UTC()
		c.mu.Lock()
		for i := range c.outbox {
			if c.outbox[i].ID != item.ID {
				continue
			}
			if err == nil {
				c.outbox = append(c.outbox[:i], c.outbox[i+1:]...)
			} else {
				c.outbox[i].Attempts++
				c.outbox[i].LastAttempt = attemptedAt
				c.outbox[i].LastError = err.Error()
				c.outbox[i].NextAttempt = attemptedAt.Add(c.retryDelay(c.outbox[i].Attempts))
			}
			break
		}
		c.mu.Unlock()
		if err != nil {
			blocked[item.Destination] = true
		}
		c.persist()
	}
}

func (c *Coordinator) removeDelivery(id uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.outbox {
		if c.outbox[i].ID == id {
			c.outbox = append(c.outbox[:i], c.outbox[i+1:]...)
			return
		}
	}
}

func (c *Coordinator) escalationRelevant(item Delivery) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, incident := range c.incidents {
		if incident.ID == item.IncidentID {
			return incident.Active && incident.AcknowledgedAt == nil && !incident.Suppressed
		}
	}
	return false
}

func (c *Coordinator) scheduleEscalations(now time.Time) {
	if len(c.cfg.Escalations) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, incident := range c.incidents {
		if !incident.Active || incident.AcknowledgedAt != nil || incident.Suppressed {
			continue
		}
		for _, policy := range c.cfg.Escalations {
			key := fmt.Sprintf("%d/%s", incident.ID, policy.Name)
			if _, done := c.escalated[key]; done || now.Before(incident.OpenedAt.Add(policy.After)) {
				continue
			}
			if !selectorMatches(incident.Alert, policy.Checks, policy.Components, policy.Probers, policy.Kinds) {
				continue
			}
			c.nextDeliveryID++
			a := incident.Alert
			a.At = now
			a.Escalation = policy.Name
			a.Detail = strings.TrimSpace(a.Detail + "; escalation " + policy.Name + " after " + policy.After.String())
			c.outbox = append(c.outbox, Delivery{ID: c.nextDeliveryID, Destination: policy.Destination,
				Alert: a, CreatedAt: now, NextAttempt: now, Escalation: policy.Name, IncidentID: incident.ID})
			c.escalated[key] = now
		}
	}
}

// cancelEscalationsLocked removes pending escalations when an incident is no
// longer page-worthy. The caller holds c.mu.
func (c *Coordinator) cancelEscalationsLocked(incidentID uint64) {
	kept := c.outbox[:0]
	for _, delivery := range c.outbox {
		if delivery.IncidentID == incidentID && delivery.Escalation != "" {
			continue
		}
		kept = append(kept, delivery)
	}
	c.outbox = kept
}

func (c *Coordinator) Outbox() []Delivery {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := append([]Delivery{}, c.outbox...)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (c *Coordinator) runDeliveries(ctx context.Context) {
	interval := c.cfg.NotificationRetryInterval
	if interval <= 0 {
		interval = defaultNotificationRetryInterval
	}
	c.processDeliveries(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.processDeliveries(ctx)
		}
	}
}
