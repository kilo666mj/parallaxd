package coordinator

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

type sequenceNotifier struct {
	mu       sync.Mutex
	failures int
	alerts   []Alert
}

func (n *sequenceNotifier) Notify(_ context.Context, alert Alert) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.failures > 0 {
		n.failures--
		return errors.New("destination unavailable")
	}
	n.alerts = append(n.alerts, alert)
	return nil
}

func (n *sequenceNotifier) all() []Alert {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]Alert(nil), n.alerts...)
}

func resultAt(status check.Status, at time.Time) check.Result {
	r := downResult(at)
	r.Status = status
	return r
}

func TestFailedDeliverySurvivesRestartAndRetries(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	stateFile := filepath.Join(t.TempDir(), "state.json")
	n := &sequenceNotifier{failures: 1}
	cfg := durableConfig(t, stateFile, n, nil)
	cfg.Now = func() time.Time { return now }
	cfg.NotificationRetryInitial = time.Second
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Process(t.Context(), resultAt(check.StatusDown, now)); err != nil {
		t.Fatal(err)
	}
	if got := c.Outbox(); len(got) != 1 || got[0].Attempts != 1 || got[0].LastError == "" {
		t.Fatalf("outbox after failure = %+v", got)
	}
	if diagnostics := c.DiagnosticState().Notifications; diagnostics.Pending != 1 || diagnostics.OldestPending.IsZero() {
		t.Fatalf("notification diagnostics = %+v", diagnostics)
	}

	now = now.Add(2 * time.Second)
	restored, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Outbox()) != 1 {
		t.Fatal("restart lost pending delivery")
	}
	restored.processDeliveries(t.Context())
	if got := restored.Outbox(); len(got) != 0 {
		t.Fatalf("outbox after retry = %+v", got)
	}
	if got := n.all(); len(got) != 1 || got[0].Kind != KindDown {
		t.Fatalf("delivered alerts = %+v", got)
	}
}

func TestDestinationDeliveryPreservesDownRecoveryOrder(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	log := &sequenceNotifier{}
	webhook := &sequenceNotifier{failures: 1}
	cfg := durableConfig(t, "", log, nil)
	cfg.Now = func() time.Time { return now }
	cfg.NotificationRetryInitial = time.Second
	cfg.Destinations = []NotificationDestination{{Name: "webhook", Notifier: webhook}}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Process(t.Context(), resultAt(check.StatusDown, now)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(500 * time.Millisecond)
	if _, err := c.Process(t.Context(), resultAt(check.StatusUp, now)); err != nil {
		t.Fatal(err)
	}
	if got := c.Outbox(); len(got) != 2 || got[0].Alert.Kind != KindDown || got[1].Alert.Kind != KindRecovered {
		t.Fatalf("queued delivery order = %+v", got)
	}
	now = now.Add(2 * time.Second)
	c.processDeliveries(t.Context())
	got := webhook.all()
	if len(got) != 2 || got[0].Kind != KindDown || got[1].Kind != KindRecovered {
		t.Fatalf("webhook delivery order = %+v", got)
	}
}

func TestRoutesSelectDestinationsByKind(t *testing.T) {
	now := time.Now().UTC()
	down := &sequenceNotifier{}
	recovery := &sequenceNotifier{}
	cfg := durableConfig(t, "", &sequenceNotifier{}, nil)
	cfg.Now = func() time.Time { return now }
	cfg.Destinations = []NotificationDestination{{Name: "page", Notifier: down}, {Name: "chat", Notifier: recovery}}
	cfg.Routes = []NotificationRoute{
		{Name: "page failures", Destination: "page", Checks: []string{"svc"}, Kinds: []Kind{KindDown}},
		{Name: "chat recoveries", Destination: "chat", Checks: []string{"svc"}, Kinds: []Kind{KindRecovered}},
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Process(t.Context(), resultAt(check.StatusDown, now)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := c.Process(t.Context(), resultAt(check.StatusUp, now)); err != nil {
		t.Fatal(err)
	}
	if got := down.all(); len(got) != 1 || got[0].Kind != KindDown {
		t.Fatalf("page alerts = %+v", got)
	}
	if got := recovery.all(); len(got) != 1 || got[0].Kind != KindRecovered {
		t.Fatalf("chat alerts = %+v", got)
	}
}

func TestEscalationFiresOnceAndStopsAfterAcknowledgement(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pager := &sequenceNotifier{}
	cfg := durableConfig(t, filepath.Join(t.TempDir(), "state.json"), &sequenceNotifier{}, nil)
	cfg.Now = func() time.Time { return now }
	cfg.Destinations = []NotificationDestination{{Name: "pager", Notifier: pager}}
	cfg.Routes = []NotificationRoute{{Name: "no initial page", Destination: "pager", Kinds: []Kind{KindRecovered}}}
	cfg.Escalations = []EscalationPolicy{{Name: "unacked", Destination: "pager", After: time.Minute, Checks: []string{"svc"}, Kinds: []Kind{KindDown}}}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Process(t.Context(), resultAt(check.StatusDown, now)); err != nil {
		t.Fatal(err)
	}
	if len(pager.all()) != 0 {
		t.Fatal("pager received initial alert despite route")
	}
	now = now.Add(2 * time.Minute)
	c.processDeliveries(t.Context())
	c.processDeliveries(t.Context())
	if got := pager.all(); len(got) != 1 || got[0].Kind != KindDown || got[0].Escalation != "unacked" {
		t.Fatalf("escalations = %+v", got)
	} else if !strings.Contains(got[0].Summary(), "ESCALATION unacked") {
		t.Fatalf("escalation summary = %q", got[0].Summary())
	}
	restored, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	restored.processDeliveries(t.Context())
	if len(pager.all()) != 1 {
		t.Fatal("restart repeated completed escalation")
	}

	// A separate incident acknowledged before its deadline never escalates.
	now = now.Add(time.Second)
	cfg.StateFile = ""
	c2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Process(t.Context(), resultAt(check.StatusDown, now)); err != nil {
		t.Fatal(err)
	}
	if err := c2.AcknowledgeIncident(1, "alice", "investigating"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	c2.processDeliveries(t.Context())
	if len(pager.all()) != 1 {
		t.Fatal("acknowledged incident escalated")
	}
}

func TestQueuedEscalationIsCancelledWhenAcknowledged(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	pager := &sequenceNotifier{failures: 1}
	cfg := durableConfig(t, "", &sequenceNotifier{}, nil)
	cfg.Now = func() time.Time { return now }
	cfg.NotificationRetryInitial = time.Second
	cfg.Destinations = []NotificationDestination{{Name: "pager", Notifier: pager}}
	cfg.Routes = []NotificationRoute{{Name: "recoveries only", Destination: "pager", Kinds: []Kind{KindRecovered}}}
	cfg.Escalations = []EscalationPolicy{{Name: "unacked", Destination: "pager", After: time.Minute, Kinds: []Kind{KindDown}}}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Process(t.Context(), resultAt(check.StatusDown, now)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	c.processDeliveries(t.Context())
	if got := c.Outbox(); len(got) != 1 || got[0].Escalation != "unacked" {
		t.Fatalf("queued escalation = %+v", got)
	}
	if err := c.AcknowledgeIncident(1, "alice", "working it"); err != nil {
		t.Fatal(err)
	}
	if got := c.Outbox(); len(got) != 0 {
		t.Fatalf("acknowledgement did not cancel queued escalation: %+v", got)
	}
	now = now.Add(2 * time.Second)
	c.processDeliveries(t.Context())
	if got := c.Outbox(); len(got) != 0 {
		t.Fatalf("acknowledged escalation remained queued: %+v", got)
	}
	if got := pager.all(); len(got) != 0 {
		t.Fatalf("acknowledged escalation delivered: %+v", got)
	}
}

func TestNotificationConfigRejectsUnknownDestination(t *testing.T) {
	cfg := durableConfig(t, "", &sequenceNotifier{}, nil)
	cfg.Routes = []NotificationRoute{{Name: "bad", Destination: "missing"}}
	if _, err := New(cfg); err == nil {
		t.Fatal("unknown route destination was accepted")
	}
}

func TestRestartRejectsPendingDeliveryWithoutItsDestination(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "state.json")
	failing := &sequenceNotifier{failures: 1}
	cfg := durableConfig(t, path, &sequenceNotifier{}, nil)
	cfg.Now = func() time.Time { return now }
	cfg.Destinations = []NotificationDestination{{Name: "removed", Notifier: failing}}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Process(t.Context(), resultAt(check.StatusDown, now)); err != nil {
		t.Fatal(err)
	}
	if len(c.Outbox()) != 1 {
		t.Fatal("expected failed named delivery")
	}
	cfg.Destinations = nil
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "unavailable notification destination") {
		t.Fatalf("missing destination restore error = %v", err)
	}
}
