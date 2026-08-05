package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kilo666mj/parallaxd/internal/quorum"
)

// Kind is what happened to a check.
type Kind string

const (
	// KindDown is a failure that reached quorum.
	KindDown Kind = "down"

	// KindRecovered is a check that was down and is now up.
	KindRecovered Kind = "recovered"
)

// Alert is one thing worth telling someone about.
//
// It carries the whole verdict rather than a status string. An alert that
// cannot say "3 of 5 across three providers, 2 still reported up" leaves the
// reader to go and find that out, and the entire point of corroborating is
// that the strength of the agreement is part of the finding.
type Alert struct {
	Check   string         `json:"check"`
	Target  string         `json:"target"`
	Kind    Kind           `json:"kind"`
	At      time.Time      `json:"at"`
	Verdict quorum.Verdict `json:"verdict"`
}

// Summary renders the alert as one line.
func (a Alert) Summary() string {
	var b strings.Builder
	switch a.Kind {
	case KindRecovered:
		fmt.Fprintf(&b, "RECOVERED %s (%s)", a.Check, a.Target)
	default:
		fmt.Fprintf(&b, "DOWN %s (%s)", a.Check, a.Target)
	}
	if a.Verdict.Reason != "" {
		fmt.Fprintf(&b, " — %s", a.Verdict.Reason)
	}
	if len(a.Verdict.Dissent) > 0 {
		fmt.Fprintf(&b, "; dissenting: %s", strings.Join(a.Verdict.Dissent, ", "))
	}
	return b.String()
}

// Notifier delivers an alert.
//
// Implementations here are deliberately generic — a log and an HTTP POST.
// Anything that knows about a particular monitoring system, chat product or
// ticket tracker belongs outside this repository: parallaxd should be useful
// to someone running none of the same infrastructure, and a webhook is the
// seam where their own glue attaches.
type Notifier interface {
	Notify(ctx context.Context, a Alert) error
}

// LogNotifier writes alerts to a logger. The default, and enough on its own
// for a host whose journal is already shipped somewhere.
type LogNotifier struct {
	Logger *slog.Logger
}

func (n LogNotifier) Notify(_ context.Context, a Alert) error {
	log := n.Logger
	if log == nil {
		log = slog.Default()
	}
	attrs := []any{
		"check", a.Check, "target", a.Target, "kind", string(a.Kind),
		"down", a.Verdict.Down, "up", a.Verdict.Up, "unknown", a.Verdict.Unknown,
		"providers", a.Verdict.Providers,
	}
	if len(a.Verdict.Dissent) > 0 {
		attrs = append(attrs, "dissent", a.Verdict.Dissent)
	}
	// Recovery at info, failure at warn: an operator filtering for problems
	// should not have to read the good news to find the bad.
	if a.Kind == KindRecovered {
		log.Info(a.Summary(), attrs...)
	} else {
		log.Warn(a.Summary(), attrs...)
	}
	return nil
}

// WebhookNotifier POSTs the alert as JSON.
type WebhookNotifier struct {
	URL    string
	Client *http.Client

	// Headers are sent with every request, which is where an authorization
	// token goes. Kept general rather than growing a field per service.
	Headers map[string]string
}

func (n WebhookNotifier) Notify(ctx context.Context, a Alert) error {
	body, err := json.Marshal(struct {
		Alert
		// Duplicated at the top level so a receiver that renders a single
		// field — most chat webhooks — shows something useful without being
		// taught this schema.
		Text string `json:"text"`
	}{Alert: a, Text: a.Summary()})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range n.Headers {
		req.Header.Set(k, v)
	}

	client := n.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

// Notifiers delivers to several destinations. One failing does not stop the
// rest: an unreachable webhook must not also cost the log line.
type Notifiers []Notifier

func (ns Notifiers) Notify(ctx context.Context, a Alert) error {
	var errs []string
	for _, n := range ns {
		if err := n.Notify(ctx, a); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d of %d notifiers failed: %s",
			len(errs), len(ns), strings.Join(errs, "; "))
	}
	return nil
}
