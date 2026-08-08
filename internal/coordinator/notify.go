package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/quorum"
)

// Kind is what happened to a check.
type Kind string

const (
	// KindDown is a failure that reached quorum.
	KindDown Kind = "down"

	// KindRecovered is a check that was down and is now up.
	KindRecovered Kind = "recovered"

	// KindSilent is a prober that has stopped reporting, so its checks are no
	// longer being run. Deliberately not KindDown: nobody probed the target,
	// so there is no evidence about it, and paging "the service is down"
	// because a prober rebooted is the false alert this project exists to
	// remove.
	KindSilent Kind = "silent"

	// KindReporting is a prober that has started reporting again.
	KindReporting Kind = "reporting"

	// KindIsolated is a prober that can reach no peer, so its results have
	// stopped being counted. Distinct from KindSilent: a silent prober said
	// nothing, an isolated one is still talking but has no working path to
	// anything and its opinion would be actively misleading.
	//
	// It is an alert rather than a quiet suppression because a silenced prober
	// is a monitoring gap — everything it was the assigned reporter for is now
	// judged on fewer opinions, or none.
	KindIsolated Kind = "isolated"

	// KindRejoined is a prober that can see the fleet again.
	KindRejoined Kind = "rejoined"

	// KindUnwatched is the coordinator reporting that its heartbeat is not
	// getting through, so nothing outside it would notice if it died.
	//
	// A coordinator must not claim to report its own death — that is what the
	// watcher is for — but "nothing is watching me" is a different fact and
	// one it is the only component positioned to know.
	KindUnwatched Kind = "unwatched"

	// KindWatched is the heartbeat getting through again.
	KindWatched Kind = "watched"

	// KindWatchLost is the watcher reporting that the coordinator has stopped
	// checking in. Sent by parallaxd-watch, not by the coordinator.
	KindWatchLost Kind = "coordinator-silent"

	// KindWatchRecovered is the coordinator checking in again.
	KindWatchRecovered Kind = "coordinator-returned"
)

// Alert is one thing worth telling someone about — either a single check, or a
// component built from several.
//
// A check alert carries the whole verdict rather than a status string. An alert
// that cannot say "3 of 5 across three providers, 2 still reported up" leaves
// the reader to go and find that out, and the entire point of corroborating is
// that the strength of the agreement is part of the finding.
type Alert struct {
	// Component is set when this alert is about a group of checks. Check and
	// Target are then empty and Members carries the per-check detail, which is
	// what keeps a grouped alert as specific as the ungrouped ones it replaces.
	Component string   `json:"component,omitempty"`
	Members   []Member `json:"members,omitempty"`

	// Prober is set when the alert is about a prober rather than about
	// anything it was watching — it has gone quiet, or come back.
	Prober string `json:"prober,omitempty"`

	Check  string `json:"check,omitempty"`
	Target string `json:"target,omitempty"`

	// Detail is free text from the configuration — a component's description.
	Detail string `json:"detail,omitempty"`

	Kind Kind      `json:"kind"`
	At   time.Time `json:"at"`

	// Verdict is the corroboration detail, and is only meaningful on a check
	// alert: a component has no probers of its own to agree or dissent.
	Verdict quorum.Verdict `json:"verdict,omitzero"`
}

// Member is one check's contribution to a component alert.
type Member struct {
	Check  string `json:"check"`
	Target string `json:"target,omitempty"`
	Status string `json:"status"`
}

// Subject is what the alert is about, for a reader who does not care which
// layer produced it.
func (a Alert) Subject() string {
	switch {
	case a.Prober != "":
		return a.Prober
	case a.Component != "":
		return a.Component
	}
	return a.Check
}

// Summary renders the alert as one line.
func (a Alert) Summary() string {
	var b strings.Builder
	verb := "DOWN"
	switch a.Kind {
	case KindRecovered:
		verb = "RECOVERED"
	case KindSilent:
		verb = "SILENT"
	case KindReporting:
		verb = "REPORTING"
	case KindIsolated:
		verb = "ISOLATED"
	case KindRejoined:
		verb = "REJOINED"
	case KindUnwatched:
		verb = "UNWATCHED"
	case KindWatched:
		verb = "WATCHED"
	case KindWatchLost:
		verb = "COORDINATOR SILENT"
	case KindWatchRecovered:
		verb = "COORDINATOR RETURNED"
	}

	// An alert about the watch itself has no check, component or prober to
	// name; the detail is the whole message.
	if a.Prober == "" && a.Component == "" && a.Check == "" {
		fmt.Fprint(&b, verb)
		if a.Detail != "" {
			fmt.Fprintf(&b, " — %s", a.Detail)
		}
		return b.String()
	}

	if a.Prober != "" {
		fmt.Fprintf(&b, "%s prober %s", verb, a.Prober)
		if a.Detail != "" {
			fmt.Fprintf(&b, " — %s", a.Detail)
		}
		if len(a.Members) > 0 {
			names := make([]string, 0, len(a.Members))
			for _, m := range a.Members {
				names = append(names, m.Check)
			}
			fmt.Fprintf(&b, ": %s", strings.Join(names, ", "))
		}
		return b.String()
	}

	if a.Component != "" {
		fmt.Fprintf(&b, "%s %s", verb, a.Component)
		// Naming the members that failed is what stops a component alert being
		// vaguer than the check alerts it replaced.
		var failing []string
		for _, m := range a.Members {
			if m.Status == string(check.StatusDown) {
				failing = append(failing, m.Check)
			}
		}
		if len(failing) > 0 {
			fmt.Fprintf(&b, " — %s", strings.Join(failing, ", "))
		} else if a.Detail != "" {
			fmt.Fprintf(&b, " — %s", a.Detail)
		}
		return b.String()
	}

	fmt.Fprintf(&b, "%s %s (%s)", verb, a.Check, a.Target)
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
	var attrs []any
	switch {
	case a.Prober == "" && a.Component == "" && a.Check == "":
		attrs = []any{"kind", string(a.Kind)}
	case a.Prober != "":
		attrs = []any{"prober", a.Prober, "kind", string(a.Kind), "checks", len(a.Members)}
	case a.Component != "":
		attrs = []any{"component", a.Component, "kind", string(a.Kind)}
	default:
		attrs = []any{
			"check", a.Check, "target", a.Target, "kind", string(a.Kind),
			"down", a.Verdict.Down, "up", a.Verdict.Up, "unknown", a.Verdict.Unknown,
			"providers", a.Verdict.Providers,
		}
		if len(a.Verdict.Dissent) > 0 {
			attrs = append(attrs, "dissent", a.Verdict.Dissent)
		}
	}
	// Good news at info, problems at warn: an operator filtering for problems
	// should not have to read the good news to find the bad.
	switch a.Kind {
	case KindRecovered, KindReporting, KindRejoined, KindWatched, KindWatchRecovered:
		log.Info(a.Summary(), attrs...)
	default:
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
		// url.Error includes the full URL in Error(), and webhook URLs often
		// carry a secret query token. Preserve the operation and underlying
		// cause without leaking the destination through logs or diagnostics.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return fmt.Errorf("webhook %s failed: %w", urlErr.Op, urlErr.Err)
		}
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
