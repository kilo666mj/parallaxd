package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/quorum"
	tintwire "go.michaelspost.com/tintwire-go"
)

type captureTintwirePublisher struct {
	card   tintwire.Card
	result tintwire.Result
}

type tintwireRoundTrip func(*http.Request) (*http.Response, error)

func (f tintwireRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTintwireFallbackKeepsOrderedPrimaryDeliveryAcrossRestart(t *testing.T) {
	for _, scenario := range []struct {
		recoveryOnly      bool
		fallbackFailsOnce bool
	}{{}, {recoveryOnly: true}, {fallbackFailsOnce: true}} {
		t.Run(fmt.Sprintf("recoveryOnly=%v/fallbackFailsOnce=%v", scenario.recoveryOnly, scenario.fallbackFailsOnce), func(t *testing.T) {
			primaryUp := scenario.recoveryOnly
			fallbackCalls := 0
			var delivered []tintwire.Card
			client, err := tintwire.New("https://tintwire.example", "token",
				tintwire.WithMattermostFailover("https://mattermost.example/hooks/fallback"),
				tintwire.WithHTTPClient(&http.Client{Transport: tintwireRoundTrip(func(r *http.Request) (*http.Response, error) {
					status := http.StatusCreated
					if r.URL.Host == "mattermost.example" {
						fallbackCalls++
						if scenario.fallbackFailsOnce && fallbackCalls == 1 {
							status = http.StatusServiceUnavailable
						}
					} else if !primaryUp {
						status = http.StatusServiceUnavailable
					} else {
						var card tintwire.Card
						if err := json.NewDecoder(r.Body).Decode(&card); err != nil {
							t.Fatal(err)
						}
						delivered = append(delivered, card)
					}
					return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
				})}))
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			cfg := durableConfig(t, filepath.Join(t.TempDir(), "state.json"), &sequenceNotifier{}, nil)
			cfg.Now = func() time.Time { return now }
			cfg.NotificationRetryInitial = time.Second
			cfg.Destinations = []NotificationDestination{{Name: "tintwire", Notifier: TintwireNotifier{Client: client}}}
			c, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Process(t.Context(), resultAt(check.StatusDown, now)); err != nil {
				t.Fatal(err)
			}
			primaryUp = false
			now = now.Add(time.Second)
			if _, err := c.Process(t.Context(), resultAt(check.StatusUp, now)); err != nil {
				t.Fatal(err)
			}
			wantFallbackCalls := 1
			if scenario.fallbackFailsOnce {
				if got := c.Outbox(); len(got) == 0 || got[0].FallbackAccepted {
					t.Fatalf("failed fallback was marked accepted: %+v", got)
				}
				now = now.Add(3 * time.Second)
				c.processDeliveries(t.Context())
				wantFallbackCalls = 2
			}
			if got := c.Outbox(); len(got) == 0 || !got[0].FallbackAccepted {
				t.Fatalf("fallback did not leave durable primary delivery: %+v", got)
			}
			c, err = New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if got := c.Outbox(); len(got) == 0 || !got[0].FallbackAccepted {
				t.Fatalf("restart lost fallback acceptance: %+v", got)
			}
			now = now.Add(3 * time.Second)
			c.processDeliveries(t.Context())
			if fallbackCalls != wantFallbackCalls || len(c.Outbox()) == 0 {
				t.Fatalf("retry lost delivery or repeated fallback: calls=%d pending=%+v", fallbackCalls, c.Outbox())
			}
			primaryUp = true
			now = now.Add(10 * time.Second)
			c.processDeliveries(t.Context())
			if len(c.Outbox()) != 0 || fallbackCalls != wantFallbackCalls {
				t.Fatalf("recovery did not drain primary outbox: pending=%+v fallback=%d", c.Outbox(), fallbackCalls)
			}
			if len(delivered) != 2 || delivered[0].State != tintwire.StateFiring || delivered[1].State != tintwire.StateResolved || delivered[0].LifecycleKey != delivered[1].LifecycleKey {
				t.Fatalf("lifecycle delivery order = %+v", delivered)
			}
		})
	}
}

func (publisher *captureTintwirePublisher) Publish(_ context.Context, card tintwire.Card) (tintwire.Result, error) {
	publisher.card = card
	return publisher.result, nil
}

func (publisher *captureTintwirePublisher) PublishPrimary(ctx context.Context, card tintwire.Card) (tintwire.Result, error) {
	return publisher.Publish(ctx, card)
}

func TestTintwireNotifierLogsMattermostFallback(t *testing.T) {
	var output bytes.Buffer
	publisher := &captureTintwirePublisher{result: tintwire.Result{
		Destination:  tintwire.DestinationMattermost,
		PrimaryError: &tintwire.HTTPError{StatusCode: 503, Status: "503 Service Unavailable"},
	}}
	notifier := TintwireNotifier{Client: publisher, Log: slog.New(slog.NewTextHandler(&output, nil))}
	if err := notifier.Notify(t.Context(), Alert{Check: "website", Kind: KindDown}); !fallbackAccepted(err) || !errors.Is(err, publisher.result.PrimaryError) {
		t.Fatalf("fallback must leave primary pending: %v", err)
	}
	logged := output.String()
	if !strings.Contains(logged, "Mattermost fallback") || !strings.Contains(logged, "503 Service Unavailable") {
		t.Fatalf("fallback log = %q", logged)
	}
}

func TestTintwireNotifierBuildsNativeAlertCard(t *testing.T) {
	publisher := &captureTintwirePublisher{}
	decided := time.Date(2026, 8, 24, 10, 30, 0, 0, time.UTC)
	alert := Alert{
		Check: "website", Target: "https://example.com/readyz", Kind: KindDown,
		At: decided, SuspectedAt: decided.Add(-2 * time.Minute), Escalation: "unacknowledged",
		Verdict: quorum.Verdict{
			Down: 3, Up: 1, Unknown: 1, Providers: []string{"hetzner", "oracle"},
			Dissent: []string{"probe-c"}, Reason: "3 of 5 probers reported down",
		},
	}
	notifier := TintwireNotifier{Client: publisher, Channel: "parallaxd", Source: "parallaxd"}
	if err := notifier.Notify(t.Context(), alert); err != nil {
		t.Fatal(err)
	}
	card := publisher.card
	if card.Title != "DOWN — website" || card.Summary != alert.Verdict.Reason ||
		card.Channel != "parallaxd" || card.Source != "parallaxd" || card.Severity != tintwire.SeverityCritical {
		t.Fatalf("card = %#v", card)
	}
	if len(card.Fields) != 6 || card.Fields[0].Label != "Target" || card.Fields[1].Label != "Evidence" {
		t.Fatalf("fields = %#v", card.Fields)
	}
	if len(card.Badges) != 1 || card.Badges[0].Tone != tintwire.ToneCritical {
		t.Fatalf("badges = %#v", card.Badges)
	}
}

func TestTintwireNotifierUsesSuccessSeverityForRecovery(t *testing.T) {
	publisher := &captureTintwirePublisher{}
	if err := (TintwireNotifier{Client: publisher}).Notify(t.Context(), Alert{
		Check: "website", Kind: KindRecovered, At: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if publisher.card.Severity != tintwire.SeveritySuccess {
		t.Fatalf("severity = %q", publisher.card.Severity)
	}
}

func TestTintwireLifecyclePairsProblemsWithRecoveries(t *testing.T) {
	pairs := []struct{ problem, clear Alert }{
		{Alert{Check: "website", Kind: KindDown}, Alert{Check: "website", Kind: KindRecovered}},
		{Alert{Component: "mail", Kind: KindDown}, Alert{Component: "mail", Kind: KindRecovered}},
		{Alert{Prober: "p1", Kind: KindSilent}, Alert{Prober: "p1", Kind: KindReporting}},
		{Alert{Prober: "p1", Kind: KindIsolated}, Alert{Prober: "p1", Kind: KindRejoined}},
		{Alert{Kind: KindUnwatched}, Alert{Kind: KindWatched}},
		{Alert{Kind: KindWatchLost}, Alert{Kind: KindWatchRecovered}},
		{Alert{Check: "website", Kind: KindWarning}, Alert{Check: "website", Kind: KindWarningCleared}},
	}
	seen := map[string]bool{}
	for _, pair := range pairs {
		problemState, problemKey := tintwireLifecycle(pair.problem)
		clearState, clearKey := tintwireLifecycle(pair.clear)
		if problemState != tintwire.StateFiring || clearState != tintwire.StateResolved || problemKey == "" || problemKey != clearKey {
			t.Fatalf("%s/%s lifecycle = (%q,%q) (%q,%q)", pair.problem.Kind, pair.clear.Kind, problemState, problemKey, clearState, clearKey)
		}
		if seen[problemKey] {
			t.Fatalf("lifecycle key %q reused across pairs", problemKey)
		}
		seen[problemKey] = true
	}
	if _, key := tintwireLifecycle(Alert{Check: "other", Kind: KindDown}); seen[key] {
		t.Fatalf("different check shares key %q", key)
	}
	if _, key := tintwireLifecycle(Alert{Check: strings.Repeat("é", 300), Kind: KindDown}); len(key) > 200 || !utf8.ValidString(key) {
		t.Fatalf("long key = %d bytes, valid UTF-8 = %v", len(key), utf8.ValidString(key))
	}
	card := tintwireCard(Alert{Check: "website", Kind: KindDown}, "", "")
	if card.State != tintwire.StateFiring || card.LifecycleKey == "" || card.Validate() != nil {
		t.Fatalf("card lifecycle = %q/%q", card.State, card.LifecycleKey)
	}
}

func TestWarningIsLessUrgentThanDown(t *testing.T) {
	if got := tintwireSeverity(KindWarning); got != tintwire.SeverityWarning {
		t.Fatalf("warning severity = %q", got)
	}
	if got := tintwireSeverity(KindDown); got != tintwire.SeverityCritical {
		t.Fatalf("down severity = %q", got)
	}
}

func TestTintwireTruncationCountsBytes(t *testing.T) {
	got := truncateRunes(strings.Repeat("é", 300), 500)
	if len(got) > 500 || !utf8.ValidString(got) || !strings.HasSuffix(got, "…") {
		t.Fatalf("truncated to %d bytes: %q", len(got), got)
	}
}
