package coordinator

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/quorum"
	tintwire "github.com/kilo666mj/tintwire-go"
)

type captureTintwirePublisher struct {
	card   tintwire.Card
	result tintwire.Result
}

func (publisher *captureTintwirePublisher) Publish(_ context.Context, card tintwire.Card) (tintwire.Result, error) {
	publisher.card = card
	return publisher.result, nil
}

func TestTintwireNotifierLogsMattermostFallback(t *testing.T) {
	var output bytes.Buffer
	publisher := &captureTintwirePublisher{result: tintwire.Result{
		Destination:  tintwire.DestinationMattermost,
		PrimaryError: &tintwire.HTTPError{StatusCode: 503, Status: "503 Service Unavailable"},
	}}
	notifier := TintwireNotifier{Client: publisher, Log: slog.New(slog.NewTextHandler(&output, nil))}
	if err := notifier.Notify(t.Context(), Alert{Check: "website", Kind: KindDown}); err != nil {
		t.Fatal(err)
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
