package coordinator

import (
	"context"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/quorum"
	tintwire "github.com/kilo666mj/tintwire-go"
)

type captureTintwirePublisher struct {
	card tintwire.Card
}

func (publisher *captureTintwirePublisher) Send(_ context.Context, card tintwire.Card) error {
	publisher.card = card
	return nil
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
