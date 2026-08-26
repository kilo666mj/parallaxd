package coordinator

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	tintwire "github.com/kilo666mj/tintwire-go"
)

type tintwirePublisher interface {
	Publish(context.Context, tintwire.Card) (tintwire.Result, error)
}

// TintwireNotifier translates a decided alert into a native Tintwire card.
// The client owns Mattermost failover policy; parallaxd's durable outbox sees
// the pair as one logical destination and retries only when neither accepted
// the notification.
type TintwireNotifier struct {
	Client  tintwirePublisher
	Channel string
	Source  string
	Log     *slog.Logger
}

func (n TintwireNotifier) Notify(ctx context.Context, alert Alert) error {
	if n.Client == nil {
		return fmt.Errorf("tintwire notifier needs a client")
	}
	result, err := n.Client.Publish(ctx, tintwireCard(alert, n.Channel, n.Source))
	if err != nil {
		return err
	}
	if result.Destination == tintwire.DestinationMattermost && n.Log != nil {
		n.Log.Warn("Tintwire delivery used Mattermost fallback",
			"subject", alert.Subject(), "kind", string(alert.Kind), "tintwire_error", result.PrimaryError)
	}
	return nil
}

func tintwireCard(alert Alert, channel, source string) tintwire.Card {
	if source == "" {
		source = "parallaxd"
	}
	title := alert.verb()
	if subject := alert.Subject(); subject != "" {
		title += " — " + subject
	}
	summary := alert.Detail
	if alert.Check != "" && alert.Verdict.Reason != "" {
		summary = alert.Verdict.Reason
	}
	if summary == "" {
		summary = alert.Summary()
	}
	card := tintwire.Card{
		Channel: channel, Title: truncateRunes(title, 200), Summary: truncateRunes(summary, 500),
		Severity: tintwireSeverity(alert.Kind), Source: source,
	}
	if alert.Check != "" {
		card.Fields = append(card.Fields,
			tintwire.Field{Label: "Target", Value: truncateRunes(alert.Target, 1000)},
			tintwire.Field{Label: "Evidence", Value: fmt.Sprintf("%d down · %d up · %d unknown", alert.Verdict.Down, alert.Verdict.Up, alert.Verdict.Unknown)},
		)
		if len(alert.Verdict.Providers) > 0 {
			card.Fields = append(card.Fields, tintwire.Field{Label: "Providers", Value: truncateRunes(strings.Join(alert.Verdict.Providers, ", "), 1000)})
		}
		if len(alert.Verdict.Dissent) > 0 {
			card.Fields = append(card.Fields, tintwire.Field{Label: "Dissenting probers", Value: truncateRunes(strings.Join(alert.Verdict.Dissent, ", "), 1000)})
		}
	}
	for _, member := range alert.Members[:min(len(alert.Members), 2000)] {
		card.Rows = append(card.Rows, tintwire.Row{Primary: truncateRunes(member.Check, 1000), Tags: []string{truncateRunes(member.Status, 80)}})
	}
	if !alert.At.IsZero() {
		card.Fields = append(card.Fields, tintwire.Field{Label: "Decided", Value: alert.At.UTC().Format(time.RFC3339)})
	}
	if !alert.SuspectedAt.IsZero() && alert.At.After(alert.SuspectedAt) {
		card.Fields = append(card.Fields, tintwire.Field{Label: "Detection time", Value: alert.At.Sub(alert.SuspectedAt).Round(time.Second).String()})
	}
	if alert.Escalation != "" {
		card.Badges = append(card.Badges, tintwire.Badge{Label: truncateRunes("ESCALATION — "+alert.Escalation, 80), Tone: tintwire.ToneCritical})
	}
	return card
}

func tintwireSeverity(kind Kind) tintwire.Severity {
	switch kind {
	case KindRecovered, KindReporting, KindRejoined, KindWatched, KindWatchRecovered:
		return tintwire.SeveritySuccess
	case KindDown, KindWatchLost:
		return tintwire.SeverityCritical
	default:
		return tintwire.SeverityWarning
	}
}

func truncateRunes(value string, maximum int) string {
	if utf8.RuneCountInString(value) <= maximum {
		return value
	}
	runes := []rune(value)
	return string(runes[:maximum-1]) + "…"
}
