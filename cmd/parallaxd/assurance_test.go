package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tintwire "go.michaelspost.com/tintwire-go"
)

type recordingPublisher struct {
	cards []tintwire.Card
	err   error
}

func (r *recordingPublisher) Publish(_ context.Context, card tintwire.Card) (tintwire.Result, error) {
	r.cards = append(r.cards, card)
	return tintwire.Result{}, r.err
}

func TestAssuranceAlertFiresOnceThenResolves(t *testing.T) {
	cfg := assuranceAlertConfig{Webhook: "unused", Host: "coord-a", StateDir: filepath.Join(t.TempDir(), "alerts")}
	unit := "parallaxd-operations-coordinator.service"
	tail := func(string) string { return "replication lag 90s exceeds 60s" }
	pub := &recordingPublisher{}

	if err := publishAssurance(t.Context(), pub, cfg, unit, "success", tail); err != nil || len(pub.cards) != 0 {
		t.Fatalf("healthy success published: %v %+v", err, pub.cards)
	}
	if err := publishAssurance(t.Context(), pub, cfg, unit, "failure", tail); err != nil {
		t.Fatal(err)
	}
	firing := pub.cards[0]
	if firing.State != tintwire.StateFiring || firing.Severity != tintwire.SeverityCritical ||
		!strings.Contains(firing.Title, unit) || firing.Summary != "replication lag 90s exceeds 60s" {
		t.Fatalf("firing card = %+v", firing)
	}
	if err := publishAssurance(t.Context(), pub, cfg, unit, "success", tail); err != nil {
		t.Fatal(err)
	}
	resolved := pub.cards[1]
	if resolved.State != tintwire.StateResolved || resolved.LifecycleKey != firing.LifecycleKey {
		t.Fatalf("resolved card = %+v, firing key %q", resolved, firing.LifecycleKey)
	}
	if err := publishAssurance(t.Context(), pub, cfg, unit, "success", tail); err != nil || len(pub.cards) != 2 {
		t.Fatalf("second success published again: %v %d", err, len(pub.cards))
	}
}

func TestAssuranceResolveKeepsMarkerWhenPublishFails(t *testing.T) {
	cfg := assuranceAlertConfig{Webhook: "unused", Host: "coord-a", StateDir: t.TempDir()}
	unit := "parallaxd-verify-backup-primary.service"
	if err := publishAssurance(t.Context(), &recordingPublisher{}, cfg, unit, "failure", func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
	if err := publishAssurance(t.Context(), &recordingPublisher{err: errors.New("offline")}, cfg, unit, "success", nil); err == nil {
		t.Fatal("publish failure was swallowed")
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, unit+".failed")); err != nil {
		t.Fatalf("marker lost after failed resolve: %v", err)
	}
}

func TestAssuranceAlertRejectsBadInput(t *testing.T) {
	if err := runAssuranceAlert(t.Context(), "/nonexistent", "../../etc/passwd.service", "failure"); err == nil {
		t.Fatal("path-like unit accepted")
	}
	cfg := assuranceAlertConfig{Webhook: "unused", Host: "h", StateDir: t.TempDir()}
	if err := publishAssurance(t.Context(), &recordingPublisher{}, cfg, "x.service", "maybe", nil); err == nil {
		t.Fatal("unknown result accepted")
	}
}
