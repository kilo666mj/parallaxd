package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	tintwire "go.michaelspost.com/tintwire-go"
)

// assuranceAlertConfig is written by operations.yml next to each assurance
// unit. It holds a Tintwire webhook, so it is root-only on disk.
type assuranceAlertConfig struct {
	Webhook  string `json:"webhook"`
	Fallback string `json:"fallback_webhook,omitempty"`
	Channel  string `json:"channel,omitempty"`
	Source   string `json:"source,omitempty"`
	Host     string `json:"host"`
	StateDir string `json:"state_dir"`
}

type cardPublisher interface {
	Publish(context.Context, tintwire.Card) (tintwire.Result, error)
}

var assuranceUnit = regexp.MustCompile(`^[A-Za-z0-9@_.:-]{1,200}\.service$`)

// runAssuranceAlert is called by systemd OnFailure=/OnSuccess= hooks. A failure
// publishes a firing card and leaves a marker; a success publishes the matching
// resolved card only when a marker exists, so a healthy timer stays silent.
func runAssuranceAlert(ctx context.Context, configPath, unit, result string) error {
	if !assuranceUnit.MatchString(unit) {
		return fmt.Errorf("invalid unit name %q", unit)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var cfg assuranceAlertConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("%s: %w", configPath, err)
	}
	if cfg.Webhook == "" || cfg.Host == "" || cfg.StateDir == "" {
		return fmt.Errorf("%s: webhook, host and state_dir are required", configPath)
	}
	options := []tintwire.Option{tintwire.WithPrimaryRetries(2, 250*time.Millisecond)}
	if cfg.Fallback != "" {
		options = append(options, tintwire.WithMattermostFailover(cfg.Fallback))
	}
	client, err := tintwire.NewFromWebhook(cfg.Webhook, options...)
	if err != nil {
		return err
	}
	return publishAssurance(ctx, client, cfg, unit, result, journalTail)
}

func publishAssurance(ctx context.Context, client cardPublisher, cfg assuranceAlertConfig, unit, result string, tail func(string) string) error {
	marker := filepath.Join(cfg.StateDir, unit+".failed")
	source := cfg.Source
	if source == "" {
		source = "parallaxd"
	}
	card := tintwire.Card{
		Channel: cfg.Channel, Source: source,
		LifecycleKey: "parallaxd/assurance/" + cfg.Host + "/" + unit,
		Fields: []tintwire.Field{
			{Label: "Host", Value: cfg.Host},
			{Label: "Inspect", Value: "journalctl -u " + unit},
		},
	}
	switch result {
	case "failure":
		card.State, card.Severity = tintwire.StateFiring, tintwire.SeverityCritical
		card.Title = "ASSURANCE FAILED — " + unit + " on " + cfg.Host
		card.Summary = truncate(tail(unit), 500)
		if card.Summary == "" {
			card.Summary = "The unit failed; its journal had no recent output."
		}
		// The marker comes first: if publishing fails, the next success still
		// resolves whatever reached Tintwire through a retry or the fallback.
		if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600); err != nil {
			return err
		}
	case "success":
		if _, err := os.Stat(marker); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		card.State, card.Severity = tintwire.StateResolved, tintwire.SeveritySuccess
		card.Title = "ASSURANCE RECOVERED — " + unit + " on " + cfg.Host
		card.Summary = "The unit succeeded again."
	default:
		return fmt.Errorf("assurance result must be failure or success, not %q", result)
	}
	if _, err := client.Publish(ctx, card); err != nil {
		return err
	}
	if result == "success" {
		return os.Remove(marker)
	}
	return nil
}

// journalTail returns the unit's last log lines; best effort, because an
// alert without them is still worth sending.
func journalTail(unit string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "journalctl", "-u", unit, "-n", "12", "-o", "cat", "--no-pager").Output()
	return strings.TrimSpace(string(out))
}

func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	// Keep the end: the last lines usually say why it failed.
	return "…" + string(r[len(r)-max+1:])
}
