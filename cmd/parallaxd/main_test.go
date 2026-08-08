package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kilo666mj/parallaxd/internal/wire"
)

func validConfigFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	pubA, priv, err := wire.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubB, _, err := wire.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "private")
	if err := os.WriteFile(keyFile, []byte(wire.EncodeKey(priv)), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{
		"name":            "coordinator",
		"key_file":        keyFile,
		"fan_out_timeout": "20s",
		"mesh_max_age":    "3m",
		"probers": []map[string]any{
			{"name": "a", "url": "http://127.0.0.1:1", "provider": "one", "public_key": wire.EncodeKey(pubA)},
			{"name": "b", "url": "http://127.0.0.1:2", "provider": "two", "public_key": wire.EncodeKey(pubB)},
		},
		"checks": []map[string]any{{
			"name": "site", "kind": "http", "target": "https://example.com", "vantage": "public",
			"interval": "1m", "timeout": "15s",
			"quorum": map[string]any{"agree": 2, "of": 2, "distinct_providers": true},
		}},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "coordinator.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateConfigUsesStartupValidationWithoutState(t *testing.T) {
	path := validConfigFile(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := validateConfig(path, log); err != nil {
		t.Fatalf("validateConfig: %v", err)
	}
}

func TestLoadConfigRejectsUnknownAndTrailingFields(t *testing.T) {
	path := validConfigFile(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	validRaw := append([]byte(nil), raw...)

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["fanout_timeout"] = "20s"
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}

	if err := os.WriteFile(path, append(validRaw, []byte(` {}`)...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("trailing value error = %v", err)
	}
}

func TestLoadConfigRejectsInvalidNotificationDestination(t *testing.T) {
	path := validConfigFile(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["notification_destinations"] = []map[string]any{{"name": "pager", "webhook": "not-a-url"}}
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "absolute http") {
		t.Fatalf("invalid destination error = %v", err)
	}
}

func TestValidateConfigAcceptsNotificationRoutingAndEscalation(t *testing.T) {
	path := validConfigFile(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["notification_destinations"] = []map[string]any{{"name": "pager", "webhook": "https://pager.example/events"}}
	doc["notification_routes"] = []map[string]any{{"name": "public down", "destination": "pager", "checks": []string{"site"}, "kinds": []string{"down"}}}
	doc["escalations"] = []map[string]any{{"name": "unacked", "destination": "pager", "after": "10m", "checks": []string{"site"}, "kinds": []string{"down"}}}
	doc["notification_retry_initial"] = "10s"
	doc["notification_retry_max"] = "5m"
	doc["notification_retry_interval"] = "2s"
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateConfig(path, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("validateConfig: %v", err)
	}
}
