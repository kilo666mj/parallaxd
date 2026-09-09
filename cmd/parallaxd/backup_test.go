package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyBackupRestoresCopiesAndFailsClosed(t *testing.T) {
	path := validConfigFile(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, field := range []string{"key_file", "operator_token_file"} {
		data, err := os.ReadFile(doc[field].(string))
		if err != nil {
			t.Fatal(err)
		}
		doc[field] = "/etc/parallaxd/" + field
		write(doc[field].(string), string(data))
	}
	doc["state_file"] = "/var/lib/parallaxd/state.json"
	doc["history_file"] = "/var/lib/parallaxd/history.jsonl"
	doc["prometheus"] = []map[string]any{{
		"name": "site", "url": "http://127.0.0.1:9090", "allow_insecure": true,
		"match_labels":      map[string]string{"job": "node"},
		"bearer_token_file": "/etc/parallaxd/prometheus-token",
	}}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	write("/etc/parallaxd/coordinator.json", string(encoded))
	state := `{"version":1,"checks":{}}`
	history := "{\"check\":\"site\",\"received_at\":\"2000-01-01T00:00:00Z\"}\n"
	write(doc["state_file"].(string), state)
	write(doc["history_file"].(string), history)
	write("/etc/parallaxd/prometheus-token", "metrics-token\n")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	verify := func() error { return verifyBackup(root, "/etc/parallaxd/coordinator.json", log) }
	if err := verify(); err != nil {
		t.Fatal(err)
	}
	// Normal restore compacts this expired journal; the backup must survive.
	got, err := os.ReadFile(filepath.Join(root, doc["history_file"].(string)))
	if err != nil || string(got) != history {
		t.Fatalf("backup modified: %q, %v", got, err)
	}
	write(doc["history_file"].(string), "{broken\n")
	if err := verify(); err == nil || !strings.Contains(err.Error(), "malformed observation") {
		t.Fatalf("corrupt journal: %v", err)
	}
	write(doc["history_file"].(string), history)
	write(doc["state_file"].(string), `{"version":99}`)
	if err := verify(); err == nil {
		t.Fatal("accepted unsupported state")
	}
	write(doc["state_file"].(string), state)
	if err := os.Remove(filepath.Join(root, "/etc/parallaxd/prometheus-token")); err != nil {
		t.Fatal(err)
	}
	if err := verify(); err == nil || !strings.Contains(err.Error(), "prometheus-token") {
		t.Fatalf("accepted missing Prometheus credential: %v", err)
	}
	write("/etc/parallaxd/prometheus-token", "metrics-token\n")
	key := filepath.Join(root, doc["key_file"].(string))
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := verify(); err == nil {
		t.Fatal("accepted missing key")
	}
	if err := os.Symlink(path, key); err != nil {
		t.Fatal(err)
	}
	if err := verify(); err == nil {
		t.Fatal("followed symlink outside backup")
	}
}
