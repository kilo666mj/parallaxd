package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/coordinator"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

type fixture struct {
	dir, config, export string
	key                 string
}

func newFixture(t *testing.T, generated time.Time) fixture {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := wire.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	export := coordinator.Export{
		Version: 1, Coordinator: "coordinator", GeneratedAt: generated,
		Checks: []coordinator.StatusEntry{
			{Check: "website", Status: "up"},
			{Check: "api", Status: "down"},
			{Check: "internal-secret-db", Status: "up"},
		},
		Uptime: []coordinator.Uptime{{Check: "website", Uptime: 0.99951}},
	}
	env, err := wire.SignDocument(priv, "coordinator", export)
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{dir: dir, export: filepath.Join(dir, "export.json"), config: filepath.Join(dir, "status.json"), key: wire.EncodeKey(pub)}
	writeJSON(t, f.export, env)
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, f.config, map[string]any{
		"source": f.export, "coordinator_name": "coordinator", "coordinator_key": f.key,
		"output_dir": out, "title": "Example status", "max_age": "5m",
		"groups": []map[string]any{{"name": "Services", "items": []map[string]string{
			{"check": "website", "label": "Website"}, {"check": "api", "label": "Public API"},
		}}},
	})
	return f
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readPage(t *testing.T, f fixture) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.dir, "out", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestRendersOnlyListedChecksFromAVerifiedExport(t *testing.T) {
	now := time.Now().UTC()
	f := newFixture(t, now.Add(-time.Minute))
	if err := run(f.config, now); err != nil {
		t.Fatal(err)
	}
	page := readPage(t, f)
	for _, want := range []string{"Example status", "Partial outage", "Website", "Public API", "99.95%", `class="status down">Outage`, `class="status up">Operational`} {
		if !strings.Contains(page, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if strings.Contains(page, "internal-secret-db") {
		t.Fatal("an unlisted check was published")
	}
}

func TestRejectsExportSignedByAnotherKeyAndKeepsThePreviousPage(t *testing.T) {
	now := time.Now().UTC()
	f := newFixture(t, now)
	if err := run(f.config, now); err != nil {
		t.Fatal(err)
	}
	before := readPage(t, f)

	other := newFixture(t, now)
	raw, err := os.ReadFile(other.export)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.export, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(f.config, now.Add(time.Minute)); err == nil {
		t.Fatal("export signed with another key was accepted")
	}
	if readPage(t, f) != before {
		t.Fatal("a failed run replaced the page")
	}
}

func TestStaleExportIsShownAsOutOfDate(t *testing.T) {
	now := time.Now().UTC()
	f := newFixture(t, now.Add(-time.Hour))
	if err := run(f.config, now); err != nil {
		t.Fatal(err)
	}
	page := readPage(t, f)
	if !strings.Contains(page, "Status data is out of date") || strings.Contains(page, ">Outage<") || strings.Contains(page, ">Operational<") {
		t.Fatal("a stale export was rendered with live statuses")
	}
}

func TestConfigRequiresExplicitItems(t *testing.T) {
	f := newFixture(t, time.Now())
	writeJSON(t, f.config, map[string]any{
		"source": f.export, "coordinator_name": "coordinator", "coordinator_key": f.key,
		"output_dir": f.dir, "title": "x",
		"groups": []map[string]any{{"name": "g", "items": []map[string]string{{"check": "a", "component": "b"}}}},
	})
	if _, err := loadConfig(f.config); err == nil {
		t.Fatal("item naming both a check and a component was accepted")
	}
}

func TestRendersNoticesWithoutUnlistedNames(t *testing.T) {
	now := time.Now().UTC()
	cfg := config{Title: "Example status", MaxAge: duration(5 * time.Minute), Groups: []group{{Name: "Services", Items: []item{
		{Check: "website", Label: "Website"}, {Check: "api", Label: "Public API"},
	}}}}
	export := coordinator.Export{Version: 1, GeneratedAt: now, Checks: []coordinator.StatusEntry{{Check: "website", Status: "up"}, {Check: "api", Status: "up"}},
		Notices: []coordinator.ExportNotice{
			{ID: 3, Kind: "incident", Title: "Slow <logins>", State: "monitoring", Checks: []string{"api", "internal-secret-db"},
				Updates: []coordinator.ExportNoticeUpdate{{At: now, State: "monitoring", Message: "A fix is out."}, {At: now.Add(-time.Hour), State: "investigating", Message: "Looking into it."}}},
			{ID: 2, Kind: "maintenance", Title: "Database upgrade", State: "scheduled", StartsAt: now.Add(time.Hour), EndsAt: now.Add(2 * time.Hour),
				Updates: []coordinator.ExportNoticeUpdate{{At: now, State: "scheduled", Message: "Brief read-only period."}}},
			{ID: 1, Kind: "incident", Title: "Earlier outage", State: "resolved", ResolvedAt: now.Add(-time.Hour),
				Updates: []coordinator.ExportNoticeUpdate{{At: now.Add(-time.Hour), State: "resolved", Message: "Fixed."}}},
		}}
	p, _ := build(cfg, export, now)
	if len(p.Incidents) != 1 || len(p.Maintenance) != 1 || len(p.Past) != 1 {
		t.Fatalf("incidents=%d maintenance=%d past=%d", len(p.Incidents), len(p.Maintenance), len(p.Past))
	}
	if p.Overall != "All systems operational" {
		t.Fatalf("a notice changed the corroborated overall status: %q", p.Overall)
	}
	var out strings.Builder
	if err := pageTemplate.Execute(&out, p); err != nil {
		t.Fatal(err)
	}
	page := out.String()
	for _, want := range []string{"Current incidents", "Slow &lt;logins&gt;", "Monitoring", "Affects Public API", "A fix is out.", "Scheduled maintenance", "Recently resolved", "Earlier outage"} {
		if !strings.Contains(page, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if strings.Contains(page, "internal-secret-db") {
		t.Fatal("an unlisted check affected by a notice was published")
	}
	if strings.Index(page, "A fix is out.") > strings.Index(page, "Looking into it.") {
		t.Fatal("updates are not newest first")
	}
}
