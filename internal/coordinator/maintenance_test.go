package coordinator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecurringMaintenanceIsActiveInEachOccurrence(t *testing.T) {
	start := time.Date(2026, 10, 18, 3, 0, 0, 0, time.UTC)
	m := Maintenance{Name: "nightly", StartsAt: start, EndsAt: start.Add(time.Hour), Every: "24h"}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		at   time.Time
		want bool
	}{
		{start.Add(-time.Minute), false},
		{start, true},
		{start.Add(59 * time.Minute), true},
		{start.Add(time.Hour), false},
		{start.Add(23 * time.Hour), false},
		{start.Add(24*time.Hour + 30*time.Minute), true},
		{start.Add(10*24*time.Hour + 30*time.Minute), true},
	} {
		if got := m.active(tc.at); got != tc.want {
			t.Errorf("active(%s)=%v, want %v", tc.at, got, tc.want)
		}
	}
	for _, every := range []string{"1h", "30m", "soon", "-24h"} {
		bad := m
		bad.Every = every
		if bad.Validate() == nil {
			t.Errorf("every %q was accepted", every)
		}
	}
}

func maintenanceRequestTo(t *testing.T, url, method string, body any) *http.Response {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(method, url, bytes.NewReader(encoded))
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

func TestManagedMaintenanceSuppressesPersistsAndReleases(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "state.json")
	n := &fakeNotifier{}
	cfg := durableConfig(t, path, n, []Maintenance{{Name: "configured", StartsAt: now.Add(time.Hour), EndsAt: now.Add(2 * time.Hour)}})
	cfg.OperatorToken = "secret"
	cfg.Now = func() time.Time { return now }
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	window := map[string]any{"actor": "alice", "name": "patching", "starts_at": now.Add(-time.Minute), "ends_at": now.Add(time.Hour), "every": "168h", "checks": []string{"svc"}}
	if resp := maintenanceRequestTo(t, srv.URL+"/v1/maintenance", http.MethodPost, window); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%d", resp.StatusCode)
	}
	if resp := maintenanceRequestTo(t, srv.URL+"/v1/maintenance", http.MethodPost, window); resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate create status=%d", resp.StatusCode)
	}
	if resp := maintenanceRequestTo(t, srv.URL+"/v1/maintenance", http.MethodPost, map[string]any{"actor": "alice", "name": "typo", "ends_at": now.Add(time.Hour), "checks": []string{"nope"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown check status=%d", resp.StatusCode)
	}
	if resp := maintenanceRequestTo(t, srv.URL+"/v1/maintenance/configured", http.MethodDelete, map[string]any{"actor": "alice"}); resp.StatusCode != http.StatusConflict {
		t.Fatalf("delete configured status=%d", resp.StatusCode)
	}

	if _, err := c.Process(t.Context(), downResult(now)); err != nil {
		t.Fatal(err)
	}
	if got := n.count(); got != 0 {
		t.Fatalf("maintenance delivered %d notifications", got)
	}
	if incident := c.Incidents()[0]; !incident.Suppressed || incident.Maintenance != "patching" {
		t.Fatalf("incident=%+v", incident)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state persistedState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	if state.Version != 8 || len(state.Maintenance) != 1 {
		t.Fatalf("persisted version=%d maintenance=%+v", state.Version, state.Maintenance)
	}
	restored, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	windows := restored.MaintenanceWindows()
	if len(windows) != 2 || windows[0].Source != maintenanceFromConfig || windows[1].Source != maintenanceFromAPI ||
		windows[1].Every != "168h" || windows[1].CreatedBy != "alice" {
		t.Fatalf("restored windows=%+v", windows)
	}

	update := map[string]any{"actor": "bob", "starts_at": now.Add(-time.Minute), "ends_at": now.Add(30 * time.Minute), "checks": []string{"svc"}}
	if resp := maintenanceRequestTo(t, srv.URL+"/v1/maintenance/patching", http.MethodPut, update); resp.StatusCode != http.StatusOK {
		t.Fatalf("update status=%d", resp.StatusCode)
	}
	if got := n.count(); got != 0 {
		t.Fatalf("updated window still covers the incident but delivered %d", got)
	}
	if w := c.MaintenanceWindows()[1]; w.Every != "" || w.CreatedBy != "alice" || w.UpdatedBy != "bob" || !w.EndsAt.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("updated window=%+v", w)
	}
	if resp := maintenanceRequestTo(t, srv.URL+"/v1/maintenance/patching", http.MethodDelete, map[string]any{"actor": "alice", "note": "done"}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d", resp.StatusCode)
	}
	if got := n.count(); got != 1 {
		t.Fatalf("deleting the window delivered %d notifications, want 1", got)
	}
	if resp := maintenanceRequestTo(t, srv.URL+"/v1/maintenance/patching", http.MethodDelete, map[string]any{"actor": "alice"}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("second delete status=%d", resp.StatusCode)
	}
}
