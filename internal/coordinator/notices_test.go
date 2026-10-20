package coordinator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNoticeLifecyclePersistsAndExportsPublicOnes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "state.json")
	cfg := durableConfig(t, path, &fakeNotifier{}, nil)
	cfg.OperatorToken = "secret"
	cfg.Now = func() time.Time { return now }
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()
	call := func(method, path string, body any, want int) {
		t.Helper()
		if resp := maintenanceRequestTo(t, srv.URL+path, method, body); resp.StatusCode != want {
			t.Fatalf("%s %s status=%d, want %d", method, path, resp.StatusCode, want)
		}
	}

	for _, bad := range []map[string]any{
		{"actor": "alice", "kind": "incident", "title": "No message"},
		{"actor": "alice", "kind": "outage", "title": "Bad kind", "message": "x"},
		{"actor": "alice", "kind": "incident", "title": "Bad state", "state": "completed", "message": "x"},
		{"actor": "alice", "kind": "incident", "title": "Unknown check", "message": "x", "checks": []string{"nope"}},
		{"actor": "alice", "kind": "maintenance", "title": "No schedule", "message": "x"},
		{"actor": "alice", "kind": "incident", "title": strings.Repeat("t", maxNoticeTitle+1), "message": "x"},
	} {
		call(http.MethodPost, "/v1/notices", bad, http.StatusBadRequest)
	}

	// 1: public incident; 2: private incident; 3: public scheduled maintenance.
	call(http.MethodPost, "/v1/notices", map[string]any{"actor": "alice", "kind": "incident", "title": "Slow logins", "message": "Looking into it.", "public": true, "checks": []string{"svc"}}, http.StatusCreated)
	call(http.MethodPost, "/v1/notices", map[string]any{"actor": "alice", "kind": "incident", "title": "Internal only", "message": "Not for the page."}, http.StatusCreated)
	call(http.MethodPost, "/v1/notices", map[string]any{"actor": "alice", "kind": "maintenance", "title": "Database upgrade", "message": "Planned.", "public": true, "starts_at": now.Add(time.Hour), "ends_at": now.Add(2 * time.Hour)}, http.StatusCreated)

	call(http.MethodPost, "/v1/notices/1/updates", map[string]any{"actor": "bob", "state": "scheduled", "message": "wrong kind"}, http.StatusBadRequest)
	call(http.MethodPost, "/v1/notices/1/updates", map[string]any{"actor": "bob", "state": "identified", "message": "Found the cause."}, http.StatusOK)
	call(http.MethodPost, "/v1/notices/1/updates", map[string]any{"actor": "bob", "state": "resolved", "message": "Fixed."}, http.StatusOK)
	call(http.MethodPost, "/v1/notices/9/updates", map[string]any{"actor": "bob", "message": "x"}, http.StatusNotFound)
	call(http.MethodPut, "/v1/notices/1", map[string]any{"actor": "carol", "state": "monitoring"}, http.StatusBadRequest)
	call(http.MethodPut, "/v1/notices/1", map[string]any{"actor": "carol", "title": "Slow logins for some users", "public": true, "checks": []string{"svc"}}, http.StatusOK)

	n := c.Notices()[2]
	if n.ID != 1 || n.State != "resolved" || n.ResolvedAt.IsZero() || len(n.Updates) != 3 ||
		n.Title != "Slow logins for some users" || n.CreatedBy != "alice" || n.UpdatedBy != "carol" {
		t.Fatalf("notice=%+v", n)
	}

	export := c.Export()
	if len(export.Notices) != 2 || export.Notices[0].ID != 3 || export.Notices[1].ID != 1 {
		t.Fatalf("export notices=%+v", export.Notices)
	}
	if u := export.Notices[1].Updates; len(u) != 3 || u[0].Message != "Fixed." {
		t.Fatalf("export updates newest first=%+v", u)
	}
	raw, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"alice", "bob", "carol", "Internal only"} {
		if strings.Contains(string(raw), private) {
			t.Fatalf("export leaks %q: %s", private, raw)
		}
	}

	state, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted persistedState
	if err := json.Unmarshal(state, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Version != 9 || len(persisted.Notices) != 3 || persisted.NextNoticeID != 3 {
		t.Fatalf("persisted version=%d notices=%d next=%d", persisted.Version, len(persisted.Notices), persisted.NextNoticeID)
	}
	restored, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := restored.Notices(); len(got) != 3 || len(got[2].Updates) != 3 {
		t.Fatalf("restored notices=%+v", got)
	}

	// Reopening clears the resolution; a week after resolving, it leaves the export.
	call(http.MethodPost, "/v1/notices/1/updates", map[string]any{"actor": "bob", "state": "monitoring", "message": "Seeing it again."}, http.StatusOK)
	if c.Notices()[2].Open() != true {
		t.Fatal("update to an open state did not reopen the notice")
	}
	call(http.MethodPost, "/v1/notices/1/updates", map[string]any{"actor": "bob", "state": "resolved", "message": "Fixed for good."}, http.StatusOK)
	now = now.Add(exportNoticeWindow + time.Minute)
	if got := c.Export().Notices; len(got) != 1 || got[0].ID != 3 {
		t.Fatalf("old resolved notice still exported: %+v", got)
	}

	call(http.MethodDelete, "/v1/notices/2", map[string]any{"actor": "alice", "note": "mistake"}, http.StatusNoContent)
	call(http.MethodDelete, "/v1/notices/2", map[string]any{"actor": "alice"}, http.StatusNotFound)
	if got := c.Notices(); len(got) != 2 {
		t.Fatalf("after delete notices=%d", len(got))
	}
}

func TestExportNoticesStayWithinTextBudget(t *testing.T) {
	now := time.Now().UTC()
	long := strings.Repeat("x", maxNoticeMessage)
	var notices []Notice
	for i := range maxExportNotices {
		n := Notice{ID: uint64(i + 1), Kind: NoticeIncident, Title: "t", State: "investigating", Public: true}
		for range maxExportNoticeUpds {
			n.Updates = append(n.Updates, NoticeUpdate{At: now, State: "investigating", Message: long})
		}
		notices = append(notices, n)
	}
	text := 0
	for _, n := range exportNotices(notices, now) {
		text += len(n.Title)
		for _, u := range n.Updates {
			text += len(u.Message)
		}
	}
	if text > maxExportNoticeText {
		t.Fatalf("exported %d bytes of notice text, budget %d", text, maxExportNoticeText)
	}
}
