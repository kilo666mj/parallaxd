package coordinator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

func monitorRequest(t *testing.T, c *Coordinator, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer secret")
	recorder := httptest.NewRecorder()
	c.Handler().ServeHTTP(recorder, request)
	return recorder
}

func testMonitor(name string) MonitorSpec {
	return MonitorSpec{Name: name, Enabled: true, Kind: check.KindTCP, Target: "example.com:443",
		Vantage: check.VantagePublic, Interval: "1m", Timeout: "10s",
		Quorum: check.Quorum{Agree: 1, Of: 1}, Prober: "probe-a", Probers: []string{"probe-a"}}
}

func TestMonitorCRUDPersistsAndRollsBack(t *testing.T) {
	dir := t.TempDir()
	cfg := durableConfig(t, filepath.Join(dir, "state.json"), &fakeNotifier{}, nil)
	cfg.OperatorToken = "secret"
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	monitor := testMonitor("new-service")
	response := monitorRequest(t, c, http.MethodPost, "/v1/monitors", map[string]any{"actor": "alice", "monitor": monitor})
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	if _, ok := c.checkByName(monitor.Name); !ok {
		t.Fatal("created monitor is not active")
	}
	if assigned := c.Assignments()["probe-a"]; len(assigned) != 2 {
		t.Fatalf("assignments=%v", assigned)
	}

	monitor.Enabled = false
	response = monitorRequest(t, c, http.MethodPut, "/v1/monitors/new-service", map[string]any{"actor": "bob", "monitor": monitor})
	if response.Code != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", response.Code, response.Body.String())
	}
	if _, ok := c.checkByName(monitor.Name); ok {
		t.Fatal("disabled monitor remains active")
	}
	got := c.monitorList()
	if len(got) != 2 {
		t.Fatalf("monitor list=%+v", got)
	}
	for _, item := range got {
		if item.Name == monitor.Name && item.Enabled {
			t.Fatalf("monitor list=%+v", got)
		}
	}

	restored, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := restored.checkByName(monitor.Name); ok {
		t.Fatal("disabled monitor became active after restart")
	}
	if revisions := restored.monitorRevisionList(); len(revisions) != 3 || revisions[1].Actor != "alice" || revisions[2].Actor != "bob" {
		t.Fatalf("restored revisions=%+v", revisions)
	}

	response = monitorRequest(t, restored, http.MethodPost, "/v1/monitors/revisions/2/rollback", map[string]any{"actor": "carol"})
	if response.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", response.Code, response.Body.String())
	}
	if _, ok := restored.checkByName(monitor.Name); !ok {
		t.Fatal("rollback did not re-enable monitor")
	}

	response = monitorRequest(t, restored, http.MethodDelete, "/v1/monitors/new-service", map[string]any{"actor": "dave"})
	if response.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", response.Code, response.Body.String())
	}
	if restored.monitorKnown(monitor.Name) {
		t.Fatal("deleted monitor remains in catalogue")
	}
}

func TestMonitorValidationRejectsUnsafeChanges(t *testing.T) {
	cfg := durableConfig(t, filepath.Join(t.TempDir(), "state.json"), &fakeNotifier{}, nil)
	cfg.OperatorToken = "secret"
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	invalid := testMonitor("bad")
	invalid.Timeout = "2m"
	response := monitorRequest(t, c, http.MethodPost, "/v1/monitors/validate", map[string]any{"actor": "alice", "monitor": invalid})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid monitor status=%d body=%s", response.Code, response.Body.String())
	}
	unauthorized := httptest.NewRecorder()
	c.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/v1/monitors", bytes.NewReader([]byte(`{}`))))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}
	unauthorized = httptest.NewRecorder()
	c.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/monitors", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized catalogue read status=%d", unauthorized.Code)
	}
}

func TestMonitorCatalogueReplicatesToStandby(t *testing.T) {
	primaryCfg := durableConfig(t, filepath.Join(t.TempDir(), "primary.json"), &fakeNotifier{}, nil)
	primaryCfg.OperatorToken = "secret"
	primary, err := New(primaryCfg)
	if err != nil {
		t.Fatal(err)
	}
	monitor := testMonitor("replicated")
	if response := monitorRequest(t, primary, http.MethodPost, "/v1/monitors", map[string]any{"actor": "alice", "monitor": monitor}); response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}

	dir := t.TempDir()
	standbyCfg := durableConfig(t, filepath.Join(dir, "state.json"), &fakeNotifier{}, nil)
	standbyCfg.HistoryFile = filepath.Join(dir, "history.jsonl")
	standbyCfg.HA = HAConfig{Role: HARoleStandby, PrimaryURL: "http://primary.example", Token: "secret"}
	standby, err := New(standbyCfg)
	if err != nil {
		t.Fatal(err)
	}
	document := replicaDocument{Version: 1, GeneratedAt: time.Now().UTC(), State: primary.snapshot()}
	if err := standby.applyReplica(document); err != nil {
		t.Fatal(err)
	}
	if _, ok := standby.checkByName(monitor.Name); !ok {
		t.Fatal("replicated monitor is not active on standby")
	}
	if revisions := standby.monitorRevisionList(); len(revisions) != 2 || revisions[1].Subject != monitor.Name {
		t.Fatalf("replicated revisions=%+v", revisions)
	}
}
