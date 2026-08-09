package coordinator

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

func durableConfig(t *testing.T, stateFile string, notifier Notifier, maintenance []Maintenance) Config {
	t.Helper()
	_, coordKey, err := wire.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := wire.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	chk := namedCheck("svc")
	chk.Quorum = check.Quorum{Agree: 1, Of: 1}
	chk.Prober = "probe-a"
	return Config{Name: "coordinator", Key: coordKey, Peers: []Peer{{Name: "probe-a", Provider: "one", PublicKey: pub}}, Checks: []check.Check{chk}, Notifier: notifier, Logger: discardLogger(), StateFile: stateFile, Maintenance: maintenance}
}

func TestIncidentsIsAnEmptyCollectionBeforeFirstIncident(t *testing.T) {
	c, err := New(durableConfig(t, "", &fakeNotifier{}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if incidents := c.Incidents(); incidents == nil || len(incidents) != 0 {
		t.Fatalf("Incidents()=%v, want a non-nil empty collection", incidents)
	}
}

func downResult(at time.Time) check.Result {
	return check.Result{Check: "svc", Prober: "probe-a", Vantage: check.VantageInternal, Status: check.StatusDown, At: at}
}

func TestStateAndIncidentHistorySurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	n := &fakeNotifier{}
	cfg := durableConfig(t, path, n, nil)
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Process(t.Context(), downResult(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := restored.Status()[0].Status; got != string(check.StatusDown) {
		t.Fatalf("restored status=%s", got)
	}
	incidents := restored.Incidents()
	if len(incidents) != 1 || !incidents[0].Active {
		t.Fatalf("restored incidents=%+v", incidents)
	}
}

func TestSuspectTimelineSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	cfg := durableConfig(t, path, &fakeNotifier{}, nil)
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Millisecond)
	last := first.Add(4 * time.Minute)
	st := c.stateFor("svc")
	st.mu.Lock()
	st.suspectedSince = first
	st.lastAttempt = last
	st.lastCorroboration = 1200 * time.Millisecond
	st.inconclusiveAttempts = 3
	st.lastInconclusive = "2 of 3 reported down, quorum needs 3"
	st.inconclusiveHistory = []CorroborationAttempt{{At: last, DurationMS: 1200, Reason: st.lastInconclusive, Counted: 2, Down: 2}}
	st.mu.Unlock()
	c.persist()

	restored, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	status := restored.Status()[0]
	if !status.SuspectedSince.Equal(first) || !status.LastAttempt.Equal(last) || status.LastCorroborationMS != 1200 || status.InconclusiveAttempts != 3 || status.LastInconclusive == "" || len(status.InconclusiveHistory) != 1 {
		t.Fatalf("restored suspect timeline = %+v", status)
	}
}

func TestMaintenanceSuppressesDeliveryButRecordsIncident(t *testing.T) {
	now := time.Now()
	n := &fakeNotifier{}
	cfg := durableConfig(t, "", n, []Maintenance{{Name: "deploy", StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Minute), Checks: []string{"svc"}}})
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Process(t.Context(), downResult(now))
	if err != nil {
		t.Fatal(err)
	}
	if n.count() != 0 {
		t.Fatalf("maintenance delivered %d notifications", n.count())
	}
	incidents := c.Incidents()
	if len(incidents) != 1 || !incidents[0].Suppressed || incidents[0].Maintenance != "deploy" {
		t.Fatalf("incidents=%+v", incidents)
	}
}

func TestIncidentLifecycleAndSilencesSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	n := &fakeNotifier{}
	cfg := durableConfig(t, path, n, nil)
	cfg.OperatorToken = "secret"
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := c.Process(t.Context(), downResult(now)); err != nil {
		t.Fatal(err)
	}
	if err := c.AcknowledgeIncident(1, "alice", "investigating"); err != nil {
		t.Fatal(err)
	}
	silence, err := c.CreateSilence(Silence{
		Name: "follow-up", StartsAt: now, EndsAt: now.Add(time.Hour),
		Checks: []string{"svc"}, CreatedBy: "alice", Comment: "working the incident",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ResolveIncident(1, "alice", "upstream issue confirmed"); err != nil {
		t.Fatal(err)
	}

	restored, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	incident := restored.Incidents()[0]
	if incident.Active || !incident.ManualResolution || incident.AcknowledgedBy != "alice" || incident.ResolvedBy != "alice" {
		t.Fatalf("restored incident=%+v", incident)
	}
	silences := restored.Silences()
	if len(silences) != 1 || silences[0].ID != silence.ID || silences[0].CreatedBy != "alice" {
		t.Fatalf("restored silences=%+v", silences)
	}
}

func TestSilenceSuppressesThenCancellationReleasesActiveIncident(t *testing.T) {
	now := time.Now().UTC()
	n := &fakeNotifier{}
	cfg := durableConfig(t, "", n, nil)
	cfg.Now = func() time.Time { return now }
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	silence, err := c.CreateSilence(Silence{
		Name: "deploy", EndsAt: now.Add(time.Hour), Checks: []string{"svc"}, CreatedBy: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Process(t.Context(), downResult(now)); err != nil {
		t.Fatal(err)
	}
	if got := n.count(); got != 0 {
		t.Fatalf("silenced incident delivered %d notifications", got)
	}
	incident := c.Incidents()[0]
	if !incident.Suppressed || incident.SilenceID != silence.ID {
		t.Fatalf("incident=%+v", incident)
	}
	if err := c.CancelSilence(silence.ID, "alice", "deploy complete"); err != nil {
		t.Fatal(err)
	}
	c.releaseSuppressions(t.Context())
	if got := n.count(); got != 1 {
		t.Fatalf("cancelling silence delivered %d notifications, want 1", got)
	}
	if c.Incidents()[0].Suppressed {
		t.Fatal("incident remained suppressed after silence cancellation")
	}
}

func TestOperatorEndpointsRequireBearerAndRecordActor(t *testing.T) {
	cfg := durableConfig(t, "", &fakeNotifier{}, nil)
	cfg.OperatorToken = "secret"
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Process(t.Context(), downResult(time.Now())); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	body := []byte(`{"actor":"alice","note":"looking"}`)
	resp, err := http.Post(srv.URL+"/v1/incidents/1/acknowledge", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/incidents/1/acknowledge", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("authorized status=%d", resp.StatusCode)
	}
	if got := c.Incidents()[0].AcknowledgedBy; got != "alice" {
		t.Fatalf("acknowledged_by=%q", got)
	}
}

func TestOperatorEndpointsAreDisabledByDefault(t *testing.T) {
	c, err := New(durableConfig(t, "", &fakeNotifier{}, nil))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/incidents/1/acknowledge", "application/json", strings.NewReader(`{"actor":"alice"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want operator API disabled", resp.StatusCode)
	}
}

func TestDashboardExposesManagementControlsWithoutEmbeddingToken(t *testing.T) {
	cfg := durableConfig(t, "", &fakeNotifier{}, nil)
	cfg.OperatorToken = "must-not-appear-in-html"
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options=%q", got)
	}
	body := rec.Body.String()
	for _, want := range []string{"Active incidents", "Create silence", "History", "Monitors", "Test from all probers", "Monitor revisions", "/v1/history/summary", "/v1/diagnostics", "/v1/monitors", "sessionStorage"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard does not contain %q", want)
		}
	}
	for _, want := range []string{"incidents:i||[]", "silences:s||[]", "$('history').innerHTML"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard does not contain empty-collection guard %q", want)
		}
	}
	if strings.Contains(body, cfg.OperatorToken) {
		t.Fatal("dashboard embedded the configured operator token")
	}
}

func TestDiagnosticsExposeRejectionsAssignmentsAndNotifierFailure(t *testing.T) {
	n := &fakeNotifier{err: errors.New("webhook unavailable")}
	c, err := New(durableConfig(t, "", n, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Process(t.Context(), downResult(time.Now())); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/results", "application/json", bytes.NewBufferString("not-json"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	diagnosticResp, err := http.Get(srv.URL + "/v1/diagnostics")
	if err != nil {
		t.Fatal(err)
	}
	defer diagnosticResp.Body.Close()
	var got Diagnostics
	if err := json.NewDecoder(diagnosticResp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.RejectedResults["malformed_envelope"] != 1 {
		t.Fatalf("rejections=%v", got.RejectedResults)
	}
	if got.Notifications.Attempts != 1 || got.Notifications.Failures != 1 || got.Notifications.LastError == "" {
		t.Fatalf("notifications=%+v", got.Notifications)
	}
	if len(got.Assignments) != 1 || got.Assignments[0].EffectiveOwner != "probe-a" {
		t.Fatalf("assignments=%+v", got.Assignments)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWebhookFailureDoesNotExposeSecretURL(t *testing.T) {
	n := WebhookNotifier{
		URL: "https://hooks.example.invalid/notify?token=super-secret",
		Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		})},
	}
	err := n.Notify(t.Context(), Alert{Check: "svc", Kind: KindDown, At: time.Now()})
	if err == nil {
		t.Fatal("Notify succeeded")
	}
	if strings.Contains(err.Error(), "super-secret") || strings.Contains(err.Error(), "hooks.example") {
		t.Fatalf("error exposed webhook URL: %v", err)
	}
}
