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
	"github.com/kilo666mj/parallaxd/internal/quorum"
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

func TestSilencesIsAnEmptyCollectionBeforeFirstSilence(t *testing.T) {
	c, err := New(durableConfig(t, "", &fakeNotifier{}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if silences := c.Silences(); silences == nil || len(silences) != 0 {
		t.Fatalf("Silences()=%v, want a non-nil empty collection", silences)
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
	for _, want := range []string{"Active incidents", "Create silence", "History", "Monitors", "Test from eligible probers", "Revision ledger", "Access control", "/v1/history/summary", "/v1/diagnostics", "/v1/monitors", "/v1/auth/login", "/v1/auth/users", "/assets/parallaxd-icon.png", "parallaxd_csrf", "sessionStorage"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard does not contain %q", want)
		}
	}
	for _, want := range []string{"incidents:[]", "silences:[]", "all=state.monitors||[]", "(state.incidents||[]).filter", "(state.silences||[]).filter", "$('history').innerHTML"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard does not contain empty-collection guard %q", want)
		}
	}
	if strings.Contains(body, cfg.OperatorToken) {
		t.Fatal("dashboard embedded the configured operator token")
	}
}

func TestDashboardServesBrandIcon(t *testing.T) {
	c, err := New(durableConfig(t, "", &fakeNotifier{}, nil))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/parallaxd-icon.png", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "image/png" {
		t.Errorf("Content-Type=%q", got)
	}
	if body := rec.Body.Bytes(); len(body) < 8 || !bytes.Equal(body[:8], []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("icon response is not a PNG")
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

func TestWebhookIncludesChatPresentation(t *testing.T) {
	var payload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := WebhookNotifier{
		URL: srv.URL, Username: "parallaxd", Channel: "parallaxd",
		IconEmoji: ":satellite:", IconURL: "https://example.invalid/parallaxd.png",
	}
	decided := time.Date(2026, 8, 22, 10, 30, 0, 0, time.FixedZone("CEST", 2*60*60))
	alert := Alert{
		Check: "svc", Target: "https://service.example/readyz", Kind: KindDown,
		At: decided, SuspectedAt: decided.Add(-2 * time.Minute), Escalation: "unacknowledged",
		Verdict: quorum.Verdict{
			Down: 3, Up: 1, Unknown: 1,
			Providers: []string{"hetzner", "oracle"}, Dissent: []string{"probe-c"},
			Reason: "3 of 5 probers reported down",
		},
	}
	if err := n.Notify(t.Context(), alert); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	for field, want := range map[string]string{
		"username": "parallaxd", "channel": "parallaxd", "icon_emoji": ":satellite:",
		"icon_url": "https://example.invalid/parallaxd.png",
	} {
		if got := payload[field]; got != want {
			t.Errorf("%s = %v, want %q", field, got, want)
		}
	}
	if _, ok := payload["text"]; ok {
		t.Error("chat payload duplicates attachment in top-level text")
	}
	attachments, ok := payload["attachments"].([]any)
	if !ok || len(attachments) != 1 {
		t.Fatalf("attachments = %#v", payload["attachments"])
	}
	attachment, ok := attachments[0].(map[string]any)
	if !ok {
		t.Fatalf("attachment = %#v", attachments[0])
	}
	if attachment["color"] != "#D24B4E" ||
		attachment["title"] != "DOWN — svc" ||
		attachment["text"] != "3 of 5 probers reported down" ||
		attachment["fallback"] == "" ||
		attachment["footer"] != "ESCALATION — unacknowledged" {
		t.Errorf("attachment = %#v", attachment)
	}
	fields, ok := attachment["fields"].([]any)
	if !ok || len(fields) != 6 {
		t.Fatalf("fields = %#v, want target, evidence, providers, dissent, decision, and detection time", attachment["fields"])
	}
	wantFields := map[string]string{
		"Target":             "https://service.example/readyz",
		"Evidence":           "3 down · 1 up · 1 unknown",
		"Providers":          "hetzner, oracle",
		"Dissenting probers": "probe-c",
		"Decided":            "2026-08-22T08:30:00Z",
		"Detection time":     "2m0s",
	}
	for _, raw := range fields {
		got := raw.(map[string]any)
		if want, exists := wantFields[got["title"].(string)]; !exists || got["value"] != want {
			t.Errorf("unexpected field = %#v", got)
		}
	}
}

func TestWebhookAttachmentColorsRecoveriesGreen(t *testing.T) {
	for _, kind := range []Kind{KindRecovered, KindReporting, KindRejoined, KindWatched, KindWatchRecovered} {
		if got := alertColor(kind); got != "#2ECC71" {
			t.Errorf("alertColor(%q) = %q, want green", kind, got)
		}
	}
	for _, kind := range []Kind{KindDown, KindSilent, KindIsolated, KindUnwatched, KindWatchLost} {
		if got := alertColor(kind); got != "#D24B4E" {
			t.Errorf("alertColor(%q) = %q, want red", kind, got)
		}
	}
}

func TestGenericWebhookRetainsTopLevelText(t *testing.T) {
	var payload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
	}))
	defer srv.Close()
	if err := (WebhookNotifier{URL: srv.URL}).Notify(t.Context(), Alert{Check: "svc", Kind: KindDown}); err != nil {
		t.Fatal(err)
	}
	if payload["text"] == "" || payload["attachments"] != nil {
		t.Errorf("generic payload = %#v", payload)
	}
}
