package coordinator

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

func TestStandbyReplicatesStateHistoryAndOutboxThenPromotes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	primaryNotifier := &fakeNotifier{err: errors.New("webhook unavailable")}
	primaryCfg := durableConfig(t, "", primaryNotifier, nil)
	primaryCfg.Now = func() time.Time { return now }
	primaryCfg.HA = HAConfig{Role: HARolePrimary, Token: "replica-secret"}
	primary, err := New(primaryCfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := primary.Process(t.Context(), resultAt(check.StatusDown, now)); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(primary.Handler())
	defer server.Close()

	unauthorized, err := http.Get(server.URL + "/v1/replica")
	if err != nil {
		t.Fatal(err)
	}
	unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized replica status=%d", unauthorized.StatusCode)
	}

	standbyNotifier := &fakeNotifier{}
	dir := t.TempDir()
	standbyCfg := durableConfig(t, filepath.Join(dir, "state.json"), standbyNotifier, nil)
	standbyCfg.HistoryFile = filepath.Join(dir, "history.jsonl")
	standbyCfg.Now = func() time.Time { return now }
	standbyCfg.OperatorToken = "operator-secret"
	standbyCfg.HA = HAConfig{Role: HARoleStandby, PrimaryURL: server.URL, Token: "replica-secret", Interval: time.Second}
	standby, err := New(standbyCfg)
	if err != nil {
		t.Fatal(err)
	}
	standby.syncReplica(t.Context())
	if status := standby.Status()[0]; status.Status != string(check.StatusDown) {
		t.Fatalf("replicated status=%+v", status)
	}
	if incidents := standby.Incidents(); len(incidents) != 1 || !incidents[0].Active {
		t.Fatalf("replicated incidents=%+v", incidents)
	}
	if got := standby.History("svc", time.Time{}, 10); len(got) != 1 {
		t.Fatalf("replicated history=%+v", got)
	}
	if got := standby.Outbox(); len(got) != 1 || got[0].Alert.Kind != KindDown {
		t.Fatalf("replicated outbox=%+v", got)
	}
	if status := standby.HAStatus(); status.Active || status.LastReplicaSync.IsZero() || status.LastReplicationError != "" {
		t.Fatalf("HA status=%+v", status)
	}

	// The inclusive cursor may return the boundary observation again; IDs
	// make repeated pulls idempotent.
	standby.syncReplica(t.Context())
	if got := standby.History("svc", time.Time{}, 10); len(got) != 1 {
		t.Fatalf("duplicate history after second sync=%+v", got)
	}
	now = now.Add(time.Minute)
	if _, err := primary.Process(t.Context(), resultAt(check.StatusDown, now)); err != nil {
		t.Fatal(err)
	}
	standby.syncReplica(t.Context())
	if got := standby.History("svc", time.Time{}, 10); len(got) != 2 {
		t.Fatalf("incremental history=%+v", got)
	}

	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/v1/assignments", nil),
		httptest.NewRequest(http.MethodPost, "/v1/results", strings.NewReader("{}")),
	} {
		recorder := httptest.NewRecorder()
		standby.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s status=%d", request.Method, request.URL.Path, recorder.Code)
		}
	}

	promote := func(confirm bool) *httptest.ResponseRecorder {
		body := []byte(`{"actor":"alice","confirm_primary_fenced":` + map[bool]string{true: "true", false: "false"}[confirm] + `}`)
		request := httptest.NewRequest(http.MethodPost, "/v1/ha/promote", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer operator-secret")
		recorder := httptest.NewRecorder()
		standby.Handler().ServeHTTP(recorder, request)
		return recorder
	}
	if recorder := promote(false); recorder.Code != http.StatusConflict {
		t.Fatalf("unconfirmed promotion status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder := promote(true); recorder.Code != http.StatusOK {
		t.Fatalf("promotion status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if standby.isStandby() || !standby.HAStatus().Promoted {
		t.Fatal("standby did not become active")
	}

	now = now.Add(time.Minute)
	standby.processDeliveries(t.Context())
	if len(standby.Outbox()) != 0 || standbyNotifier.count() != 1 {
		t.Fatalf("promoted delivery outbox=%+v alerts=%+v", standby.Outbox(), standbyNotifier.all())
	}
	restored, err := New(standbyCfg)
	if err != nil {
		t.Fatal(err)
	}
	if restored.isStandby() || !restored.HAStatus().Promoted || restored.HAStatus().PromotedBy != "alice" {
		t.Fatalf("restored HA status=%+v", restored.HAStatus())
	}
}

func TestStandbyRunPromotionCancelsBlockedReplication(t *testing.T) {
	started := make(chan struct{})
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer primary.Close()
	cfg := durableConfig(t, filepath.Join(t.TempDir(), "state.json"), &fakeNotifier{}, nil)
	cfg.HistoryFile = filepath.Join(t.TempDir(), "history.jsonl")
	cfg.HA = HAConfig{Role: HARoleStandby, PrimaryURL: primary.URL, Token: "secret", Timeout: time.Minute}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	<-started
	if err := c.promote("alice", true); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for c.isStandby() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.isStandby() {
		t.Fatal("promotion did not cancel blocked replication")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestStandbyConfigurationRequiresDurableFilesAndToken(t *testing.T) {
	cfg := durableConfig(t, "", &fakeNotifier{}, nil)
	cfg.HA = HAConfig{Role: HARoleStandby, PrimaryURL: "http://primary.example"}
	if _, err := New(cfg); err == nil {
		t.Fatal("standby without durable files/token was accepted")
	}
}

func TestPromotionRemainsStandbyWhenStateCannotBePersisted(t *testing.T) {
	dir := t.TempDir()
	cfg := durableConfig(t, filepath.Join(dir, "state.json"), &fakeNotifier{}, nil)
	cfg.HistoryFile = filepath.Join(dir, "history.jsonl")
	cfg.HA = HAConfig{Role: HARoleStandby, PrimaryURL: "http://primary.example", Token: "secret"}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(parent, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	c.cfg.StateFile = filepath.Join(parent, "state.json")
	if err := c.promote("alice", true); err == nil {
		t.Fatal("promotion succeeded without durable state")
	}
	if !c.isStandby() || c.HAStatus().Promoted {
		t.Fatalf("failed promotion became active: %+v", c.HAStatus())
	}
}
