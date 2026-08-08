package coordinator

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

func historyConfig(t *testing.T, path string, kind check.Kind) Config {
	t.Helper()
	cfg := durableConfig(t, "", &fakeNotifier{}, nil)
	cfg.HistoryFile = path
	cfg.HistoryRetention = 24 * time.Hour
	cfg.HistoryMaxPerCheck = 100
	cfg.Checks[0].Kind = kind
	switch kind {
	case check.KindDNS:
		cfg.Checks[0].Target = "example.com"
		cfg.Checks[0].DNSRecord = "A"
	case check.KindTLS:
		cfg.Checks[0].Target = "example.com:443"
	}
	return cfg
}

func TestObservationHistorySurvivesRestartAndSummarizesDNS(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "observations.jsonl")
	cfg := historyConfig(t, path, check.KindDNS)
	cfg.Now = func() time.Time { return now }
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := resultAt(check.StatusUp, now)
	r.Latency = 150 * time.Millisecond
	r.Detail = "192.0.2.10\n192.0.2.11"
	if _, err := c.Process(t.Context(), r); err != nil {
		t.Fatal(err)
	}

	observations := c.History("svc", time.Time{}, 10)
	if len(observations) != 1 || observations[0].LatencyMS != 150 || len(observations[0].DNSAnswers) != 2 {
		t.Fatalf("observations = %+v", observations)
	}
	summaries := c.HistorySummaries()
	if len(summaries) != 1 || summaries[0].Availability != 1 || summaries[0].P95LatencyMS != 150 || len(summaries[0].DNSAnswers) != 2 {
		t.Fatalf("summaries = %+v", summaries)
	}
	if diagnostics := c.DiagnosticState().History; diagnostics.Retained != 1 || diagnostics.LastWrite.IsZero() || diagnostics.LastError != "" {
		t.Fatalf("history diagnostics = %+v", diagnostics)
	}
	restored, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := restored.History("svc", time.Time{}, 10); len(got) != 1 || got[0].Detail != r.Detail {
		t.Fatalf("restored history = %+v", got)
	}
}

func TestHistoryWriteFailureIsDiagnostic(t *testing.T) {
	now := time.Now().UTC()
	blockedParent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedParent, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := historyConfig(t, "", check.KindTCP)
	cfg.Now = func() time.Time { return now }
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.cfg.HistoryFile = filepath.Join(blockedParent, "observations.jsonl")
	if _, err := c.Process(t.Context(), resultAt(check.StatusUp, now)); err != nil {
		t.Fatal(err)
	}
	diagnostics := c.DiagnosticState().History
	if diagnostics.WriteFailures != 1 || diagnostics.LastError == "" || diagnostics.Retained != 1 {
		t.Fatalf("history diagnostics = %+v", diagnostics)
	}
}

func TestObservationHistoryExtractsTLSExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cfg := historyConfig(t, "", check.KindTLS)
	cfg.Now = func() time.Time { return now }
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := resultAt(check.StatusUp, now)
	r.Latency = 80 * time.Millisecond
	r.Detail = "TLS 304; example.com; expires " + now.Add(45*24*time.Hour).Format(time.RFC3339)
	if _, err := c.Process(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	summary := c.HistorySummaries()[0]
	if summary.TLSDaysRemaining != 45 || summary.TLSExpiresAt.IsZero() {
		t.Fatalf("TLS summary = %+v", summary)
	}
}

func TestObservationHistoryRetentionCapsJournalOnRestart(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "observations.jsonl")
	cfg := historyConfig(t, path, check.KindTCP)
	cfg.HistoryMaxPerCheck = 2
	cfg.Now = func() time.Time { return now }
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		r := resultAt(check.StatusUp, now)
		r.Latency = time.Duration(10+i) * time.Millisecond
		if _, err := c.Process(t.Context(), r); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}
	if got := c.History("svc", time.Time{}, 10); len(got) != 2 || got[0].LatencyMS != 11 {
		t.Fatalf("bounded history = %+v", got)
	}
	restored, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := restored.History("svc", time.Time{}, 10); len(got) != 2 || got[0].LatencyMS != 11 {
		t.Fatalf("compacted history = %+v", got)
	}
}

func TestHistoryEndpointValidatesQuery(t *testing.T) {
	c, err := New(historyConfig(t, "", check.KindTCP))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/history?check=missing", "/v1/history?since=yesterday", "/v1/history?limit=10001"} {
		recorder := httptest.NewRecorder()
		c.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%s status=%d", path, recorder.Code)
		}
	}
}

func TestHistorySummaryDoesNotBiasAvailabilityWithCorroboration(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 3, Of: 3}, nil)
	h.target.down()
	if _, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown)); err != nil {
		t.Fatal(err)
	}
	summary := h.coord.HistorySummaries()[0]
	if summary.Samples != 3 || summary.Down != 1 || summary.Corroborations != 2 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestHistoryAvailabilityTreatsUnmetQuorumAsUnknown(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 3, Of: 3}, nil)
	h.target.down()
	h.probers["probe-c"].server.Close()
	if _, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown)); err != nil {
		t.Fatal(err)
	}
	summary := h.coord.HistorySummaries()[0]
	if summary.Down != 0 || summary.Unknown != 1 || summary.Corroborations != 1 {
		t.Fatalf("summary = %+v", summary)
	}
}
