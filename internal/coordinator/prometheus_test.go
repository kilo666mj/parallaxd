package coordinator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPrometheusHostMetricsAreNormalizedAndBounded(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		query := r.URL.Query().Get("query")
		if !strings.Contains(query, `job="node"`) {
			t.Errorf("query does not contain configured match label: %s", query)
		}
		metric := map[string]string{"instance": "node-a:9100"}
		value := "1"
		switch {
		case strings.Contains(query, "node_uname_info"):
			metric["nodename"] = "node-a"
		case strings.Contains(query, "node_cpu_seconds_total"):
			value = "25.5"
		case strings.Contains(query, "node_memory_MemAvailable_bytes"):
			value = "62.25"
		case strings.Contains(query, "node_filesystem_avail_bytes"):
			value = "81.5"
		case strings.Contains(query, "node_load1"):
			value = "1.75"
		case strings.Contains(query, "node_boot_time_seconds"):
			value = "86400"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]any{"resultType": "vector", "result": []any{
				map[string]any{"metric": metric, "value": []any{1234, value}},
			}},
		})
	}))
	defer server.Close()

	cfg := durableConfig(t, "", &fakeNotifier{}, nil)
	cfg.Prometheus = []PrometheusSource{{
		Name: "site", URL: server.URL, AllowInsecure: true,
		MatchLabels: map[string]string{"job": "node"}, Client: server.Client(),
	}}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	c.handleHostMetrics(recorder, httptest.NewRequest(http.MethodGet, "/v1/metrics/hosts", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	c.handleHostMetrics(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/metrics/hosts", nil))
	var got []HostMetricsSource
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 7 {
		t.Fatalf("queries=%d, want 7 after cached second read", calls.Load())
	}
	if len(got) != 1 || len(got[0].Hosts) != 1 {
		t.Fatalf("sources=%+v", got)
	}
	host := got[0].Hosts[0]
	if host.Instance != "node-a:9100" || host.Hostname != "node-a" || host.Up == nil || !*host.Up {
		t.Errorf("identity/up=%+v", host)
	}
	if host.CPUUsedPercent == nil || *host.CPUUsedPercent != 25.5 ||
		host.MemoryUsedPercent == nil || *host.MemoryUsedPercent != 62.25 ||
		host.FilesystemUsedPeak == nil || *host.FilesystemUsedPeak != 81.5 ||
		host.Load1 == nil || *host.Load1 != 1.75 ||
		host.UptimeSeconds == nil || *host.UptimeSeconds != 86400 {
		t.Errorf("measurements=%+v", host)
	}
}

func TestPrometheusSourceValidation(t *testing.T) {
	base := durableConfig(t, "", &fakeNotifier{}, nil)
	cases := []struct {
		name   string
		source PrometheusSource
		want   string
	}{
		{"http requires opt in", PrometheusSource{Name: "site", URL: "http://prometheus.example", MatchLabels: map[string]string{"job": "node"}}, "allow_insecure"},
		{"selector required", PrometheusSource{Name: "site", URL: "https://prometheus.example"}, "match_labels"},
		{"credentials forbidden in URL", PrometheusSource{Name: "site", URL: "https://user:pass@prometheus.example", MatchLabels: map[string]string{"job": "node"}}, "userinfo"},
		{"label validated", PrometheusSource{Name: "site", URL: "https://prometheus.example", MatchLabels: map[string]string{"bad-label": "node"}}, "invalid match label"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.Prometheus = []PrometheusSource{tc.source}
			if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestPrometheusSourceDoesNotFollowRedirects(t *testing.T) {
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer source.Close()
	runtimes, err := preparePrometheusSources([]PrometheusSource{{
		Name: "site", URL: source.URL, AllowInsecure: true,
		MatchLabels: map[string]string{"job": "node"}, Client: source.Client(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtimes[0].query(t.Context(), "up"); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("redirect error=%v", err)
	}
	if redirected.Load() != 0 {
		t.Fatal("followed a Prometheus redirect")
	}
}

func TestPrometheusFailureDoesNotFailHostMetricsEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "private upstream detail", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	cfg := durableConfig(t, "", &fakeNotifier{}, nil)
	cfg.Prometheus = []PrometheusSource{{Name: "site", URL: server.URL, AllowInsecure: true, MatchLabels: map[string]string{"job": "node"}, Client: server.Client()}}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	c.handleHostMetrics(recorder, httptest.NewRequest(http.MethodGet, "/v1/metrics/hosts", nil))
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "private upstream detail") || !strings.Contains(recorder.Body.String(), "metrics source unavailable") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestHostMetricsRouteRequiresViewerAuthentication(t *testing.T) {
	cfg := durableConfig(t, "", &fakeNotifier{}, nil)
	cfg.OperatorToken = "secret"
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	unauthorized := httptest.NewRecorder()
	c.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/metrics/hosts", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}
	authorized := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/metrics/hosts", nil)
	request.Header.Set("Authorization", "Bearer secret")
	c.Handler().ServeHTTP(authorized, request)
	if authorized.Code != http.StatusOK || strings.TrimSpace(authorized.Body.String()) != "[]" {
		t.Fatalf("authorized status=%d body=%s", authorized.Code, authorized.Body.String())
	}
}
