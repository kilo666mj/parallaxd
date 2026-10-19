package coordinator

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestMetricsExposeBoundedCoordinatorHealth(t *testing.T) {
	now := time.Now().UTC()
	cfg := durableConfig(t, "", &fakeNotifier{}, nil)
	cfg.OperatorToken = "secret"
	cfg.Now = func() time.Time { return now }
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Process(t.Context(), downResult(now)); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("status=%d content-type=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	body := string(raw)
	for _, want := range []string{
		`parallaxd_ha_active 1`,
		`parallaxd_ha_role{role="primary"} 1`,
		`parallaxd_check_status{check="svc",status="down"} 1`,
		`parallaxd_check_status{check="svc",status="up"} 0`,
		`parallaxd_incidents_active 1`,
		`parallaxd_prober_silent{prober="probe-a"} 0`,
		`parallaxd_notifications_pending 0`,
		`# TYPE parallaxd_corroborations_total counter`,
	} {
		if !strings.Contains(body, want+"\n") {
			t.Errorf("metrics missing %q", want)
		}
	}
	sample := regexp.MustCompile(`^[a-z_]+(\{[a-z_]+="[^"]*"(,[a-z_]+="[^"]*")*\})? [-+0-9.e]+$`)
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if !strings.HasPrefix(line, "# ") && !sample.MatchString(line) {
			t.Errorf("malformed sample line %q", line)
		}
	}
}
