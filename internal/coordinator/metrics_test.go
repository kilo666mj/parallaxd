package coordinator

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
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

// A prober wrong about one target is outvoted without an alert, but the
// counter still points at it.
func TestOverruledProberIsCounted(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	h.target.up(t)

	for range 2 {
		v, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown))
		if err != nil {
			t.Fatal(err)
		}
		if v.Status == check.StatusDown || v.IndependentUp < 2 {
			t.Fatalf("status = %q (%s), want the peers to overrule", v.Status, v.Reason)
		}
	}
	if _, err := h.coord.Process(t.Context(), h.reportFrom("probe-b", check.StatusUp)); err != nil {
		t.Fatal(err)
	}
	if h.notifier.count() != 0 {
		t.Errorf("an overruled result produced %d alerts", h.notifier.count())
	}

	var out strings.Builder
	h.coord.writeMetrics(&out)
	body := out.String()
	if !strings.Contains(body, `parallaxd_prober_overruled_total{prober="probe-a",check="svc"} 2`+"\n") {
		t.Errorf("probe-a not counted as overruled twice:\n%s", body)
	}
	if strings.Contains(body, `parallaxd_prober_overruled_total{prober="probe-b"`) {
		t.Error("a prober that agreed with quorum was counted")
	}
}

func TestConfirmedOutageIsNotOverruled(t *testing.T) {
	h := newHarness(t, 3, check.Quorum{Agree: 2, Of: 3}, nil)
	h.target.down()
	v, err := h.coord.Process(t.Context(), h.reportFrom("probe-a", check.StatusDown))
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != check.StatusDown {
		t.Fatalf("status = %q (%s), want down", v.Status, v.Reason)
	}
	var out strings.Builder
	h.coord.writeMetrics(&out)
	if strings.Contains(out.String(), `parallaxd_prober_overruled_total{`) {
		t.Error("a prober confirmed by quorum was counted as overruled")
	}
}
