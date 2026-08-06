package coordinator

import (
	"path/filepath"
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

func TestStateAndIncidentHistorySurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	n := &fakeNotifier{}
	cfg := durableConfig(t, path, n, nil)
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Process(t.Context(), check.Result{Check: "svc", Prober: "probe-a", Vantage: check.VantageInternal, Status: check.StatusDown, At: time.Now()})
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

func TestMaintenanceSuppressesDeliveryButRecordsIncident(t *testing.T) {
	now := time.Now()
	n := &fakeNotifier{}
	cfg := durableConfig(t, "", n, []Maintenance{{Name: "deploy", StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Minute), Checks: []string{"svc"}}})
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Process(t.Context(), check.Result{Check: "svc", Prober: "probe-a", Vantage: check.VantageInternal, Status: check.StatusDown, At: now})
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
