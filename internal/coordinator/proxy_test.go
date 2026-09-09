package coordinator

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/quorum"
)

func TestProxyEligibilityAndIndependentQuorum(t *testing.T) {
	peers := []Peer{{Name: "a", Provider: "one", ProxyProfiles: map[string]string{"corp": "shared"}},
		{Name: "b", Provider: "two", ProxyProfiles: map[string]string{"corp": "shared"}},
		{Name: "c", Provider: "three"},
		{Name: "d", Provider: "four", ProxyProfiles: map[string]string{"corp": "separate"}}}
	byName := map[string]Peer{}
	for _, p := range peers {
		byName[p.Name] = p
	}
	chk := check.Check{Name: "service", ProxyProfile: "corp", Quorum: check.Quorum{Agree: 2, Of: 3}}
	eligible, err := validateEligibleProbers(chk, peers, byName)
	if err != nil || len(eligible) != 3 {
		t.Fatalf("eligible: %v, %v", eligible, err)
	}
	if err := validateRouteQuorum(chk, eligible[:2]); err == nil {
		t.Fatal("accepted shared-exit quorum")
	}
	if err := validateRouteQuorum(chk, eligible); err != nil {
		t.Fatal(err)
	}
	c := &Coordinator{peers: peers, byName: byName}
	if got := c.eligiblePeers(chk); len(got) != 3 {
		t.Fatalf("assignment candidates: %v", got)
	}
	chk.Quorum.Of = 2
	selected := c.corroborators(chk, routeResult(chk, peers[0]))
	if len(selected) != 1 || selected[0].Name != "d" {
		t.Fatalf("corroboration reused exit: %v", selected)
	}
	chk.Probers = []string{"c"}
	if _, err := validateEligibleProbers(chk, peers, byName); err == nil {
		t.Fatal("explicit unsupported prober accepted")
	}
}

func TestProxyRouteMismatchCannotTriggerOrRecover(t *testing.T) {
	chk := check.Check{Name: "service", ProxyProfile: "corp", Vantage: check.VantagePublic, Quorum: check.Quorum{Agree: 2, Of: 2}}
	peer := Peer{Name: "a", Provider: "registered", ProxyProfiles: map[string]string{"corp": "exit"}}
	for _, r := range []check.Result{
		{Status: check.StatusDown}, // older prober ignored proxy_profile
		{Status: check.StatusUp, ProxyProfile: "corp", Egress: "invented"},
	} {
		r = normalizeRoute(chk, peer, r)
		if r.Status != check.StatusUnknown || r.Provider != "registered" || r.Egress != "exit" {
			t.Fatalf("route spoof accepted: %+v", r)
		}
	}
	results := []check.Result{}
	for _, name := range []string{"a", "b"} {
		results = append(results, check.Result{Check: chk.Name, Prober: name, ProxyProfile: "corp", Egress: "shared", Vantage: chk.Vantage, Status: check.StatusUp, At: time.Now()})
	}
	v := quorum.Evaluate(chk, results, quorum.Options{})
	if recoveryConfirmed(chk, v) {
		t.Fatal("shared proxy exit cleared an outage")
	}
	results[1].Egress = "other"
	if !recoveryConfirmed(chk, quorum.Evaluate(chk, results, quorum.Options{})) {
		t.Fatal("independent recovery failed")
	}

}

func TestProxyMonitorRoundTripPreservesProfile(t *testing.T) {
	chk := check.Check{Name: "service", Kind: check.KindHTTP, Target: "https://example.com", ProxyProfile: "corp", Vantage: check.VantagePublic, Interval: time.Minute, Timeout: time.Second, Quorum: check.Quorum{Agree: 1, Of: 1}}
	m := monitorFromCheck(chk)
	got, err := m.toCheck()
	if err != nil || got.ProxyProfile != "corp" {
		t.Fatalf("profile lost in catalog: %+v %v", got, err)
	}
}

func TestProxyProcessPersistsAndReplicatesRoute(t *testing.T) {
	cfg := durableConfig(t, filepath.Join(t.TempDir(), "state.json"), &fakeNotifier{}, nil)
	cfg.Checks[0].Kind = check.KindHTTP
	cfg.Checks[0].Target = "https://example.com"
	cfg.Checks[0].ProxyProfile = "corp"
	cfg.Peers[0].ProxyProfiles = map[string]string{"corp": "west"}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := resultAt(check.StatusDown, time.Now())
	// Legacy direct results must not open an incident, even with Agree: 1.
	v, err := c.Process(t.Context(), r)
	if err != nil || v.Status != check.StatusUnknown || len(c.Incidents()) != 0 {
		t.Fatalf("legacy result accepted: %+v %v", v, err)
	}
	r.ProxyProfile, r.Egress = "corp", "west"
	v, err = c.Process(t.Context(), r)
	if err != nil || v.Status != check.StatusDown {
		t.Fatalf("routed result: %+v %v", v, err)
	}
	r.Status, r.Egress = check.StatusUp, "invented"
	v, err = c.Process(t.Context(), r)
	if err != nil || v.Status != check.StatusUnknown || !c.Incidents()[0].Active {
		t.Fatalf("spoofed route cleared incident: %+v %v", v, err)
	}
	history := c.History("svc", time.Time{}, 10)
	for _, observation := range history {
		if observation.ProxyProfile != "corp" || observation.Egress != "west" {
			t.Fatalf("unregistered history route: %+v", observation)
		}
	}
	if len(history) != 3 {
		t.Fatalf("history: %+v", history)
	}
	snapshot := c.snapshot()
	if snapshot.Version != 7 {
		t.Fatalf("unsafe state version: %d", snapshot.Version)
	}
	restored, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if restored.monitorList()[0].ProxyProfile != "corp" || !restored.Incidents()[0].Active {
		t.Fatal("restore lost route or incident")
	}
	cfg.StateFile = ""
	standby, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := standby.applyReplica(replicaDocument{State: snapshot, History: history}); err != nil {
		t.Fatal(err)
	}
	if standby.monitorList()[0].ProxyProfile != "corp" || standby.History("svc", time.Time{}, 10)[0].Egress != "west" {
		t.Fatal("replication lost route")
	}
	// A retained rollback revision must keep the downgrade guard active too.
	m := c.monitorList()[0]
	c.monitorRevisions = []MonitorRevision{{Catalog: []MonitorSpec{m}}}
	m.ProxyProfile = ""
	if err := c.replaceMonitorCatalog([]MonitorSpec{m}); err != nil {
		t.Fatal(err)
	}
	if c.snapshot().Version != 7 {
		t.Fatal("proxy rollback revision allowed old state format")
	}
	c.monitorRevisions = nil
	if c.snapshot().Version != 6 {
		t.Fatal("direct-only state no longer backward compatible")
	}
}
