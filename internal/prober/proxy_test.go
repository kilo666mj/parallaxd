package prober

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
	"github.com/kilo666mj/parallaxd/internal/probe"
)

func TestSignedProxyFailureCarriesRouteWithoutCredentials(t *testing.T) {
	f := newFixture(t)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusProxyAuthRequired) }))
	defer endpoint.Close()
	cfg := f.prober.cfg
	cfg.ProxyProfiles = map[string]probe.ProxyProfile{"corp": {URL: endpoint.URL, Egress: "west"}}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := tcpCheck("http://127.0.0.1:80")
	c.Kind, c.ProxyProfile = check.KindHTTP, "corp"
	env, err := p.Run(t.Context(), c, "proxy-request")
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.coordRing.OpenResult(env, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := got.Result
	if r.Status != check.StatusUnknown || r.ProxyProfile != "corp" || r.Egress != "west" {
		t.Fatalf("signed proxy result: %+v", r)
	}
}
