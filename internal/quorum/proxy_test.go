package quorum

import (
	"testing"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

func TestProxyExitsAreIndependentEvenWithoutProviderRule(t *testing.T) {
	c := check.Check{Name: "service", ProxyProfile: "corp", Vantage: check.VantagePublic, Quorum: check.Quorum{Agree: 2, Of: 3}}
	results := []check.Result{
		{Check: c.Name, Prober: "a", Provider: "one", ProxyProfile: "corp", Egress: "shared", Vantage: c.Vantage, Status: check.StatusDown, At: time.Now()},
		{Check: c.Name, Prober: "b", Provider: "two", ProxyProfile: "corp", Egress: "shared", Vantage: c.Vantage, Status: check.StatusDown, At: time.Now()},
	}
	v := Evaluate(c, results, Options{})
	if v.Status != check.StatusUnknown || v.IndependentDown != 1 {
		t.Fatalf("shared exit manufactured quorum: %+v", v)
	}
	results[1].Egress = "different"
	if v := Evaluate(c, results, Options{}); v.Status != check.StatusDown {
		t.Fatalf("independent exits failed: %+v", v)
	}
	results[1].ProxyProfile = ""
	if v := Evaluate(c, results, Options{}); v.Status != check.StatusUnknown || v.Discarded != 1 {
		t.Fatalf("direct legacy answer accepted: %+v", v)
	}
	results[1].ProxyProfile = "corp"
	results[1].Egress = ""
	if v := Evaluate(c, results, Options{}); v.Discarded != 1 {
		t.Fatal("unidentified exit counted")
	}
}

func TestProxyProviderAndExitDiversityMustHoldForSameVotes(t *testing.T) {
	results := []check.Result{
		{Prober: "a", Provider: "one", ProxyProfile: "corp", Egress: "x"},
		{Prober: "b", Provider: "one", ProxyProfile: "corp", Egress: "y"},
		{Prober: "c", Provider: "one", ProxyProfile: "corp", Egress: "z"},
		{Prober: "d", Provider: "two", ProxyProfile: "corp", Egress: "x"},
		{Prober: "e", Provider: "three", ProxyProfile: "corp", Egress: "x"},
	}
	if got := IndependentCount(results, true); got != 2 {
		t.Fatalf("three providers and three exits only allow two independent votes; got %d", got)
	}
	if got := IndependentCount(results, false); got != 3 {
		t.Fatalf("distinct exits: %d", got)
	}
	// This requires reassigning an earlier matching edge, not greedy dedupe.
	if got := IndependentCount([]check.Result{results[0], results[1], results[3]}, true); got != 2 {
		t.Fatalf("failed augmenting path: %d", got)
	}
}
