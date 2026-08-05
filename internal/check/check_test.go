package check

import (
	"strings"
	"testing"
	"time"
)

func valid() Check {
	return Check{
		Name: "mx-smtps", Kind: KindTCP, Target: "mx.example.com:465",
		Vantage: VantagePublic, Interval: time.Minute, Timeout: 10 * time.Second,
		Quorum: Quorum{Agree: 3, Of: 5},
	}
}

func TestValidateAcceptsAGoodCheck(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid check rejected: %v", err)
	}
}

// A check that does not declare its path cannot be corroborated: a peer might
// verify over a private mesh and report an all-clear about the public
// internet. So an unset vantage is an error rather than a default.
func TestVantageIsRequired(t *testing.T) {
	c := valid()
	c.Vantage = ""
	err := c.Validate()
	if err == nil {
		t.Fatal("a check with no vantage was accepted")
	}
	if !strings.Contains(err.Error(), "corroborated") {
		t.Errorf("error = %q, want it to explain why vantage matters", err)
	}

	for _, v := range []Vantage{VantagePublic, VantageInternal} {
		c.Vantage = v
		if err := c.Validate(); err != nil {
			t.Errorf("vantage %q rejected: %v", v, err)
		}
	}
	c.Vantage = "wireguard-ish"
	if c.Validate() == nil {
		t.Error("an unrecognised vantage was accepted")
	}
}

// A probe still running when the next one starts means the check quietly
// stops being periodic.
func TestTimeoutMustBeShorterThanInterval(t *testing.T) {
	c := valid()
	c.Timeout = c.Interval
	if err := c.Validate(); err == nil {
		t.Error("timeout equal to interval was accepted")
	}
	c.Timeout = c.Interval + time.Second
	if err := c.Validate(); err == nil {
		t.Error("timeout longer than interval was accepted")
	}
}

func TestValidateRejects(t *testing.T) {
	for name, mangle := range map[string]func(*Check){
		"no name":       func(c *Check) { c.Name = "" },
		"unknown kind":  func(c *Check) { c.Kind = "gopher" },
		"no target":     func(c *Check) { c.Target = "" },
		"zero interval": func(c *Check) { c.Interval = 0 },
		"zero timeout":  func(c *Check) { c.Timeout = 0 },
	} {
		c := valid()
		mangle(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// A quorum that asks fewer probers than it needs to agree can never be
// satisfied, and would leave a check permanently unresolvable.
func TestQuorumMustBeSatisfiable(t *testing.T) {
	c := valid()
	c.Quorum = Quorum{Agree: 5, Of: 3}
	err := c.Validate()
	if err == nil {
		t.Fatal("an unsatisfiable quorum was accepted")
	}
	if !strings.Contains(err.Error(), "agree") {
		t.Errorf("error = %q, want it to describe the impossibility", err)
	}

	c.Quorum = Quorum{Agree: 0, Of: 3}
	if c.Validate() == nil {
		t.Error("a quorum requiring nobody to agree was accepted")
	}

	c.Quorum = Quorum{Agree: 1, Of: 1}
	if err := c.Validate(); err != nil {
		t.Errorf("a single-prober quorum was rejected: %v", err)
	}
}

// The rule the design rests on: an unknown is a statement about the prober,
// not about the target, and must never be counted toward a verdict.
func TestOnlyUpAndDownAreEvidence(t *testing.T) {
	for status, want := range map[Status]bool{
		StatusUp:      true,
		StatusDown:    true,
		StatusUnknown: false,
	} {
		if got := (Result{Status: status}).IsEvidence(); got != want {
			t.Errorf("%q: IsEvidence = %v, want %v", status, got, want)
		}
	}
}
