package probe

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kilo666mj/parallaxd/internal/check"
)

// A prober that cannot set a deadline on its own socket has not learned
// anything about the target. classify recognises causes by type, so the plain
// fmt.Errorf this path used to return fell through to the default and reported
// StatusDown — inverting the rule check.go states, that an Unknown must never
// become a vote for Down.
func TestClassifyTreatsProberSetupFailureAsUnknown(t *testing.T) {
	err := &proberSetupError{op: "set probe deadline", err: errors.New("use of closed network connection")}

	status, detail := classify(err)

	if status != check.StatusUnknown {
		t.Errorf("classify(proberSetupError) = %v, want %v", status, check.StatusUnknown)
	}
	if detail == "" {
		t.Error("classify returned an empty detail for a setup failure")
	}
}

// exchangeDNS returns this through an ordinary error return that callers wrap,
// so recognition has to survive wrapping.
func TestClassifyUnwrapsWrappedProberSetupFailure(t *testing.T) {
	cause := errors.New("bad file descriptor")
	wrapped := fmt.Errorf("dns udp exchange: %w", &proberSetupError{op: "set probe deadline", err: cause})

	status, _ := classify(wrapped)

	if status != check.StatusUnknown {
		t.Errorf("classify(wrapped) = %v, want %v", status, check.StatusUnknown)
	}
	if !errors.Is(wrapped, cause) {
		t.Error("proberSetupError does not unwrap to its cause")
	}
}

// The guard that makes the DNS path correct: a bare fmt.Errorf on a setup
// failure is reported as Down, which is the regression this type prevents.
func TestClassifyStillReportsUntypedFailuresAsDown(t *testing.T) {
	status, _ := classify(errors.New("set probe deadline: bad file descriptor"))

	if status != check.StatusDown {
		t.Errorf("classify(untyped) = %v, want %v", status, check.StatusDown)
	}
}
