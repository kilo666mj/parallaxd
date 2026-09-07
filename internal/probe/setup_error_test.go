package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

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

// deadlineFailingConn refuses to take a deadline, the way a socket that has
// been closed underneath us does, and counts how often it is closed.
type deadlineFailingConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *deadlineFailingConn) SetDeadline(time.Time) error {
	return errors.New("bad file descriptor")
}

func (c *deadlineFailingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// SMTP is the one probe that hands its connection to something else partway
// through: smtp.Client takes ownership, and defer client.Close() only exists
// after that. An early return before the handover therefore leaks the socket
// unless Probe closes it itself, which is what happened when the deadline
// check was added.
func TestSMTPClosesConnectionWhenDeadlineCannotBeSet(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	// Accept and stay silent: the probe must fail on the deadline, before any
	// SMTP conversation, which is the path under test.
	done := make(chan struct{})
	defer close(done)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		<-done
	}()

	var tracked *deadlineFailingConn
	probe := SMTP{wrapConn: func(c net.Conn) net.Conn {
		tracked = &deadlineFailingConn{Conn: c}
		return tracked
	}}

	// The deadline check only runs when the context carries one.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status, _, detail := probe.Probe(ctx, testCheck(check.KindSMTP, listener.Addr().String()))

	if status != check.StatusUnknown {
		t.Errorf("status = %v (%s), want %v", status, detail, check.StatusUnknown)
	}
	if tracked == nil {
		t.Fatal("probe never dialled")
	}
	if got := tracked.closes.Load(); got != 1 {
		t.Errorf("connection closed %d times, want 1 — the socket leaks on this path", got)
	}
}
