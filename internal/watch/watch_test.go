package watch

import (
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func beat(at time.Time) Beat {
	return Beat{Coordinator: "coordinator", At: at, Checks: 12, Probers: 4}
}

// The thing this exists for: the coordinator stops, and something says so.
func TestSilenceIsReported(t *testing.T) {
	c := newClock()
	w := New(5*time.Minute, c.now)

	w.Record(beat(c.now()))
	c.advance(time.Minute)
	if w.Check() {
		t.Fatal("declared dead inside the grace period")
	}

	c.advance(5 * time.Minute)
	if !w.Check() {
		t.Fatal("did not declare the coordinator dead after the grace period")
	}
	if w.State().Alive {
		t.Error("state still says alive")
	}
	if !strings.Contains(w.State().Summary(), "not checked in") {
		t.Errorf("summary = %q", w.State().Summary())
	}
}

// Alerting every tick for as long as it is down is the same mistake as
// alerting per failing result.
func TestDeathIsReportedOnce(t *testing.T) {
	c := newClock()
	w := New(time.Minute, c.now)
	w.Record(beat(c.now()))

	c.advance(5 * time.Minute)
	if !w.Check() {
		t.Fatal("first check did not report the death")
	}
	for range 5 {
		c.advance(time.Minute)
		if w.Check() {
			t.Fatal("reported the same death twice")
		}
	}
}

func TestRecoveryIsReportedOnce(t *testing.T) {
	c := newClock()
	w := New(time.Minute, c.now)
	w.Record(beat(c.now()))
	c.advance(5 * time.Minute)
	w.Check()

	if !w.Record(beat(c.now())) {
		t.Fatal("a beat after death was not reported as a recovery")
	}
	if !w.State().Alive {
		t.Error("state still says dead")
	}
	// Further beats are not news.
	c.advance(time.Second)
	if w.Record(beat(c.now())) {
		t.Error("a second beat was reported as another recovery")
	}
}

// Everything is silent the instant a watcher starts. Declaring the coordinator
// dead on that basis is how a useful signal becomes one people mute.
func TestStartupIsNotSilence(t *testing.T) {
	c := newClock()
	w := New(5*time.Minute, c.now)

	if w.Check() {
		t.Fatal("declared the coordinator dead at startup")
	}
	// But a coordinator that never checks in at all is exactly as absent as
	// one that stopped, so the grace period does expire.
	c.advance(6 * time.Minute)
	if !w.Check() {
		t.Error("a coordinator that never checked in was never reported")
	}
	// And the summary still names the situation without a coordinator name to
	// use, because none was ever received.
	if !strings.Contains(w.State().Summary(), "coordinator") {
		t.Errorf("summary = %q", w.State().Summary())
	}
}

// Out-of-order delivery must not resurrect an older view.
func TestOlderBeatIsIgnored(t *testing.T) {
	c := newClock()
	w := New(time.Minute, c.now)

	now := c.now()
	newer := beat(now)
	newer.Checks = 99
	w.Record(newer)

	older := beat(now.Add(-time.Minute))
	older.Checks = 1
	w.Record(older)

	if got := w.State().Last.Checks; got != 99 {
		t.Errorf("last.checks = %d, want the newer beat's 99", got)
	}
}

// The watcher stores what it was told rather than a reduction of it: after an
// outage, the last thing the coordinator managed to say is the most useful
// record there is.
func TestStateCarriesTheLastBeat(t *testing.T) {
	c := newClock()
	w := New(time.Minute, c.now)

	b := beat(c.now())
	b.Stale = 3
	w.Record(b)

	s := w.State()
	if s.Last.Checks != 12 || s.Last.Probers != 4 || s.Last.Stale != 3 {
		t.Fatalf("last = %+v, want the beat as sent", s.Last)
	}
	if !strings.Contains(s.Summary(), "3 stale") {
		t.Errorf("summary = %q, want it to surface the stale count", s.Summary())
	}
}

// A beat timestamped slightly ahead — within the skew the transport allows —
// must not produce negative silence and wrap the comparison.
func TestBeatFromTheNearFutureIsHarmless(t *testing.T) {
	c := newClock()
	w := New(time.Minute, c.now)

	w.Record(beat(c.now().Add(30 * time.Second)))
	if got := w.State().Silence; got != 0 {
		t.Errorf("silence = %s, want 0", got)
	}
	if w.Check() {
		t.Error("a future beat declared the coordinator dead")
	}
}

func TestConcurrentRecordAndCheck(t *testing.T) {
	c := newClock()
	w := New(time.Minute, c.now)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.Record(beat(c.now()))
			w.Check()
			_ = w.State()
		}()
	}
	wg.Wait()
}
