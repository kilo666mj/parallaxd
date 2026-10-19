package coordinator

import (
	"testing"
	"time"
)

func TestUptimeCountsCorroboratedOutagesAndExcludesMaintenance(t *testing.T) {
	to := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	from := to.Add(-10 * 24 * time.Hour)
	maintenanceStart := from.Add(2 * time.Hour)
	cfg := durableConfig(t, "", &fakeNotifier{}, []Maintenance{{
		Name: "nightly", StartsAt: maintenanceStart, EndsAt: maintenanceStart.Add(time.Hour), Every: "24h", Checks: []string{"svc"},
	}})
	cfg.Now = func() time.Time { return to.Add(time.Hour) }
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	down := func(opened, resolved time.Time) Incident {
		return Incident{Kind: KindDown, OpenedAt: opened, ResolvedAt: resolved, Alert: Alert{Check: "svc", Kind: KindDown}}
	}
	c.incidents = []Incident{
		// Two hours, half of it inside the 02:00-03:00 window on day 3.
		down(maintenanceStart.Add(48*time.Hour-30*time.Minute), maintenanceStart.Add(48*time.Hour+90*time.Minute)),
		// Began before the period: only the part inside counts.
		down(from.Add(-time.Hour), from.Add(30*time.Minute)),
		// Still active: counts until the end of the period.
		{Kind: KindDown, OpenedAt: to.Add(-time.Hour), Active: true, Alert: Alert{Check: "svc", Kind: KindDown}},
		// Not outages of the check.
		{Kind: KindWarning, OpenedAt: from.Add(time.Hour), ResolvedAt: from.Add(5 * time.Hour), Alert: Alert{Check: "svc", Kind: KindWarning}},
		{Kind: KindSilent, OpenedAt: from.Add(time.Hour), ResolvedAt: from.Add(5 * time.Hour), Alert: Alert{Prober: "probe-a", Kind: KindSilent}},
	}
	report := c.UptimeReport(from, to)
	if len(report) != 1 {
		t.Fatalf("report=%+v", report)
	}
	u := report[0]
	wantDown := (time.Hour + 30*time.Minute + time.Hour).Seconds()
	if u.Check != "svc" || u.Outages != 3 || u.DowntimeSeconds != wantDown || u.MaintenanceSeconds != time.Hour.Seconds() {
		t.Fatalf("uptime=%+v, want downtime %v", u, wantDown)
	}
	if want := 1 - wantDown/(10*24*time.Hour).Seconds(); u.Uptime != want {
		t.Fatalf("uptime=%v, want %v", u.Uptime, want)
	}
}

func TestTotalDurationCountsOverlapOnce(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got := totalDuration([]interval{
		{at.Add(time.Hour), at.Add(3 * time.Hour)},
		{at, at.Add(2 * time.Hour)},
		{at.Add(90 * time.Minute), at.Add(100 * time.Minute)},
		{at.Add(5 * time.Hour), at.Add(6 * time.Hour)},
	})
	if got != 4*time.Hour {
		t.Fatalf("totalDuration=%v, want 4h", got)
	}
}
