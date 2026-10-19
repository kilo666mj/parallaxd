package coordinator

import (
	"net/http"
	"sort"
	"time"
)

const defaultUptimePeriod = 30 * 24 * time.Hour

// Uptime is the share of a period that a check or component spent outside a
// corroborated outage. Outage time inside a maintenance window is excluded
// from downtime and reported separately. It is computed from durable incidents
// rather than observation history, which is capped per check and would not
// cover a month at short intervals.
type Uptime struct {
	Check              string    `json:"check,omitempty"`
	Component          string    `json:"component,omitempty"`
	From               time.Time `json:"from"`
	To                 time.Time `json:"to"`
	Uptime             float64   `json:"uptime"`
	DowntimeSeconds    float64   `json:"downtime_seconds"`
	MaintenanceSeconds float64   `json:"maintenance_seconds,omitempty"`
	Outages            int       `json:"outages"`
}

type interval struct{ from, to time.Time }

// UptimeReport returns uptime for every check and component over [from, to).
func (c *Coordinator) UptimeReport(from, to time.Time) []Uptime {
	if now := c.now(); to.After(now) {
		to = now
	}
	byCheck := map[string]*Uptime{}
	byComponent := map[string]*Uptime{}
	var out []*Uptime
	for _, chk := range c.allChecks() {
		u := &Uptime{Check: chk.Name, From: from, To: to}
		byCheck[chk.Name] = u
		out = append(out, u)
	}
	for _, comp := range c.cfg.Components {
		u := &Uptime{Component: comp.Name, From: from, To: to}
		byComponent[comp.Name] = u
		out = append(out, u)
	}

	c.mu.Lock()
	windows := c.maintenanceLocked()
	incidents := append([]Incident(nil), c.incidents...)
	c.mu.Unlock()

	for _, incident := range incidents {
		a := incident.Alert
		if incident.Kind != KindDown || a.Prober != "" {
			continue
		}
		u := byCheck[a.Check]
		if a.Component != "" {
			u = byComponent[a.Component]
		}
		end := incident.ResolvedAt
		if incident.Active || end.IsZero() {
			end = to
		}
		outage, ok := clip(interval{incident.OpenedAt, end}, from, to)
		if u == nil || !ok {
			continue
		}
		u.Outages++
		var covered []interval
		for _, m := range windows {
			if alertMatches(a, m.Checks, m.Components, m.Probers) {
				covered = append(covered, m.occurrences(outage)...)
			}
		}
		excluded := totalDuration(covered)
		u.MaintenanceSeconds += excluded.Seconds()
		u.DowntimeSeconds += (outage.to.Sub(outage.from) - excluded).Seconds()
	}

	period := to.Sub(from).Seconds()
	result := make([]Uptime, 0, len(out))
	for _, u := range out {
		u.Uptime = 1
		if period > 0 {
			u.Uptime = max(0, 1-u.DowntimeSeconds/period)
		}
		result = append(result, *u)
	}
	return result
}

// occurrences returns the parts of span that fall inside this window.
func (m Maintenance) occurrences(span interval) []interval {
	length := m.EndsAt.Sub(m.StartsAt)
	every, err := time.ParseDuration(m.Every)
	if err != nil || every <= 0 {
		if part, ok := clip(interval{m.StartsAt, m.EndsAt}, span.from, span.to); ok {
			return []interval{part}
		}
		return nil
	}
	start := m.StartsAt
	if span.from.After(start) {
		start = start.Add(span.from.Sub(start) / every * every)
	}
	var out []interval
	for ; start.Before(span.to); start = start.Add(every) {
		if part, ok := clip(interval{start, start.Add(length)}, span.from, span.to); ok {
			out = append(out, part)
		}
	}
	return out
}

func clip(i interval, from, to time.Time) (interval, bool) {
	if i.from.Before(from) {
		i.from = from
	}
	if i.to.After(to) {
		i.to = to
	}
	return i, i.to.After(i.from)
}

// totalDuration sums intervals, counting overlapping time once.
func totalDuration(intervals []interval) time.Duration {
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].from.Before(intervals[j].from) })
	var total time.Duration
	var end time.Time
	for _, i := range intervals {
		if i.from.Before(end) {
			i.from = end
		}
		if i.to.After(i.from) {
			total += i.to.Sub(i.from)
			end = i.to
		}
	}
	return total
}

func (c *Coordinator) handleUptime(w http.ResponseWriter, r *http.Request) {
	to := c.now().UTC()
	from := to.Add(-defaultUptimePeriod)
	for name, dst := range map[string]*time.Time{"since": &from, "until": &to} {
		if raw := r.URL.Query().Get(name); raw != "" {
			parsed, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				http.Error(w, name+" must be RFC3339", http.StatusBadRequest)
				return
			}
			*dst = parsed.UTC()
		}
	}
	if !to.After(from) {
		http.Error(w, "until must be after since", http.StatusBadRequest)
		return
	}
	writeJSON(w, c.UptimeReport(from, to))
}
