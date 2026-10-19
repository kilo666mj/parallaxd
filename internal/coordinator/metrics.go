package coordinator

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/kilo666mj/parallaxd/internal/check"
)

// handleMetrics serves the coordinator's own health in the Prometheus text
// format. Label values come only from configured checks, probers,
// destinations and fixed rejection reasons, so the series count stays bounded.
func (c *Coordinator) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	c.writeMetrics(w)
}

func (c *Coordinator) writeMetrics(out io.Writer) {
	now := c.now()
	d := c.DiagnosticState()
	m := metricWriter{w: out}

	m.family("parallaxd_ha_active", "gauge", "1 when this coordinator is the active writer.")
	m.sample("parallaxd_ha_active", nil, boolValue(d.HA.Active))
	m.family("parallaxd_ha_promoted", "gauge", "1 when this coordinator is a promoted standby.")
	m.sample("parallaxd_ha_promoted", nil, boolValue(d.HA.Promoted))
	m.family("parallaxd_ha_role", "gauge", "Configured HA role.")
	m.sample("parallaxd_ha_role", []string{"role", d.HA.Role}, 1)
	if !d.HA.LastReplicaSync.IsZero() {
		m.family("parallaxd_replication_last_sync_timestamp_seconds", "gauge", "Unix time of the last successful replica sync.")
		m.sample("parallaxd_replication_last_sync_timestamp_seconds", nil, unixSeconds(d.HA.LastReplicaSync))
		m.family("parallaxd_replication_lag_seconds", "gauge", "Age of the primary state at the last replica sync.")
		m.sample("parallaxd_replication_lag_seconds", nil, float64(d.HA.ReplicationLagMS)/1000)
	}
	m.family("parallaxd_replication_error", "gauge", "1 when the last replication attempt failed.")
	m.sample("parallaxd_replication_error", nil, boolValue(d.HA.LastReplicationError != ""))

	m.family("parallaxd_result_queue_depth", "gauge", "Results waiting for evaluation.")
	m.sample("parallaxd_result_queue_depth", nil, float64(d.ResultQueue.Depth))
	m.family("parallaxd_result_queue_capacity", "gauge", "Capacity of the result queue.")
	m.sample("parallaxd_result_queue_capacity", nil, float64(d.ResultQueue.Capacity))
	m.family("parallaxd_results_rejected_total", "counter", "Rejected prober results by reason since start.")
	for _, reason := range sortedKeys(d.RejectedResults) {
		m.sample("parallaxd_results_rejected_total", []string{"reason", reason}, float64(d.RejectedResults[reason]))
	}

	m.family("parallaxd_corroborations_total", "counter", "Corroboration rounds started by a suspected failure or new warning since start.")
	m.sample("parallaxd_corroborations_total", nil, float64(c.corroborations.Load()))
	m.family("parallaxd_corroborations_inconclusive_total", "counter", "Corroboration rounds that ended without a quorum verdict since start.")
	m.sample("parallaxd_corroborations_inconclusive_total", nil, float64(c.inconclusiveCorroborations.Load()))
	m.family("parallaxd_corroboration_duration_seconds_total", "counter", "Total time spent in corroboration rounds since start.")
	m.sample("parallaxd_corroboration_duration_seconds_total", nil, time.Duration(c.corroborationNanos.Load()).Seconds())

	m.family("parallaxd_notifications_pending", "gauge", "Deliveries waiting in the durable outbox.")
	m.sample("parallaxd_notifications_pending", nil, float64(d.Notifications.Pending))
	m.family("parallaxd_notifications_oldest_pending_age_seconds", "gauge", "Age of the oldest pending delivery, 0 when none.")
	m.sample("parallaxd_notifications_oldest_pending_age_seconds", nil, ageSeconds(now, d.Notifications.OldestPending))
	m.family("parallaxd_notification_attempts_total", "counter", "Delivery attempts by destination since start.")
	m.family("parallaxd_notification_failures_total", "counter", "Failed delivery attempts by destination since start.")
	for _, name := range sortedKeys(d.Notifications.Destinations) {
		dest := d.Notifications.Destinations[name]
		m.sample("parallaxd_notification_attempts_total", []string{"destination", name}, float64(dest.Attempts))
		m.sample("parallaxd_notification_failures_total", []string{"destination", name}, float64(dest.Failures))
	}
	m.family("parallaxd_history_write_failures_total", "counter", "Failed observation journal writes since start.")
	m.sample("parallaxd_history_write_failures_total", nil, float64(d.History.WriteFailures))

	var active, suppressed int
	for _, incident := range c.Incidents() {
		if incident.Active {
			active++
			if incident.Suppressed {
				suppressed++
			}
		}
	}
	m.family("parallaxd_incidents_active", "gauge", "Open incidents, including suppressed ones.")
	m.sample("parallaxd_incidents_active", nil, float64(active))
	m.family("parallaxd_incidents_suppressed", "gauge", "Open incidents suppressed by maintenance or a silence.")
	m.sample("parallaxd_incidents_suppressed", nil, float64(suppressed))

	statuses := []check.Status{check.StatusUp, check.StatusWarning, check.StatusDown, check.StatusUnknown}
	m.family("parallaxd_check_status", "gauge", "1 for the current verdict of each check.")
	entries := c.Status()
	for _, e := range entries {
		for _, status := range statuses {
			m.sample("parallaxd_check_status", []string{"check", e.Check, "status", string(status)}, boolValue(e.Status == string(status)))
		}
	}
	m.family("parallaxd_check_stale", "gauge", "1 when nobody has reported on the check recently.")
	m.family("parallaxd_check_suspected", "gauge", "1 while a failure is suspected but not decided.")
	m.family("parallaxd_check_last_verdict_age_seconds", "gauge", "Seconds since the check last produced a verdict.")
	for _, e := range entries {
		m.sample("parallaxd_check_stale", []string{"check", e.Check}, boolValue(e.Stale))
		m.sample("parallaxd_check_suspected", []string{"check", e.Check}, boolValue(!e.SuspectedSince.IsZero()))
		if !e.LastVerdict.IsZero() {
			m.sample("parallaxd_check_last_verdict_age_seconds", []string{"check", e.Check}, ageSeconds(now, e.LastVerdict))
		}
	}

	reports := map[string]time.Time{}
	for _, r := range c.meshState.all() {
		reports[r.Prober] = r.At
	}
	meshView := c.Mesh()
	c.mu.Lock()
	silent := make(map[string]bool, len(c.silent))
	for name, value := range c.silent {
		silent[name] = value
	}
	c.mu.Unlock()
	m.family("parallaxd_prober_mesh_report_age_seconds", "gauge", "Seconds since the prober's last mesh report.")
	m.family("parallaxd_prober_isolated", "gauge", "1 when the prober reached none of its peers.")
	m.family("parallaxd_prober_silent", "gauge", "1 when the prober's assigned checks have gone stale.")
	for _, peer := range c.peers {
		if at, ok := reports[peer.Name]; ok {
			m.sample("parallaxd_prober_mesh_report_age_seconds", []string{"prober", peer.Name}, ageSeconds(now, at))
		}
		m.sample("parallaxd_prober_isolated", []string{"prober", peer.Name}, boolValue(meshView.IsIsolated(peer.Name)))
		m.sample("parallaxd_prober_silent", []string{"prober", peer.Name}, boolValue(silent[peer.Name]))
	}
}

type metricWriter struct{ w io.Writer }

func (m metricWriter) family(name, kind, help string) {
	_, _ = fmt.Fprintf(m.w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
}

// sample writes one series; labels alternate name and value.
func (m metricWriter) sample(name string, labels []string, value float64) {
	var b strings.Builder
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(labels[i])
			b.WriteString(`="`)
			b.WriteString(labelEscaper.Replace(labels[i+1]))
			b.WriteByte('"')
		}
		b.WriteByte('}')
	}
	_, _ = fmt.Fprintf(m.w, "%s %g\n", b.String(), value)
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func boolValue(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

func unixSeconds(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

func ageSeconds(now, t time.Time) float64 {
	if t.IsZero() || t.After(now) {
		return 0
	}
	return now.Sub(t).Seconds()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
