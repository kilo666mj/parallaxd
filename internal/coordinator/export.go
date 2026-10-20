package coordinator

import (
	"net/http"
	"time"

	"github.com/kilo666mj/parallaxd/internal/wire"
)

// parallaxd exports the state used by both its small operational dashboard and
// off-fleet public status renderers.
//
// A public status page has to survive the outage it reports, and one served
// from the monitored fleet is unavailable in the only situation it exists for.
// That is a property of where it runs, not of how it is written, so no amount
// of code here fixes it. The split instead: the coordinator publishes a signed
// document, and something off-fleet — object storage, a static host — renders
// it. A status page can then be built later, by anything, without this growing
// a template engine.
//
// Operator-written notices travel in the export so a status page can show
// them, but they never change the corroborated statuses next to them.
// Subscriber notification stays outside this monitor.

// exportVersion is the schema version of the document. A renderer off the
// fleet is upgraded on someone else's schedule, so it needs to be able to say
// "I do not understand this" rather than misread a field that changed meaning.
const exportVersion = 1

// Export is the published view of the coordinator's state.
type Export struct {
	Version     int    `json:"version"`
	Coordinator string `json:"coordinator"`

	// GeneratedAt is what makes staleness detectable. A page rendered from an
	// export the coordinator stopped producing an hour ago shows everything as
	// it was, which is worse than showing nothing — so a renderer must compare
	// this against its own clock and say so when the gap is large.
	GeneratedAt time.Time `json:"generated_at"`

	Components []ComponentEntry `json:"components"`

	// Checks is the detail behind the components, included because a
	// component-only export cannot answer "which part" and the renderer has no
	// way to ask a follow-up question.
	Checks []StatusEntry `json:"checks"`

	// Probers is how many the coordinator knows about.
	Probers int `json:"probers"`

	// Isolated names probers that can currently reach no peer, so their
	// results are not being counted. A page claiming corroborated results has
	// to say when the corroboration is running short — otherwise it presents a
	// verdict reached on two opinions exactly as it would one reached on five.
	Isolated []string `json:"isolated,omitempty"`

	// Partitioned means several probers are cut off at once, which is the
	// fleet splitting rather than a host dropping out.
	Partitioned bool `json:"partitioned,omitempty"`

	// Uptime covers the last 30 days for every check and component.
	Uptime []Uptime `json:"uptime"`

	// Notices are the public operator notices that are open, or were resolved
	// in the last week, newest first. Older renderers ignore the field.
	Notices []ExportNotice `json:"notices,omitempty"`
}

const (
	exportNoticeWindow  = 7 * 24 * time.Hour
	maxExportNotices    = 20
	maxExportNoticeUpds = 10
	maxExportNoticeText = 128 << 10
)

// ExportNotice is a public notice without operator identities.
type ExportNotice struct {
	ID         uint64               `json:"id"`
	Kind       string               `json:"kind"`
	Title      string               `json:"title"`
	State      string               `json:"state"`
	Checks     []string             `json:"checks,omitempty"`
	Components []string             `json:"components,omitempty"`
	StartsAt   time.Time            `json:"starts_at,omitzero"`
	EndsAt     time.Time            `json:"ends_at,omitzero"`
	CreatedAt  time.Time            `json:"created_at"`
	UpdatedAt  time.Time            `json:"updated_at"`
	ResolvedAt time.Time            `json:"resolved_at,omitzero"`
	Updates    []ExportNoticeUpdate `json:"updates"`
}

type ExportNoticeUpdate struct {
	At      time.Time `json:"at"`
	State   string    `json:"state"`
	Message string    `json:"message"`
}

// exportNotices bounds what leaves the fleet: at most 20 notices with their 10
// newest updates each, and at most 128 KiB of text. JSON escaping can grow
// text up to six times, which still keeps the export under the renderer's
// 1 MiB limit when a busy incident has many long updates.
func exportNotices(notices []Notice, now time.Time) []ExportNotice {
	var out []ExportNotice
	budget := maxExportNoticeText
	for _, n := range notices {
		if !n.Public || (!n.Open() && now.Sub(n.ResolvedAt) > exportNoticeWindow) {
			continue
		}
		if budget -= len(n.Title); budget < 0 {
			break
		}
		e := ExportNotice{ID: n.ID, Kind: n.Kind, Title: n.Title, State: n.State, Checks: n.Checks, Components: n.Components,
			StartsAt: n.StartsAt, EndsAt: n.EndsAt, CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt, ResolvedAt: n.ResolvedAt}
		for i := len(n.Updates) - 1; i >= 0 && len(e.Updates) < maxExportNoticeUpds; i-- {
			u := n.Updates[i]
			if budget -= len(u.Message); budget < 0 {
				break
			}
			e.Updates = append(e.Updates, ExportNoticeUpdate{At: u.At, State: u.State, Message: u.Message})
		}
		if out = append(out, e); len(out) == maxExportNotices || budget < 0 {
			break
		}
	}
	return out
}

// Export builds the published document.
func (c *Coordinator) Export() Export {
	m := c.Mesh()
	checks := c.Status()
	for i := range checks {
		checks[i].Target = ""
		checks[i].AssignedTo = ""
		checks[i].InconclusiveHistory = nil
		checks[i].LastInconclusive = ""
	}
	return Export{
		Version:     exportVersion,
		Coordinator: c.cfg.Name,
		GeneratedAt: c.now().UTC(),
		Components:  c.Components(),
		Checks:      checks,
		Probers:     len(c.peers),
		Isolated:    m.Isolated,
		Partitioned: m.Partitioned,
		Uptime:      c.UptimeReport(c.now().UTC().Add(-defaultUptimePeriod), c.now().UTC()),
		Notices:     exportNotices(c.Notices(), c.now().UTC()),
	}
}

// SignedExport wraps the export in a signature.
//
// The document leaves the fleet and is rendered by something that cannot
// otherwise tell an authentic export from a file someone replaced. Signing it
// with the key probers already verify means the renderer can check
// provenance without a second trust relationship — and means an export can be
// served from untrusted storage, which is the whole point of putting it there.
func (c *Coordinator) SignedExport() (wire.Envelope, error) {
	return wire.SignDocument(c.cfg.Key, c.cfg.Name, c.Export())
}

func (c *Coordinator) handleExport(w http.ResponseWriter, r *http.Request) {
	// Unsigned by default: the common consumer is an operator with curl or a
	// dashboard on the same host, and making them verify a signature to read
	// their own coordinator is friction with no gain. Signing is for the copy
	// that travels.
	if r.URL.Query().Get("signed") != "true" {
		writeJSON(w, c.Export())
		return
	}
	env, err := c.SignedExport()
	if err != nil {
		c.log.Error("signing export", "err", err)
		http.Error(w, "could not sign export", http.StatusInternalServerError)
		return
	}
	writeJSON(w, env)
}
