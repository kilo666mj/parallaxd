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
// Human-written updates and subscriber notification stay outside this
// automatic monitor. Durable automatic incidents and maintenance suppression
// are exposed separately by the coordinator.

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
}

// Export builds the published document.
func (c *Coordinator) Export() Export {
	m := c.Mesh()
	return Export{
		Version:     exportVersion,
		Coordinator: c.cfg.Name,
		GeneratedAt: c.now().UTC(),
		Components:  c.Components(),
		Checks:      c.Status(),
		Probers:     len(c.peers),
		Isolated:    m.Isolated,
		Partitioned: m.Partitioned,
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
