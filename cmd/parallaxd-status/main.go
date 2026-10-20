// Command parallaxd-status renders a static public status page from the
// coordinator's signed export.
//
// It runs once: fetch the export, verify its signature with the coordinator's
// public key, keep only the checks and components the configuration lists, and
// atomically replace index.html in the output directory. Run it from a timer
// and serve the directory from somewhere that does not share the monitored
// fleet's failure modes. When fetching or verification fails, the previous page
// is left in place; the page itself tells readers when its data is old.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kilo666mj/parallaxd/internal/coordinator"
	"github.com/kilo666mj/parallaxd/internal/wire"
)

var version = "dev"

const maxExportBytes = 1 << 20

type duration time.Duration

func (d *duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf(`duration must be a string like "5m": %w`, err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = duration(parsed)
	return nil
}

type config struct {
	// Source is the signed export: an http(s) URL such as
	// http://127.0.0.1:8972/v1/export?signed=true, or a local file path.
	Source          string `json:"source"`
	CoordinatorName string `json:"coordinator_name"`
	CoordinatorKey  string `json:"coordinator_key"`
	OutputDir       string `json:"output_dir"`

	Title   string `json:"title"`
	LogoURL string `json:"logo_url,omitempty"`
	// MaxAge is how old the data may be before the page says it is stale.
	MaxAge duration `json:"max_age,omitempty"`
	// Groups list everything the page shows. Nothing else in the export is
	// published, so internal check names stay private.
	Groups []group `json:"groups"`
}

type group struct {
	Name  string `json:"name"`
	Items []item `json:"items"`
}

type item struct {
	Check     string `json:"check,omitempty"`
	Component string `json:"component,omitempty"`
	Label     string `json:"label,omitempty"`
}

func loadConfig(path string) (config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}
	var cfg config
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = duration(5 * time.Minute)
	}
	switch {
	case cfg.Source == "" || cfg.OutputDir == "":
		return config{}, errors.New("source and output_dir are required")
	case cfg.CoordinatorName == "" || cfg.CoordinatorKey == "":
		return config{}, errors.New("coordinator_name and coordinator_key are required")
	case cfg.Title == "":
		return config{}, errors.New("title is required")
	case len(cfg.Groups) == 0:
		return config{}, errors.New("at least one group is required; only listed checks and components are published")
	}
	for _, g := range cfg.Groups {
		if g.Name == "" || len(g.Items) == 0 {
			return config{}, errors.New("every group needs a name and at least one item")
		}
		for _, it := range g.Items {
			if (it.Check == "") == (it.Component == "") {
				return config{}, fmt.Errorf("group %q: each item names exactly one check or component", g.Name)
			}
		}
	}
	return cfg, nil
}

func fetch(source string) ([]byte, error) {
	var body io.Reader
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(source)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch %s: %s", source, resp.Status)
		}
		body = resp.Body
	} else {
		f, err := os.Open(source)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		body = f
	}
	raw, err := io.ReadAll(io.LimitReader(body, maxExportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxExportBytes {
		return nil, fmt.Errorf("export exceeds %d bytes", maxExportBytes)
	}
	return raw, nil
}

func verify(raw []byte, name, key string) (coordinator.Export, error) {
	pub, err := wire.DecodePublicKey(key)
	if err != nil {
		return coordinator.Export{}, fmt.Errorf("coordinator key: %w", err)
	}
	keys := wire.NewKeyring()
	if err := keys.Add(name, pub); err != nil {
		return coordinator.Export{}, err
	}
	var env wire.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return coordinator.Export{}, fmt.Errorf("decode envelope: %w", err)
	}
	if env.Peer != name {
		return coordinator.Export{}, fmt.Errorf("export signed by %q, expected %q", env.Peer, name)
	}
	payload, err := keys.OpenDocument(env)
	if err != nil {
		return coordinator.Export{}, err
	}
	var export coordinator.Export
	if err := json.Unmarshal(payload, &export); err != nil {
		return coordinator.Export{}, fmt.Errorf("decode export: %w", err)
	}
	if export.Version != 1 {
		return coordinator.Export{}, fmt.Errorf("unsupported export version %d", export.Version)
	}
	return export, nil
}

type pageRow struct {
	Label  string
	Status string // up, warning, down or unknown
	Since  time.Time
	Uptime string
}

type pageGroup struct {
	Name string
	Rows []pageRow
}

type pageNotice struct {
	Title    string
	State    string
	Tone     string // down for open incidents, warning for maintenance, up when closed
	Affected []string
	StartsAt time.Time
	EndsAt   time.Time
	Updates  []coordinator.ExportNoticeUpdate
}

type page struct {
	Title       string
	LogoURL     string
	Overall     string
	OverallTone string
	GeneratedAt time.Time
	Stale       bool
	MaxAge      time.Duration
	Groups      []pageGroup
	// Incidents and Maintenance are open notices; Past were closed in the
	// last week. Notices never change the statuses above.
	Incidents   []pageNotice
	Maintenance []pageNotice
	Past        []pageNotice
}

func build(cfg config, export coordinator.Export, now time.Time) (page, []string) {
	checks := map[string]coordinator.StatusEntry{}
	for _, e := range export.Checks {
		checks[e.Check] = e
	}
	components := map[string]coordinator.ComponentEntry{}
	for _, e := range export.Components {
		components[e.Component] = e
	}
	uptime := map[string]float64{}
	for _, u := range export.Uptime {
		if u.Component != "" {
			uptime["component:"+u.Component] = u.Uptime
		} else {
			uptime["check:"+u.Check] = u.Uptime
		}
	}

	var warnings []string
	counts := map[string]int{}
	p := page{Title: cfg.Title, LogoURL: cfg.LogoURL, GeneratedAt: export.GeneratedAt, MaxAge: time.Duration(cfg.MaxAge)}
	p.Stale = now.Sub(export.GeneratedAt) > p.MaxAge
	for _, g := range cfg.Groups {
		pg := pageGroup{Name: g.Name}
		for _, it := range g.Items {
			row := pageRow{Label: it.Label, Status: "unknown"}
			key := "check:" + it.Check
			if it.Component != "" {
				key = "component:" + it.Component
				if row.Label == "" {
					row.Label = it.Component
				}
				if e, ok := components[it.Component]; ok {
					row.Status, row.Since = e.Status, e.Since
				} else {
					warnings = append(warnings, fmt.Sprintf("component %q is not in the export", it.Component))
				}
			} else {
				if row.Label == "" {
					row.Label = it.Check
				}
				if e, ok := checks[it.Check]; ok {
					row.Status, row.Since = e.Status, e.Since
					if e.Stale {
						row.Status = "unknown"
					}
				} else {
					warnings = append(warnings, fmt.Sprintf("check %q is not in the export", it.Check))
				}
			}
			if p.Stale {
				row.Status = "unknown"
			}
			if u, ok := uptime[key]; ok {
				row.Uptime = fmt.Sprintf("%.2f%%", 100*u)
			}
			counts[row.Status]++
			pg.Rows = append(pg.Rows, row)
		}
		p.Groups = append(p.Groups, pg)
	}

	p.Incidents, p.Maintenance, p.Past = notices(cfg, export.Notices)

	total := counts["up"] + counts["warning"] + counts["down"] + counts["unknown"]
	switch {
	case p.Stale:
		p.Overall, p.OverallTone = "Status data is out of date", "unknown"
	case counts["down"] > 0 && counts["down"] == total:
		p.Overall, p.OverallTone = "Major outage", "down"
	case counts["down"] > 0:
		p.Overall, p.OverallTone = "Partial outage", "down"
	case counts["warning"] > 0:
		p.Overall, p.OverallTone = "Degraded performance", "warning"
	case counts["unknown"] > 0:
		p.Overall, p.OverallTone = "Some services cannot be checked", "unknown"
	default:
		p.Overall, p.OverallTone = "All systems operational", "up"
	}
	return p, warnings
}

// notices sorts the export's public notices for the page. Only affected items
// that the page lists are named, so internal names stay private.
func notices(cfg config, exported []coordinator.ExportNotice) (incidents, maintenance, past []pageNotice) {
	labels := map[string]string{}
	for _, g := range cfg.Groups {
		for _, it := range g.Items {
			if it.Component != "" {
				labels["component:"+it.Component] = cmpOr(it.Label, it.Component)
			} else {
				labels["check:"+it.Check] = cmpOr(it.Label, it.Check)
			}
		}
	}
	for _, n := range exported {
		pn := pageNotice{Title: n.Title, State: n.State, StartsAt: n.StartsAt, EndsAt: n.EndsAt, Updates: n.Updates}
		seen := map[string]bool{}
		for _, key := range append(prefixed("component:", n.Components), prefixed("check:", n.Checks)...) {
			if label, ok := labels[key]; ok && !seen[label] {
				seen[label] = true
				pn.Affected = append(pn.Affected, label)
			}
		}
		switch {
		case !n.ResolvedAt.IsZero():
			pn.Tone = "up"
			past = append(past, pn)
		case n.Kind == coordinator.NoticeMaintenance:
			pn.Tone = "warning"
			maintenance = append(maintenance, pn)
		default:
			pn.Tone = "down"
			incidents = append(incidents, pn)
		}
	}
	return incidents, maintenance, past
}

func prefixed(prefix string, names []string) []string {
	out := make([]string, len(names))
	for i, name := range names {
		out[i] = prefix + name
	}
	return out
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

var pageTemplate = template.Must(template.New("page").Funcs(template.FuncMap{
	"label": func(status string) string {
		switch status {
		case "up":
			return "Operational"
		case "warning":
			return "Degraded"
		case "down":
			return "Outage"
		}
		return "Unknown"
	},
	"stateLabel": func(state string) string {
		switch state {
		case "in_progress":
			return "In progress"
		case "":
			return ""
		}
		return strings.ToUpper(state[:1]) + state[1:]
	},
	"rfc3339":   func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
	"humanTime": func(t time.Time) string { return t.UTC().Format("2 Jan 2006 15:04 UTC") },
	"seconds":   func(d time.Duration) int64 { return int64(d.Seconds()) },
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>{{.Title}}</title>
<style>
:root{--bg:#f7f7f5;--card:#fff;--text:#1d1d1b;--muted:#6b6b66;--line:#e4e4df;--up:#1f8a4c;--warning:#b7791f;--down:#c53030;--unknown:#7a7a75}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--card:#1e1e1c;--text:#ecece8;--muted:#a3a39d;--line:#33332f;--up:#48bb78;--warning:#ecc94b;--down:#fc8181;--unknown:#a3a39d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:760px;margin:0 auto;padding:32px 16px 48px}header{display:flex;align-items:center;gap:12px;margin-bottom:24px}
header img{height:36px;width:auto}h1{font-size:22px;margin:0}
.overall{border-radius:10px;padding:16px 18px;color:#fff;font-weight:600;margin-bottom:8px}
.overall.up{background:var(--up)}.overall.warning{background:var(--warning)}.overall.down{background:var(--down)}.overall.unknown{background:var(--unknown)}
.updated{color:var(--muted);font-size:13px;margin:0 0 24px}
#stale{display:none;border:1px solid var(--warning);border-radius:10px;padding:12px 16px;margin-bottom:24px}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;margin-bottom:16px}
h2{font-size:15px;margin:0;padding:12px 16px;border-bottom:1px solid var(--line)}
.row{display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--line)}.row:last-child{border-bottom:0}
.name{flex:1;min-width:0;overflow-wrap:anywhere}.uptime{color:var(--muted);font-size:13px;white-space:nowrap}
.status{font-size:13px;font-weight:600;white-space:nowrap}.status.up{color:var(--up)}.status.warning{color:var(--warning)}.status.down{color:var(--down)}.status.unknown{color:var(--unknown)}
footer{color:var(--muted);font-size:12px;margin-top:24px}
.notice{padding:14px 16px;border-bottom:1px solid var(--line)}.notice:last-child{border-bottom:0}
.notice h3{font-size:15px;margin:0 0 4px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.notice .state{font-size:12px;font-weight:600}.state.up{color:var(--up)}.state.warning{color:var(--warning)}.state.down{color:var(--down)}
.meta{color:var(--muted);font-size:13px;margin:0 0 8px}.update{margin:8px 0 0}.update p{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}
details summary{cursor:pointer;padding:12px 16px;font-weight:600}
</style>
</head>
<body>
<main>
<header>{{if .LogoURL}}<img src="{{.LogoURL}}" alt="">{{end}}<h1>{{.Title}}</h1></header>
<div class="overall {{.OverallTone}}">{{.Overall}}</div>
<p class="updated">Updated <time datetime="{{rfc3339 .GeneratedAt}}">{{humanTime .GeneratedAt}}</time></p>
<div id="stale" role="status">This page has not been updated recently, so the statuses below may be out of date.</div>
{{if .Incidents}}<section><h2>Current incidents</h2>{{range .Incidents}}{{template "notice" .}}{{end}}</section>
{{end}}{{if .Maintenance}}<section><h2>Scheduled maintenance</h2>{{range .Maintenance}}{{template "notice" .}}{{end}}</section>
{{end}}{{range .Groups}}<section><h2>{{.Name}}</h2>
{{range .Rows}}<div class="row"><span class="name">{{.Label}}</span>{{if .Uptime}}<span class="uptime" title="Uptime over the last 30 days">{{.Uptime}}</span>{{end}}<span class="status {{.Status}}">{{label .Status}}</span></div>
{{end}}</section>
{{end}}{{if .Past}}<section><details><summary>Recently resolved</summary>{{range .Past}}{{template "notice" .}}{{end}}</details></section>
{{end}}<footer>Corroborated by independent probers with parallaxd. Uptime covers the last 30 days.</footer>
</main>
<script>
(function(){var g=Date.parse("{{rfc3339 .GeneratedAt}}"),max={{seconds .MaxAge}}*1000;
function check(){if(Date.now()-g>max){document.getElementById("stale").style.display="block"}}
check();setInterval(check,30000)})();
</script>
</body>
</html>
{{define "notice"}}<div class="notice"><h3>{{.Title}} <span class="state {{.Tone}}">{{stateLabel .State}}</span></h3>
{{if not .StartsAt.IsZero}}<p class="meta">Scheduled <time datetime="{{rfc3339 .StartsAt}}">{{humanTime .StartsAt}}</time> to <time datetime="{{rfc3339 .EndsAt}}">{{humanTime .EndsAt}}</time></p>{{end}}
{{if .Affected}}<p class="meta">Affects {{range $i, $a := .Affected}}{{if $i}}, {{end}}{{$a}}{{end}}</p>{{end}}
{{range .Updates}}<div class="update"><p class="meta"><strong>{{stateLabel .State}}</strong> · <time datetime="{{rfc3339 .At}}">{{humanTime .At}}</time></p><p>{{.Message}}</p></div>
{{end}}</div>{{end}}`))

// writeAtomic replaces dir/index.html so a reader never sees a partial page.
func writeAtomic(dir string, content []byte) error {
	tmp, err := os.CreateTemp(dir, ".index-*.html")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(dir, "index.html"))
}

func run(configPath string, now time.Time) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	raw, err := fetch(cfg.Source)
	if err != nil {
		return err
	}
	export, err := verify(raw, cfg.CoordinatorName, cfg.CoordinatorKey)
	if err != nil {
		return err
	}
	p, warnings := build(cfg, export, now)
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	var out bytes.Buffer
	if err := pageTemplate.Execute(&out, p); err != nil {
		return err
	}
	return writeAtomic(cfg.OutputDir, out.Bytes())
}

func main() {
	configPath := flag.String("config", "/etc/parallaxd-status/status.json", "status page configuration")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if err := run(*configPath, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "parallaxd-status:", err)
		os.Exit(1)
	}
}
