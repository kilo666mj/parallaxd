package coordinator

import (
	"fmt"
	"net/http"
)

const dashboardHTML = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>parallaxd status</title><style>body{font:16px system-ui;margin:auto;max-width:1000px;padding:2rem;background:#111;color:#eee}h1{margin-bottom:.2rem}.meta{color:#aaa}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem}.card{border:1px solid #444;border-radius:10px;padding:1rem}.up{border-left:6px solid #36c275}.down{border-left:6px solid #ef5350}.unknown{border-left:6px solid #f1b44c}code{color:#bbb}a{color:#8ab4f8}</style></head><body><h1>parallaxd</h1><p id="meta" class="meta">Loading…</p><h2>Components</h2><div id="components" class="grid"></div><h2>Checks</h2><div id="checks" class="grid"></div><h2>Active incidents</h2><div id="incidents" class="grid"></div><script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function card(title,status,detail){return '<article class="card '+esc(status)+'"><strong>'+esc(title)+'</strong><p>'+esc(status)+'</p><code>'+esc(detail)+'</code></article>'}
async function load(){const [e,i]=await Promise.all([fetch('/v1/export').then(r=>r.json()),fetch('/v1/incidents').then(r=>r.json())]);const history=Array.isArray(i)?i:[];meta.textContent=e.coordinator+' · generated '+new Date(e.generated_at).toLocaleString()+' · '+e.probers+' probers';components.innerHTML=e.components.map(x=>card(x.component,x.status,x.description)).join('')||'<p>No components configured.</p>';checks.innerHTML=e.checks.map(x=>card(x.check,x.status,x.target+(x.stale?' · STALE':''))).join('');incidents.innerHTML=history.filter(x=>x.active).map(x=>card(x.subject,'down',x.kind+' since '+new Date(x.opened_at).toLocaleString())).join('')||'<p>No active incidents.</p>'}load().catch(e=>meta.textContent='Could not load status: '+e);setInterval(load,30000);
</script></body></html>`

func (c *Coordinator) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, dashboardHTML)
}
