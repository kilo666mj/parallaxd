package coordinator

import (
	"fmt"
	"net/http"
)

const dashboardHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>parallaxd operations</title><style>
:root{color-scheme:dark;--bg:#111;--panel:#191b1f;--line:#414650;--text:#eee;--muted:#aaa;--blue:#8ab4f8;--green:#36c275;--red:#ef5350;--amber:#f1b44c}
*{box-sizing:border-box}body{font:15px/1.45 system-ui;margin:auto;max-width:1180px;padding:2rem;background:var(--bg);color:var(--text)}h1{margin:0;font-size:2.2rem}h2{margin:2rem 0 .8rem}h3{margin:.2rem 0}.meta,.muted{color:var(--muted)}.top{display:flex;gap:1rem;align-items:end;justify-content:space-between;flex-wrap:wrap}.operator{display:flex;gap:.5rem;flex-wrap:wrap;align-items:end}.field{display:grid;gap:.25rem}.field label{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}input,select,button{font:inherit;border:1px solid var(--line);border-radius:7px;padding:.55rem .7rem;background:#202329;color:var(--text)}button{cursor:pointer}button:hover{border-color:var(--blue)}button.danger{color:#ffaaa8}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:.8rem}.card{border:1px solid var(--line);border-radius:10px;padding:1rem;background:var(--panel);min-width:0}.up{border-left:6px solid var(--green)}.down{border-left:6px solid var(--red)}.unknown{border-left:6px solid var(--amber)}code{color:#c0c6cf;overflow-wrap:anywhere}.actions{display:flex;gap:.5rem;margin-top:.8rem;flex-wrap:wrap}.badge{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:.15rem .5rem;margin:.2rem .2rem 0 0;color:var(--muted);font-size:.8rem}.notice{display:none;margin:1rem 0;padding:.7rem 1rem;border-radius:8px;background:#202329;border-left:5px solid var(--blue)}.notice.error{border-color:var(--red)}.silence-form{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.7rem}.wide{grid-column:span 2}.silence-form button{align-self:end}.empty{color:var(--muted);padding:.5rem 0}@media(max-width:760px){body{padding:1rem}.silence-form{grid-template-columns:1fr}.wide{grid-column:auto}}
</style></head><body>
<header class="top"><div><h1>parallaxd</h1><p id="meta" class="meta">Loading…</p></div>
<div class="operator"><div class="field"><label for="actor">Operator</label><input id="actor" autocomplete="username" placeholder="name"></div><div class="field"><label for="token">API token</label><input id="token" type="password" autocomplete="current-password" placeholder="session only"></div><button id="saveAuth">Use credentials</button></div></header>
<p id="notice" class="notice"></p>
<h2>Components</h2><div id="components" class="grid"></div>
<h2>Checks</h2><div id="checks" class="grid"></div>
<h2>Active incidents</h2><div id="incidents" class="grid"></div>
<h2>Silences</h2>
<form id="silenceForm" class="card silence-form"><div class="field"><label for="silenceName">Name</label><input id="silenceName" required placeholder="mail deploy"></div><div class="field"><label for="silenceEnd">Ends</label><input id="silenceEnd" type="datetime-local" required></div><div class="field"><label for="scopeType">Scope</label><select id="scopeType"><option value="checks">Checks</option><option value="components">Components</option><option value="probers">Probers</option><option value="fleet">Entire fleet</option></select></div><div class="field wide"><label for="scopeNames">Names, comma separated</label><input id="scopeNames" placeholder="mx-smtp, mxs-smtp"></div><div class="field wide"><label for="silenceComment">Comment</label><input id="silenceComment" placeholder="change or ticket reference"></div><button type="submit">Create silence</button></form>
<div id="silences" class="grid" style="margin-top:.8rem"></div>
<h2>Diagnostics</h2><div id="diagnostics" class="grid"></div>
<script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const byId=id=>document.getElementById(id);let state={incidents:[],silences:[]};
actor.value=sessionStorage.getItem('parallaxd.actor')||'';token.value=sessionStorage.getItem('parallaxd.token')||'';
function message(text,error){notice.textContent=text;notice.className='notice'+(error?' error':'');notice.style.display='block';setTimeout(()=>notice.style.display='none',6000)}
saveAuth.onclick=()=>{sessionStorage.setItem('parallaxd.actor',actor.value.trim());sessionStorage.setItem('parallaxd.token',token.value);message('Credentials saved for this browser tab.')};
function card(title,status,detail,extra){return '<article class="card '+esc(status)+'"><h3>'+esc(title)+'</h3><span class="badge">'+esc(status)+'</span><p><code>'+esc(detail)+'</code></p>'+(extra||'')+'</article>'}
async function json(url){const r=await fetch(url);if(!r.ok)throw new Error(url+' returned '+r.status);return r.json()}
async function mutate(url,method,body){const who=actor.value.trim(),secret=token.value;if(!who||!secret)throw new Error('Enter operator name and API token first');sessionStorage.setItem('parallaxd.actor',who);sessionStorage.setItem('parallaxd.token',secret);body.actor=who;const r=await fetch(url,{method:method,headers:{'Authorization':'Bearer '+secret,'Content-Type':'application/json'},body:JSON.stringify(body)});if(!r.ok)throw new Error((await r.text()).trim()||('request returned '+r.status));return r.status===204?null:r.json()}
function renderIncidents(items){const active=(Array.isArray(items)?items:[]).filter(x=>x.active);incidents.innerHTML=active.map(x=>{const ack=x.acknowledged_by?'Acknowledged by '+x.acknowledged_by:'Unacknowledged';const buttons='<div class="actions"><button onclick="incidentAction('+x.id+',\'acknowledge\')">Acknowledge</button><button class="danger" onclick="incidentAction('+x.id+',\'resolve\')">Resolve</button></div>';return card(x.subject,'down',x.kind+' since '+new Date(x.opened_at).toLocaleString()+' · '+ack,buttons)}).join('')||'<p class="empty">No active incidents.</p>'}
async function incidentAction(id,action){const note=prompt(action==='acknowledge'?'Acknowledgement note':'Resolution note')||'';try{await mutate('/v1/incidents/'+id+'/'+action,'POST',{note:note});message('Incident '+action+'d.');await load()}catch(e){message(e.message,true)}}
function renderSilences(items){const now=Date.now(),live=(Array.isArray(items)?items:[]).filter(x=>!x.cancelled_at&&new Date(x.ends_at).getTime()>now);silences.innerHTML=live.map(x=>{const scope=[...(x.checks||[]),...(x.components||[]),...(x.probers||[])].join(', ')||'entire fleet';const buttons='<div class="actions"><button class="danger" onclick="cancelSilence('+x.id+')">Cancel</button></div>';return card(x.name,new Date(x.starts_at)>new Date()?'unknown':'up','until '+new Date(x.ends_at).toLocaleString()+' · '+scope+' · by '+x.created_by,buttons)}).join('')||'<p class="empty">No active or scheduled silences.</p>'}
async function cancelSilence(id){const note=prompt('Cancellation note')||'';try{await mutate('/v1/silences/'+id,'DELETE',{note:note});message('Silence cancelled.');await load()}catch(e){message(e.message,true)}}
silenceForm.onsubmit=async e=>{e.preventDefault();const end=new Date(silenceEnd.value);if(!Number.isFinite(end.getTime()))return message('Choose a valid end time.',true);const type=scopeType.value,names=scopeNames.value.split(',').map(x=>x.trim()).filter(Boolean);const body={name:silenceName.value.trim(),ends_at:end.toISOString(),comment:silenceComment.value.trim()};if(type!=='fleet')body[type]=names;try{await mutate('/v1/silences','POST',body);silenceForm.reset();message('Silence created.');await load()}catch(err){message(err.message,true)}};
function renderDiagnostics(d){const n=d.notifications||{},q=d.result_queue||{},rejected=Object.entries(d.rejected_results||{}).filter(x=>x[1]).map(x=>x[0]+': '+x[1]).join(', ')||'none';const moved=(d.assignments||[]).filter(x=>x.preferred_owner!==x.effective_owner);const suspects=(d.checks||[]).filter(x=>x.suspected_since);const suspectDetail=suspects.map(x=>x.check+' since '+new Date(x.suspected_since).toLocaleString()+' · '+(x.inconclusive_attempts||0)+' inconclusive'+(x.last_inconclusive_reason?' · '+x.last_inconclusive_reason:'')).join('; ')||'none';const destinationErrors=Object.entries(n.destinations||{}).filter(x=>x[1].last_error).map(x=>x[0]+': '+x[1].last_error).join(' · ');const oldest=n.oldest_pending?' · oldest '+new Date(n.oldest_pending).toLocaleString():'';diagnostics.innerHTML=card('Result queue',q.depth>=q.capacity&&q.capacity?'down':'up',(q.depth||0)+' / '+(q.capacity||0)+' slots')+card('Notifications',(n.pending||destinationErrors)?'unknown':'up',(n.attempts||0)+' attempts · '+(n.failures||0)+' failures · '+(n.pending||0)+' pending'+oldest+(destinationErrors?' · '+destinationErrors:''))+card('Suspect checks',suspects.length?'unknown':'up',suspectDetail)+card('Rejected results','unknown',rejected)+card('Assignment failover',moved.length?'unknown':'up',moved.map(x=>x.check+': '+x.preferred_owner+' → '+x.effective_owner).join(', ')||'all preferred owners active')}
async function load(){try{const [e,i,s,d]=await Promise.all([json('/v1/export'),json('/v1/incidents'),json('/v1/silences'),json('/v1/diagnostics')]);state={incidents:i,silences:s};meta.textContent=e.coordinator+' · generated '+new Date(e.generated_at).toLocaleString()+' · '+e.probers+' probers';components.innerHTML=(e.components||[]).map(x=>card(x.component,x.status,x.description)).join('')||'<p class="empty">No components configured.</p>';checks.innerHTML=(e.checks||[]).map(x=>{const suspect=x.suspected_since?' · suspected since '+new Date(x.suspected_since).toLocaleString():'';return card(x.check,x.status,x.target+(x.stale?' · STALE':'')+suspect)}).join('');renderIncidents(i);renderSilences(s);renderDiagnostics(d)}catch(e){meta.textContent='Could not load status: '+e;message(e.message,true)}}
load();setInterval(load,30000);
</script></body></html>`

func (c *Coordinator) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	fmt.Fprint(w, dashboardHTML)
}
