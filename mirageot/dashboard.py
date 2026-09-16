"""Self-contained read-only dashboard."""

DASHBOARD_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MirageOT — Deception Console</title><style>
:root{--bg:#0b1017;--card:#141d29;--card2:#1b2836;--line:#26384c;--ink:#e8eef5;--soft:#9fb0c3;
--mut:#6d8197;--ac:#3fc7b4;--bl:#4a9eff;--gd:#e8b93f;--dg:#ef5a5a;--ok:#5fd08a}
*{box-sizing:border-box}body{margin:0;font-family:'Segoe UI',Arial,sans-serif;background:var(--bg);color:var(--ink)}
.top{display:flex;justify-content:space-between;align-items:center;padding:14px 22px;border-bottom:1px solid var(--line);background:#0d141d;position:sticky;top:0}
.brand{font-weight:800;font-size:1.15rem;letter-spacing:.5px}.brand b{color:var(--ac)}
.brand .v{color:var(--mut);font-size:.7rem;font-weight:400;margin-left:6px}
.pills{display:flex;gap:8px;color:var(--soft);font-size:.8rem}.pill{background:var(--card2);border:1px solid var(--line);border-radius:999px;padding:5px 12px}
.wrap{max-width:1200px;margin:0 auto;padding:18px 22px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
@media(max-width:800px){.cards{grid-template-columns:repeat(2,1fr)}}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
.kpi .n{font-size:2rem;font-weight:800}.kpi .l{color:var(--mut);font-size:.78rem}
.kpi.dg .n{color:var(--dg)}.kpi.gd .n{color:var(--gd)}.kpi.ac .n{color:var(--ac)}.kpi.bl .n{color:var(--bl)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}
@media(max-width:800px){.grid{grid-template-columns:1fr}}
.panel{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
.panel h3{margin:0 0 12px;font-size:.95rem}
.bar{display:flex;align-items:center;gap:8px;margin:5px 0;font-size:.82rem}
.bar .lb{width:90px;color:var(--soft)}.bar .tr{flex:1;background:var(--card2);border-radius:6px;height:14px;overflow:hidden}
.bar .fl{height:100%;background:linear-gradient(90deg,var(--ac),var(--bl))}.bar .vv{width:34px;text-align:left;color:var(--soft)}
table{width:100%;border-collapse:collapse;font-size:.8rem}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-weight:600}
.chip{display:inline-block;font-size:.68rem;padding:2px 7px;border-radius:5px;margin:2px;background:var(--card2);border:1px solid var(--line);color:var(--soft)}
.stage{font-size:.66rem;padding:2px 7px;border-radius:5px}
.stage.RECON{background:rgba(74,158,255,.18);color:#9fd0ff}.stage.INTERACTION{background:rgba(232,185,63,.18);color:#f0d888}
.stage.MANIPULATION{background:rgba(239,90,90,.2);color:#ffb3b3}
.feed{max-height:340px;overflow-y:auto;font-family:Consolas,monospace;font-size:.75rem}
.ev{padding:4px 6px;border-bottom:1px solid rgba(38,56,76,.5);display:flex;gap:8px}
.ev .s{width:64px}.sev-LOW{color:var(--mut)}.sev-MEDIUM{color:var(--gd)}.sev-HIGH{color:var(--dg)}.sev-CRITICAL{color:#fff;background:var(--dg);padding:0 4px;border-radius:3px}
.mut{color:var(--mut)}.live{width:9px;height:9px;border-radius:50%;background:var(--ok);display:inline-block;box-shadow:0 0 10px var(--ok);animation:p 1.5s infinite}
@keyframes p{50%{opacity:.4}}
</style></head><body>
<div class="top"><div class="brand"><span class="live"></span> Mirage<b>OT</b> <span class="v">Deception Console</span></div>
<div class="pills"><span class="pill" id="p-decoys">decoys: —</span><span class="pill" id="p-up">uptime: —</span></div></div>
<div class="wrap">
<div class="cards">
  <div class="kpi ac"><div class="n" id="k-ev">0</div><div class="l">Total interactions</div></div>
  <div class="kpi gd"><div class="n" id="k-atk">0</div><div class="l">Unique attackers</div></div>
  <div class="kpi dg"><div class="n" id="k-man">0</div><div class="l">In manipulation stage</div></div>
  <div class="kpi bl"><div class="n" id="k-blk">0</div><div class="l">Auto-blocked IPs</div></div>
</div>
<div class="grid">
  <div class="panel"><h3>Decoys hit (by protocol)</h3><div id="proto"></div></div>
  <div class="panel"><h3>MITRE ATT&CK for ICS — techniques observed</h3><div id="mitre"></div></div>
</div>
<div class="grid">
  <div class="panel"><h3>Top attackers</h3><div style="overflow-x:auto"><table id="tatk">
    <tr><th>Source IP</th><th>Stage</th><th>Score</th><th>Events</th><th>Decoys</th><th>Last seen</th></tr></table></div></div>
  <div class="panel"><h3>Live event feed</h3><div class="feed" id="feed"></div></div>
</div>
</div>
<script>
const $=i=>document.getElementById(i);
function fmtUp(s){const h=(s/3600|0),m=((s%3600)/60|0);return h+"h "+m+"m";}
function esc(v){return String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
async function tick(){
 let d; try{const response=await fetch('/api/stats',{headers:window.mirageToken?{'Authorization':'Bearer '+window.mirageToken}:{}});
 if(response.status===401){if(!window.authPrompted){window.authPrompted=true;const token=prompt('MirageOT console token');if(token){window.mirageToken=token;sessionStorage.setItem('mirageToken',token);window.authPrompted=false;}}return;}
 if(!response.ok)return;d=await response.json();}catch(e){return;}
 $('k-ev').textContent=d.totals.events;$('k-atk').textContent=d.totals.attackers;
 $('k-man').textContent=d.totals.manipulation;$('k-blk').textContent=d.totals.blocked;
 $('p-decoys').textContent='decoys online: '+d.decoys_online.length;
 $('p-up').textContent='uptime: '+fmtUp(d.uptime);
 const mx=Math.max(1,...Object.values(d.by_protocol));
 $('proto').innerHTML=Object.entries(d.by_protocol).sort((a,b)=>b[1]-a[1]).map(([k,v])=>
   `<div class="bar"><span class="lb">${esc(k)}</span><span class="tr"><span class="fl" style="width:${esc(v/mx*100)}%"></span></span><span class="vv">${esc(v)}</span></div>`).join('')||'<span class="mut">no activity yet</span>';
 $('mitre').innerHTML=d.techniques.map(t=>`<span class="chip">${esc(t.id)} · ${esc(t.name)}</span>`).join('')||'<span class="mut">none observed</span>';
 $('tatk').innerHTML='<tr><th>Source IP</th><th>Stage</th><th>Score</th><th>Events</th><th>Decoys</th><th>Last seen</th></tr>'+
   d.top_attackers.map(a=>`<tr><td><b>${esc(a.ip)}</b></td><td><span class="stage ${esc(a.stage)}">${esc(a.stage)}</span></td>
   <td>${esc(a.score)}</td><td>${esc(a.events)}</td><td class="mut">${esc(a.decoys.join(', '))}</td><td class="mut">${esc(a.last_seen.replace('T',' '))}</td></tr>`).join('');
 $('feed').innerHTML=d.recent.map(e=>`<div class="ev"><span class="s sev-${esc(e.severity)}">${esc(e.severity)}</span>
   <span class="mut">${esc(e.time.split('T')[1])}</span><b>${esc(e.protocol)}</b><span class="mut">${esc(e.src_ip)}</span>${esc(e.action)} — ${esc(e.detail)}</div>`).join('');
}
window.mirageToken=sessionStorage.getItem('mirageToken')||'';
tick();setInterval(tick,2000);
</script></body></html>"""
