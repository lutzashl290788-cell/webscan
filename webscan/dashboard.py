"""Self-contained browser dashboard served by ``webscan serve``."""

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebScan Dashboard</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#11182a;--line:#26314a;--text:#e9eef7;
--muted:#93a2ba;--blue:#58a6ff;--red:#f85149;--orange:#db6d28;--yellow:#d29922;
--low:#388bfd;--info:#7d8590}*{box-sizing:border-box}body{margin:0;background:var(--bg);
color:var(--text);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
button,input,select{font:inherit}.app{display:grid;grid-template-columns:280px minmax(0,1fr);
min-height:100vh}.side{border-right:1px solid var(--line);background:#0e1526;min-width:0}
.brand{height:72px;display:flex;align-items:center;gap:12px;padding:0 18px;border-bottom:1px solid var(--line)}
.mark{display:grid;place-items:center;width:34px;height:34px;border:1px solid var(--blue);
border-radius:7px;color:#9ecbff;font-weight:800;font-size:11px}.brand strong{display:block;font-size:15px}
.brand small{color:var(--muted)}.side-head{padding:16px 14px 10px;display:flex;align-items:center;
justify-content:space-between}.side-head span{color:var(--muted);font-size:11px;font-weight:700;
text-transform:uppercase;letter-spacing:1px}.history{padding:0 8px 20px}.history button{width:100%;
text-align:left;border:1px solid transparent;background:transparent;color:var(--text);padding:10px;
border-radius:6px;cursor:pointer;margin:2px 0}.history button:hover{background:#151f34}
.history button.active{background:#17243b;border-color:#31527c}.history .target{display:block;
white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:600}.history .sub{display:flex;
justify-content:space-between;color:var(--muted);font-size:11px;margin-top:4px}.empty{color:var(--muted);
padding:18px 10px}.main{min-width:0}.top{min-height:72px;display:flex;align-items:center;gap:10px;
padding:12px 24px;border-bottom:1px solid var(--line);background:#0d1424;position:sticky;top:0;z-index:3}
.target-input{flex:1;min-width:180px}.input,select{height:38px;border:1px solid #34415d;
border-radius:6px;background:#111a2e;color:var(--text);padding:0 11px;outline:none}.input:focus,select:focus{
border-color:var(--blue);box-shadow:0 0 0 2px #1f6feb33}.primary,.ghost,.danger{height:38px;
border-radius:6px;padding:0 14px;font-weight:700;cursor:pointer}.primary{border:1px solid #2f81f7;
background:#1f6feb;color:white}.primary:hover{background:#2879e8}.primary:disabled{opacity:.55;cursor:wait}
.ghost{border:1px solid #34415d;background:#151e31;color:var(--text)}.danger{border:1px solid #6e3030;
background:#281719;color:#ff9b95}.content{padding:26px 24px 56px;max-width:1500px;margin:0 auto}
.overview{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin-bottom:20px}
.overview h1{font-size:24px;margin:0 0 4px;letter-spacing:0}.overview p{color:var(--muted);margin:0;
overflow-wrap:anywhere}.metrics{display:grid;grid-template-columns:repeat(6,minmax(90px,1fr));border:1px solid var(--line);
border-radius:7px;overflow:hidden;margin-bottom:18px}.metric{padding:14px 16px;background:var(--panel);
border-right:1px solid var(--line)}.metric:last-child{border:0}.metric strong{display:block;font-size:22px}
.metric span{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.7px}
.filters{display:flex;flex-wrap:wrap;gap:8px;padding:12px 0;border-top:1px solid var(--line);
border-bottom:1px solid var(--line);margin-bottom:14px}.filters .input{min-width:230px;flex:1}.table-wrap{
overflow:auto;border:1px solid var(--line);border-radius:7px}table{width:100%;border-collapse:collapse;
min-width:820px;background:var(--panel)}th{text-align:left;padding:10px 12px;color:var(--muted);
font-size:11px;text-transform:uppercase;letter-spacing:.7px;background:#0f1728;border-bottom:1px solid var(--line)}
td{padding:12px;border-bottom:1px solid #202b41;vertical-align:top}tr:last-child td{border-bottom:0}
tr:hover td{background:#151f34}.badge{display:inline-block;min-width:72px;text-align:center;
padding:3px 7px;border-radius:4px;color:white;font-size:10px;font-weight:800;letter-spacing:.5px}
.critical{background:var(--red)}.high{background:var(--orange)}.medium{background:var(--yellow)}
.low{background:var(--low)}.info{background:var(--info)}.finding-title{font-weight:650}.finding-url{
color:var(--muted);font-size:11px;max-width:360px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.confidence{color:#c1cbe0;font-size:12px}.plugin{color:#9ecbff;font-family:ui-monospace,monospace}
.message{padding:44px 10px;text-align:center;color:var(--muted);border:1px dashed #34415d;border-radius:7px}
.summary{padding:14px 16px;border-left:3px solid var(--blue);background:#111b2f;margin:0 0 18px;
white-space:pre-wrap}.status{color:var(--muted);font-size:12px;min-width:70px;text-align:right}
@media(max-width:850px){.app{grid-template-columns:1fr}.side{display:none}.top{padding:10px 14px;
flex-wrap:wrap}.content{padding:20px 14px}.metrics{grid-template-columns:repeat(3,1fr)}
.metric:nth-child(3){border-right:0}.overview{align-items:flex-start}.danger{height:34px}}
</style>
</head>
<body>
<div class="app">
  <aside class="side">
    <div class="brand"><div class="mark">WS</div><div><strong>WebScan</strong><small>Local dashboard</small></div></div>
    <div class="side-head"><span>Scan history</span><button class="ghost" id="refresh" title="Refresh history">Refresh</button></div>
    <nav class="history" id="history"><div class="empty">No scans yet.</div></nav>
  </aside>
  <main class="main">
    <form class="top" id="scan-form">
      <input class="input target-input" id="target" type="url" required placeholder="https://example.com" aria-label="Target URL">
      <select id="profile" aria-label="Scan profile"><option value="safe">Safe scan</option><option value="default">Default scan</option></select>
      <button class="primary" id="run" type="submit">Run scan</button>
      <span class="status" id="status">Ready</span>
    </form>
    <div class="content">
      <section class="overview"><div><h1 id="heading">Scan history</h1><p id="meta">Choose a scan or start a new one.</p></div>
      <button class="danger" id="delete" hidden>Delete scan</button></section>
      <section class="metrics" id="metrics" aria-label="Finding totals"></section>
      <div class="summary" id="summary" hidden></div>
      <section class="filters" aria-label="Finding filters">
        <input class="input" id="query" placeholder="Filter title, URL, plugin...">
        <select id="severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
        <select id="confidence"><option value="">All confidence</option><option>firm</option><option>tentative</option><option>informational</option></select>
        <select id="plugin"><option value="">All plugins</option></select>
      </section>
      <div id="results" class="message">No report selected.</div>
    </div>
  </main>
</div>
<script>
const state={id:null,report:null,findings:[]};
const $=id=>document.getElementById(id);
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function flatten(report){return (report.targets||[]).flatMap(t=>(t.findings||[]).map(f=>({...f,target:t.target})));}
function renderMetrics(){const counts={critical:0,high:0,medium:0,low:0,info:0};state.findings.forEach(f=>counts[f.severity]=(counts[f.severity]||0)+1);$('metrics').innerHTML=`<div class="metric"><strong>${state.findings.length}</strong><span>Total</span></div>`+Object.entries(counts).map(([k,v])=>`<div class="metric"><strong>${v}</strong><span>${k}</span></div>`).join('');}
function renderFilters(){const plugins=[...new Set(state.findings.map(f=>f.plugin).filter(Boolean))].sort();$('plugin').innerHTML='<option value="">All plugins</option>'+plugins.map(p=>`<option>${esc(p)}</option>`).join('');}
function renderFindings(){const q=$('query').value.toLowerCase(),sev=$('severity').value,conf=$('confidence').value,plugin=$('plugin').value;const rows=state.findings.filter(f=>(!sev||f.severity===sev)&&(!conf||f.confidence===conf)&&(!plugin||f.plugin===plugin)&&(!q||[f.title,f.url,f.plugin,f.description,f.target].join(' ').toLowerCase().includes(q)));if(!rows.length){$('results').className='message';$('results').innerHTML=state.findings.length?'No findings match these filters.':'No findings in this scan.';return;}$('results').className='table-wrap';$('results').innerHTML=`<table><thead><tr><th>Severity</th><th>Finding</th><th>Plugin</th><th>Confidence</th><th>Target</th></tr></thead><tbody>${rows.map(f=>`<tr><td><span class="badge ${esc(f.severity)}">${esc(f.severity).toUpperCase()}</span></td><td><div class="finding-title">${esc(f.title)}</div><div class="finding-url" title="${esc(f.url)}">${esc(f.url)}</div></td><td class="plugin">${esc(f.plugin)}</td><td class="confidence">${esc(f.confidence)}</td><td>${esc(f.target)}</td></tr>`).join('')}</tbody></table>`;}
async function historyList(){const rows=await fetch('/api/history').then(r=>r.json());$('history').innerHTML=rows.length?rows.map(x=>`<button data-id="${x.id}" class="${x.id===state.id?'active':''}"><span class="target">${esc(x.target||'Untitled scan')}</span><span class="sub"><span>${new Date(x.created_at).toLocaleString()}</span><span>${x.total_findings} findings</span></span></button>`).join(''):'<div class="empty">No scans yet.</div>';document.querySelectorAll('[data-id]').forEach(b=>b.onclick=()=>loadScan(Number(b.dataset.id)));}
async function loadScan(id){const response=await fetch(`/api/history/${id}`);if(!response.ok)return;const item=await response.json();state.id=id;state.report=item.report;state.findings=flatten(item.report);$('heading').textContent=(item.report.targets?.[0]?.target)||'Scan report';$('meta').textContent=`${item.report.targets?.length||0} targets | ${item.report.scan_started||item.created_at}`;$('summary').hidden=!item.summary;$('summary').textContent=item.summary||'';$('delete').hidden=false;renderMetrics();renderFilters();renderFindings();historyList();}
$('scan-form').onsubmit=async e=>{e.preventDefault();const run=$('run');run.disabled=true;$('status').textContent='Scanning...';try{const safe=$('profile').value==='safe';const response=await fetch('/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({targets:[$('target').value],concurrency:safe?8:10,timeout:10,soft_404:safe})});const body=await response.json();if(!response.ok)throw new Error(body.detail||'Scan failed');await historyList();await loadScan(body.history_id);$('status').textContent='Complete';}catch(error){$('status').textContent=error.message;}finally{run.disabled=false;}};
$('delete').onclick=async()=>{if(!state.id||!confirm('Delete this scan from local history?'))return;await fetch(`/api/history/${state.id}`,{method:'DELETE'});state.id=null;state.report=null;state.findings=[];$('heading').textContent='Scan history';$('meta').textContent='Choose a scan or start a new one.';$('delete').hidden=true;$('summary').hidden=true;renderMetrics();renderFindings();historyList();};
['query','severity','confidence','plugin'].forEach(id=>$(id).addEventListener(id==='query'?'input':'change',renderFindings));$('refresh').onclick=historyList;renderMetrics();historyList().then(async()=>{const rows=await fetch('/api/history').then(r=>r.json());if(rows[0])loadScan(rows[0].id);});
</script>
</body></html>"""
