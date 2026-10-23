'use strict';
const $ = id => document.getElementById(id);
const node = (tag, text, cls) => { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; if (cls) el.className = cls; return el; };
let busy = false;
function notice(text, error=false) { $('notice').textContent = text; $('notice').className = error ? 'error' : ''; }
async function api(path, body) {
  const r = await fetch(path, body === undefined ? {} : {method:'POST', headers:{'Content-Type':'application/json','X-Requested-With':'PHP-SelfCheck'},body:JSON.stringify(body)});
  const data = await r.json(); if (!r.ok) throw new Error(data.error || '请求失败'); return data;
}
const states = {queued:'排队中',running:'检测中',done:'已完成',failed:'任务异常',interrupted:'服务重启中断，请复测'};
function badge(verdict) { return node('span', verdict, 'badge ' + (verdict === '疑似受影响' ? 'risk' : /待核验|未知|疑似使用/.test(verdict) ? 'pending' : '')); }
function details(label, data) { const d = node('details'); d.append(node('summary',label),node('pre',JSON.stringify(data,null,2))); return d; }
function renderJobs(jobs) {
  $('jobs').replaceChildren();
  if (!jobs.length) { $('jobs').append(node('p','还没有检测记录。提交你的第一个业务地址。','empty')); return; }
  for (const j of jobs) {
    const block = node('div',undefined,'job'), head = node('div',undefined,'jobhead');
    head.append(node('span',`${new Date(j.created*1000).toLocaleString()} · ${states[j.state] || j.state} · ${j.results.length} 个结果`));
    const links = node('div',undefined,'links');
    for (const format of ['json','csv']) { const a = node('a',`导出 ${format.toUpperCase()}`); a.href = `/api/jobs/${j.id}?format=${format}`; a.download = `php-selfcheck.${format}`; links.append(a); }
    head.append(links); block.append(head);
    if (j.results.length) {
      const table = node('table'), tr = node('tr'), thead = node('thead');
      ['目标 / 连接 IP','结论','证据与下一步'].forEach(t=>tr.append(node('th',t))); thead.append(tr); table.append(thead);
      const tbody = node('tbody');
      for (const r of j.results) {
        const row=node('tr'), target=node('td'), verdict=node('td'), evidence=node('td');
        target.append(node('div',r.target),node('p',`${r.connected_ip || '—'} · HTTP ${r.http_status || '—'}`,'fine'));
        verdict.append(badge(r.verdict)); evidence.append(node('div',r.reason));
        evidence.append(details('查看完整检测依据',r));
        row.append(target,verdict,evidence); tbody.append(row);
      }
      table.append(tbody); const wrap=node('div',undefined,'tablewrap'); wrap.append(table); block.append(wrap);
    }
    $('jobs').append(block);
  }
}
async function refresh() {
  const jobs = await api('/api/jobs'); renderJobs(jobs);
  busy = jobs.some(j => ['queued','running'].includes(j.state));
}
async function loadReports() {
  const reports = await api('/api/reports'); $('reports').replaceChildren();
  for (const r of reports) { const block=node('div',undefined,'report'); block.append(node('b',r.target),node('p',`${new Date(r.created*1000).toLocaleString()} · ${r.payload.trust}`),details('查看主机核验材料',r.payload)); $('reports').append(block); }
}
$('scan').onclick = async () => {
  $('scan').disabled=true;
  try {
    const targets=$('targets').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
    if (!targets.length || targets.length>50) throw new Error('请输入 1–50 个目标，每行一个');
    await api('/api/scan',{targets}); notice('任务已提交，检测结果会自动更新。'); await refresh();
  } catch(e) { notice(e.message,true); } finally { $('scan').disabled=false; }
};
$('refresh').onclick=()=>refresh().catch(e=>notice(e.message,true));
$('import').onclick=async()=>{
  $('import').disabled=true;
  try {
    const file=$('reportFile').files[0]; if(!file || file.size>200000) throw new Error('请选择不超过 200 KB 的报告 JSON');
    const report=JSON.parse(await file.text());
    await api('/api/reports',{target:$('reportTarget').value.trim(),report});
    notice('材料已保存，标记为“开发者提交，未经独立核验”。'); await loadReports();
  } catch(e) { notice(e.message,true); } finally { $('import').disabled=false; }
};
async function boot() {
  try {
    const me=await api('/api/me'); $('account').textContent=`${me.user} · 个人工作台`;
    if(!me.scope_configured) notice('管理员尚未配置资产网段白名单，检测将被拒绝。请先按部署说明配置。',true);
    await refresh(); await loadReports();
  } catch(e) { notice(e.message,true); }
}
setInterval(()=>{if(busy) refresh().catch(e=>notice(e.message,true));},4000);
boot();
