'use strict';
const $ = id => document.getElementById(id);
const node = (tag, text, cls) => { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; if (cls) el.className = cls; return el; };
let busy = false;
function notice(text, error=false) { $('notice').textContent = text; $('notice').className = error ? 'error' : ''; }
async function api(path, body) {
  const r = await fetch(path, body === undefined ? {} : {method:'POST', headers:{'Content-Type':'application/json','X-Requested-With':'PHP-SelfCheck'},body:JSON.stringify(body)});
  const data = await r.json(); if (!r.ok) {const error=new Error(data.error || '请求失败');error.status=r.status;throw error;} return data;
}
const states = {queued:'排队中',running:'检测中',done:'已完成',failed:'任务异常',interrupted:'服务重启中断，请复测'};
function badge(verdict) { return node('span', verdict, 'badge ' + (verdict === '疑似受影响' ? 'risk' : /待核验|未知|疑似使用/.test(verdict) ? 'pending' : '')); }
function details(label, data) { const d = node('details'); d.append(node('summary',label),node('pre',JSON.stringify(data,null,2))); return d; }
const statusNames = {unknown:'未知',header_claim:'响应头声明',form_hint:'页面表单线索',field_hint:'页面字段线索',responded:'收到响应，未确认 PHP 解析',rejected:'当前请求被拒绝',below_upstream_fix:'低于上游修复基线',meets_upstream_fix:'达到上游基线，待核验',eol:'停止上游维护，补丁未知',supported_branch:'上游支持分支',enabled:'开启（提交材料声明）',disabled:'关闭（提交材料声明）',fixed_claimed:'已修复（提交材料声明）',missing_claimed:'未修复（提交材料声明）'};
const sourceNames={response_header:'HTTP 响应头',page_reference:'页面线索',not_observed:'未观测到',not_tested:'未进行主动检查',minimal_multipart_control:'小型表单请求'};
const confidenceNames={none:'未知',low:'低可信线索',unverified:'提交材料，未独立核验'};
function assessmentView(a) {
  const wrap=node('div');
  for (const [key,label] of [['web_server','Web 服务器'],['sapi','SAPI'],['multipart','multipart'],['upload_progress','upload_progress'],['patch','补丁状态'],['lifecycle','版本维护状态']]) {
    const o=a?.[key]; if(!o) continue;
    wrap.append(node('p',`${label}：${statusNames[o.status] || o.status} · ${o.detail || ''}〔${sourceNames[o.source] || o.source || '未知来源'} / ${confidenceNames[o.confidence] || o.confidence || '未知可信度'}〕`,'fine'));
  }
  if(a?.review_priority) wrap.append(node('p',`复核优先级：${a.review_priority === 'high' ? '高' : '需复核'}；不代表漏洞已确认。`,'fine'));
  return wrap;
}
function hostEvidenceView(e) {
  const wrap=node('div');
  wrap.append(node('b','主机材料 / 手工复核：未经独立核验'));
  for(const r of e.runtime_observations || []) {
    wrap.append(node('p',`${r.scope === 'cli_only' ? '仅 CLI，不能代表 Web' : r.scope === 'web_runtime_claimed' ? '提交人声明为 Web 实例' : '运行环境归属未知'} · SAPI ${r.sapi} · PHP ${r.version || '未知'} · upload_progress ${statusNames[r.upload_progress] || '未知'}`,'fine'));
  }
  if(e.review && Object.keys(e.review).length) {
    const r=e.review;
    wrap.append(node('p',`手工复核声明：SAPI ${r.sapi || '未知'} · upload_progress ${statusNames[r.upload_progress] || '未知'} · 补丁 ${statusNames[r.patch_status] || '未知'}`,'fine'));
    wrap.append(node('p',`补丁来源：${r.patch_vendor || '未提供'} · 软件包修订号：${r.package_revision || '未提供'} · 公告：${r.advisory_url || '未提供'}`,'fine'));
    if(r.notes) wrap.append(node('p',r.notes,'fine'));
    wrap.append(details('手工复核原始声明（不提升远程结论）',r));
  }
  return wrap;
}
function renderJobs(jobs, endpoint='/api/jobs', showOwners=false, options={}) {
  $('jobs').replaceChildren();
  if (!jobs.length) { $('jobs').append(node('p','当前没有扫描结果。提交业务地址开始自查。','empty')); return; }
  for (const j of jobs) {
    const block = node('div',undefined,'job'), head = node('div',undefined,'jobhead');
    if(showOwners) head.append(node('span',`来源：${j.owner}`));
    head.append(node('span',`${new Date(j.created*1000).toLocaleString()} · ${states[j.state] || j.state} · ${j.results.length} 个结果${j.total_results != null && j.total_results !== j.results.length ? `（本次共 ${j.total_results} 个）` : ''}`));
    const links = node('div',undefined,'links');
    for (const format of ['json','csv']) { const a = node('a',`导出 ${format.toUpperCase()}`); a.href = `${endpoint}/${j.id}?format=${format}${options.verdict ? '&verdict='+encodeURIComponent(options.verdict) : ''}`; a.download = `php-selfcheck.${format}`; links.append(a); }
    if(options.deleteJob) {
      const remove=node('button','删除本次扫描','secondary');remove.disabled=['queued','running'].includes(j.state);
      remove.onclick=()=>options.deleteJob(j);links.append(remove);
    }
    head.append(links); block.append(head);
    if (j.results.length) {
      const table = node('table'), tr = node('tr'), thead = node('thead');
      ['目标 / 连接 IP','结论','证据与下一步'].forEach(t=>tr.append(node('th',t))); thead.append(tr); table.append(thead);
      const tbody = node('tbody');
      for (const r of j.results) {
        const row=node('tr'), target=node('td'), verdict=node('td'), evidence=node('td');
        target.append(node('div',r.target),node('p',`${r.connected_ip || '—'} · HTTP ${r.http_status || '—'}`,'fine'));
        verdict.append(badge(r.verdict)); evidence.append(node('div',r.reason));
        evidence.append(assessmentView(r.assessment));
        for(const h of r.host_evidence || []) evidence.append(hostEvidenceView(h.assessment));
        evidence.append(details('查看完整检测依据',r));
        row.append(target,verdict,evidence); tbody.append(row);
      }
      table.append(tbody); const wrap=node('div',undefined,'tablewrap'); wrap.append(table); block.append(wrap);
    }
    $('jobs').append(block);
  }
}
