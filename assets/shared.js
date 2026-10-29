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
const statusNames = {session_cookie_hint:'观测到会话 Cookie，配置仍未知',unknown:'未知',header_claim:'响应头声明',form_hint:'页面表单线索',field_hint:'页面字段线索',responded:'收到响应，未确认 PHP 解析',rejected:'当前请求被拒绝',below_upstream_fix:'低于上游修复基线',meets_upstream_fix:'达到上游基线，待核验',eol:'停止上游维护，补丁未知',supported_branch:'上游支持分支',enabled:'开启（提交材料声明）',disabled:'关闭（提交材料声明）',fixed_claimed:'已修复（提交材料声明）',missing_claimed:'未修复（提交材料声明）'};
const sourceNames={minimal_upload_progress_observation:'普通文本文件 POST',response_header:'HTTP 响应头',page_reference:'页面线索',not_observed:'未观测到',not_tested:'未进行主动检查',minimal_multipart_control:'小型表单请求'};
const confidenceNames={none:'未知',low:'低可信线索',unverified:'提交材料，未独立核验'};
function emphasizedText(text,terms,tone='info') {
  text=typeof text==='string'?text:'';terms=Array.isArray(terms)?terms:[];
  const wrap=node('span'),words=[...new Set(terms.filter(v=>typeof v==='string' && v.length>0 && v.length<=100))].slice(0,16);let at=0;
  while(at<text.length){let index=-1,word='';for(const candidate of words){const found=text.indexOf(candidate,at);if(found>=0 && (index<0 || found<index || found===index && candidate.length>word.length)){index=found;word=candidate;}}if(index<0){wrap.append(node('span',text.slice(at)));break;}if(index>at)wrap.append(node('span',text.slice(at,index)));wrap.append(node('mark',word,'evidence-mark '+tone));at=index+word.length;}
  return wrap;
}
function evidenceSummary(r) {
  const versions=Array.isArray(r.versions)?r.versions.filter(v=>typeof v==='string'):[];
  const tone=r.verdict==='疑似受影响'?'risk':r.verdict==='无法完成检测' || r.verdict==='无法判断'?'warning':'info';
  const wrap=node('div',undefined,'evidence-summary '+tone);
  wrap.append(node('strong',tone==='risk'?'优先复核 · 版本风险线索':tone==='warning'?'证据受限 · 需要复核':'已观测到的证据','evidence-heading'));
  if(versions.length){const row=node('p');row.append(node('span','PHP 版本声明：'));for(const version of versions.slice(0,8))row.append(node('code','PHP '+version,'evidence-value '+tone));wrap.append(row);}
  wrap.append(node('p',r.reason || '请结合下面的观测与主机材料复核。','evidence-reason'));
  for(const evidence of (Array.isArray(r.evidence)?r.evidence:[]).filter(e=>e && typeof e==='object').slice(0,4)){const row=node('p',undefined,'direct-evidence');row.append(node('strong',evidence.kind==='response_header'?'响应头：':evidence.kind==='cookie_name'?'Cookie 名称：':'页面线索：'));row.append(emphasizedText(evidence.detail || '',versions,tone));wrap.append(row);}
  return wrap;
}
function nextStep(r){
  const wrap=node('div',undefined,'next-step');wrap.append(node('strong','下一步'));
  const advice=r.verdict==='疑似受影响'?'核对实际 Web/FPM 版本、厂商回补记录并安排修复，逐个后端实例复核。':r.verdict==='无法完成检测'?'先核对访问控制、防护页或服务异常，再从允许访问的环境复测。':r.verdict==='版本达到修复基线（待核验）'?'核对实际 Web 实例与完整修补包，确认更新后的进程已重启。':'补充实际 Web/FPM 运行时和软件包材料；隐藏版本或未命中特征不能认定安全。';
  wrap.append(node('p',advice));return wrap;
}
function assessmentView(a) {
  const wrap=node('div');
  for (const [key,label] of [['web_server','Web 服务器'],['sapi','SAPI'],['multipart','multipart'],['upload_progress','upload_progress'],['upload_progress_probe','上传进度基础观察'],['patch','补丁状态'],['lifecycle','版本维护状态']]) {
    const o=a?.[key]; if(!o) continue;
    const tone=['below_upstream_fix','eol'].includes(o.status)?'risk':['meets_upstream_fix','form_hint','field_hint','responded','session_cookie_hint'].includes(o.status)?'warning':'';
    const row=node('p',undefined,'assessment-fact '+tone);row.append(node('strong',label+'：'),node('span',statusNames[o.status] || o.status,'fact-status'));row.append(node('span',` · ${o.detail || ''}〔${sourceNames[o.source] || o.source || '未知来源'} / ${confidenceNames[o.confidence] || o.confidence || '未知可信度'}〕`));wrap.append(row);
  }
  const surface=a?.surfaces;
  if(surface){
    const box=node('div',undefined,'next-step');box.append(node('strong','上传入口与运行异常（被动线索）'));
    for(const form of (Array.isArray(surface.forms)?surface.forms:[]).slice(0,16)){
      const ep=form.endpoint || {},row=node('p');row.append(node('strong',ep.relation==='external_reference'?'外部表单引用：':'表单入口：'),node('code',(ep.origin || '')+(ep.path || '地址未知'),'technology-version'));
      row.append(node('span',` · ${form.method || '未知方法'} · multipart ${form.multipart?'是':'未声明'} · 文件字段 ${(Array.isArray(form.file_fields)?form.file_fields:[]).join(', ') || '未发现'}${form.progress_field?' · 含上传进度字段':''}`));box.append(row);
    }
    for(const error of (Array.isArray(surface.errors)?surface.errors:[]).slice(0,8)){const row=node('p',undefined,'assessment-fact warning');row.append(node('strong','错误文本线索：'),node('span',error.detail || '需要人工复核'));box.append(row);}
    if(surface.errors?.length)box.append(node('p','复核：对照同一请求的服务端日志、实际 Web SAPI 和会话配置；不以错误文本或响应时间确认 CVE。','fine'));
    if(surface.forms?.length)box.append(node('p','复核：由开发团队检查上传入口的鉴权、类型校验、存储隔离与执行权限。表单存在不等于可上传或可执行。','fine'));
    if(!surface.forms?.length && !surface.errors?.length)box.append(node('p','当前响应未提取到上传表单或指定错误文本；不能排除相关功能或风险。','fine'));
    if(surface.limits_reached)box.append(node('p','达到分析上限，线索可能不完整。','fine'));
    box.append(node('p','仅分析已取得的响应，不提交表单、不验证执行；外部表单不会被访问。','fine'));wrap.append(box);
  }
  if(a?.review_priority) wrap.append(node('p',`复核优先级：${a.review_priority === 'high' ? '高' : '需复核'}；不代表漏洞已确认。`,a.review_priority==='high'?'review-priority':'fine'));
  return wrap;
}
function fingerprintsView(f) {
  const wrap=node('div');
  if(!f) return wrap;
  const categories={cms:'CMS / 商城',framework:'框架',runtime:'运行时声明',static_generator:'静态生成器',hosted_platform:'托管平台',hosting:'托管服务',web_server:'Web 中间件',cdn:'CDN',waf:'WAF',challenge:'挑战页'};
  if(f.matches?.length) wrap.append(node('b','网站特征（仅为线索）'));
  for(const hit of (Array.isArray(f.matches)?f.matches:[]).filter(h=>h && typeof h==='object').slice(0,64)) {
    const heading=node('p',undefined,'technology-heading');heading.append(node('span',(categories[hit.category] || hit.category)+' · '),node('strong',hit.name,'technology-name'));for(const version of (Array.isArray(hit.versions)?hit.versions:[]).filter(v=>typeof v==='string').slice(0,8))heading.append(node('code',version,'technology-version'));heading.append(node('span',` · ${hit.relation==='external_reference' ? '仅外部资源引用' : '响应中的线索'} · ${hit.confidence==='medium' ? '中等特征可信度' : '低可信特征'}${hit.version_conflict ? ' · 产品版本声明冲突' : ''}`,'fine'));wrap.append(heading);
    const first=hit.evidence?.[0];if(first){const proof=node('p',undefined,'technology-proof');proof.append(node('strong','命中依据：'),node('code',first.header || first.source,'proof-location'),node('span',' · '+(first.detail || '规则匹配')));wrap.append(proof);}
    if(hit.advice) wrap.append(node('p',hit.advice,'fine'));
    const observed=node('details');observed.append(node('summary','命中依据'));
    for(const e of (Array.isArray(hit.evidence)?hit.evidence:[]).filter(e=>e && typeof e==='object').slice(0,8)) observed.append(node('p',`${e.source}${e.header ? ' / '+e.header : ''} · ${e.detail || ''} ${e.resource_origin ? ' · 资源来源 '+e.resource_origin : ''} · 规则 ${e.pattern}${e.pattern_truncated ? '…（表达式已截断）' : ''} · 来源 ${e.url || '本地观测'}`,'fine'));
    wrap.append(observed);
  }
  if(f.matches_truncated) wrap.append(node('p','命中特征达到数量上限，结果可能不完整。','fine'));
  if(f.library) wrap.append(node('p',`特征库 ${f.library.version || '未知'} · ${f.library.rule_count ?? '未知'} 条规则 · ${f.library.source || ''}`,'fine'));
  return wrap;
}
function hostEvidenceView(e) {
  const wrap=node('div');
  wrap.append(node('b','主机材料 / 手工复核：未经独立核验'));
  if(e.report_limits?.truncated) wrap.append(node('p','报告因大小限制省略了部分条目，结果不完整；未列出不代表不存在。','fine'));
  if(e.php_command?.status === 'disabled') wrap.append(node('p','本次未开启 PHP 命令采集。','fine'));
  for(const r of e.runtime_observations || []) {
    wrap.append(node('p',`${r.scope === 'cli_only' ? '仅 CLI，不能代表 Web' : r.scope === 'web_runtime_claimed' ? '提交人声明为 Web 实例' : '运行环境归属未知'} · SAPI ${r.sapi} · PHP ${r.version || '未知'} · upload_progress ${statusNames[r.upload_progress] || '未知'}`,'fine'));
  }
  for(const r of e.runtime_observations || []){
    const settings=r.settings || {},row=node('p',undefined,'fine');
    row.append(node('strong','会话配置（当前采集实例）：'));
    row.append(node('code',`serialize_handler=${settings['session.serialize_handler'] ?? '未知'} · save_handler=${settings['session.save_handler'] ?? '未知'} · upload_progress.cleanup=${settings['session.upload_progress.cleanup'] ?? '未知'}`,'technology-version'));wrap.append(row);
    const controls=node('p',undefined,'fine');controls.append(node('strong','会话控制与进度配置：'),node('code',`strict_mode=${settings['session.use_strict_mode'] ?? '未知'} · only_cookies=${settings['session.use_only_cookies'] ?? '未知'} · progress.name=${settings['session.upload_progress.name'] ?? '未知'} · freq=${settings['session.upload_progress.freq'] ?? '未知'} · min_freq=${settings['session.upload_progress.min_freq'] ?? '未知'}`,'technology-version'));wrap.append(controls);
  }
  if(e.middleware && !['not_collected','disabled'].includes(e.middleware.status)) {
    wrap.append(node('b','Web 中间件与监听端口（提交材料，未经独立核验）'));
    for(const m of e.middleware.instances || []) {
      const libraries=Array.isArray(m.php_modules?.php_libraries) ? m.php_modules.php_libraries.join(', ') : '';
      const ports=Array.isArray(m.listeners?.items) ? m.listeners.items.map(p=>`${p.address}:${p.port}`).join(', ') : '';
      wrap.append(node('p',`${m.family || '未知中间件'} · PID ${m.pid || '未知'} · ${m.binary?.version || '版本未知'} · 监听：${ports || m.listeners?.status || '未知'}`,'fine'));
      const declared=Array.isArray(m.binary?.modules?.lines) ? m.binary.modules.lines.join(', ') : '';
      const mapped=libraries || (m.php_modules?.status==='disabled' ? '未启用检查' : m.php_modules?.status==='observed' ? '未发现 PHP 映射（不能排除 PHP）' : '未知或权限不足');
      wrap.append(node('p',`PHP 进程映射：${mapped}；默认配置模块：${declared || '未取得明确模块声明'}。构建/配置声明不等于当前进程实际使用 PHP。`,'fine'));
    }
    for(const probe of e.middleware.web_probes || []) {
      wrap.append(node('p',`本机 Web：${probe.scheme || ''} ${probe.host || probe.bind_address || ''}:${probe.port || ''}${probe.path || '/'} · ${probe.status} · HTTP ${probe.response?.http_status || '未知'} · ${probe.response?.findings?.verdict || probe.reason || '无法完成请求或证据不足'}`,'fine'));
      if(probe.response?.findings?.fingerprints) wrap.append(fingerprintsView(probe.response.findings.fingerprints));
    }
  }
  if(e.package_audit && !['not_collected','disabled'].includes(e.package_audit.status)) {
    const audit=e.package_audit;
    wrap.append(node('b','运行实例与厂商补丁参考核验（提交材料，未经独立核验）'));
    const labels={unknown:'未知',matches_disk_image:'运行映像与磁盘一致',restart_required:'运行映像已删除或替换，需要重启复核',meets_vendor_reference:'达到厂商参考修订号，待核验',below_vendor_reference:'低于厂商参考修订号，需处理'};
    for(const m of audit.instances || []) {
      wrap.append(node('p',`PID ${m.pid || '未知'} · ${m.name || ''} · ${m.executable || '路径未知'}`,'fine'));
      for(const a of m.artifacts || []) {
        const p=a.package || {};
        wrap.append(node('p',`${a.path || ''} · ${labels[a.running_image_status] || '未知'} · 包 ${p.name || '未知'} ${p.version || ''} · ${labels[a.running_patch_status] || '未知'} · ${p.reason || p.detail || ''}`,'fine'));
        if(p.reference_rule?.advisory) wrap.append(node('p',`参考公告：${p.reference_rule.advisory}；阈值 ${p.reference_rule.fixed_version || '未知'}。参考表匹配不等于公告或修复已核实。`,'fine'));
      }
      if(!m.php_maps_readable || !m.process_identity_stable) wrap.append(node('p','进程或模块信息不完整，不能确认当前运行状态。','fine'));
    }
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
        verdict.append(badge(r.verdict)); evidence.append(evidenceSummary(r));
        evidence.append(assessmentView(r.assessment),fingerprintsView(r.fingerprints));
        if(r.version_warnings?.length) evidence.append(node('p',`需优先复核的版本声明：${r.version_warnings.join('、')}。多版本冲突时仍需确认实际后端。`,'fine'));
        for(const h of r.host_evidence || []) evidence.append(hostEvidenceView(h.assessment));
        evidence.append(nextStep(r),details('查看完整检测依据',r));
        row.append(target,verdict,evidence); tbody.append(row);
      }
      table.append(tbody); const wrap=node('div',undefined,'tablewrap'); wrap.append(table); block.append(wrap);
    }
    $('jobs').append(block);
  }
}
