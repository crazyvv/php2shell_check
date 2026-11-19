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
function badge(verdict) { return node('span', verdict, 'badge ' + (verdict === '疑似受影响' ? 'risk' : /待核验|未知|疑似使用|受影响范围|证据受限/.test(verdict) ? 'pending' : '')); }
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
  const tone=r.verdict==='疑似受影响'?'risk':r.verdict==='无法完成检测' || r.verdict==='无法判断' || r.verdict?.includes('Java4Shell')?'warning':'info';
  const wrap=node('div',undefined,'evidence-summary '+tone);
  wrap.append(node('strong',tone==='risk'?'优先复核 · 版本风险线索':tone==='warning'?'证据受限 · 需要复核':'已观测到的证据','evidence-heading'));
  if(versions.length){const row=node('p');row.append(node('span','PHP 版本声明：'));for(const version of versions.slice(0,8))row.append(node('code','PHP '+version,'evidence-value '+tone));wrap.append(row);}
  wrap.append(node('p',r.reason || '请结合下面的观测与主机材料复核。','evidence-reason'));
  for(const evidence of (Array.isArray(r.evidence)?r.evidence:[]).filter(e=>e && typeof e==='object').slice(0,4)){const row=node('p',undefined,'direct-evidence');row.append(node('strong',evidence.kind==='response_header'?'响应头：':evidence.kind==='cookie_name'?'Cookie 名称：':'页面线索：'));row.append(emphasizedText(evidence.detail || '',versions,tone));wrap.append(row);}
  return wrap;
}
function nextStep(r){
  const wrap=node('div',undefined,'next-step');wrap.append(node('strong','下一步'));
  const advice=r.verdict==='疑似受影响'?'核对实际 Web/FPM 版本、厂商回补记录并安排修复，逐个后端实例复核。':r.verdict?.includes('Java4Shell')?'在实际 Java 节点运行带 --java-command 的主机采集，核对 JVM build、VM、CPU、运行参数和全部实例重启状态。':r.verdict==='无法完成检测'?'先核对访问控制、防护页或服务异常，再从允许访问的环境复测。':r.verdict==='版本达到修复基线（待核验）'?'核对实际 Web 实例与完整修补包，确认更新后的进程已重启。':'补充实际 Web/FPM 运行时和软件包材料；隐藏版本或未命中特征不能认定安全。';
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
function java4shellView(j) {
  const wrap=node('div');if(!j || j.status==='not_observed')return wrap;
  const box=node('div',undefined,'runtime-comparison java4shell-evidence');box.append(node('strong','Java4Shell / CVE-2026-114938 · 主机条件待核验'));
  box.append(node('p',j.detail || '网页只能提供 Java 产品线索。','comparison-conclusion'));
  const products=(Array.isArray(j.products)?j.products:[]).map(p=>p?.name).filter(Boolean);if(products.length)box.append(node('p','响应产品线索：'+products.join('、'),'fine'));
  box.append(node('p','远程检查没有增加请求、没有发送畸形 Base64、没有运行 PoC。','fine'));
  const required=Array.isArray(j.required_evidence)?j.required_evidence:[];if(required.length)box.append(node('p','缺失证据：'+required.join('；'),'fine'));
  wrap.append(box);return wrap;
}
function nginx2rootView(n) {
  const wrap=node('div');
  if(!n?.status || ['disabled','not_observed'].includes(n.status))return wrap;
  const box=node('div',undefined,'runtime-comparison java4shell-evidence');
  box.append(node('strong','Nginx2Root · '+(n.status==='nginx_hint'?'HTTP 响应线索':'主机提交证据')));
  const status={potential:'命中披露版本范围',meets_vendor_reference:'达到厂商修复版本参考',meets_upstream_reference:'达到上游版本基线',outside_upstream_range:'低于披露范围',unknown:'未知'};
  const rows=[...(n.running_processes || []),...(n.installations || [])];
  if(n.status==='nginx_hint')rows.push(n);
  for(const row of rows.slice(0,24)){
    const product = {nginx:'NGINX',plus:'NGINX Plus',openresty:'OpenResty',tengine:'Tengine'}[row.flavor] || 'NGINX 系';
    const release = row.plus_release || row.product_version || row.version || '版本未知';
    const core = row.embedded_nginx_version && row.embedded_nginx_version !== release ? ' · 内嵌 NGINX '+row.embedded_nginx_version : '';
    box.append(node('p',`${row.pid ? 'PID '+row.pid+' · ' : ''}${product} ${release}${core}${row.path ? ' · '+row.path : ''}`,'fine'));
    if(row.package_evidence?.version)box.append(node('p',`软件包 ${row.package_evidence.name || ''} ${row.package_evidence.version} · 回补待核验`,'fine'));
    if(row.configuration_entry)box.append(node('p',(row.configuration_entry_source!=='process_argument'?'安装布局配置入口 · ':'进程配置入口 · ')+row.configuration_entry,'fine'));
    for(const item of (row.configuration?.evidence || []).slice(0,8)){
      box.append(node('p',`${item.hint} · ${item.file}:${item.line}`,'fine'));
    }
    for(const cve of (row.cves || []).slice(0,5))
      box.append(node('p',`${cve.cve} · ${status[cve.status] || '未知'}`,'fine'));
  }
  if(n.configuration?.files_examined){
    const c=n.configuration;
    const found=[['http2_on','HTTP/2'],['http2_off','HTTP/2 关闭指令'],['http3_or_quic','HTTP/3/QUIC'],['upstream','上游代理'],['resolver','resolver'],['dynamic_proxy_pass','变量 proxy_pass'],['mirror','mirror'],['ssi','SSI'],['mail_proxy','邮件代理'],['auth_http','auth_http']].filter(([k])=>c[k]===true).map(([,label])=>label);
    box.append(node('p',`磁盘配置线索（${c.files_examined} 个文件）：${found.join('、') || '未观察到相关指令'}`,'fine'));
  }
  for(const item of (n.configuration?.evidence || []).slice(0,8)){
    box.append(node('p',`${item.hint} · ${item.file}:${item.line}`,'fine'));
  }
  if(n.sctp)box.append(node('p',`Linux ${n.sctp.kernel_release || '未知'} · SCTP 模块：${n.sctp.module_visible===true?'可见':'未确认'} · modprobe 禁载配置：${n.sctp.modprobe_install_block_hint===true?'有线索':'未确认'} · 内核补丁待核验`,'fine'));
  box.append(node('p','根据上游公告解释所见版本；需要核对发行包回补和实际配置。','fine'));
  wrap.append(box);return wrap;
}
function apache2rootView(report){
  const wrap=node('div');
  if(!report?.status || ['disabled','not_observed'].includes(report.status))return wrap;
  const box=node('div',undefined,'runtime-comparison java4shell-evidence');
  box.append(node('strong','Apache2Root · CVE-2026-119618'));
  const labels={potential:'上游受影响范围',outside_upstream_range:'早于披露范围',meets_upstream_reference:'达到上游修复基线',unknown:'版本证据不足'};
  if(report.status==='apache_hint'){
    box.append(node('p',`响应版本 ${report.version || '未知'} · ${labels[report.version_status] || '未知'} · 本次协议 ${report.response_protocol || '未知'}`,'fine'));
    if(report.http2_advertised)box.append(node('p','响应声明支持 h2 或 h2c。','fine'));
  }
  for(const r of [...(report.running_processes || []),...(report.installations || []),...(report.module_installations || [])].slice(0,24)){
    const mapped=r.mod_http2_mapped===true?' · 观察到 mod_http2 映射':'';
    box.append(node('p',`${r.pid ? 'PID '+r.pid+' · ' : ''}${r.path || '路径未知'} · ${r.version || '版本未知'} · ${labels[r.version_status] || '未知'}${mapped}`,'fine'));
  }
  if(report.configuration?.files_examined){
    const c=report.configuration;
    const signals=[c.h2&&'h2',c.h2c&&'h2c',c.http1_only_directive&&'HTTP/1.1 限制指令',c.load_module&&'LoadModule http2_module'].filter(Boolean);
    box.append(node('p','磁盘配置线索：'+(signals.join('、') || '未观察到相关指令'),'fine'));
  }
  box.append(node('p','补丁和站点协议以实际运行实例及厂商公告核验。','fine'));
  wrap.append(box);return wrap;
}
function javaHostEvidenceView(j) {
  const wrap=node('div');if(!j || !j.status || j.status==='disabled')return wrap;
  const labels={candidate_found:'发现候选，需优先复核',no_runtime_found:'未发现可见 Java 运行时',no_candidate_in_discovered_scope:'已发现范围内未形成候选',unknown:'证据不足'};
  const box=node('div',undefined,'runtime-comparison java4shell-evidence');box.append(node('strong','Java4Shell 主机核验（提交材料，未经独立核验）'));
  box.append(node('p',labels[j.status] || j.status,j.status==='candidate_found'?'review-priority':'fine'));
  const hw=j.hardware || {};box.append(node('p',`当前节点：${hw.arch || '未知'} · CPU 条件 ${hw.status || '未知'} · 已见 ${Array.isArray(hw.observed_flags)?hw.observed_flags.join(', '):'未知'} · 缺少 ${Array.isArray(hw.missing_flags)?hw.missing_flags.join(', '):'未知'}`,'fine'));
  const statuses={affected_candidate:'受影响版本候选',affected_candidate_eol:'非支持线候选',candidate_hardware_unknown:'CPU 条件未知',candidate_default_mitigated:'采集器清洁环境观察到缓解默认值',fixed_release:'达到公开修复基线',not_in_disclosed_range:'不在披露版本范围',not_applicable_hardware:'当前节点硬件不适用',not_applicable_vm:'VM 实现不适用',unknown:'未知'};
  for(const r of (Array.isArray(j.runtimes)?j.runtimes:[]).slice(0,32))box.append(node('p',`${r.binary || 'Java 路径未知'} · ${r.vm || 'VM 未知'} · Java ${r.version || '版本未知'} · ${statuses[r.status] || r.status || '未知'} · ${r.detail || ''}`,'fine'));
  for(const p of (Array.isArray(j.running_processes)?j.running_processes:[]).slice(0,32)){const flags=Array.isArray(p.known_command_line_flags)?p.known_command_line_flags.join(', '):'';box.append(node('p',`JVM PID ${p.pid || '未知'} · ${p.name || ''} · 相关命令行参数 ${flags || '未观察到（环境与参数文件未读取）'}`,'fine'));}
  for(const p of (j.runtime_audit?.processes || []).slice(0,32)){
    box.append(node('p',`JVM PID ${p.pid ?? '未知'} · ${p.status || '未知'} · 运行构建 ${p.runtime_build || '未知'} · ${p.flag_source==='startup_arguments_estimated'?'启动参数估算（显式信任）':'生效参数 '+(p.flag_status || '未知')}`,'fine'));
    for(const m of (p.mappings || []).slice(0,4)){
      const d=m.disk_evidence;
      if(d?.full_build)box.append(node('p',`磁盘构建 ${d.full_build} · ${d.vendor || '发行商未知'} · ${m.disk_identity_matched===true?'身份匹配':'身份待核'}`,'fine'));
    }
  }
  box.append(node('p','该材料不确认外部输入到达 Base64 解码器，也不确认漏洞可利用或修复已独立验证。','fine'));wrap.append(box);return wrap;
}
function hostEvidenceView(e) {
  const wrap=node('div');
  wrap.append(node('b','主机材料 / 手工复核：未经独立核验'));
  if(e.report_limits?.truncated) wrap.append(node('p','报告因大小限制省略了部分条目，结果不完整；未列出不代表不存在。','fine'));
  if(e.php_command?.status === 'disabled') wrap.append(node('p','本次未开启 PHP 命令采集。','fine'));
  wrap.append(javaHostEvidenceView(e.java4shell),nginx2rootView(e.nginx2root),apache2rootView(e.apache2root));
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
function hostComparisonView(c) {
  const wrap=node('div',undefined,'runtime-comparison');
  wrap.append(node('strong','最近两份主机材料：修复前后对比（未经独立核验）'));
  const before=c?.before_imported_at ? new Date(c.before_imported_at*1000).toLocaleString() : '较早材料';
  const after=c?.after_imported_at ? new Date(c.after_imported_at*1000).toLocaleString() : '最新材料';
  wrap.append(node('p',`${before} → ${after}。Web 与 CLI 分列；CLI 版本不会替代 Web/FPM 结论。`,'fine'));
  const labels={'web.version':'Web PHP 版本','web.version_status':'Web 版本基线','web.sapi':'Web SAPI','web.upload_progress':'Web upload_progress','web.serialize_handler':'Web serialize_handler','cli.version':'CLI PHP 版本','patch_evidence.complete_claimed':'修复材料完整声明'};
  for(const item of (Array.isArray(c?.changes)?c.changes:[])){
    const value=v=>v===null || v===undefined || v===''?'未知':Array.isArray(v)?(v.length?v.join('、'):'未知'):typeof v==='object'?JSON.stringify(v):String(v);
    const row=node('p',undefined,item.changed?'comparison-change':'fine');
    row.append(node('strong',(labels[item.field] || item.field)+'：'),node('code',value(item.before),'technology-version'),node('span',' → '),node('code',value(item.after),'technology-version'));
    if(item.changed)row.append(node('span',' · 已变化'));
    wrap.append(row);
  }
  wrap.append(node('p',c?.conclusion==='remediation_evidence_improved'?'材料显示修复证据有所改善；仍需独立核对实际运行 worker。':'现有材料仍不足以形成完整修复证据。','comparison-conclusion'));
  wrap.append(node('p','该对比不确认漏洞利用，也不把提交声明升级为已验证修复。','fine'));
  return wrap;
}
function overviewResult(r) {
  const result=node('article',undefined,'target-result');
  const header=node('div',undefined,'target-heading');
  const blocked=r.verdict==='无法完成检测';
  header.append(node('h3',r.target),node('p',[
    blocked?'HTTP 检测受阻':'HTTP 观测',
    r.http_status || '状态未知',r.connected_ip
  ].filter(Boolean).join(' · '),'fine'));
  if(blocked && r.reason)header.append(node('p',r.reason,'hint'));
  result.append(header);

  const grid=node('div',undefined,'result-modules');
  const apache=r.apache2root;
  const nginx=r.nginx2root;
  const java=r.java4shell;
  const phpVerdict=r.verdict?.includes('Java4Shell')?'未观测到 PHP 线索':r.verdict;
  const modules=[
    ['Apache HTTP Server','apache2root',apache?.status==='apache_hint',
      apache?.version_status==='potential'?'版本命中受影响范围':'观察到 Apache 线索',()=>apache2rootView(apache)],
    ['NGINX','nginx2root',nginx?.status==='nginx_hint',
      nginx?.cves?.some(cve=>cve.status==='potential')?'版本命中受影响范围':'观察到 NGINX 线索',()=>nginx2rootView(nginx)],
    ['Java / JVM','java4shell',java?.status==='java_product_hint',
      '观察到 Java 产品线索',()=>java4shellView(java)],
    ['PHP','php2shell',Boolean(phpVerdict && !phpVerdict.startsWith('未')),phpVerdict,()=>{
      const content=node('div');
      content.append(evidenceSummary(r),assessmentView(r.assessment),nextStep(r));
      if(r.version_warnings?.length) content.append(node('p','需复核的 PHP 版本声明：'+r.version_warnings.join('、'),'fine'));
      return content;
    }],
  ];
  for(const [name,anchor,observed,label,view] of modules){
    const card=node('section',undefined,'result-module');
    const link=node('a',name);link.href='/knowledge#'+anchor;
    const title=node('h4');title.append(link);
    card.append(title,badge(blocked?'证据受限':observed?label:'未观测到线索'));
    if(observed && (!blocked || anchor!=='php2shell')){
      const detail=node('details');detail.append(node('summary','查看专项证据'),view());
      card.append(detail);
    }
    grid.append(card);
  }
  result.append(grid);

  const supplemental=node('details',undefined,'result-supplement');
  supplemental.append(node('summary','技术指纹与完整检测记录'),fingerprintsView(r.fingerprints),details('查看完整检测依据',r));
  result.append(supplemental);
  if(r.host_comparison || r.host_evidence?.length){
    const host=node('section',undefined,'result-host');
    host.append(node('h4','关联主机材料'));
    if(r.host_comparison)host.append(hostComparisonView(r.host_comparison));
    for(const h of r.host_evidence || [])host.append(hostEvidenceView(h.assessment));
    result.append(host);
  }
  return result;
}
function renderJobs(jobs, endpoint='/api/jobs', showOwners=false, options={}) {
  $('jobs').replaceChildren();
  if (!jobs.length) { $('jobs').append(node('p','当前没有扫描结果。提交业务地址开始自查。','empty')); return; }
  for (const j of jobs) {
    const block = node('div',undefined,'job'), head = node('div',undefined,'jobhead');
    if(showOwners) head.append(node('span',`来源：${j.owner}`));
    head.append(node('span',`${new Date(j.created*1000).toLocaleString()} · ${states[j.state] || j.state} · ${j.results.length} 个结果${j.total_results != null && j.total_results !== j.results.length ? `（本次共 ${j.total_results} 个）` : ''}`));
    const links = node('div',undefined,'links');
    for (const format of ['json','csv']) { const a = node('a',`导出 ${format.toUpperCase()}`); a.href = `${endpoint}/${j.id}?format=${format}${options.verdict ? '&verdict='+encodeURIComponent(options.verdict) : ''}`; a.download = `x2shell-check.${format}`; links.append(a); }
    if(options.deleteJob) {
      const remove=node('button','删除本次扫描','secondary');remove.disabled=['queued','running'].includes(j.state);
      remove.onclick=()=>options.deleteJob(j);links.append(remove);
    }
    head.append(links); block.append(head);
    if (options.overview) {
      for(const result of j.results)block.append(overviewResult(result));
    } else if (j.results.length) {
      const table = node('table'), tr = node('tr'), thead = node('thead');
      ['目标 / 连接 IP','结论','证据与下一步'].forEach(t=>tr.append(node('th',t))); thead.append(tr); table.append(thead);
      const tbody = node('tbody');
      for (const r of j.results) {
        const row=node('tr'), target=node('td'), verdict=node('td'), evidence=node('td');
        target.append(node('div',r.target),node('p',`${r.connected_ip || '—'} · HTTP ${r.http_status || '—'}`,'fine'));
        verdict.append(badge(r.verdict)); evidence.append(evidenceSummary(r));
        evidence.append(assessmentView(r.assessment),fingerprintsView(r.fingerprints),java4shellView(r.java4shell),nginx2rootView(r.nginx2root),apache2rootView(r.apache2root));
        if(r.version_warnings?.length) evidence.append(node('p',`需优先复核的版本声明：${r.version_warnings.join('、')}。多版本冲突时仍需确认实际后端。`,'fine'));
        if(r.host_comparison) evidence.append(hostComparisonView(r.host_comparison));
        for(const h of r.host_evidence || []) evidence.append(hostEvidenceView(h.assessment));
        evidence.append(nextStep(r),details('查看完整检测依据',r));
        row.append(target,verdict,evidence); tbody.append(row);
      }
      table.append(tbody); const wrap=node('div',undefined,'tablewrap'); wrap.append(table); block.append(wrap);
    }
    $('jobs').append(block);
  }
}
