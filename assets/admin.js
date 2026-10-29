'use strict';
let offset=0,search='',total=0,verdict='',sort='newest';
const limit=25;
let historyRequest=0;
function showLogin(){
  historyRequest++;
  $('dashboard').hidden=true;$('loginPanel').hidden=false;
  $('jobs').replaceChildren();$('summary').replaceChildren();$('adminAccount').textContent='';
  clearRuleEditor();clearSettingsEditor();
}
async function loadHistory(){
  const requestId=++historyRequest;
  try {
    const data=await api(`/api/admin/jobs?offset=${offset}&limit=${limit}&search=${encodeURIComponent(search)}&verdict=${encodeURIComponent(verdict)}&sort=${encodeURIComponent(sort)}`);
    if(requestId!==historyRequest)return;
    total=data.total;
    if(offset>0 && !data.jobs.length && total>0){offset=Math.floor((total-1)/limit)*limit;return loadHistory();}
    if(!total)offset=0;
    renderJobs(data.jobs,'/api/admin/jobs',true,{verdict,deleteJob});
    const selected=verdict;$('verdictFilter').replaceChildren(node('option','全部检测结论'));$('verdictFilter').children[0].value='';
    const choices=new Set(Object.keys(data.summary.verdicts));if(selected)choices.add(selected);
    for(const label of [...choices].sort()){const option=node('option',`${label}（${data.summary.verdicts[label] || 0} 个目标）`);option.value=label;$('verdictFilter').append(option);}
    $('verdictFilter').value=selected;
    $('summary').replaceChildren(node('p',`累计扫描 ${data.summary.jobs} 次 · 主机材料 ${data.summary.reports} 份`));
    for(const [state,count] of Object.entries(data.summary.states)) $('summary').append(node('span',`${states[state] || state}：${count}　`));
    const verdicts=node('div');for(const [verdict,count] of Object.entries(data.summary.verdicts)) verdicts.append(node('p',`${verdict}：${count}`));$('summary').append(verdicts);
    $('pageInfo').textContent=`匹配 ${total} 条 · 第 ${Math.floor(offset/limit)+1} 页`;
    $('previous').disabled=offset===0;$('next').disabled=offset+limit>=total;
  } catch(e){if(e.status===401)showLogin();throw e;}
}
async function enterDashboard(user){
  $('adminAccount').textContent=`${user} · 管理员`;$('loginPanel').hidden=true;$('dashboard').hidden=false;await loadHistory();await loadRules();await loadSettings();
}
$('loginForm').onsubmit=async event=>{
  event.preventDefault();$('loginButton').disabled=true;
  const password=$('adminPassword').value;$('adminPassword').value='';
  try{const me=await api('/api/admin/login',{user:$('adminUser').value.trim(),password});offset=0;await enterDashboard(me.user);notice('');}
  catch(e){notice(e.message,true);}finally{$('loginButton').disabled=false;}
};
$('logout').onclick=async()=>{try{await api('/api/admin/logout',{});showLogin();notice('已退出管理员登录。');}catch(e){notice(e.message,true);}};
function applyFilters(){offset=0;search=$('search').value.trim();verdict=$('verdictFilter').value;sort=$('sortOrder').value;loadHistory().catch(e=>notice(e.message,true));}
$('searchForm').onsubmit=event=>{event.preventDefault();applyFilters();};
$('verdictFilter').onchange=applyFilters;$('sortOrder').onchange=applyFilters;
async function deleteJob(job){
  const count=job.total_results ?? job.results.length;
  if(!confirm(`确认删除这次扫描？\n任务：${job.id}\n将删除整次扫描的 ${count} 个结果，包括当前筛选中隐藏的结果。主机材料和审计记录保留。`))return;
  try{await api(`/api/admin/jobs/${encodeURIComponent(job.id)}/delete`,{confirm:true});await loadHistory();notice('扫描记录已删除。');}
  catch(e){if(e.status===401)showLogin();notice(e.message,true);}
}
$('adminRefresh').onclick=()=>loadHistory().catch(e=>notice(e.message,true));
$('previous').onclick=()=>{offset=Math.max(0,offset-limit);loadHistory().catch(e=>notice(e.message,true));};
$('next').onclick=()=>{offset+=limit;loadHistory().catch(e=>notice(e.message,true));};
let ruleRevision=null,ruleBuiltin=null,ruleBase='',selectedRule='',ruleGeneration=0,ruleObjectDirty=false;
function ruleNotice(message,error=false){$('rulesNotice').textContent=message;$('rulesNotice').className=error?'rule-error':'rule-success';}
function clearRuleEditor(){ruleGeneration++;ruleRevision=null;ruleBuiltin=null;ruleBase='';selectedRule='';ruleObjectDirty=false;$('rulesDocument').value='';$('ruleObject').value='';$('ruleSelect').replaceChildren();$('rulesMeta').textContent='';$('rulesVersion').value='';$('ruleSearch').value='';ruleNotice('');}
function parseRuleDraft(){const doc=JSON.parse($('rulesDocument').value);if(!doc || typeof doc!=='object' || !Array.isArray(doc.rules))throw Error('完整 JSON 必须包含 rules 数组');if(!Array.isArray(doc.disabled_rules ?? []))throw Error('disabled_rules 必须是数组');return doc;}
function draftRuleMap(doc){const map=new Map();if((doc.mode || 'extend')==='extend')for(const rule of ruleBuiltin?.rules || [])map.set(rule.id,rule);for(const rule of doc.rules)map.set(rule.id,rule);return map;}
function renderRuleList(){
  const doc=parseRuleDraft(),map=draftRuleMap(doc),disabled=new Set(doc.disabled_rules || []),query=$('ruleSearch').value.trim().toLowerCase();
  $('rulesVersion').value=doc.version || '';
  $('ruleSelect').replaceChildren();
  for(const [id,rule] of map){if(query && !`${id} ${rule.name}`.toLowerCase().includes(query))continue;const option=node('option',`${disabled.has(id)?'停用':'启用'} · ${id} · ${rule.name || ''}`);option.value=id;$('ruleSelect').append(option);}
  if([...$('ruleSelect').children].some(o=>o.value===selectedRule))$('ruleSelect').value=selectedRule;
  else selectedRule=$('ruleSelect').children[0]?.value || '';
  $('ruleSelect').value=selectedRule;selectRule();
}
function selectRule(){
  selectedRule=$('ruleSelect').value || '';const doc=parseRuleDraft(),rule=draftRuleMap(doc).get(selectedRule);
  $('ruleObject').value=rule?JSON.stringify(rule,null,2):'';ruleObjectDirty=false;
  $('ruleToggle').disabled=!rule;$('ruleRemove').disabled=!doc.rules.some(r=>r.id===selectedRule);
  $('ruleToggle').textContent=(doc.disabled_rules || []).includes(selectedRule)?'启用所选规则':'禁用所选规则';
}
function updateRuleDraft(doc){$('rulesDocument').value=JSON.stringify(doc,null,2);renderRuleList();ruleNotice('草稿已修改，校验并保存后才会生效。');}
function acceptRuleData(data){ruleRevision=data.revision;ruleBuiltin=JSON.parse(data.builtin_document);ruleBase=data.document;$('rulesDocument').value=data.document;$('rulesMeta').textContent=`当前修订 ${data.revision} · ${data.metadata.version} · ${data.metadata.rule_count} 条有效规则 · ${data.origin==='database'?'数据库保存':data.origin==='file'?'启动文件':'内置默认'}`;renderRuleList();}
async function loadRules(){const generation=++ruleGeneration;const data=await api('/api/admin/fingerprints');if(generation!==ruleGeneration)return;acceptRuleData(data);ruleNotice('');}
function ruleAction(fn){try{fn();}catch(e){ruleNotice(e.message,true);}}
$('rulesReload').onclick=()=>{if(ruleRevision!==null && (ruleObjectDirty || $('rulesDocument').value!==ruleBase) && !confirm('重新加载会丢弃尚未保存的草稿，是否继续？'))return;loadRules().catch(e=>{if(e.status===401)showLogin();ruleNotice(e.message,true);});};
$('ruleSearch').oninput=()=>{if(ruleObjectDirty){ruleNotice('请先应用单条修改到草稿，再筛选规则。',true);return;}ruleAction(renderRuleList);};$('ruleSelect').onchange=()=>{if(ruleObjectDirty && !confirm('单条修改尚未应用到草稿，切换会丢弃这些修改，是否继续？')){$('ruleSelect').value=selectedRule;return;}ruleAction(selectRule);};
$('ruleObject').oninput=()=>{ruleObjectDirty=true;ruleNotice('单条修改尚未应用，请点击“应用单条修改到草稿”。');};
$('ruleNew').onclick=()=>{if(ruleObjectDirty && !confirm('单条修改尚未应用，新增会丢弃这些修改，是否继续？'))return;selectedRule='';$('ruleSelect').value='';ruleObjectDirty=true;$('ruleToggle').disabled=true;$('ruleRemove').disabled=true;$('ruleObject').value=JSON.stringify({id:'custom-app',name:'自定义应用',category:'framework',runtime:'unknown',confidence:'low',any:[{source:'header',header:'x-app',pattern:'^your-app$'}]},null,2);ruleNotice('编辑新规则后点击“应用单条修改到草稿”。');};
$('ruleApply').onclick=()=>ruleAction(()=>{const doc=parseRuleDraft(),rule=JSON.parse($('ruleObject').value);if(!rule || typeof rule.id!=='string')throw Error('规则需要字符串 ID');if(selectedRule && rule.id!==selectedRule)throw Error('编辑时请保持 ID 不变；更换 ID 请使用新增规则');if(!selectedRule && draftRuleMap(doc).has(rule.id))throw Error('ID 已存在，请选择该规则进行编辑');const at=doc.rules.findIndex(r=>r.id===rule.id);if(at>=0)doc.rules[at]=rule;else doc.rules.push(rule);selectedRule=rule.id;updateRuleDraft(doc);});
$('ruleToggle').onclick=()=>ruleAction(()=>{if(ruleObjectDirty)throw Error('请先应用单条修改，再启用或禁用');const doc=parseRuleDraft();if(!selectedRule)return;const disabled=new Set(doc.disabled_rules || []);if(disabled.has(selectedRule))disabled.delete(selectedRule);else disabled.add(selectedRule);doc.disabled_rules=[...disabled];updateRuleDraft(doc);});
$('ruleRemove').onclick=()=>ruleAction(()=>{if(ruleObjectDirty)throw Error('请先应用单条修改，再删除规则');const doc=parseRuleDraft();doc.rules=doc.rules.filter(r=>r.id!==selectedRule);doc.disabled_rules=(doc.disabled_rules || []).filter(id=>id!==selectedRule);updateRuleDraft(doc);});
$('rulesVersion').onchange=()=>ruleAction(()=>{if(ruleObjectDirty){$('rulesVersion').value=parseRuleDraft().version || '';throw Error('请先应用单条修改，再修改库版本');}const doc=parseRuleDraft();doc.version=$('rulesVersion').value.trim();updateRuleDraft(doc);});
$('rulesFormat').onclick=()=>ruleAction(()=>{if(ruleObjectDirty)throw Error('请先应用单条修改，再刷新完整草稿');updateRuleDraft(parseRuleDraft());});
$('rulesBuiltin').onclick=()=>ruleAction(()=>{if((ruleObjectDirty || $('rulesDocument').value!==ruleBase) && !confirm('加载内置库会替换当前草稿，是否继续？'))return;if(!ruleBuiltin)throw Error('请先加载特征库');updateRuleDraft(JSON.parse(JSON.stringify(ruleBuiltin)));});
function setRuleBusy(busy){for(const id of ['ruleObject','rulesDocument','rulesVersion','ruleSearch','ruleSelect','ruleApply','ruleToggle','ruleRemove','ruleNew','rulesReload','rulesFormat','rulesBuiltin','rulesSave','rulesValidate'])$(id).disabled=busy;if(!busy && ruleRevision!==null){try{$('ruleRemove').disabled=!parseRuleDraft().rules.some(r=>r.id===selectedRule);$('ruleToggle').disabled=!selectedRule;}catch(_){}}}
async function submitRuleDraft(save){
  if(ruleObjectDirty){ruleNotice('单条修改尚未应用，请先应用到草稿。',true);return;}
  if(ruleRevision===null){ruleNotice('请先加载特征库。',true);return;}
  const generation=ruleGeneration,document=$('rulesDocument').value;
  setRuleBusy(true);
  try{const data=await api('/api/admin/fingerprints/'+(save?'save':'validate'),{document,revision:ruleRevision});if(generation!==ruleGeneration)return;if(save){acceptRuleData(data);ruleNotice('已保存并立即启用，新提交的扫描使用该修订。');}else ruleNotice(`校验通过：${data.metadata.rule_count} 条有效规则；尚未保存。`);}
  catch(e){if(e.status===401)showLogin();ruleNotice(e.message,true);}
  finally{setRuleBusy(false);}
}
$('rulesValidate').onclick=()=>submitRuleDraft(false);$('rulesSave').onclick=()=>submitRuleDraft(true);
let settingsRevision=null,settingsGeneration=0,settingsBase='';
function settingsNotice(message,error=false){$('settingsNotice').textContent=message;$('settingsNotice').className=error?'rule-error':'rule-success';}
function clearSettingsEditor(){settingsGeneration++;settingsRevision=null;settingsBase='';$('settingsDocument').value='';$('settingsFile').value='';$('settingsSwitches').replaceChildren();$('settingsMeta').textContent='';$('settingsDeployment').textContent='';settingsNotice('');}
function settingsSwitches(){
  const doc=JSON.parse($('settingsDocument').value);$('settingsSwitches').replaceChildren();
  for(const [key,label] of [['allow_anonymous','允许免密码访问'],['allow_without_whitelist','允许空白名单'],['probe_multipart','允许开发者选择小型 multipart 检查'],['headers_only','强制仅响应头检查']]){
    const input=node('input');input.type='checkbox';input.checked=doc[key]===true;input.disabled=settingsBusy;
    input.onchange=()=>{try{const current=JSON.parse($('settingsDocument').value);current[key]=input.checked;$('settingsDocument').value=JSON.stringify(current,null,2);settingsNotice('草稿已修改，保存后生效。');}catch(e){settingsNotice(e.message,true);}};
    const wrap=node('label');wrap.append(input,node('span',label));$('settingsSwitches').append(wrap);
  }
  for(const [key,label] of [['php_command','默认采集 PHP 命令配置'],['package_audit','默认采集软件包补丁'],['middleware','默认采集中间件'],['php_modules','默认采集 PHP 模块'],['ports','默认采集监听端口'],['web_probe','默认本机 Web 探测']]){
    const input=node('input');input.type='checkbox';input.checked=doc.collection_defaults?.[key]===true;input.disabled=settingsBusy;
    input.onchange=()=>{try{const current=JSON.parse($('settingsDocument').value);current.collection_defaults=current.collection_defaults || {};current.collection_defaults[key]=input.checked;$('settingsDocument').value=JSON.stringify(current,null,2);settingsNotice('采集默认选项草稿已修改，保存后生效。');}catch(e){settingsNotice(e.message,true);}};
    const wrap=node('label');wrap.append(input,node('span',label));$('settingsSwitches').append(wrap);
  }
}
function acceptSettings(data){settingsRevision=data.revision;settingsBase=data.document;$('settingsDocument').value=data.document;$('settingsMeta').textContent=`配置修订 ${data.revision} · ${data.origin==='database'?'数据库保存':'启动 JSON'}`;if(data.deployment)$('settingsDeployment').textContent=JSON.stringify(data.deployment,null,2);settingsSwitches();}
async function loadSettings(){const generation=++settingsGeneration;const data=await api('/api/admin/settings');if(generation!==settingsGeneration)return;acceptSettings(data);settingsNotice('');}
let settingsBusy=false;
function setSettingsBusy(busy){settingsBusy=busy;for(const id of ['settingsDocument','settingsFile','settingsExport','settingsReload','settingsValidate','settingsSave'])$(id).disabled=busy;try{settingsSwitches();}catch(_){}}
$('settingsDocument').oninput=()=>{try{settingsSwitches();settingsNotice('草稿已修改，校验并保存后生效。');}catch(e){$('settingsSwitches').replaceChildren();settingsNotice('JSON 尚未完整：'+e.message,true);}};
$('settingsReload').onclick=()=>{if(settingsRevision!==null && $('settingsDocument').value!==settingsBase && !confirm('重新加载会丢弃未保存的配置草稿，是否继续？'))return;loadSettings().catch(e=>{if(e.status===401)showLogin();settingsNotice(e.message,true);});};
async function submitSettings(save){
  if(settingsRevision===null){settingsNotice('请先加载当前配置。',true);return;}
  const generation=settingsGeneration,document=$('settingsDocument').value;setSettingsBusy(true);
  try{const data=await api('/api/admin/settings/'+(save?'save':'validate'),{document,revision:settingsRevision});if(generation!==settingsGeneration)return;if(save){acceptSettings(data);settingsNotice('配置已保存并生效。新提交的扫描使用该修订，开发者页面刷新后更新可选项。');}else settingsNotice('配置校验通过，尚未保存。');}
  catch(e){if(e.status===401)showLogin();settingsNotice(e.message,true);}finally{setSettingsBusy(false);}
}
$('settingsFile').onchange=async()=>{
  const file=$('settingsFile').files[0],generation=settingsGeneration;if(!file)return;
  try{if(file.size>262144)throw Error('请选择不超过 256 KiB 的配置 JSON');const raw=JSON.parse(await file.text());if(generation!==settingsGeneration)return;const doc=JSON.parse($('settingsDocument').value);
    for(const key of ['allow_anonymous','allow_without_whitelist','allowed_networks','allowed_domains','allowed_ports','probe_multipart','headers_only','collection_defaults'])if(Object.hasOwn(raw,key))doc[key]=raw[key];
    $('settingsDocument').value=JSON.stringify(doc,null,2);settingsSwitches();settingsNotice('已导入在线字段为草稿，校验并保存后生效；账号、部署路径及其他字段不会导入。');
  }catch(e){settingsNotice(e.message,true);}finally{$('settingsFile').value='';}
};
$('settingsExport').onclick=()=>{try{const text=JSON.stringify(JSON.parse($('settingsDocument').value),null,2),url=URL.createObjectURL(new Blob([text],{type:'application/json'})),link=node('a');link.href=url;link.download='php-selfcheck-online-settings.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),0);settingsNotice('已导出当前草稿的在线字段，不含账号凭据；可合并到服务器配置 JSON。');}catch(e){settingsNotice(e.message,true);}};
$('settingsValidate').onclick=()=>submitSettings(false);$('settingsSave').onclick=()=>submitSettings(true);
(async()=>{try{const me=await api('/api/admin/me');await enterDashboard(me.user);}catch(e){showLogin();if(e.status!==401)notice(e.message,true);}})();
