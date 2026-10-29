let currentJob=null;
try {currentJob=sessionStorage.getItem('php-selfcheck-current-job');}catch(_){}
async function refresh() {
  if(!currentJob){renderJobs([]);busy=false;return;}
  const requested=currentJob;
  try {
    const job=await api('/api/jobs/'+encodeURIComponent(requested));
    if(currentJob!==requested) return;
    renderJobs([job]);busy=['queued','running'].includes(job.state);
  }catch(e){
    if(currentJob!==requested) return;
    if(e.status===404){currentJob=null;busy=false;try{sessionStorage.removeItem('php-selfcheck-current-job');}catch(_){}renderJobs([]);return;}
    throw e;
  }
}
$('scan').onclick = async () => {
  $('scan').disabled=true;
  try {
    const targets=$('targets').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
    if (!targets.length || targets.length>50) throw new Error('请输入 1–50 个目标，每行一个');
    const submitted=await api('/api/scan',{targets,headers_only:Boolean($('headersOnly').checked),probe_multipart:Boolean($('probeMultipart').checked)});currentJob=submitted.id;try{sessionStorage.setItem('php-selfcheck-current-job',currentJob);}catch(_){}renderJobs([]); notice('任务已提交，检测结果会自动更新。'); await refresh();
  } catch(e) { notice(e.message,true); } finally { $('scan').disabled=false; }
};
$('refresh').onclick=()=>refresh().catch(e=>notice(e.message,true));
$('import').onclick=async()=>{
  $('import').disabled=true;
  try {
    const file=$('reportFile').files[0]; if(file && file.size>200000) throw new Error('请选择不超过 200 KB 的报告 JSON');
    const report=file ? JSON.parse(await file.text()) : {schema:'php-selfcheck-host/v1',source:'manual_review'};
    const review={sapi:$('reviewSapi').value,upload_progress:$('reviewProgress').value,patch_status:$('reviewPatch').value,patch_vendor:$('reviewVendor').value.trim(),package_revision:$('reviewPackage').value.trim(),advisory_url:$('reviewAdvisory').value.trim(),notes:$('reviewNotes').value.trim()};
    await api('/api/reports',{target:$('reportTarget').value.trim(),report,review});
    notice('材料已保存，标记为“开发者提交，未经独立核验”。'); await refresh();
  } catch(e) { notice(e.message,true); } finally { $('import').disabled=false; }
};
async function boot() {
  try {
    const me=await api('/api/me'); $('account').textContent=me.allow_anonymous ? '免密码访问 · 当前浏览器独立会话' : `${me.user} · 个人工作台`;
    if(me.headers_only) { $('account').textContent+=' · 仅响应头检测'; $('headersOnly').checked=true; $('headersOnly').disabled=true; }
    if(!me.scope_configured) notice('管理员尚未配置资产网段白名单，检测将被拒绝。请先按部署说明配置。',true);
    $('probeMultipart').disabled=!me.probe_multipart_allowed || Boolean(me.headers_only);
    if($('probeMultipart').disabled)$('probeMultipart').checked=false;
    const defaults=me.collection_defaults || {};
    for(const [id,key] of [['collectPhpCommand','php_command'],['collectPackageAudit','package_audit'],['collectMiddleware','middleware'],['collectModules','php_modules'],['collectPorts','ports'],['collectWeb','web_probe']])if(typeof defaults[key]==='boolean')$(id).checked=defaults[key];
    updateCollectCommand();
    await refresh();
  } catch(e) { notice(e.message,true); }
}
setInterval(()=>{if(busy) refresh().catch(e=>notice(e.message,true));},4000);
boot();

function updateCollectCommand(){
  const middleware=$('collectMiddleware').checked;
  for(const id of ['collectModules','collectPorts']){$(id).disabled=!middleware;if(!middleware)$(id).checked=false;}
  $('collectWeb').disabled=!middleware || !$('collectPorts').checked;if($('collectWeb').disabled)$('collectWeb').checked=false;
  $('collectHost').disabled=!$('collectWeb').checked;
  const command=['php-selfcheck collect'];
  for(const [id,flag] of [['collectPhpCommand','--php-command'],['collectPackageAudit','--package-audit'],['collectMiddleware','--middleware'],['collectModules','--php-modules'],['collectPorts','--ports'],['collectWeb','--web-probe']])if($(id).checked)command.push(flag);
  const host=$('collectHost').value.trim();
  if($('collectWeb').checked && host){if(!/^[a-zA-Z0-9._:[\]-]+$/.test(host)){$('collectCommand').textContent='请输入不含端口、凭据或路径的 Host；IPv6 使用方括号。';return;}command.push("--web-host '"+host+"'");}
  $('collectCommand').textContent=command.join(' ')+' > host-report.json';
}
for(const id of ['collectPhpCommand','collectPackageAudit','collectMiddleware','collectModules','collectPorts','collectWeb'])$(id).onchange=updateCollectCommand;
$('collectHost').oninput=updateCollectCommand;
updateCollectCommand();
