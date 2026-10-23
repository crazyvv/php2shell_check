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
    const submitted=await api('/api/scan',{targets});currentJob=submitted.id;try{sessionStorage.setItem('php-selfcheck-current-job',currentJob);}catch(_){}renderJobs([]); notice('任务已提交，检测结果会自动更新。'); await refresh();
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
    if(!me.scope_configured) notice('管理员尚未配置资产网段白名单，检测将被拒绝。请先按部署说明配置。',true);
    await refresh();
  } catch(e) { notice(e.message,true); }
}
setInterval(()=>{if(busy) refresh().catch(e=>notice(e.message,true));},4000);
boot();
