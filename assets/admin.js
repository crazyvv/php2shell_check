'use strict';
let offset=0,search='',total=0,verdict='',sort='newest';
const limit=25;
let historyRequest=0;
function showLogin(){
  historyRequest++;
  $('dashboard').hidden=true;$('loginPanel').hidden=false;
  $('jobs').replaceChildren();$('summary').replaceChildren();$('adminAccount').textContent='';
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
  $('adminAccount').textContent=`${user} · 管理员`;$('loginPanel').hidden=true;$('dashboard').hidden=false;await loadHistory();
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
(async()=>{try{const me=await api('/api/admin/me');await enterDashboard(me.user);}catch(e){showLogin();if(e.status!==401)notice(e.message,true);}})();
