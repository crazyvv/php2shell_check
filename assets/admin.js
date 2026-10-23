'use strict';
let offset=0,search='',total=0;
const limit=25;
function showLogin(){
  $('dashboard').hidden=true;$('loginPanel').hidden=false;
  $('jobs').replaceChildren();$('summary').replaceChildren();$('adminAccount').textContent='';
}
async function loadHistory(){
  try {
    const data=await api(`/api/admin/jobs?offset=${offset}&limit=${limit}&search=${encodeURIComponent(search)}`);
    total=data.total;renderJobs(data.jobs,'/api/admin/jobs',true);
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
$('searchForm').onsubmit=event=>{event.preventDefault();offset=0;search=$('search').value.trim();loadHistory().catch(e=>notice(e.message,true));};
$('adminRefresh').onclick=()=>loadHistory().catch(e=>notice(e.message,true));
$('previous').onclick=()=>{offset=Math.max(0,offset-limit);loadHistory().catch(e=>notice(e.message,true));};
$('next').onclick=()=>{offset+=limit;loadHistory().catch(e=>notice(e.message,true));};
(async()=>{try{const me=await api('/api/admin/me');await enterDashboard(me.user);}catch(e){showLogin();if(e.status!==401)notice(e.message,true);}})();
