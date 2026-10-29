const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
class Element {
  constructor(){this.children=[];this.textContent='';this.value='';this.files=[];this.disabled=false;}
  append(...children){this.children.push(...children);}
  replaceChildren(...children){this.children=children;}
}
function setup(initial=null){
  const elements=new Map();const storage=new Map(initial?[['php-selfcheck-current-job',initial]]:[]);const calls=[];let sequence=0;
  const document={getElementById:id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);},createElement:()=>new Element()};
  const context=vm.createContext({document,sessionStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},setInterval:()=>{},console,
    fetch:async(path,options)=>{
      calls.push(path);let data;
      if(path==='/api/me') data={allow_anonymous:true,scope_configured:true};
      else if(path==='/api/scan'){sequence++;data={id:'job'+sequence};}
      else if(path.startsWith('/api/jobs/'))data={id:path.split('/').pop(),created:1,state:'done',results:[{target:path.split('/').pop(),verdict:'未发现 PHP 特征',reason:'test'}]};
      else throw new Error('Unexpected request: '+path);
      return {ok:true,status:200,json:async()=>data};
    }
  });
  vm.runInContext(fs.readFileSync('assets/shared.js','utf8'),context);
  vm.runInContext(fs.readFileSync('assets/ui.js','utf8'),context);
  return {context,document,storage,calls};
}
const flush=()=>new Promise(resolve=>setImmediate(resolve));
test('developer page fetches only the current tab job, never a history list',async()=>{
  const app=setup();await flush();assert.deepEqual(app.calls,['/api/me']);
  app.document.getElementById('targets').value='example.com';
  await app.document.getElementById('scan').onclick();
  assert.equal(app.storage.get('php-selfcheck-current-job'),'job1');
  await app.document.getElementById('scan').onclick();
  assert.equal(app.storage.get('php-selfcheck-current-job'),'job2');
  assert.equal(app.document.getElementById('jobs').children.length,1);
  assert(!app.calls.includes('/api/jobs'));assert(!app.calls.includes('/api/reports'));
  const restored=setup('job2');await flush();assert.deepEqual(restored.calls,['/api/me','/api/jobs/job2']);
  const freshTab=setup();await flush();assert.deepEqual(freshTab.calls,['/api/me']);
});

test('administrator filters, filtered exports and deletion confirmation',async()=>{
  const elements=new Map();const calls=[];let confirmed=false,deleted=false,confirmation='';
  const document={getElementById:id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);},createElement:()=>new Element()};
  document.getElementById('sortOrder').value='newest';
  const context=vm.createContext({document,console,confirm:message=>{confirmation=message;return confirmed;},fetch:async(path,options)=>{
    calls.push({path,options});let data;
    if(path==='/api/admin/me')data={user:'admin'};
    else if(path==='/api/admin/settings')data={revision:0,origin:'file',document:'{}'};
    else if(path==='/api/admin/fingerprints')data={revision:0,origin:'builtin',document:JSON.stringify({schema:'php-selfcheck-fingerprints/v1',version:'test',mode:'replace',rules:[]}),builtin_document:JSON.stringify({rules:[]}),metadata:{version:'test',rule_count:0}};
    else if(path.endsWith('/delete')){deleted=true;data={ok:true};}
    else if(path.startsWith('/api/admin/jobs?'))data={jobs:deleted?[]:[{id:'mixed',owner:'visitor:test',created:1,state:'done',total_results:3,results:[{target:'risk.example',verdict:'疑似受影响'}]}],total:deleted?0:1,summary:{jobs:deleted?0:1,reports:1,states:{done:1},verdicts:{'疑似受影响':1}}};
    else throw Error(path);
    return {ok:true,status:200,json:async()=>data};
  }});
  vm.runInContext(fs.readFileSync('assets/shared.js','utf8'),context);vm.runInContext(fs.readFileSync('assets/admin.js','utf8'),context);await flush();
  document.getElementById('verdictFilter').value='疑似受影响';document.getElementById('sortOrder').value='risk_desc';document.getElementById('verdictFilter').onchange();await flush();
  assert(calls.some(c=>c.path.includes('verdict='+encodeURIComponent('疑似受影响')) && c.path.includes('sort=risk_desc')));
  function flatten(e){return [e,...(e.children||[]).flatMap(flatten)];}
  const links=flatten(document.getElementById('jobs')).filter(e=>e.href);assert(links.every(e=>e.href.includes('&verdict='+encodeURIComponent('疑似受影响'))));
  const remove=flatten(document.getElementById('jobs')).find(e=>e.textContent==='删除本次扫描');assert(remove);
  await remove.onclick();assert(!calls.some(c=>c.path.endsWith('/delete')));assert(confirmation.includes('3 个结果'));
  confirmed=true;await remove.onclick();assert(deleted);assert(calls.some(c=>c.path.endsWith('/delete') && JSON.parse(c.options.body).confirm===true));
  assert.equal(document.getElementById('jobs').children.length,1); // Empty-state paragraph.
});

test('collector switches build a safe command and disable dependent probes',async()=>{
  const app=setup();await flush();const get=id=>app.document.getElementById(id);
  assert.equal(get('collectCommand').textContent,'php-selfcheck collect > host-report.json');
  get('collectMiddleware').checked=true;get('collectMiddleware').onchange();
  get('collectModules').checked=true;get('collectPorts').checked=true;get('collectPorts').onchange();get('collectWeb').checked=true;get('collectWeb').onchange();
  get('collectHost').value='app.internal';get('collectHost').oninput();
  assert(get('collectCommand').textContent.includes("--middleware --php-modules --ports --web-probe --web-host 'app.internal'"));
  get('collectHost').value="x'; touch /tmp/unsafe";get('collectHost').oninput();assert(!get('collectCommand').textContent.includes('touch'));
  get('collectMiddleware').checked=false;get('collectMiddleware').onchange();assert.equal(get('collectWeb').checked,false);assert.equal(get('collectWeb').disabled,true);assert.equal(get('collectCommand').textContent,'php-selfcheck collect > host-report.json');
});

test('PHP command and package audit are independent explicit collection switches',async()=>{
  const app=setup();await flush();const get=id=>app.document.getElementById(id);
  get('collectPhpCommand').checked=true;get('collectPhpCommand').onchange();
  assert.equal(get('collectCommand').textContent,'php-selfcheck collect --php-command > host-report.json');
  get('collectPackageAudit').checked=true;get('collectPackageAudit').onchange();
  assert.equal(get('collectCommand').textContent,'php-selfcheck collect --php-command --package-audit > host-report.json');
  assert(!get('collectMiddleware').checked);
  get('collectPhpCommand').checked=false;get('collectPhpCommand').onchange();
  assert.equal(get('collectCommand').textContent,'php-selfcheck collect --package-audit > host-report.json');
});

test('fingerprint rendering shows evidence as plain text and handles older records',async()=>{
  const app=setup();await flush();
  function flatten(e){return [e,...(e.children||[]).flatMap(flatten)];}
  const f={library:{version:'company-1',rule_count:1,source:'custom_extend'},matches:[{id:'own',name:'<script>unsafe</script>',category:'framework',relation:'external_reference',versions:['2.0'],confidence:'low',advice:'仅线索',evidence:[{source:'resource_path',pattern:'/wp-content/',detail:'资源路径命中',url:'https://app.example/',resource_origin:'https://other.example'}]}]};
  app.context.fingerprintFixture=f;
  const view=vm.runInContext('fingerprintsView(fingerprintFixture)',app.context);
  const content=flatten(view).map(n=>n.textContent).join('\n');
  assert(content.includes('<script>unsafe</script>'));assert(content.includes('仅外部资源引用'));assert(content.includes('https://other.example'));assert(content.includes('company-1'));
  assert(!flatten(view).some(n=>n.innerHTML));
  assert.equal(vm.runInContext('fingerprintsView(undefined).children.length',app.context),0);
});

test('administrator rule drafts validate, save, preserve conflicts and clear on logout',async()=>{
  const elements=new Map(),calls=[];let revision=0;
  const definition={schema:'php-selfcheck-fingerprints/v1',version:'test-1',mode:'replace',rules:[{id:'example',name:'Example',category:'framework',any:[{source:'header',header:'x-app',pattern:'yes'}]}]};
  let stored=JSON.stringify(definition);const builtin=stored;
  const get=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
  get('sortOrder').value='newest';
  const data=()=>({revision,origin:revision?'database':'builtin',document:stored,builtin_document:builtin,metadata:{version:JSON.parse(stored).version,rule_count:1}});
  const document={getElementById:get,createElement:()=>new Element()};
  const context=vm.createContext({document,console,confirm:()=>true,fetch:async(path,options)=>{
    calls.push({path,body:options?.body?JSON.parse(options.body):null});let result,status=200;
    if(path==='/api/admin/me')result={user:'admin'};
    else if(path.startsWith('/api/admin/jobs?'))result={jobs:[],total:0,summary:{jobs:0,reports:0,states:{},verdicts:{}}};
    else if(path==='/api/admin/settings')result={revision:0,origin:'file',document:'{}'};
    else if(path==='/api/admin/fingerprints')result=data();
    else if(path.endsWith('/validate'))result={valid:true,metadata:{rule_count:1}};
    else if(path.endsWith('/save')){const body=JSON.parse(options.body);if(body.revision!==revision){status=409;result={error:'其他管理员已更新，请合并草稿'};}else{stored=body.document;revision++;result=data();}}
    else if(path==='/api/admin/logout')result={ok:true};else throw Error(path);
    return {ok:status===200,status,json:async()=>result};
  }});
  vm.runInContext(fs.readFileSync('assets/shared.js','utf8'),context);vm.runInContext(fs.readFileSync('assets/admin.js','utf8'),context);await flush();
  assert.equal(JSON.parse(get('ruleObject').value).id,'example');
  const edited=JSON.parse(get('ruleObject').value);edited.name='Changed';get('ruleObject').value=JSON.stringify(edited);get('ruleObject').oninput();
  await get('rulesSave').onclick();assert(!calls.some(c=>c.path.endsWith('/save')));assert(get('rulesNotice').textContent.includes('先应用'));
  get('ruleApply').onclick();await get('rulesValidate').onclick();assert.equal(revision,0);assert(get('rulesNotice').textContent.includes('尚未保存'));
  await get('rulesSave').onclick();assert.equal(revision,1);assert.equal(JSON.parse(stored).rules[0].name,'Changed');
  get('ruleToggle').onclick();assert.deepEqual(JSON.parse(get('rulesDocument').value).disabled_rules,['example']);await get('rulesSave').onclick();assert.equal(revision,2);
  revision++;const draft=JSON.parse(get('rulesDocument').value);draft.version='unsaved';get('rulesDocument').value=JSON.stringify(draft);await get('rulesSave').onclick();
  assert(get('rulesNotice').textContent.includes('合并'));assert.equal(JSON.parse(get('rulesDocument').value).version,'unsaved');
  await get('logout').onclick();assert.equal(get('rulesDocument').value,'');assert.equal(get('ruleObject').value,'');assert.equal(get('dashboard').hidden,true);
});

test('important evidence has semantic emphasis without HTML injection or safe-status claims',async()=>{
  const app=setup();await flush();app.context.fixture={verdict:'疑似受影响',reason:'回补状态未知',versions:['8.4.26'],evidence:[{kind:'response_header',detail:'X-Powered-By: PHP/8.4.26 <img onerror=unsafe>'}]};
  const element=vm.runInContext('evidenceSummary(fixture)',app.context);
  const flat=e=>[e,...(e.children||[]).flatMap(flat)];const nodes=flat(element);
  assert(element.className.includes('risk'));assert(nodes.some(n=>n.className?.includes('evidence-value') && n.textContent==='PHP 8.4.26'));
  assert(nodes.some(n=>n.className?.includes('evidence-mark risk') && n.textContent==='8.4.26'));
  assert(nodes.some(n=>n.textContent.includes('<img onerror=unsafe>')));assert(!nodes.some(n=>n.innerHTML));
  const step=vm.runInContext('nextStep(fixture)',app.context);assert(flat(step).some(n=>n.textContent==='下一步'));assert(!flat(step).some(n=>n.textContent.includes('漏洞已确认')));
});

test('passive upload and error clues render as text with explicit review limitations',()=>{
  const {context}=setup();
  const element=vm.runInContext(`assessmentView({surfaces:{forms:[{endpoint:{origin:'https://external.example',path:'/<img onerror=unsafe>',relation:'external_reference'},method:'POST',multipart:true,file_fields:['<script>'],progress_field:true}],errors:[{detail:'会话解码错误不是 CVE 证明'}],limits_reached:true}})`,context);
  const flat=e=>[e,...(e.children||[]).flatMap(flat)],nodes=flat(element),text=nodes.map(n=>n.textContent).join(' ');
  assert(text.includes('外部表单引用'));assert(text.includes('/<img onerror=unsafe>'));assert(text.includes('会话解码错误不是 CVE 证明'));assert(text.includes('不提交表单'));assert(text.includes('达到分析上限'));assert(!nodes.some(n=>n.innerHTML));
});

test('administrator settings import only online fields, validate, save and preserve conflicts',async()=>{
  const elements=new Map(),get=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
  let revision=0,policy={allow_anonymous:true,allow_without_whitelist:true,allowed_networks:[],allowed_domains:[],allowed_ports:[],probe_multipart:false,headers_only:false,collection_defaults:{php_command:false,package_audit:false,middleware:false,php_modules:false,ports:false,web_probe:false}};
  const view=()=>({revision,origin:'database',document:JSON.stringify(policy),deployment:{users:[],admins:['admin']}});
  const document={getElementById:get,createElement:()=>new Element()};
  const context=vm.createContext({document,console,confirm:()=>true,fetch:async(path,options)=>{
    let data,status=200;
    if(path==='/api/admin/me')data={user:'admin'};
    else if(path.startsWith('/api/admin/jobs?'))data={jobs:[],total:0,summary:{jobs:0,reports:0,states:{},verdicts:{}}};
    else if(path==='/api/admin/fingerprints')data={revision:0,origin:'builtin',document:JSON.stringify({mode:'replace',rules:[]}),builtin_document:'{"rules":[]}',metadata:{version:'test',rule_count:0}};
    else if(path==='/api/admin/settings')data=view();
    else if(path==='/api/admin/settings/validate')data={valid:true};
    else if(path==='/api/admin/settings/save'){const body=JSON.parse(options.body);if(body.revision!==revision){status=409;data={error:'其他管理员已更新配置'};}else{policy=JSON.parse(body.document);revision++;data=view();}}
    else if(path==='/api/admin/logout')data={ok:true};else throw Error(path);
    return {ok:status===200,status,json:async()=>data};
  }});
  vm.runInContext(fs.readFileSync('assets/shared.js','utf8'),context);vm.runInContext(fs.readFileSync('assets/admin.js','utf8'),context);await flush();
  get('settingsFile').files=[{size:100,text:async()=>JSON.stringify({probe_multipart:true,users:{admin:'SECRET_HASH'},database:'/private'})}];
  await get('settingsFile').onchange();
  assert(!get('settingsDocument').value.includes('SECRET_HASH'));assert(!get('settingsDocument').value.includes('/private'));
  await get('settingsValidate').onclick();assert.equal(policy.probe_multipart,false);assert.equal(revision,0);
  await get('settingsSave').onclick();assert.equal(policy.probe_multipart,true);assert.equal(revision,1);
  revision++;const draft=JSON.parse(get('settingsDocument').value);draft.headers_only=true;get('settingsDocument').value=JSON.stringify(draft);
  await get('settingsSave').onclick();assert(get('settingsNotice').textContent.includes('其他管理员'));assert.equal(JSON.parse(get('settingsDocument').value).headers_only,true);
  await get('logout').onclick();assert.equal(get('settingsDocument').value,'');assert.equal(get('settingsDeployment').textContent,'');
});
