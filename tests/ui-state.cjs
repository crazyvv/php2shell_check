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
