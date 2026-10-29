#!/usr/bin/env node
// Real-browser checks against an isolated local service and synthetic evidence only.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const net=require('node:net');
const crypto=require('node:crypto');
const {spawn,spawnSync}=require('node:child_process');
const {chromium}=require('playwright');

async function freePort(){const server=net.createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;}
const reportDirectory=path.resolve(process.argv[3] || 'artifacts/ui');
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function main(){
  const binary=path.resolve(process.argv[2]);const output=path.resolve(process.argv[3] || 'artifacts/ui');fs.mkdirSync(output,{recursive:true});
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'php-selfcheck-browser-'));let processHandle,browser;
  try{
    const port=await freePort(),base=`http://127.0.0.1:${port}`;
    const config=JSON.parse(fs.readFileSync('config.open.example.json','utf8'));
    const password='admin-ui-test';const salt='00'.repeat(16),hash=crypto.pbkdf2Sync(password,Buffer.from(salt,'hex'),260000,32,'sha256').toString('hex');
    Object.assign(config,{public_origin:base,database:path.join(temp,'state.sqlite3'),admins:{admin:`${salt}:${hash}`}});
    const file=path.join(temp,'config.json');fs.writeFileSync(file,JSON.stringify(config));
    processHandle=spawn(binary,['serve','--config',file,'--port',String(port)],{stdio:'ignore'});
    for(let i=0;i<100;i++){try{const response=await fetch(base);if(response.ok)break;}catch(_){}if(i===99 || processHandle.exitCode!==null)throw Error('Local service did not start');await sleep(100);}
    browser=await chromium.launch({headless:true,...(process.env.CHROME_BIN?{executablePath:process.env.CHROME_BIN}:{}),args:['--no-sandbox','--disable-background-networking']});
    const context=await browser.newContext({viewport:{width:1440,height:1100}});const page=await context.newPage();
    const errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto(base);
    const me=await(await page.request.get(base+'/api/me')).json();
    const fixture=[{target:'https://app.example.com/',verdict:'疑似受影响',reason:'披露版本低于官方修复基线，回补状态待核实',versions:['8.4.26'],evidence:[{kind:'response_header',detail:'X-Powered-By: PHP/8.4.26 <img src=x onerror="window.__injected=1">'}],assessment:{patch:{status:'below_upstream_fix',source:'response_header',confidence:'low',detail:'低于修复基线，厂商回补状态未知'},review_priority:'high',surfaces:{forms:[{endpoint:{origin:'https://external.example',path:'/upload',relation:'external_reference'},method:'POST',multipart:true,file_fields:['document'],progress_field:true}],errors:[{kind:'session_decode',detail:'会话解码错误文本不能确认特定 CVE'}]}},fingerprints:{library:{version:'ui-fixture',rule_count:1,source:'test'},matches:[{id:'wordpress',name:'WordPress',category:'cms',versions:['6.6.2'],relation:'response',confidence:'low',advice:'CMS 版本不是 PHP 版本，实际实例仍需核验',evidence:[{source:'meta_generator',pattern:'WordPress',detail:'generator 标签命中',url:'https://app.example.com/'}]}]}}];
    const fixtureFile=path.join(temp,'fixture.json');fs.writeFileSync(fixtureFile,JSON.stringify(fixture));
    const seeded=spawnSync('python3',['-c',"import sqlite3,sys,time; db=sqlite3.connect(sys.argv[1]); db.execute('INSERT INTO jobs VALUES(?,?,?,?,?)',('ui-fixture',sys.argv[2],time.time(),'done',open(sys.argv[3]).read())); db.commit()",config.database,me.user,fixtureFile],{encoding:'utf8'});assert.equal(seeded.status,0,seeded.stderr);
    await page.evaluate(()=>sessionStorage.setItem('php-selfcheck-current-job','ui-fixture'));await page.reload();
    await page.locator('#jobs .evidence-value').waitFor();
    const style=await page.locator('#jobs .evidence-value').evaluate(e=>({family:getComputedStyle(e).fontFamily,weight:getComputedStyle(e).fontWeight,color:getComputedStyle(e).color,background:getComputedStyle(e).backgroundColor}));
    assert(Number(style.weight)>=700);assert(style.family.includes('monospace'));assert.notEqual(style.color,'rgb(99, 120, 122)');assert.notEqual(style.background,'rgba(0, 0, 0, 0)');
    assert.equal(await page.locator('#jobs .evidence-mark.risk').first().textContent(),'8.4.26');assert.equal(await page.evaluate(()=>window.__injected),undefined);
    assert(await page.locator('#jobs .next-step').first().isVisible());assert(await page.locator('#jobs .technology-name').isVisible());
    assert((await page.locator('#jobs').textContent()).includes('外部表单引用'));assert((await page.locator('#jobs').textContent()).includes('会话解码错误文本不能确认特定 CVE'));
    await page.locator('#jobs').screenshot({path:path.join(output,'evidence.png')});
    await page.goto(base+'/admin');await page.locator('#adminUser').fill('admin');await page.locator('#adminPassword').fill(password);await page.locator('#loginButton').click();
    await page.waitForFunction(()=>document.getElementById('rulesMeta').textContent.includes('修订 0'));
    await page.locator('#rulesVersion').fill('browser-ui-1');await page.locator('#rulesVersion').press('Tab');await page.locator('#ruleSelect').selectOption('wordpress');await page.locator('#ruleToggle').click();
    let publicMeta=await(await page.request.get(base+'/api/me')).json();assert.equal(publicMeta.fingerprint_library.rule_count,51);
    await page.locator('#rulesValidate').click();await page.waitForFunction(()=>document.getElementById('rulesNotice').textContent.includes('校验通过'));
    publicMeta=await(await page.request.get(base+'/api/me')).json();assert.equal(publicMeta.fingerprint_library.rule_count,51);
    await page.locator('#rulesSave').click();await page.waitForFunction(()=>document.getElementById('rulesMeta').textContent.includes('修订 1'));
    publicMeta=await(await page.request.get(base+'/api/me')).json();assert.equal(publicMeta.fingerprint_library.version,'browser-ui-1');assert.equal(publicMeta.fingerprint_library.rule_count,50);
    const saved=await page.locator('#rulesDocument').inputValue();await page.locator('#fingerprintPanel details summary').click();await page.locator('#rulesDocument').fill('{');await page.locator('#rulesValidate').click();await page.waitForFunction(()=>document.getElementById('rulesNotice').textContent.includes('校验失败'));
    assert.equal(await page.locator('#rulesDocument').inputValue(),'{');publicMeta=await(await page.request.get(base+'/api/me')).json();assert.equal(publicMeta.fingerprint_library.rule_count,50);
    await page.locator('#rulesDocument').fill(saved);await page.locator('#rulesFormat').click();await page.locator('#ruleSelect').selectOption('wordpress');await page.locator('#ruleToggle').click();await page.locator('#rulesSave').click();await page.waitForFunction(()=>document.getElementById('rulesMeta').textContent.includes('修订 2'));
    await page.locator('#ruleNew').click();const item=JSON.parse(await page.locator('#ruleObject').inputValue());item.id='browser-added';item.name='Browser added';await page.locator('#ruleObject').fill(JSON.stringify(item));await page.locator('#ruleApply').click();await page.locator('#rulesSave').click();await page.waitForFunction(()=>document.getElementById('rulesMeta').textContent.includes('修订 3'));
    publicMeta=await(await page.request.get(base+'/api/me')).json();assert.equal(publicMeta.fingerprint_library.rule_count,52);
    await page.locator('#ruleRemove').click();await page.locator('#rulesSave').click();await page.waitForFunction(()=>document.getElementById('rulesMeta').textContent.includes('修订 4'));
    const second=await context.newPage();second.on('pageerror',e=>errors.push(e.message));await second.goto(base+'/admin');await second.waitForFunction(()=>document.getElementById('rulesMeta').textContent.includes('修订 4'));
    await page.locator('#rulesVersion').fill('browser-ui-2');await page.locator('#rulesVersion').press('Tab');await page.locator('#rulesSave').click();await page.waitForFunction(()=>document.getElementById('rulesMeta').textContent.includes('修订 5'));
    await second.locator('#rulesVersion').fill('stale-draft');await second.locator('#rulesVersion').press('Tab');await second.locator('#rulesSave').click();await second.waitForFunction(()=>document.getElementById('rulesNotice').textContent.includes('其他管理员'));
    assert.equal(JSON.parse(await second.locator('#rulesDocument').inputValue()).version,'stale-draft');
    await page.locator('#fingerprintPanel details summary').click();await page.locator('#fingerprintPanel').screenshot({path:path.join(output,'administrator-rules.png')});
    await page.waitForFunction(()=>document.getElementById('settingsMeta').textContent.includes('修订 0'));
    await page.locator('#settingsFile').setInputFiles({name:'config.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify({probe_multipart:true,users:{ignored:'SECRET_HASH'},database:'/ignored/path'}))});
    await page.waitForFunction(()=>document.getElementById('settingsNotice').textContent.includes('已导入'));
    assert(!(await page.locator('#settingsDocument').inputValue()).includes('SECRET_HASH'));
    const policy=JSON.parse(await page.locator('#settingsDocument').inputValue());policy.headers_only=true;policy.probe_upload_progress=true;policy.collection_defaults.php_command=true;
    await page.locator('#settingsDocument').fill(JSON.stringify(policy));
    const validationResponsePromise=page.waitForResponse(r=>r.url().endsWith('/api/admin/settings/validate') && r.request().method()==='POST');
    await page.locator('#settingsValidate').click();
    const validationResponse=await validationResponsePromise,validation=await validationResponse.json();
    assert.equal(validationResponse.status(),200,`Configuration validation HTTP failure: ${validation.error || 'unknown'}`);assert.equal(validation.valid,true);
    try{await page.waitForFunction(()=>document.getElementById('settingsNotice').textContent.includes('校验通过'));}
    catch(e){throw Error(`Configuration validation returned HTTP 200 but UI did not settle: ${await page.locator('#settingsNotice').textContent()}; page errors: ${errors.join('; ')}`,{cause:e});}
    publicMeta=await(await page.request.get(base+'/api/me')).json();assert.equal(publicMeta.probe_multipart_allowed,false);
    await page.locator('#settingsSave').click();await page.waitForFunction(()=>document.getElementById('settingsMeta').textContent.includes('修订 1'));
    publicMeta=await(await page.request.get(base+'/api/me')).json();assert.equal(publicMeta.probe_multipart_allowed,true);assert.equal(publicMeta.probe_upload_progress_allowed,true);assert.equal(publicMeta.headers_only,true);assert.equal(publicMeta.collection_defaults.php_command,true);
    await second.locator('#settingsDocument').fill(JSON.stringify(policy));await second.locator('#settingsSave').click();await second.waitForFunction(()=>document.getElementById('settingsNotice').textContent.includes('其他管理员'));
    assert.equal(JSON.parse(await second.locator('#settingsDocument').inputValue()).probe_multipart,true);
    const forced=await context.newPage();await forced.goto(base);await forced.waitForFunction(()=>document.getElementById('headersOnly').disabled);assert(await forced.locator('#probeMultipart').isDisabled());assert(await forced.locator('#probeProgress').isDisabled());assert(!(await forced.locator('#probeProgress').isChecked()));await forced.close();
    policy.headers_only=false;await page.locator('#settingsDocument').fill(JSON.stringify(policy));await page.locator('#settingsSave').click();await page.waitForFunction(()=>document.getElementById('settingsMeta').textContent.includes('修订 2'));
    await page.locator('#settingsPanel').screenshot({path:path.join(output,'administrator-settings.png')});
    const developer=await context.newPage();await developer.goto(base);await developer.waitForFunction(()=>!document.getElementById('probeProgress').disabled);assert(!(await developer.locator('#probeProgress').isChecked()));assert(!(await developer.locator('#probeMultipart').isDisabled()));assert(await developer.locator('#collectPhpCommand').isChecked());await developer.close();
    await page.locator('#logout').click();await page.locator('#loginPanel').waitFor();assert.equal(await page.locator('#rulesDocument').inputValue(),'');assert.equal(await page.locator('#settingsDocument').inputValue(),'');
    assert.deepEqual(errors,[]);fs.writeFileSync(path.join(output,'browser-result.json'),JSON.stringify({state:'passed',checks:['evidence-fonts-colors','text-only-rendering','rule-edit-validation-save','live-activation','conflict-preserves-draft','logout-cleanup','passive-surface-clues','settings-import-validation-save','settings-live-policy','settings-conflict-preserves-draft','progress-permissions-and-defaults'],evidence_style:style},null,2));console.log('Browser smoke passed: evidence fonts/colors, text-only rendering, rule editing/validation/save, live activation, conflicts, and logout cleanup.');
  }finally{
    if(browser)await browser.close();
    if(processHandle && processHandle.exitCode===null){processHandle.kill('SIGTERM');await Promise.race([new Promise(resolve=>processHandle.once('exit',resolve)),sleep(5000)]);if(processHandle.exitCode===null)processHandle.kill('SIGKILL');}
    fs.rmSync(temp,{recursive:true,force:true});
  }
}
main().catch(e=>{fs.mkdirSync(reportDirectory,{recursive:true});fs.writeFileSync(path.join(reportDirectory,'browser-result.json'),JSON.stringify({state:'failed',error:String(e.stack || e).slice(0,3000)},null,2));console.error(e);process.exitCode=1;});
