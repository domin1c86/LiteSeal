const {test}=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs/promises');const path=require('node:path');const os=require('node:os');const {buildSync}=require('esbuild');
const bundle=buildSync({entryPoints:[path.resolve('electron/history-files.ts')],bundle:true,platform:'node',format:'cjs',write:false});const mod={exports:{}};new Function('require','module','exports',bundle.outputFiles[0].text)(require,mod,mod.exports);const {historyFileCommand:run}=mod.exports;
const scope='a'.repeat(64),id='01234567-89ab-4cde-8fab-0123456789ab';
test('history dialogs exclusively save verified output and never accept renderer paths',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'liteseal-history-file-test-'));const destination=path.join(root,'selected.lhistory');const calls=[];
  const bridge={call:async(name,args)=>{calls.push({name,args});await fs.writeFile(args.path,'synthetic sealed package',{flag:'wx'});return 'saved';}};
  const dialogs={open:async()=>null,save:async()=>destination};
  try {
    await assert.rejects(run('export_direct_history_transfer',{scope,id,revision:1,path:'injected'},bridge,dialogs,()=>{}));assert.equal(calls.length,0);
    assert.equal(await run('export_direct_history_transfer',{scope,id,revision:1},bridge,dialogs,()=>{}),'saved');assert.equal(await fs.readFile(destination,'utf8'),'synthetic sealed package');
    assert.notEqual(calls[0].args.path,destination);assert.equal(calls[0].args.id,id);assert.equal(calls[0].args.revision,1);
    await assert.rejects(run('export_direct_history_transfer',{scope,id,revision:1},bridge,dialogs,()=>{}),{code:'EEXIST'});assert.equal(await fs.readFile(destination,'utf8'),'synthetic sealed package');
    assert.deepEqual(await fs.readdir(root),['selected.lhistory']);
  } finally {await fs.rm(root,{recursive:true,force:true});}
});
test('history scope retirement and canceled dialogs prevent import or output',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'liteseal-history-retire-test-'));let retired=false;let calls=0;
  const check=()=>{if(retired)throw new Error('scope retired');};const bridge={call:async(_name,args)=>{calls++;await fs.writeFile(args.path,'authenticated',{flag:'wx'});retired=true;}};
  try {
    const dialogs={open:async()=>null,save:async()=>path.join(root,'media')};
    assert.equal(await run('import_direct_history_transfer',{scope},bridge,dialogs,check),null);assert.equal(calls,0);
    await assert.rejects(run('export_transferred_media',{scope,id},bridge,dialogs,check),/scope retired/);assert.deepEqual(await fs.readdir(root),[]);
    retired=false;
    await assert.rejects(run('import_direct_history_transfer',{scope},bridge,{...dialogs,open:async()=>{retired=true;return path.join(root,'chosen.lhistory');}},check),/scope retired/);assert.equal(calls,1);
  } finally {await fs.rm(root,{recursive:true,force:true});}
});
test('history import forwards the chosen path without forwarding bytes or secrets',async()=>{
  let call;const selected=path.resolve(os.tmpdir(),'synthetic.lhistory');
  const result=await run('import_direct_history_transfer',{scope},{call:async(name,args)=>{call={name,args};return{id,state:'imported'};}},{open:async()=>selected,save:async()=>null},()=>{});
  assert.equal(result.state,'imported');assert.deepEqual(call,{name:'import_direct_history_transfer',args:{scope,path:selected}});
  await assert.rejects(run('export_backup_transferred_media',{id,messageId:id,path:'injected'},{call:async()=>assert.fail('must reject')},{open:async()=>null,save:async()=>null},()=>{}));
});
