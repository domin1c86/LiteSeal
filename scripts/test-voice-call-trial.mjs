import {build} from 'esbuild';import {mkdir,mkdtemp,writeFile,readFile} from 'node:fs/promises';import path from 'node:path';import {createRequire} from 'node:module';import {spawn,spawnSync} from 'node:child_process';import {stopTree} from './process.mjs';
const types=spawnSync(process.execPath,['node_modules/typescript/bin/tsc','-p','ui/tsconfig.tests.json'],{stdio:'inherit',windowsHide:true});if(types.status!==0)process.exit(1);
const compiled=spawnSync('cargo',['build','--locked','-p','liteseal-shared','--example','voice_call_trial'],{stdio:'inherit',windowsHide:true,env:{...process.env,CARGO_BUILD_JOBS:'1'}});if(compiled.status!==0)process.exit(1);
await mkdir('target/test-results',{recursive:true});const directory=await mkdtemp(path.resolve('target/test-results/voice-call-trial-'));
await build({entryPoints:['ui/tests/voice-call-harness.ts'],bundle:true,outfile:path.join(directory,'harness.js'),platform:'browser'});
await writeFile(path.join(directory,'index.html'),'<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'; connect-src \'self\'; media-src \'self\' blob:"></head><body><script src="harness.js"></script></body></html>');
const env={...process.env};delete env.ELECTRON_RUN_AS_NODE;
const child=spawn(createRequire(import.meta.url)('electron'),[path.resolve('scripts/voice-call-trial-electron.cjs'),directory],{env,stdio:'ignore',windowsHide:true});let timedOut=false;
const timer=setTimeout(()=>{timedOut=true;void stopTree(child);},60000);
const code=await new Promise(resolve=>{child.once('error',()=>resolve(1));child.once('exit',resolve);});clearTimeout(timer);
try{console.log(await readFile(path.join(directory,'result.json'),'utf8'));}catch{console.log('No voice trial report');}
console.log('Voice trial evidence: '+directory);process.exitCode=code===0&&!timedOut?0:1;
