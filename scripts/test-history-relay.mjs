import {runSuite,execute} from './test-database.mjs';
import {mkdirSync,writeFileSync} from 'node:fs';
const run=(command,args,env)=>{
  const result=execute(command,args,env);
  if(result.code && command==='cargo'){
    // Only source locations and the SDK's fixed public error are diagnostic.
    // Never save arbitrary panic output, database URLs or fixture credentials.
    const locations=[...result.output.matchAll(/panicked at ([^\r\n]+\.rs:\d+:\d+)/g)].map(m=>m[1]);
    const apiErrors=[...result.output.matchAll(/ApiError \{ status: (None|Some\(\d+\)), message: "([^"\r\n]+)" \}/g)].map(m=>({status:m[1],message:m[2]}));
    console.log(JSON.stringify({diagnostic:{locations,apiErrors}}));
  }
  return result;
};
const report=runSuite(process.env,run,'trusted_device_tests::direct_message_tests::history_tests::');
report.scope='synthetic isolated PostgreSQL/HTTP and native Windows stores, no GUI or real profiles';
mkdirSync('target/test-results',{recursive:true});
const file='target/test-results/history-relay-'+report.at.replace(/[:.]/g,'-')+'.json';
writeFileSync(file,JSON.stringify(report,null,2));console.log(JSON.stringify(report,null,2));console.log(file);
process.exitCode=report.status==='passed'?0:2;
