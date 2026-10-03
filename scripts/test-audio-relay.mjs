import {runSuite} from './test-database.mjs';
import {mkdirSync,writeFileSync} from 'node:fs';
const report=runSuite(process.env,undefined,'trusted_device_tests::direct_message_tests::audio_tests::');
report.scope='Synthetic isolated audio HTTP/native boundaries; no microphone, user profiles or GUI';
mkdirSync('target/test-results',{recursive:true});
const file='target/test-results/audio-relay-'+report.at.replace(/[:.]/g,'-')+'.json';
writeFileSync(file,JSON.stringify(report,null,2));console.log(JSON.stringify(report,null,2));console.log(file);
process.exitCode=report.status==='passed'?0:2;
