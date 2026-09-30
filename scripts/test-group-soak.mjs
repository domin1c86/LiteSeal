// Real relay/DPAPI soak. Default is 24 hours; --smoke validates six iterations
// of the same topology/fault path and explicitly does not claim long-run proof.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdir, mkdtemp, writeFile, readFile, rm, copyFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { preflight, execute } from './test-database.mjs';
import { stopTree } from './process.mjs';
const smoke = process.argv.includes('--smoke');
const report = { at: new Date().toISOString(), status: 'not_executed', mode: smoke ? 'smoke' : '24h', planned_seconds: smoke ? null : 86400, topology: '10 isolated accounts, 10 groups, all 10 accounts in every group', samples: [], faults: [], stage: 'preflight' };
report.features=['text','group files','synthetic WebM/Opus','activities and RSVP','extension response loss/restart','original join phase download isolation'];
const revision = execute('git', ['rev-parse', 'HEAD']); report.commit = revision.output.trim();
await mkdir('target/test-results', { recursive: true });
const evidence = path.resolve('target/test-results/group-soak-' + report.at.replace(/[:.]/g, '-') + '.json');
const persist = () => writeFile(evidence, JSON.stringify(report, null, 2) + '\n');
let root, server, proxy, origin, upstream, desktopExecutable;
const people = [], bridges = [];
let stop = false, offlineToken = null, loseResponse = false,loseExtensionResponse=false;
process.on('SIGINT', () => { stop = true; }); process.on('SIGTERM', () => { stop = true; });
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const start = async person => {
  const { DesktopBridge } = createRequire(import.meta.url)('../dist-electron/bridge.cjs');
  const bridge = new DesktopBridge(60000); bridges.push(bridge);
  await bridge.start(desktopExecutable, ['--db-path', path.join(root, person.name + '.db'), '--keystore-path', path.join(root, person.name + '.bin')]);
  person.bridge = bridge;
};
const save = person => person.bridge.call('save_session', { userId: person.id, deviceId: person.device, token: person.token, refreshToken: person.refresh, serverUrl: origin });
const inviteAndAccept = async (owner, person, groupId) => {
  const target = await owner.bridge.call('inspect_group_peer', { peerId: person.id });
  await owner.bridge.call('invite_group_member', { groupId, peerId: person.id, confirmedFingerprint: target.fingerprint });
  const invitations = (await person.bridge.call('get_groups', { refresh: true })).invitations;
  const invitation = invitations.find(i => i.group_id === groupId); assert.ok(invitation);
  const detail = await person.bridge.call('inspect_group', { groupId, inviteId: invitation.id });
  await person.bridge.call('accept_group_invite', { inviteId: invitation.id, confirmedFingerprint: detail.fingerprint });
  await owner.bridge.call('sync_group', { groupId });
};
const memory = () => {
  const ids = [server?.pid, ...people.map(p => p.bridge.child?.pid)].filter(Number.isInteger);
  const sampled = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `Get-Process -Id ${ids.join(',')} -ErrorAction SilentlyContinue | Select-Object Id,WorkingSet64,CPU | ConvertTo-Json -Compress`], { encoding: 'utf8', windowsHide: true, timeout: 10000 });
  try { const values = JSON.parse(sampled.stdout); return (Array.isArray(values) ? values : [values]).map(p => ({ pid: p.Id, working_set: p.WorkingSet64, cpu_seconds: p.CPU })); } catch { return []; }
};
try {
  if (process.platform !== 'win32') throw new Error();
  const checked = preflight(); if (!checked.ok) throw new Error(); report.server_version_num = checked.server_version_num;
  report.stage = 'build'; assert.equal(execute('cargo', ['build', '--locked', '-p', 'liteseal-desktop']).code, 0); assert.equal(execute(process.execPath, ['scripts/build-electron.mjs']).code, 0);
  root = await mkdtemp(path.join(os.tmpdir(), 'liteseal-soak-'));
  desktopExecutable = path.join(root, 'liteseal-desktop.exe');
  const serverExecutable = path.join(root, 'liteseal-server.exe');
  await copyFile(path.resolve('target/debug/liteseal-desktop.exe'), desktopExecutable); await copyFile(checked.binary, serverExecutable);
  const invite = randomUUID();
  server = spawn(serverExecutable, [], { windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'], env: { ...process.env, DATABASE_URL: process.env.LITESEAL_TEST_DATABASE_URL, LITESEAL_BIND: '127.0.0.1:0', RUST_LOG: 'liteseal_server=info', LITESEAL_CORS_ALLOW_ORIGIN: 'http://localhost:5173', LITESEAL_INVITE_CODES: invite } });
  let output = ''; let serverError = false; server.on('error', () => { serverError = true; });
  server.stdout.on('data', bytes => { if (upstream) return; output = (output + bytes.toString()).slice(-4096); const match = /Server listening on (127\.0\.0\.1:\d+)/.exec(output); if (match) { upstream = 'http://' + match[1]; output = ''; } });
  report.stage = 'server readiness';
  let ready = false;
  for (let attempt = 0; attempt < 300 && !serverError && server.exitCode === null; attempt++) { try { ready = !!upstream && (await fetch(upstream + '/readyz', { signal: AbortSignal.timeout(500) })).ok; } catch {} if (ready) break; await pause(100); }
  assert.ok(ready);
  proxy = createServer(async (req, res) => {
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk); const body = Buffer.concat(chunks);
      if (req.headers.authorization === offlineToken) { res.writeHead(503); res.end(); return; }
      const response = await fetch(upstream + req.url, { method: req.method, headers: { 'content-type': 'application/json', ...(req.headers.authorization ? { authorization: req.headers.authorization } : {}) }, body: body.length ? body : undefined, signal: AbortSignal.timeout(15000) });
      const data = Buffer.from(await response.arrayBuffer());
      if (loseResponse && req.method === 'POST' && req.url.endsWith('/messages') && response.ok) { loseResponse = false; res.writeHead(503); res.end(); return; }
      if (loseExtensionResponse && req.method === 'POST' && req.url.endsWith('/extensions') && response.ok) { loseExtensionResponse = false; res.writeHead(503); res.end(); return; }
      res.writeHead(response.status, { 'content-type': 'application/json' }); res.end(data);
    } catch { res.writeHead(502); res.end(); }
  });
  await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve)); origin = `http://127.0.0.1:${proxy.address().port}`;
  report.stage = 'ten isolated accounts';
  for (let n = 0; n < 10; n++) {
    const person = { name: 'member-' + n }; await start(person);
    person.identity = await person.bridge.call('prepare_identity', {});
    const response = await fetch(origin + '/auth/register', { signal: AbortSignal.timeout(15000), method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ invite_code: invite, username: 'soak-' + randomUUID(), password: randomUUID(), device_name: person.name, ...person.identity }) });
    assert.equal(response.status, 200); const auth = await response.json(); Object.assign(person, { id: auth.user_id, device: auth.device_id, token: auth.token, refresh: auth.refresh_token }); await save(person); people.push(person);
  }
  for (const owner of people) for (const peer of people) if (owner !== peer) { await owner.bridge.call('add_contact', { userId: peer.id, username: peer.name, publicKey: peer.identity.public_key, ed25519Pk: peer.identity.ed25519_pk }); await owner.bridge.call('set_contact_trust', { userId: peer.id, trustState: 'verified' }); }
  report.stage = 'ten groups and hundred memberships';
  const groups = [];
  for (const owner of people) { const groupId = await owner.bridge.call('create_group', { name: 'synthetic soak group' }); groups.push({ id: groupId, owner }); for (const person of people) if (person !== owner) await inviteAndAccept(owner, person, groupId); }
  for (const person of people) { const all = await person.bridge.call('get_groups', { refresh: true }); assert.equal(all.groups.length, 10); for (const group of groups) await person.bridge.call('sync_group', { groupId: group.id }); }
  const mediaPath=path.join(root,'soak-file.txt');const fileBody=Buffer.from('isolated group media 中文 🎉'.repeat(200));await writeFile(mediaPath,fileBody);
  const voicePath=path.join(root,'voice.webm');const voiceEnv={...process.env};delete voiceEnv.ELECTRON_RUN_AS_NODE;assert.equal(execute(createRequire(import.meta.url)('electron'),['scripts/generate-test-voice.cjs',voicePath],voiceEnv).code,0);const voiceBody=await readFile(voicePath);
  report.status = 'running'; report.stage = 'message fault and memory cycles'; const began = performance.now(); let lastRefresh = began; report.started = new Date().toISOString(); await persist();
  let iteration = 0;
  while (!stop && (smoke ? iteration < 6 : performance.now() - began < 86400000)) {
    const cycle = performance.now(); iteration++;
    if (smoke && iteration === 2 || cycle - lastRefresh >= 20 * 60 * 1000) {
      for (const person of people) { const auth = await person.bridge.call('refresh_session', { serverUrl: origin, refreshToken: person.refresh }); person.token = auth.token; person.refresh = auth.refresh_token; await save(person); }
      lastRefresh = performance.now(); report.faults.push({ iteration, kind: 'access token renewal without identity replacement' });
    }
    const disconnected = people[iteration % people.length]; offlineToken = iteration % 3 === 0 ? `Bearer ${disconnected.token}` : null;
    if (offlineToken) report.faults.push({ iteration, kind: 'temporary request outage' });
    const expected = [];
    for (const [index, group] of groups.entries()) {
      const sender = people[(iteration + index) % people.length]; if (offlineToken === `Bearer ${sender.token}`) continue;
      const lose = iteration % 4 === 0 && index === 0; loseResponse = lose;
      const sent = await sender.bridge.call('send_group_text', { groupId: group.id, text: 'synthetic soak message' });
      if (lose) { const retried = await sender.bridge.call('send_group_text', { groupId: group.id }); assert.equal(retried.state, 'accepted'); expected.push({ group, id: retried.message_id }); report.faults.push({ iteration, kind: 'lost accepted send response, original batch retry' }); }
      else { assert.equal(sent.state, 'accepted'); expected.push({ group, id: sent.message_id }); }
    }
    offlineToken = null;
    if (iteration % 3 === 0) { await disconnected.bridge.stop(); await start(disconnected); await save(disconnected); report.faults.push({ iteration, kind: 'client process restart and offline catchup' }); }
    report.stage='group attachment, voice and activity cycle';
    const extensionGroup=groups[(iteration-1)%groups.length],extensionOwner=extensionGroup.owner,extensionReceiver=people[(iteration+1)%people.length];
    const voiceCycle=iteration%2===0;
    let media=voiceCycle?await extensionOwner.bridge.call('stage_group_recorded_audio',{groupId:extensionGroup.id,encoded:voiceBody.toString('base64'),durationMs:1000}):await extensionOwner.bridge.call('select_group_attachment',{groupId:extensionGroup.id,path:mediaPath});
    while(media.offset<media.total)media=await extensionOwner.bridge.call('group_attachment_step',{groupId:extensionGroup.id,id:media.id});
    let originalRoot;
    if(iteration%4===0){loseExtensionResponse=true;await assert.rejects(extensionOwner.bridge.call('publish_group_attachment',{groupId:extensionGroup.id,id:media.id}));originalRoot=(await extensionOwner.bridge.call('get_group_extensions',{groupId:extensionGroup.id,messageIds:[]})).pending_root;await extensionOwner.bridge.stop();await start(extensionOwner);await save(extensionOwner);report.faults.push({iteration,kind:'lost accepted group extension response and restart of original media task'});}
    const mediaRoot=await extensionOwner.bridge.call('publish_group_attachment',{groupId:extensionGroup.id,id:media.id});if(originalRoot)assert.equal(mediaRoot,originalRoot);expected.push({group:extensionGroup,id:mediaRoot});
    await extensionReceiver.bridge.call('sync_group',{groupId:extensionGroup.id});await extensionReceiver.bridge.call('sync_group_extensions',{groupId:extensionGroup.id});let downloading=await extensionReceiver.bridge.call('begin_group_attachment_download',{groupId:extensionGroup.id,messageId:mediaRoot});while(downloading.offset<downloading.total)downloading=await extensionReceiver.bridge.call('group_attachment_step',{groupId:extensionGroup.id,id:downloading.id});const verifiedPath=path.join(root,'verified-media-'+iteration);await extensionReceiver.bridge.call('export_group_attachment',{groupId:extensionGroup.id,id:media.id,path:verifiedPath});assert.deepEqual(await readFile(verifiedPath),voiceCycle?voiceBody:fileBody);await rm(verifiedPath);
    await extensionOwner.bridge.call('submit_group_extension',{groupId:extensionGroup.id,command:{kind:'activity',title:'soak activity '+iteration,start_at:Date.now()+3600000,timezone:'UTC',location:'',description:'isolated synthetic activity'}});await extensionReceiver.bridge.call('sync_group',{groupId:extensionGroup.id});await extensionReceiver.bridge.call('sync_group_extensions',{groupId:extensionGroup.id});const recent=(await extensionReceiver.bridge.call('get_group_history',{groupId:extensionGroup.id})).messages;let activity=(await extensionReceiver.bridge.call('get_group_extensions',{groupId:extensionGroup.id,messageIds:recent.map(m=>m.id)})).activities.find(a=>a.title==='soak activity '+iteration);assert.ok(activity);expected.push({group:extensionGroup,id:activity.id});await extensionReceiver.bridge.call('submit_group_extension',{groupId:extensionGroup.id,command:{kind:'respond',activity:activity.id,answer:'maybe',revision:activity.revision}});await extensionOwner.bridge.call('sync_group_extensions',{groupId:extensionGroup.id});activity=(await extensionOwner.bridge.call('get_group_extensions',{groupId:extensionGroup.id,messageIds:[activity.id]})).activities[0];assert.equal(activity.responses[extensionReceiver.id],'maybe');await extensionOwner.bridge.call('submit_group_extension',{groupId:extensionGroup.id,command:{kind:iteration%2===0?'cancel':'close',activity:activity.id,revision:activity.revision}});
    report.stage='message fault and memory cycles';
    for (const person of people) {
      // Exercise the actual background scheduler (at most three groups/round).
      for (let turn = 0; turn < 4; turn++) await person.bridge.call('process_groups', {});
      for (const item of expected) { const history = await person.bridge.call('get_group_history', { groupId: item.group.id }); assert.equal(history.messages.filter(m => m.id === item.id).length, 1); }
    }
    if (iteration % 5 === 0) {
      const group = extensionGroup, person = extensionReceiver;
      await group.owner.bridge.call('change_group_membership', { groupId: group.id, action: 'remove', value: person.id });
      const excluded = await group.owner.bridge.call('send_group_text', { groupId: group.id, text: 'unauthorized rejoin interval' }); assert.equal(excluded.state, 'accepted');
      await inviteAndAccept(group.owner, person, group.id); await person.bridge.call('sync_group', { groupId: group.id });
      assert.ok(!(await person.bridge.call('get_group_history', { groupId: group.id })).messages.some(m => m.id === excluded.message_id)); report.faults.push({ iteration, kind: 'remove/rejoin keeps excluded history unavailable' });
      const oldDownload=await fetch(`${origin}/groups/${group.id}/attachments/${media.id}/0?device_id=${encodeURIComponent(person.device)}`,{headers:{authorization:`Bearer ${person.token}`},signal:AbortSignal.timeout(15000)});assert.equal(oldDownload.status,404);report.faults.push({iteration,kind:'rejoin denies original group attachment remote download'});
    }
    let pendingTasks = 0;
    for (const person of people) for (const group of groups) pendingTasks += (await person.bridge.call('get_group_storage_stats', { groupId: group.id })).pending_tasks;
    assert.equal(pendingTasks, 0);
    report.samples.push({ iteration, elapsed_seconds: Math.round((performance.now() - began) / 1000), catchup_ms: Math.round(performance.now() - cycle), pending_tasks: pendingTasks, processes: memory() });
    await persist(); if (!smoke) { for (let n = 0; n < 60 && !stop; n++) await pause(1000); } else await pause(500);
  }
  report.actual_seconds = Math.round((performance.now() - began) / 1000); report.status = stop ? 'interrupted' : 'passed'; report.stage = 'finished';
} catch { if (report.stage !== 'preflight') report.status = 'failed'; report.reason = 'failed at ' + report.stage + '; raw errors suppressed'; }
finally {
  offlineToken = null; for (const bridge of bridges) await bridge.stop().catch(() => {});
  if (proxy?.listening) { proxy.closeAllConnections(); await new Promise(resolve => proxy.close(resolve)); }
  await stopTree(server);
  if (root && path.dirname(root) === path.resolve(os.tmpdir()) && path.basename(root).startsWith('liteseal-soak-')) await rm(root, { recursive: true, force: true });
  await persist(); console.log(JSON.stringify({ status: report.status, mode: report.mode, iterations: report.samples.length, evidence, reason: report.reason })); process.exitCode = report.status === 'passed' ? 0 : 2;
}
