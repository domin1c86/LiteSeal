import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, rm, mkdir, writeFile, readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { preflight, execute } from './test-database.mjs';
import { stopTree } from './process.mjs';

const report = { at: new Date().toISOString(), status: 'not_executed', stages: [], scope: 'same-host real PostgreSQL/server/three Rust desktops; proxy injects ACK loss and replay' };
const commit = execute('git', ['rev-parse', 'HEAD']);
report.commit = /^[a-f0-9]{40}$/.test(commit.output.trim()) ? commit.output.trim() : 'unknown';
let root, server, proxy;
const bridges = [];
let stage = 'preflight';
const listen = server => new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
const close = server => new Promise(resolve => { if (!server?.listening) return resolve(); server.closeAllConnections(); server.close(resolve); });
try {
  if (process.platform !== 'win32') throw new Error('Windows DPAPI required');
  const checked = preflight();
  if (!checked.ok) throw new Error(checked.reason);
  report.server_version_num = checked.server_version_num;
  stage = 'build';
  assert.equal(execute('cargo', ['build', '--locked', '-p', 'liteseal-desktop']).code, 0);
  // Build bridge without shell interpolation or reliance on an earlier npm build.
  assert.equal(execute(process.execPath, ['scripts/build-electron.mjs']).code, 0);
  const { DesktopBridge } = createRequire(import.meta.url)('../dist-electron/bridge.cjs');
  root = await mkdtemp(path.join(os.tmpdir(), 'liteseal-real-groups-'));
  let upstream;
  const code = randomUUID();
  server = spawn(checked.binary, [], { windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'], env: { ...process.env, DATABASE_URL: process.env.LITESEAL_TEST_DATABASE_URL, LITESEAL_BIND: '127.0.0.1:0', RUST_LOG: 'liteseal_server=info', LITESEAL_CORS_ALLOW_ORIGIN: 'http://localhost:5173', LITESEAL_INVITE_CODES: code } });
  let serverError = false, startupOutput = '';
  server.on('error', error => { serverError = true; report.server_spawn_code = typeof error.code === 'string' ? error.code : 'unknown'; });
  server.stdout.on('data', chunk => {
    if (upstream) return;
    startupOutput = (startupOutput + chunk.toString('utf8')).slice(-4096);
    const address = /Server listening on (127\.0\.0\.1:\d+)/.exec(startupOutput);
    if (address) { upstream = 'http://' + address[1]; startupOutput = ''; }
  });
  stage = 'server readiness';
  let ready = false;
  for (let attempt = 0; attempt < 300; attempt++) {
    if (serverError || server.exitCode !== null) break;
    try { ready = !!upstream && (await fetch(`${upstream}/readyz`, { signal: AbortSignal.timeout(500) })).ok; } catch {}
    if (ready) break;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.ok(ready && server.exitCode === null && !serverError);
  let dropAckFor, replayFor, replayEnvelope, captured, loseCollaborationResponse = false, loseExtensionResponse = false, offlineRequests = 0;
  proxy = createServer(async (req, res) => {
    offlineRequests++;
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      if (req.url.endsWith('/messages/ack') && req.headers.authorization === dropAckFor) { res.writeHead(503); res.end(); return; }
      if (req.method === 'GET' && /\/messages(?:\?|$)/.test(req.url) && req.headers.authorization === replayFor && replayEnvelope) {
        const envelope = replayEnvelope; replayEnvelope = undefined;
        res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ envelopes: [envelope], has_more: false })); return;
      }
      const response = await fetch(upstream + req.url, { method: req.method, headers: { 'content-type': 'application/json', ...(req.headers.authorization ? { authorization: req.headers.authorization } : {}) }, body: body.length ? body : undefined, signal: AbortSignal.timeout(15000) });
      const data = Buffer.from(await response.arrayBuffer());
      if (req.method === 'GET' && /\/messages(?:\?|$)/.test(req.url) && response.ok && req.headers.authorization === dropAckFor) captured = JSON.parse(data).envelopes[0] ?? captured;
      if (loseCollaborationResponse && req.method === 'POST' && req.url.endsWith('/collaboration') && response.ok) { loseCollaborationResponse = false; res.writeHead(503); res.end(); return; }
      if (loseExtensionResponse && req.method === 'POST' && req.url.endsWith('/extensions') && response.ok) { loseExtensionResponse = false; res.writeHead(503); res.end(); return; }
      res.writeHead(response.status, { 'content-type': 'application/json' }); res.end(data);
    } catch { res.writeHead(502); res.end(); }
  });
  await listen(proxy); const origin = `http://127.0.0.1:${proxy.address().port}`;
  const start = async person => {
    const bridge = new DesktopBridge(30000); bridges.push(bridge);
    await bridge.start(path.resolve('target/debug/liteseal-desktop.exe'), ['--db-path', path.join(root, person.name + '.db'), '--keystore-path', path.join(root, person.name + '.bin')]);
    person.bridge = bridge;
    return bridge;
  };
  const save = person => person.bridge.call('save_session', { userId: person.id, deviceId: person.device, token: person.token, refreshToken: person.refresh, serverUrl: origin });
  const account = async name => {
    const person = { name }; await start(person);
    person.identity = await person.bridge.call('prepare_identity', {});
    const response = await fetch(origin + '/auth/register', { signal: AbortSignal.timeout(15000), method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ invite_code: code, username: `trial-${randomUUID()}`, password: randomUUID(), device_name: name, ...person.identity }) });
    assert.equal(response.status, 200);
    const auth = await response.json(); Object.assign(person, { id: auth.user_id, device: auth.device_id, token: auth.token, refresh: auth.refresh_token }); await save(person); return person;
  };
  stage = 'three accounts and verified contacts';
  const alice = await account('alice'), bob = await account('bob'), carol = await account('carol');
  for (const owner of [alice, bob, carol]) for (const peer of [alice, bob, carol]) if (owner !== peer) {
    await owner.bridge.call('add_contact', { userId: peer.id, username: peer.name, publicKey: peer.identity.public_key, ed25519Pk: peer.identity.ed25519_pk });
    await owner.bridge.call('set_contact_trust', { userId: peer.id, trustState: 'verified' });
  }
  const groupId = await alice.bridge.call('create_group', { name: 'real isolated group' });
  const invite = async person => {
    const peer = await alice.bridge.call('inspect_group_peer', { peerId: person.id });
    await alice.bridge.call('invite_group_member', { groupId, peerId: person.id, confirmedFingerprint: peer.fingerprint });
  };
  const accept = async person => {
    const snapshot = await person.bridge.call('get_groups', { refresh: true });
    const invitation = snapshot.invitations.find(item => item.group_id === groupId); assert.ok(invitation);
    const detail = await person.bridge.call('inspect_group', { groupId, inviteId: invitation.id });
    await person.bridge.call('accept_group_invite', { inviteId: invitation.id, confirmedFingerprint: detail.fingerprint });
    await alice.bridge.call('sync_group', { groupId });
  };
  stage = 'sent invitation revocation and acceptance';
  await invite(bob);
  const issued = await alice.bridge.call('get_sent_group_invites', { groupId });
  await alice.bridge.call('revoke_group_invite', { inviteId: issued.invites[0].id });
  assert.equal((await alice.bridge.call('get_sent_group_invites', { groupId })).invites[0].status, 'revoked');
  await invite(bob); await accept(bob); await invite(carol); await accept(carol);
  await assert.rejects(bob.bridge.call('get_sent_group_invites', { groupId }));
  report.stages.push(stage);
  const history = async person => (await person.bridge.call('get_group_history', { groupId })).messages;
  const send = async (person, text) => { const result = await person.bridge.call('send_group_text', { groupId, text }); assert.equal(result.state, 'accepted'); };
  stage = 'offline receive, lost ACK, restart and deduplication';
  await bob.bridge.stop(); await send(alice, 'first synthetic message');
  await carol.bridge.call('sync_group', { groupId }); assert.equal((await history(carol)).length, 1);
  await start(bob); await save(bob); dropAckFor = `Bearer ${bob.token}`;
  // Local persistence must survive a failed ACK; sync may report the transport failure.
  await bob.bridge.call('sync_group', { groupId }).catch(() => {});
  assert.equal((await history(bob)).length, 1); assert.ok(captured);
  await bob.bridge.stop(); await start(bob); await save(bob); dropAckFor = undefined;
  await bob.bridge.call('sync_group', { groupId }); assert.equal((await history(bob)).length, 1);
  const pending = await fetch(`${upstream}/groups/${groupId}/messages?device_id=${encodeURIComponent(bob.device)}`, { signal: AbortSignal.timeout(15000), headers: { authorization: `Bearer ${bob.token}` } });
  assert.equal(pending.status, 200); assert.equal((await pending.json()).envelopes.length, 0);
  report.stages.push(stage);
  stage = 'mute, hidden history, replay and preserved draft across restart';
  await bob.bridge.call('set_group_muted', { groupId, muted: true });
  await bob.bridge.call('group_draft', { groupId, text: 'retained draft' });
  assert.equal(await bob.bridge.call('clear_group_history', { groupId }), 1);
  replayFor = `Bearer ${bob.token}`; replayEnvelope = captured;
  await bob.bridge.call('sync_group', { groupId }); assert.equal((await history(bob)).length, 0);
  await bob.bridge.stop(); await start(bob); await save(bob);
  assert.equal((await bob.bridge.call('get_groups', {})).groups[0].muted, true);
  assert.equal(await bob.bridge.call('group_draft', { groupId }), 'retained draft');
  assert.equal((await bob.bridge.call('get_group_storage_stats', { groupId })).hidden_messages, 1);
  await send(carol, 'new after hide'); await alice.bridge.call('sync_group', { groupId }); await bob.bridge.call('sync_group', { groupId });
  assert.deepEqual((await history(bob)).map(item => item.text), ['new after hide']);
  await send(bob, 'reply from bob'); await alice.bridge.call('sync_group', { groupId }); await carol.bridge.call('sync_group', { groupId });
  assert.ok((await history(alice)).some(item => item.text === 'reply from bob'));
  report.stages.push(stage);
  stage = 'removal and fresh rejoin isolate unavailable history';
  await alice.bridge.call('change_group_membership', { groupId, action: 'remove', value: bob.id });
  await send(alice, 'not authorized for bob'); await carol.bridge.call('sync_group', { groupId });
  await assert.rejects(bob.bridge.call('send_group_text', { groupId, text: 'removed attempt' }));
  await invite(bob); await accept(bob); await carol.bridge.call('sync_group', { groupId });
  assert.ok(!(await history(bob)).some(item => item.text === 'not authorized for bob'));
  await send(alice, 'after rejoin'); await bob.bridge.call('sync_group', { groupId });
  assert.ok((await history(bob)).some(item => item.text === 'after rejoin'));
  report.stages.push(stage);
  stage = 'collaboration mentions and encrypted retry across restart';
  const syncCollab = async person => { assert.equal(await person.bridge.call('sync_group_collaboration', { groupId }), true); return person.bridge.call('get_group_collaboration', { groupId }); };
  const submit = (person, command) => person.bridge.call('submit_group_collaboration', { groupId, command });
  for (const person of [alice,bob,carol]) await syncCollab(person);
  const bobMember = (await alice.bridge.call('get_groups', {})).groups[0].members.find(m => m.user_id === bob.id);
  loseCollaborationResponse = true;
  await assert.rejects(submit(alice, { kind:'mention', text:'synthetic @member', mentions:[{user:bob.id,device:bob.device,joined:bobMember.joined_epoch}] }));
  assert.equal((await alice.bridge.call('get_group_collaboration',{groupId})).pending,true);
  await alice.bridge.stop(); await start(alice); await save(alice);
  await alice.bridge.call('retry_group_collaboration',{groupId});
  await syncCollab(bob); await syncCollab(carol);
  assert.equal((await history(bob)).filter(m=>m.text==='synthetic @member').length,1);
  assert.equal((await alice.bridge.call('get_group_collaboration',{groupId})).pending,false);
  report.stages.push(stage);
  stage = 'pin permissions and original recipient incarnation';
  const oldMessage = (await history(alice)).find(m=>m.text==='first synthetic message'); assert.ok(oldMessage);
  await submit(alice,{kind:'pin',message:oldMessage.id,revision:0});
  assert.equal((await syncCollab(carol)).pin,oldMessage.id);
  const bobPin=await syncCollab(bob); assert.equal(bobPin.pin,null); assert.equal(bobPin.pin_unavailable,true);
  await assert.rejects(submit(bob,{kind:'pin',message:null,revision:1}));
  await submit(alice,{kind:'pin',message:null,revision:1}); assert.equal((await syncCollab(carol)).pin,null);
  report.stages.push(stage);
  stage = 'named polls replace votes and reject edits after closing';
  await submit(carol,{kind:'poll',question:'Synthetic poll question',options:['First','Second']});
  let poll=(await syncCollab(bob)).polls[0]; assert.equal(poll.question,'Synthetic poll question');
  await submit(bob,{kind:'vote',poll:poll.id,option:poll.options[0].id,revision:poll.revision});
  poll=(await syncCollab(bob)).polls[0];
  await submit(bob,{kind:'vote',poll:poll.id,option:poll.options[1].id,revision:poll.revision});
  poll=(await syncCollab(alice)).polls[0];assert.equal(Object.keys(poll.votes).length,1);assert.equal(poll.votes[bob.id],poll.options[1].id);
  await submit(alice,{kind:'close',poll:poll.id,revision:poll.revision});poll=(await syncCollab(bob)).polls[0];assert.equal(poll.closed,true);
  await assert.rejects(submit(bob,{kind:'vote',poll:poll.id,option:poll.options[0].id,revision:poll.revision}));
  await submit(carol,{kind:'poll',question:'Incarnation poll',options:['Yes','No']}); await syncCollab(bob);
  await alice.bridge.call('change_group_membership',{groupId,action:'remove',value:bob.id}); await invite(bob); await accept(bob);
  const oldPoll=(await syncCollab(bob)).polls.find(p=>p.question==='Incarnation poll'); assert.ok(oldPoll);assert.equal(oldPoll.eligible,false);
  await assert.rejects(submit(bob,{kind:'vote',poll:oldPoll.id,option:oldPoll.options[0].id,revision:oldPoll.revision}));
  await bob.bridge.call('clear_group_history',{groupId}); assert.equal((await bob.bridge.call('get_group_collaboration',{groupId})).polls.length,0);
  await bob.bridge.stop();await start(bob);await save(bob);await syncCollab(bob);assert.equal((await bob.bridge.call('get_group_collaboration',{groupId})).polls.length,0);
  report.stages.push(stage);
  stage = 'group attachment upload, lost publication response, restart and authenticated download';
  const fileBody = Buffer.from('isolated group file 中文 🎉\n'.repeat(50000));
  const inputPath = path.join(root,'isolated-file.txt'); await writeFile(inputPath,fileBody);
  let task=await carol.bridge.call('select_group_attachment',{groupId,path:inputPath}); const attachmentBlob=task.id;
  assert.ok(!('key' in task));
  task=await carol.bridge.call('group_attachment_step',{groupId,id:task.id});
  await carol.bridge.stop(); await start(carol); await save(carol);
  task=(await carol.bridge.call('group_attachment_tasks',{groupId})).find(t=>t.id===attachmentBlob);assert.ok(task.offset>0);
  while(task.offset<task.total)task=await carol.bridge.call('group_attachment_step',{groupId,id:task.id});
  loseExtensionResponse=true; await assert.rejects(carol.bridge.call('publish_group_attachment',{groupId,id:task.id}));
  const beforeRetry=(await carol.bridge.call('get_group_extensions',{groupId,messageIds:[]})).pending_root;assert.ok(beforeRetry);
  await carol.bridge.stop(); await start(carol); await save(carol);
  const attachmentRoot=await carol.bridge.call('publish_group_attachment',{groupId,id:task.id});assert.equal(attachmentRoot,beforeRetry);
  assert.equal((await carol.bridge.call('group_attachment_tasks',{groupId})).length,0);
  const syncExtensions=async person=>{await person.bridge.call('sync_group',{groupId});assert.equal(await person.bridge.call('sync_group_extensions',{groupId}),true);const ids=(await history(person)).map(m=>m.id);return person.bridge.call('get_group_extensions',{groupId,messageIds:ids});};
  for(const person of [alice,bob]) {const view=await syncExtensions(person);assert.equal(view.attachments.find(f=>f.id===attachmentRoot).name,'isolated-file.txt');assert.equal((await history(person)).filter(m=>m.id===attachmentRoot).length,1);}
  let downloaded=await bob.bridge.call('begin_group_attachment_download',{groupId,messageId:attachmentRoot});
  while(downloaded.offset<downloaded.total)downloaded=await bob.bridge.call('group_attachment_step',{groupId,id:downloaded.id});
  const downloadedPath=path.join(root,'downloaded.txt');await bob.bridge.call('export_group_attachment',{groupId,id:downloaded.id,path:downloadedPath});assert.deepEqual(await readFile(downloadedPath),fileBody);
  const cancelled=await alice.bridge.call('select_group_attachment',{groupId,path:inputPath});await alice.bridge.call('cancel_group_attachment',{groupId,id:cancelled.id});assert.equal((await alice.bridge.call('group_attachment_tasks',{groupId})).length,0);
  report.stages.push(stage);
  stage='activity RSVP replacement, manual close and cancel, departure and rejoin isolation';
  const fixturePath=path.join(root,'voice.webm');const fixtureEnv={...process.env};delete fixtureEnv.ELECTRON_RUN_AS_NODE;
  assert.equal(execute(createRequire(import.meta.url)('electron'),['scripts/generate-test-voice.cjs',fixturePath],fixtureEnv).code,0);
  const voice=await readFile(fixturePath);let voiceTask=await alice.bridge.call('stage_group_recorded_audio',{groupId,encoded:voice.toString('base64'),durationMs:1000});while(voiceTask.offset<voiceTask.total)voiceTask=await alice.bridge.call('group_attachment_step',{groupId,id:voiceTask.id});const voiceRoot=await alice.bridge.call('publish_group_attachment',{groupId,id:voiceTask.id});
  const voiceView=(await syncExtensions(carol)).attachments.find(f=>f.id===voiceRoot);assert.equal(voiceView.duration_ms,1000);assert.equal(voiceView.mime,'audio/webm');let voiceDownload=await carol.bridge.call('begin_group_attachment_download',{groupId,messageId:voiceRoot});while(voiceDownload.offset<voiceDownload.total)voiceDownload=await carol.bridge.call('group_attachment_step',{groupId,id:voiceDownload.id});const voiceCopy=path.join(root,'voice-downloaded.webm');await carol.bridge.call('export_group_attachment',{groupId,id:voiceDownload.id,path:voiceCopy});assert.deepEqual(await readFile(voiceCopy),voice);
  await assert.rejects(alice.bridge.call('stage_group_recorded_audio',{groupId,encoded:voice.toString('base64'),durationMs:60001}));
  report.stages.push('synthetic WebM/Opus generation, codec decode and encrypted group voice roundtrip');
  const extensionSubmit=(person,command)=>person.bridge.call('submit_group_extension',{groupId,command});
  await extensionSubmit(carol,{kind:'activity',title:'活动 中文 🎉',start_at:Date.now()-1000,timezone:'Asia/Singapore',location:'meeting room',description:'immutable details'});
  let activity=(await syncExtensions(bob)).activities[0];assert.equal(activity.title,'活动 中文 🎉');assert.equal(Object.keys(activity.responses).length,0);
  await extensionSubmit(bob,{kind:'respond',activity:activity.id,answer:'maybe',revision:activity.revision});activity=(await syncExtensions(bob)).activities[0];
  await extensionSubmit(bob,{kind:'respond',activity:activity.id,answer:'yes',revision:activity.revision});activity=(await syncExtensions(alice)).activities[0];assert.equal(Object.keys(activity.responses).length,1);assert.equal(activity.responses[bob.id],'yes');
  await assert.rejects(extensionSubmit(bob,{kind:'close',activity:activity.id,revision:activity.revision}));
  await extensionSubmit(alice,{kind:'close',activity:activity.id,revision:activity.revision});activity=(await syncExtensions(carol)).activities[0];assert.ok(activity.closed&&!activity.cancelled);
  await assert.rejects(extensionSubmit(bob,{kind:'respond',activity:activity.id,answer:'no',revision:activity.revision}));
  await extensionSubmit(carol,{kind:'cancel',activity:activity.id,revision:activity.revision});activity=(await syncExtensions(bob)).activities[0];assert.ok(activity.closed&&activity.cancelled);
  await alice.bridge.call('change_group_membership',{groupId,action:'remove',value:bob.id});await invite(bob);await accept(bob);await syncExtensions(bob);
  const oldActivity=(await syncExtensions(bob)).activities.find(a=>a.id===activity.id);assert.ok(oldActivity&&!oldActivity.eligible&&oldActivity.departed.includes(bob.id));
  const remote=await fetch(`${upstream}/groups/${groupId}/attachments/${attachmentBlob}/0?device_id=${encodeURIComponent(bob.device)}`,{headers:{authorization:`Bearer ${bob.token}`}});assert.equal(remote.status,404);
  const retainedPath=path.join(root,'retained-after-rejoin.txt');await bob.bridge.call('export_group_attachment',{groupId,id:attachmentBlob,path:retainedPath});assert.deepEqual(await readFile(retainedPath),fileBody);
  await bob.bridge.call('clear_group_history',{groupId});await syncExtensions(bob);assert.equal((await bob.bridge.call('get_group_extensions',{groupId,messageIds:[activity.id,attachmentRoot]})).activities.length,0);
  report.stages.push(stage);
  stage = 'T22 v2 offline archive preserves activities, group cache, polls, drafts and hidden history';
  const waitBackup = async (bridge, id) => {
    for (let attempt = 0; attempt < 600; attempt++) {
      const job = await bridge.call('get_backup_job', { id });
      if (job.state !== 'running') { assert.equal(job.state, 'completed'); return job; }
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw new Error('archive task timeout');
  };
  const secret = randomUUID();
  for (const person of [carol, bob]) {
    const file = path.join(root, person.name + '.lseal');
    const exported = await person.bridge.call('start_backup_export', { path: file, password: secret, includeAttachments: person===carol });
    await waitBackup(person.bridge, exported);
    if(person===carol&&process.env.LITESEAL_TEST_LEGACY_READER){
      const old=new DesktopBridge();bridges.push(old);await old.start(process.env.LITESEAL_TEST_LEGACY_READER,['--db-path',path.join(root,'legacy-reader.db'),'--keystore-path',path.join(root,'legacy-reader.bin')]);
      const immutable=await readFile(file);const job=await old.call('start_backup_restore',{path:file,parent:root,password:secret});let result;
      for(let i=0;i<600;i++){result=await old.call('get_backup_job',{id:job});if(result.state!=='running')break;await new Promise(resolve=>setTimeout(resolve,50));}
      assert.equal(result.state,'failed');assert.match(result.error,/版本/);assert.deepEqual(await readFile(file),immutable);report.stages.push('legacy T22 reader explicitly rejects authenticated payload v2');await old.stop();
    }
    const viewer = new DesktopBridge(); bridges.push(viewer);
    await viewer.start(path.resolve('target/debug/liteseal-desktop.exe'), ['--db-path', path.join(root, person.name + '-offline.db'), '--keystore-path', path.join(root, person.name + '-offline.bin')]);
    const restored = await viewer.call('start_backup_restore', { path: file, parent: root, password: secret });
    const requestsBefore=offlineRequests;
    await waitBackup(viewer, restored);
    const info = await viewer.call('open_backup_archive', { id: restored });
    assert.equal(info.user_id, person.id); assert.ok(!('token' in info) && !('secret_key' in info));
    const page = await viewer.call('get_backup_history', { id: restored, kind: 'group', conversationId: groupId });
    if (person === carol) {
      assert.ok(page.messages.some(m => m.text === 'synthetic @member'));
      assert.ok(page.collaboration.polls.some(p => p.question === 'Synthetic poll question' && p.closed));
      assert.ok(page.extensions.activities.some(a=>a.title==='活动 中文 🎉'&&a.cancelled&&a.closed));
      const offlineFile=path.join(root,'archive-group-file.txt');await viewer.call('export_backup_attachment',{id:restored,messageId:attachmentRoot,groupId,path:offlineFile});assert.deepEqual(await readFile(offlineFile),fileBody);
    } else { assert.equal(page.messages.length, 0); assert.equal(page.collaboration.polls.length, 0); }
    await viewer.call('close_backup_archive', {});
    assert.equal(offlineRequests,requestsBefore);
    await assert.rejects(viewer.call('get_backup_archive_info', { id: restored }));
    await viewer.stop();
  }
  report.stages.push(stage); report.status = 'passed';
} catch {
  if (stage === 'server readiness') { report.server_exit_code = server?.exitCode; report.server_signal = server?.signalCode; }
  report.reason = stage === 'preflight' ? 'Windows and marked dedicated test database required; see database runner report' : `failed at ${stage}; raw errors suppressed`;
  if (stage !== 'preflight') report.status = 'failed';
} finally {
  for (const bridge of bridges) await bridge.stop().catch(() => {});
  await close(proxy); await stopTree(server);
  if (root && path.dirname(root) === path.resolve(os.tmpdir()) && path.basename(root).startsWith('liteseal-real-groups-')) await rm(root, { recursive: true, force: true });
  await mkdir('target/test-results', { recursive: true });
  const evidence = JSON.stringify(report, null, 2) + '\n';
  await writeFile('target/test-results/group-integration.json', evidence);
  await writeFile('target/test-results/group-integration-' + report.at.replace(/[:.]/g, '-') + '.json', evidence);
  console.log(JSON.stringify(report, null, 2)); process.exitCode = report.status === 'passed' ? 0 : 2;
}
