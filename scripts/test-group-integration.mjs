import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
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
  const reservation = createServer(); await listen(reservation);
  const port = reservation.address().port; await close(reservation);
  const upstream = `http://127.0.0.1:${port}`;
  const code = randomUUID();
  server = spawn(checked.binary, [], { windowsHide: true, stdio: 'ignore', env: { ...process.env, DATABASE_URL: process.env.LITESEAL_TEST_DATABASE_URL, LITESEAL_BIND: `127.0.0.1:${port}`, LITESEAL_CORS_ALLOW_ORIGIN: 'http://localhost:5173', LITESEAL_INVITE_CODES: code } });
  let serverError = false; server.on('error', () => { serverError = true; });
  stage = 'server readiness';
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    if (serverError || server.exitCode !== null) break;
    try { ready = (await fetch(`${upstream}/readyz`, { signal: AbortSignal.timeout(500) })).ok; } catch {}
    if (ready) break;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.ok(ready && server.exitCode === null && !serverError);
  let dropAckFor, replayFor, replayEnvelope, captured;
  proxy = createServer(async (req, res) => {
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
  report.stages.push(stage); report.status = 'passed';
} catch {
  report.reason = stage === 'preflight' ? 'Windows and marked dedicated test database required; see database runner report' : `failed at ${stage}; raw errors suppressed`;
  if (stage !== 'preflight') report.status = 'failed';
} finally {
  for (const bridge of bridges) await bridge.stop().catch(() => {});
  await close(proxy); await stopTree(server);
  if (root && path.dirname(root) === path.resolve(os.tmpdir()) && path.basename(root).startsWith('liteseal-real-groups-')) await rm(root, { recursive: true, force: true });
  await mkdir('target/test-results', { recursive: true });
  await writeFile('target/test-results/group-integration.json', JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2)); process.exitCode = report.status === 'passed' ? 0 : 2;
}
