const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs/promises');
const http = require('node:http');
const vm = require('node:vm');
const { DesktopBridge } = require('../../dist-electron/bridge.cjs');
const { commandNames } = require('../../dist-electron/contracts.cjs');
const executable = path.resolve('target/debug/liteseal-desktop' + (process.platform === 'win32' ? '.exe' : ''));

// Every test uses its own keystore file; the developer's identity is never touched.
async function start(t, dbPath, keystorePath = path.join(os.tmpdir(), `liteseal-keystore-${process.pid}-${Date.now()}-${Math.random()}.bin`)) {
  const bridge = new DesktopBridge(10000);
  t.after(() => bridge.stop());
  await bridge.start(executable, ['--db-path', dbPath, '--keystore-path', keystorePath]);
  return bridge;
}

test('preload exposes exactly the typed business commands, with error propagation', async () => {
  let exposed;
  let fail = false;
  vm.runInNewContext(await fs.readFile('dist-electron/preload.cjs', 'utf8'), {
    require(name) {
      assert.equal(name, 'electron');
      return { contextBridge: { exposeInMainWorld(key, value) { assert.equal(key, 'desktop'); exposed = value; } },
        ipcRenderer: { async invoke(channel, args) { assert.equal(channel, 'liteseal:get_contacts'); assert.deepEqual(args, {}); return fail ? { ok: false, error: 'test error' } : { ok: true, result: [] }; } } };
    },
  });
  assert.deepEqual(Object.keys(exposed).sort(), [...commandNames].sort());
  assert.deepEqual(await exposed.get_contacts({}), []);
  fail = true;
  await assert.rejects(exposed.get_contacts({}), /test error/);
});

test('real Rust process supports crypto, contacts, storage, errors and database reuse', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'liteseal-electron-'));
  // Explicitly stop before deletion, including on Windows where SQLite holds the file open.
  let bridge;
  t.after(async () => { await bridge?.stop(); await fs.rm(dir, { recursive: true, force: true }); });
  const db = path.join(dir, 'data.db');
  const keystore = path.join(dir, 'keystore.bin');
  bridge = await start(t, db, keystore);
  const identity = await bridge.call('prepare_identity', {});
  assert.equal(identity.saved, false);
  assert.equal('secret_key' in identity || 'ed25519_sk' in identity, false);
  assert.deepEqual([identity.public_key.length, identity.ed25519_pk.length], [32, 32]);
  const plaintext = Array.from(Buffer.from('Electron 中文消息'));
  await assert.rejects(bridge.call('encrypt_message', { plaintext, recipientPublicKey: identity.public_key }), /No saved keypair/);
  await bridge.call('save_session', { userId: 'alice', token: 'token', refreshToken: 'refresh', deviceId: 'device', serverUrl: 'http://127.0.0.1:9' });
  const ciphertext = await bridge.call('encrypt_message', { plaintext, recipientPublicKey: identity.public_key });
  assert.deepEqual(await bridge.call('decrypt_message', { ciphertext, senderPublicKey: identity.public_key }), plaintext);
  const signature = await bridge.call('sign_message', { message: plaintext });
  assert.equal(await bridge.call('verify_message', { message: plaintext, signature, senderPublicKey: identity.ed25519_pk }), true);
  assert.equal(await bridge.call('verify_message', { message: [1], signature, senderPublicKey: identity.ed25519_pk }), false);
  assert.deepEqual(await bridge.call('add_contact', { userId: 'bob', username: 'Bob', publicKey: identity.public_key, ed25519Pk: identity.ed25519_pk }), { success: true });
  await bridge.call('set_contact_trust', { userId: 'bob', trustState: 'verified' });
  assert.equal((await bridge.call('get_contacts', {}))[0].trust_state, 'verified');
  assert.deepEqual(await bridge.call('get_local_messages', { conversationId: 'dm:alice:bob', limit: 50, offset: 0 }), []);
  assert.equal((await bridge.call('get_storage_stats', {})).message_count, 0);
  assert.equal(await bridge.call('clear_expired_messages', {}), 0);
  assert.equal(await bridge.call('clear_downloaded_attachments', {}), 0);
  await assert.rejects(bridge.call('poll_messages', {}), /Not connected/);
  await assert.rejects(bridge.call('send_message', { senderId: 'alice', ciphertext, signature, senderDeviceId: 'a', payloads: [] }), /no recipient/);
  await assert.rejects(bridge.call('connect_relay', { serverUrl: 'invalid', userId: 'alice', token: 'token', deviceId: '' }), /Device id/);
  await assert.rejects(bridge.call('add_contact', { userId: 'bad', username: 'Bad', publicKey: [256] }), /Invalid command/);
  await assert.rejects(bridge.call('get_contacts', { surprise: true }), /Invalid command/);
  await assert.rejects(bridge.call('get_local_messages', { conversationId: 'x', limit: 'wrong', offset: 0 }), /Invalid command/);
  await assert.rejects(bridge.call('sign_message', { message: plaintext, signingKey: [1] }), /Invalid command/);
  assert.equal(await bridge.call('disconnect', {}), null);
  await bridge.stop();
  bridge = await start(t, db, keystore);
  assert.deepEqual((await bridge.call('load_identity', {})).public_key, identity.public_key);
  assert.equal((await bridge.call('get_contacts', {}))[0].username, 'Bob');
  await bridge.call('remove_contact', { userId: 'bob' });
  assert.deepEqual(await bridge.call('get_contacts', {}), []);
});

test('REST bridge preserves invitation, login, refresh and lookup payloads', async t => {
  const received = [];
  const server = http.createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    received.push({ url: req.url, body: body ? JSON.parse(body) : null });
    res.setHeader('content-type', 'application/json');
    if (req.url === '/auth/invite/validate') return res.end('true');
    if (req.url.startsWith('/users/')) return res.end('[]');
    res.end(JSON.stringify({ user_id: 'alice', token: 'token', access_token: 'access', refresh_token: 'refresh', device_id: 'device' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const bridge = await start(t, ':memory:');
  const serverUrl = `http://127.0.0.1:${server.address().port}`;
  assert.equal(await bridge.call('validate_invite', { serverUrl, inviteCode: ' LITESEAL-WIN-ALPHA ' }), true);
  const identity = await bridge.call('prepare_identity', {});
  const keys = [identity.public_key, null, identity.ed25519_pk];
  const auth = { username: 'alice', password: 'password8', serverUrl, publicKey: keys[0], ed25519Pk: keys[2] };
  assert.equal((await bridge.call('register', { ...auth, inviteCode: 'LITESEAL-WIN-ALPHA' })).user_id, 'alice');
  assert.equal((await bridge.call('login', { ...auth, deviceId: 'device' })).device_id, 'device');
  assert.equal((await bridge.call('refresh_session', { serverUrl, refreshToken: 'refresh' })).token, 'token');
  assert.deepEqual(await bridge.call('search_users', { serverUrl, query: 'alice bob', accessToken: 'access' }), []);
  assert.deepEqual(await bridge.call('get_user_devices', { serverUrl, userId: 'alice', accessToken: 'access' }), []);
  assert.equal(received[0].body.invite_code, 'LITESEAL-WIN-ALPHA');
  assert.equal(received[1].body.device_name, 'Windows desktop');
  assert.equal(received[1].body.invite_code, 'LITESEAL-WIN-ALPHA');
  assert.deepEqual(received[2].body.device_public_key, keys[0]);
  assert.equal(received[2].body.device_id, 'device');
  assert.equal(received[3].body.refresh_token, 'refresh');
  assert.equal(received[4].url, '/users/search?q=alice+bob');
});

test('Rust stream accepts fragmented requests, rejects unknown commands and exits on EOF', { timeout: 10000 }, async t => {
  const { spawn } = require('node:child_process');
  const { createInterface } = require('node:readline');
  const child = spawn(executable, ['--db-path', ':memory:'], { stdio: 'pipe' });
  t.after(() => child.kill());
  child.stderr.resume();
  const exit = new Promise(resolve => child.once('exit', resolve));
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  assert.equal(JSON.parse((await lines.next()).value).ready, true);
  child.stdin.write('{"id":1,"command":{"name":"get_');
  child.stdin.write('contacts","args":{}}}\n{"id":2,"command":{"name":"unknown","args":{}}}\n');
  const results = [JSON.parse((await lines.next()).value), JSON.parse((await lines.next()).value)].sort((a, b) => a.id - b.id);
  assert.deepEqual(results[0], { id: 1, result: [] });
  assert.equal(results[1].id, 2);
  assert.match(results[1].error, /Invalid command/);
  child.stdin.end();
  assert.equal(await exit, 0);
});
