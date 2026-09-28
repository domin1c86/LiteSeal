const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { randomUUID } = require('node:crypto');
const { DesktopBridge } = require('../../dist-electron/bridge.cjs');

test('two isolated Rust desktops verify group consent, encrypted delivery, drafts and token rotation', { timeout: 25000, skip: process.platform !== 'win32' }, async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'liteseal-group-bridge-'));
  assert.ok(path.resolve(root).startsWith(path.resolve(os.tmpdir()) + path.sep));
  const people = new Map(), groups = new Map(), invitations = new Map(), batches = new Map(), payloads = new Map(), cancelled = new Set();
  const requests = [];
  let failAfterAdmission = false, slowLists = false, slowReadStarted;
  const server = http.createServer(async (req, res) => {
    const bytes = []; for await (const chunk of req) bytes.push(chunk);
    const body = bytes.length ? JSON.parse(Buffer.concat(bytes)) : {};
    const url = new URL(req.url, 'http://test'); const parts = url.pathname.split('/').filter(Boolean);
    const user = [...people.values()].find(person => req.headers.authorization === `Bearer ${person.token}`);
    const answer = (status, data) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(status === 204 ? '' : JSON.stringify(data)); };
    requests.push({ path: url.pathname, actor: user?.id });
    if (!user) { answer(401, {}); return; }
    if (parts[0] === 'auth' && parts[1] === 'logout') { answer(204); return; }
    if (parts[0] === 'users' && parts[2] === 'devices') {
      const person = people.get(parts[1]); answer(200, [{ id: person.device, name: person.name, public_key: person.identity.public_key, ed25519_pk: person.identity.ed25519_pk, revoked: false }]); return;
    }
    if (parts[0] === 'group-invites') {
      if (req.method === 'DELETE') { invitations.delete(parts[1]); answer(204); return; }
      answer(200, { invites: [...invitations.values()].filter(invite => invite.member.user_id === user.id && invite.epoch === groups.get(invite.group_id).events.at(-1).epoch), next_cursor: null }); return;
    }
    if (parts[0] === 'groups' && parts.length === 1) {
      if (slowLists && req.method === 'GET') await new Promise(resolve => setTimeout(resolve, 1000));
      if (req.method === 'GET') { answer(200, { groups: [...groups.values()].filter(group => group.members.has(user.id)).map(group => ({ group_id: group.id, joined_epoch: group.members.get(user.id).joined, visible_epoch: group.events.at(-1).epoch, active: !group.closed })), next_cursor: null }); return; }
      assert.equal(body.device_id, user.device); assert.equal(body.change.actor, user.id);
      groups.set(body.change.group_id, { id: body.change.group_id, events: [body.change], members: new Map([[user.id, { device: user.device, joined: 1 }]]), closed: false }); answer(200, body.change); return;
    }
    const group = groups.get(parts[1]); if (!group) { answer(404, {}); return; }
    if (parts[2] === 'changes') {
      if (req.method==='GET' && slowLists) {slowReadStarted?.();await new Promise(resolve=>setTimeout(resolve,1000));}
      if (req.method === 'GET') { answer(200, { changes: group.events.filter(event => event.epoch > Number(url.searchParams.get('after_epoch'))), through_epoch: group.events.at(-1).epoch, has_more: false }); return; }
      assert.equal(body.device_id, user.device); assert.equal(body.change.actor, user.id);
      const change = body.change;
      if (change.epoch <= group.events.at(-1).epoch) { answer(409, {}); return; }
      if (change.action.kind === 'join') { group.members.set(user.id, { device: user.device, joined: change.epoch }); invitations.delete(change.action.invite.id); }
      if (change.action.kind === 'close') group.closed = true;
      if (change.action.kind === 'remove') group.members.delete(change.action.user_id);
      if (change.action.kind === 'leave') group.members.delete(user.id);
      group.events.push(change); answer(200, change); return;
    }
    if (parts[2] === 'invites' && req.method === 'GET') { const owner=group.events[0].action.owner; if(owner.user_id!==user.id){answer(404,{});return;} answer(200,{invites:[...invitations.values()].filter(invite=>invite.group_id===group.id).sort((a,b)=>a.id.localeCompare(b.id)).map(invite=>({invite,status:invite.epoch===group.events.at(-1).epoch?'pending':'invalidated'})),next_cursor:null});return; }
    if (parts[2] === 'invites') { assert.equal(body.device_id, user.device); invitations.set(body.invite.id, body.invite); answer(200, { invite: body.invite, status: 'pending' }); return; }
    if (parts[2] === 'messages') {
      if (parts[4] === 'cancel') {
        const original = batches.get(parts[3]); if (original) { answer(200, { group_id: group.id, message_id: parts[3], cancelled: false, receipt: original.receipt }); return; }
        cancelled.add(parts[3]); answer(200, { group_id: group.id, message_id: parts[3], cancelled: true, receipt: null }); return;
      }
      if (parts[4] === 'receipt') { const original = batches.get(parts[3]); answer(original ? 200 : 404, original?.receipt ?? {}); return; }
      if (parts[3] === 'ack') {
        assert.equal(body.device_id, user.device);
        for (const id of body.message_ids) {
          const batch = batches.get(id); const recipient = batch.receipt.recipients.find(recipient => recipient.recipient_device_id === user.device);
          assert.equal(recipient.recipient_join_epoch, body.recipient_join_epoch); recipient.status = 'delivered'; payloads.delete(`${user.device}:${id}`);
        }
        answer(204); return;
      }
      if (req.method === 'GET') { answer(200, { envelopes: [...payloads.values()].filter(envelope => envelope.group_id === group.id && envelope.recipient_device_id === user.device), has_more: false }); return; }
      const first = body.envelopes[0]; assert.equal(body.device_id, user.device); assert.equal(first.sender_user_id, user.id);
      if (cancelled.has(first.message_id)) { answer(409, {}); return; }
      let batch = batches.get(first.message_id);
      if (!batch) {
        const receipt = { group_id: group.id, message_id: first.message_id, recipients: body.envelopes.map(envelope => ({ recipient_user_id: envelope.recipient_user_id, recipient_device_id: envelope.recipient_device_id, recipient_join_epoch: envelope.recipient_join_epoch, status: 'pending' })) };
        batch = { envelopes: body.envelopes, receipt }; batches.set(first.message_id, batch);
        for (const envelope of body.envelopes) payloads.set(`${envelope.recipient_device_id}:${envelope.message_id}`, envelope);
      } else assert.deepEqual(batch.envelopes, body.envelopes);
      if (failAfterAdmission) { failAfterAdmission = false; answer(503, {}); return; }
      answer(200, batch.receipt); return;
    }
    answer(404, {});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const bridges = [];
  t.after(async () => { for (const bridge of bridges) await bridge.stop(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await fs.rm(root, { recursive: true, force: true }); });
  const start = async name => {
    const bridge = new DesktopBridge(10000); bridges.push(bridge);
    const db = path.join(root, `${name}.db`), keys = path.join(root, `${name}.bin`);
    await bridge.start(path.resolve('target/debug/liteseal-desktop.exe'), ['--db-path', db, '--keystore-path', keys]);
    const identity = await bridge.call('prepare_identity', {});
    const person = { name, id: randomUUID(), device: randomUUID(), token: `synthetic-${randomUUID()}`, identity, bridge, db, keys };
    people.set(person.id, person);
    await bridge.call('save_session', { userId: person.id, deviceId: person.device, token: person.token, refreshToken: 'synthetic-refresh', serverUrl: origin });
    return person;
  };
  const alice = await start('alice'), bob = await start('bob');
  const contact = async (owner, peer, verified) => {
    await owner.bridge.call('add_contact', { userId: peer.id, username: peer.name, publicKey: peer.identity.public_key, ed25519Pk: peer.identity.ed25519_pk });
    if (verified) await owner.bridge.call('set_contact_trust', { userId: peer.id, trustState: 'verified' });
  };
  await contact(alice, bob, false); await contact(bob, alice, true);
  await assert.rejects(alice.bridge.call('inspect_group_peer', { peerId: bob.id }), /核实/);
  await alice.bridge.call('set_contact_trust', { userId: bob.id, trustState: 'verified' });
  const peer = await alice.bridge.call('inspect_group_peer', { peerId: bob.id });
  const group = await alice.bridge.call('create_group', { name: '隔离群聊验证' });
  await assert.rejects(alice.bridge.call('group_draft', {groupId:group,text:'x',secretKey:[1]}), /Invalid command or arguments/);
  const snapshot = await alice.bridge.call('get_groups', {});
  assert.equal(snapshot.groups[0].members.length, 1); assert.equal(snapshot.groups[0].owner, alice.id);
  assert.doesNotMatch(JSON.stringify(snapshot), /"(?:token|refresh_token|secret_key|ed25519_sk)"/);
  await assert.rejects(alice.bridge.call('invite_group_member', { groupId: group, peerId: bob.id, confirmedFingerprint: 'wrong' }), /指纹/);
  await alice.bridge.call('invite_group_member', { groupId: group, peerId: bob.id, confirmedFingerprint: peer.fingerprint });
  const issued = await alice.bridge.call('get_sent_group_invites', { groupId: group });
  assert.equal(issued.invites.length, 1); assert.equal(issued.invites[0].user_id, bob.id); assert.equal(issued.invites[0].status, 'pending');
  assert.doesNotMatch(JSON.stringify(issued), /signature|signing_key|public_key/);
  await alice.bridge.call('revoke_group_invite', { inviteId: issued.invites[0].id });
  assert.equal((await alice.bridge.call('get_sent_group_invites', { groupId: group })).invites.length, 0);
  await alice.bridge.call('invite_group_member', { groupId: group, peerId: bob.id, confirmedFingerprint: peer.fingerprint });
  const inbox = await bob.bridge.call('get_groups', { refresh: true }); assert.equal(inbox.invitations.length, 1);
  const invitation = inbox.invitations[0];
  const inspected = await bob.bridge.call('inspect_group', { groupId: group, inviteId: invitation.id }); assert.equal(inspected.eligible, true);
  await bob.bridge.call('accept_group_invite', { inviteId: invitation.id, confirmedFingerprint: inspected.fingerprint });
  await alice.bridge.call('sync_group', { groupId: group });
  await alice.bridge.call('group_draft', { groupId: group, text: 'unique-group-draft 字符' });
  assert.equal((await alice.bridge.call('group_draft', { groupId: group })), 'unique-group-draft 字符');
  assert.equal((await fs.readFile(alice.db)).includes(Buffer.from('unique-group-draft')), false);
  failAfterAdmission = true;
  const sent = await alice.bridge.call('send_group_text', { groupId: group, text: 'group text: 密文往返' }); assert.equal(sent.state, 'queued');
  assert.equal((await alice.bridge.call('group_draft', { groupId: group })), '');
  await alice.bridge.call('send_group_text', { groupId: group }); assert.equal(batches.size, 1);
  assert.equal(await bob.bridge.call('sync_group', { groupId: group }), 1);
  const sentInvites = await alice.bridge.call('get_sent_group_invites', { groupId: group });
  assert.deepEqual(sentInvites.invites, []);
  await assert.rejects(bob.bridge.call('get_sent_group_invites', { groupId: group }), /群主/);
  const history = await bob.bridge.call('get_group_history', { groupId: group }); assert.equal(history.messages[0].text, 'group text: 密文往返'); assert.equal(payloads.size, 0);
  assert.equal((await bob.bridge.call('get_groups', {})).groups[0].unread, 1);
  await bob.bridge.call('mark_group_seen', { groupId: group, ids: [history.messages[0].id] });
  assert.equal((await bob.bridge.call('get_groups', {})).groups[0].unread, 0);
  alice.token = `rotated-${randomUUID()}`;
  await alice.bridge.call('save_session', { userId: alice.id, deviceId: alice.device, token: alice.token, refreshToken: 'next-refresh', serverUrl: origin });
  const rotated = await alice.bridge.call('get_groups', { refresh: true }); assert.deepEqual(rotated.errors, []); assert.equal(rotated.groups.length, 1);
  slowLists = true;
  const waiting=new Promise(resolve=>{slowReadStarted=resolve;});
  const background = alice.bridge.call('process_groups', {});
  await waiting;
  const local = await Promise.race([alice.bridge.call('group_draft', { groupId: group, text: 'local while network waits' }), new Promise((_, reject) => setTimeout(() => reject(new Error('local draft blocked by network')), 600))]);
  assert.equal(local, 'local while network waits'); await background; slowLists = false;
  await alice.bridge.call('sign_out', {}); await assert.rejects(alice.bridge.call('get_groups', {}), /登录/);
  assert.ok(requests.some(request => request.path.includes('/messages/ack') && request.actor === bob.id));
});
