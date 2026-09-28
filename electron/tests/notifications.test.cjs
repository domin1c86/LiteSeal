const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const vm = require('node:vm');
const ts = require('typescript');

test('group notifications hide content, deduplicate, throttle and invalidate routing across locks and identities', () => {
  const shown = [];
  let focused = false;
  const window = { isFocused: () => focused, isMinimized: () => false, show() {}, focus() {} };
  class Notification extends EventEmitter {
    static isSupported() { return true; }
    constructor(options) { super(); this.options = options; }
    show() { shown.push(this); }
    close() { this.closed = true; this.emit('close'); }
  }
  const exports = {};
  const source = ts.transpileModule(fs.readFileSync('electron/notifications.ts', 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  vm.runInNewContext(source, { exports, URL, Date, require: () => ({ Notification }) });
  const notices = new exports.ChatNotifications(() => window, {});
  const identity = { user_id: 'alice', device_id: 'device', server_url: 'http://localhost:3000/' };
  const report = (group, message) => ({ notification_identity: identity, notifications: [{ group_id: group, message_id: message }] });
  notices.context('alice', null, null, identity);
  const generation = notices.generation();
  notices.receiveGroups(report('g1', 'm1'), generation);
  assert.equal(shown.length, 1);
  assert.equal(shown[0].options.body, '有新群消息，打开应用查看');
  shown[0].emit('click');
  assert.equal(notices.takeTarget().groupId, 'g1');
  notices.receiveGroups(report('g1', 'm1'), generation);
  notices.receiveGroups(report('g1', 'm2'), generation);
  assert.equal(shown.length, 1);
  focused = true; notices.context('alice', null, 'g2', identity);
  notices.receiveGroups(report('g2', 'm3'), generation);
  assert.equal(shown.length, 1);
  focused = false;
  notices.lock(true);
  notices.receiveGroups(report('g3', 'm4'), notices.generation());
  shown[0].emit('click'); assert.equal(notices.takeTarget(), null);
  notices.lock(false);
  notices.receiveGroups(report('g3', 'm4'), notices.generation());
  notices.receiveGroups(report('g4', 'm5'), generation);
  assert.equal(shown.length, 1);
  const beforeMute = notices.generation(); notices.suppressGroup('g5');
  notices.receiveGroups(report('g5', 'm6'), beforeMute);
  assert.equal(shown.length, 1);
  notices.context('alice', null, null, { ...identity, server_url: 'http://localhost:3001' });
  notices.receiveGroups(report('g6', 'm7'), notices.generation());
  shown[0].emit('click'); assert.equal(notices.takeTarget(), null);
  assert.equal(shown.length, 1);
});
