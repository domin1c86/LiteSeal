const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const vm = require('node:vm');
const ts = require('typescript');

test('v3 notifications use only claimed IDs, scoped click targets and foreground, mute and lock guards', () => {
  const shown=[],events=[];let focused=false,now=100000;
  const window={isFocused:()=>focused,isMinimized:()=>false,show(){},focus(){},webContents:{send(name){events.push(name);}}};
  class Notification extends EventEmitter {
    static isSupported(){return true;}
    constructor(options){super();this.options=options;}
    show(){shown.push(this);}
    close(){this.closed=true;this.emit('close');}
  }
  const exports={};
  const source=ts.transpileModule(fs.readFileSync('electron/notifications.ts','utf8'),{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
  vm.runInNewContext(source,{exports,URL,Date:{now:()=>now},require:()=>({Notification})});
  const notices=new exports.ChatNotifications(()=>window,{call(){throw new Error('v3 must not query legacy contacts/preferences');}});
  const report=(peer,id,scope='scope-a')=>({notification_scope:scope,notifications:[{peer,id}]});
  notices.directContext('scope-a',null);let epoch=notices.directGeneration();
  notices.receiveDirect(report('bob','m1'),epoch);
  assert.equal(shown.length,1);assert.deepEqual({...shown[0].options},{title:'LiteSeal',body:'有新消息，打开应用查看',silent:false});
  shown[0].emit('click');assert.equal(notices.takeDirect('scope-a').peer,'bob');assert.equal(events.at(-1),'liteseal:direct-notification-target');
  now+=31000;notices.receiveDirect(report('bob','m1'),epoch);assert.equal(shown.length,1);
  focused=true;notices.directContext('scope-a','bob');notices.receiveDirect(report('bob','m2'),epoch);assert.equal(shown.length,1);
  notices.receiveDirect(report('carol','m3'),epoch);assert.equal(shown.length,2);shown[1].emit('click');assert.equal(notices.takeDirect('scope-a').peer,'carol');
  focused=false;const beforeMute=notices.directRevision();notices.dismissDirect('dave');notices.receiveDirect(report('dave','m4'),epoch,beforeMute);assert.equal(shown.length,2);
  notices.lock(true);shown[1].emit('click');assert.equal(notices.takeDirect('scope-a'),null);notices.receiveDirect(report('erin','m5'),notices.directGeneration());assert.equal(shown.length,2);
  notices.lock(false);notices.receiveDirect(report('erin','m5'),epoch);assert.equal(shown.length,2);
  notices.directContext('scope-b',null);notices.receiveDirect(report('frank','m6'),epoch);assert.equal(shown.length,2);
  notices.receiveDirect(report('frank','m7','scope-b'),notices.directGeneration());assert.equal(shown.length,3);shown[2].emit('click');assert.equal(notices.takeDirect('scope-a'),null);
  shown[2].emit('click');assert.equal(notices.takeDirect('scope-b').peer,'frank');
});

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
  notices.receiveGroups(report('other', 'm-other'), notices.generation());
  const other = shown.at(-1);
  const beforeMute = notices.generation(), beforeRevision = notices.groupRevision(); notices.suppressGroup('g5');
  other.emit('click'); assert.equal(notices.takeTarget()?.groupId, 'other');
  notices.receiveGroups(report('g5', 'm6'), beforeMute, beforeRevision);
  assert.equal(shown.length, 2);
  notices.context('alice', null, null, { ...identity, server_url: 'http://localhost:3001' });
  notices.receiveGroups(report('g6', 'm7'), notices.generation());
  shown[0].emit('click'); assert.equal(notices.takeTarget(), null);
  assert.equal(shown.length, 2);
});
