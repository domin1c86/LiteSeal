const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { DesktopBridge } = require('../../dist-electron/bridge.cjs');
const fixture = path.join(__dirname, 'fixtures/sidecar.cjs');

async function mock(t, mode, timeout = 2000) {
  const bridge = new DesktopBridge(timeout);
  t.after(() => bridge.stop());
  await bridge.start(process.execPath, [fixture, mode]);
  return bridge;
}

test('matches concurrent responses and handles split JSON / UTF-8 frames', async t => {
  const bridge = await mock(t, 'normal');
  assert.deepEqual(await Promise.all([bridge.call('get_contacts', {}), bridge.call('get_contacts', {})]), ['中文-1', '中文-2']);
  await assert.rejects(bridge.call('arbitrary_command', {}), /无效/);
  await assert.rejects(bridge.call('get_contacts', []), /无效/);
  await bridge.stop();
  await assert.rejects(bridge.call('get_contacts', {}), /不可用/);
});
test('preserves business error text', async t => {
  const bridge = await mock(t, 'business');
  await assert.rejects(bridge.call('get_contacts', {}), /邀请码无效/);
});
test('times out without replaying commands', async t => {
  const bridge = await mock(t, 'hang', 30);
  await assert.rejects(bridge.call('get_contacts', {}), /超时/);
});
for (const mode of ['crash', 'malformed']) test(`rejects all pending calls on ${mode}`, async t => {
  const bridge = await mock(t, mode);
  const results = await Promise.allSettled([bridge.call('get_contacts', {}), bridge.call('get_storage_stats', {})]);
  assert.ok(results.every(result => result.status === 'rejected'));
});
test('reports missing executable without hanging', async t => {
  const bridge = new DesktopBridge();
  t.after(() => bridge.stop());
  await assert.rejects(bridge.start(path.join(__dirname, 'missing-executable')), /无法启动/);
});
