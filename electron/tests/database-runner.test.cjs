const { test } = require('node:test');
const assert = require('node:assert/strict');
test('database runner refuses missing/unsafe configuration and does not expose connection errors', async () => {
  const { runSuite, preflight, validateConfig } = await import('../../scripts/test-database.mjs');
  const env = { LITESEAL_TEST_DATABASE_URL: 'postgres://tester:secret@127.0.0.1/liteseal_test_suite' };
  assert.equal(validateConfig({ DATABASE_URL: env.LITESEAL_TEST_DATABASE_URL }), 'test database not configured');
  assert.ok(validateConfig({ LITESEAL_TEST_DATABASE_URL: 'postgres://x/production' }));
  assert.ok(validateConfig({ LITESEAL_TEST_DATABASE_URL: 'not a URL' }));
  const missing = runSuite({}, (cmd) => { assert.equal(cmd, 'git'); return { code: 0, output: 'a'.repeat(40) }; });
  assert.equal(missing.status, 'not_executed');
  const failed = preflight(env, cmd => ({ code: cmd === 'cargo' ? 0 : 2, output: env.LITESEAL_TEST_DATABASE_URL }));
  assert.equal(failed.ok, false); assert.ok(!JSON.stringify(failed).includes('secret'));
  const calls = [];
  const result = runSuite(env, (cmd, args) => {
    calls.push(args);
    if (cmd === 'git') return { code: 0, output: 'a'.repeat(40) };
    if (args[0] === 'build') return { code: 0, output: '' };
    if (args[0] === '--test-database-check') return { code: 0, output: '{"dedicated":true,"server_version_num":"170000"}' };
    if (args.includes('--list')) return { code: 0, output: 'suite::first: test\nsuite::second: test\n' };
    return { code: args.includes('suite::first') ? 0 : 1, output: args.includes('suite::first') ? 'test result: ok. 1 passed; 0 failed; 0 ignored' : 'secret panic' };
  });
  assert.equal(result.passed, 1); assert.equal(result.failed, 1); assert.equal(result.status, 'failed');
  assert.ok(!JSON.stringify(result).includes('secret'));
  assert.equal(calls.filter(args => args.includes('--exact')).length, 2);
});
