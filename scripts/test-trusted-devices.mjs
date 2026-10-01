// Offline T23 proof only: no login, relay, real identity, or long-running test.
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { execute } from './test-database.mjs';
const at = new Date().toISOString();
const report = { at, status: 'running', mode: 'offline_protocol_trial', steps: [],
  commit: execute('git', ['rev-parse', 'HEAD']).output.trim(),
  worktree_changes: execute('git', ['diff', '--quiet']).code !== 0,
  second_device_login_enabled: false };
const began = performance.now();
const evidence = path.resolve('target/test-results/trusted-devices-' + at.replace(/[:.]/g, '-') + '.json');
mkdirSync(path.dirname(evidence), { recursive: true });
try {
  const args = ['test', '--locked', '-p', 'liteseal-shared', '--test', 'trusted_device_test'];
  const tests = execute('cargo', args);
  const counts = /test result: ok\. (\d+) passed; 0 failed; 0 ignored/.exec(tests.output);
  report.steps.push({ name: 'signed chain and dual key possession', passed: Number(counts?.[1] ?? 0), command: ['cargo', ...args], status: tests.code === 0 && counts ? 'passed' : 'failed' });
  if (tests.code || !counts) throw new Error('protocol tests failed');
  const storeArgs = ['test', '--locked', '-p', 'liteseal-core', '--test', 'trusted_devices_test'];
  const store = execute('cargo', storeArgs);
  const storedCounts = /test result: ok\. (\d+) passed; 0 failed; 0 ignored/.exec(store.output);
  report.steps.push({ name: 'atomic SQLite trust log and restart replay', passed: Number(storedCounts?.[1] ?? 0), command: ['cargo', ...storeArgs], status: store.code === 0 && storedCounts ? 'passed' : 'failed' });
  if (store.code || !storedCounts) throw new Error('directory persistence tests failed');
  const trial = execute('cargo', ['run', '--quiet', '--locked', '-p', 'liteseal-shared', '--example', 'trusted_device_trial']);
  const line = trial.output.split(/\r?\n/).find(line => line.startsWith('{'));
  const result = line ? JSON.parse(line) : null;
  if (trial.code || result?.status !== 'passed') throw new Error('offline trial failed');
  report.steps.push({ name: 'two independent Rust identities grant and revoke', ...result });
  report.status = 'passed';
} catch (error) {
  report.status = 'failed';
  report.reason = error.message;
  process.exitCode = 1;
} finally {
  report.actual_seconds = Math.round((performance.now() - began) / 1000);
  writeFileSync(evidence, JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ status: report.status, report: evidence }));
}
