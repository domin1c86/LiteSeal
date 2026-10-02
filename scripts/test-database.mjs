import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function execute(command, args, env = process.env) {
  const result = spawnSync(command, args, { env, encoding: 'utf8', windowsHide: true, timeout: 900000, maxBuffer: 16 * 1024 * 1024 });
  return { code: result.status ?? 2, output: (result.stdout ?? '') + (result.stderr ?? '') };
}
export function validateConfig(env) {
  if (!env.LITESEAL_TEST_DATABASE_URL) return 'test database not configured';
  try {
    const url = new URL(env.LITESEAL_TEST_DATABASE_URL);
    if (!['postgres:', 'postgresql:'].includes(url.protocol) || !/^liteseal_test_[a-z0-9_]+$/.test(decodeURIComponent(url.pathname.slice(1)))) return 'dedicated test database name required';
  } catch { return 'invalid test database URL'; }
  return null;
}
export function preflight(env = process.env, run = execute) {
  const invalid = validateConfig(env);
  if (invalid) return { ok: false, reason: invalid };
  const build = run('cargo', ['build', '--locked', '-p', 'liteseal-server', '--bin', 'liteseal-server'], env);
  if (build.code) return { ok: false, reason: 'server build failed' };
  const binary = path.resolve('target/debug/liteseal-server' + (process.platform === 'win32' ? '.exe' : ''));
  const probe = run(binary, ['--test-database-check', '--migrate'], env);
  if (probe.code) return { ok: false, reason: 'database connection, marker or migration check failed' };
  try {
    const info = JSON.parse(probe.output.trim());
    if (info.dedicated !== true || !/^\d+$/.test(info.server_version_num)) throw new Error();
    return { ok: true, ...info, binary };
  } catch { return { ok: false, reason: 'invalid database probe result' }; }
}
export function runSuite(env = process.env, run = execute, testPrefix = '') {
  const report = { at: new Date().toISOString(), status: 'not_executed', passed: 0, failed: 0, skipped: 0, tests: [] };
  const commit = run('git', ['rev-parse', 'HEAD'], env);
  report.commit = /^[a-f0-9]{40}$/.test(commit.output.trim()) ? commit.output.trim() : 'unknown';
  const checked = preflight(env, run);
  if (!checked.ok) return { ...report, reason: checked.reason };
  report.server_version_num = checked.server_version_num;
  const base = ['test', '--locked', '-p', 'liteseal-server', '--bin', 'liteseal-server'];
  const listed = run('cargo', [...base, '--', '--ignored', '--list'], env);
  if (listed.code) return { ...report, status: 'failed', reason: 'test discovery failed' };
  const names = [...listed.output.matchAll(/^([a-zA-Z0-9_:]+): test\r?$/gm)].map(match => match[1]).filter(name => name.startsWith(testPrefix));
  if (!names.length) return { ...report, status: 'failed', reason: 'no ignored tests discovered' };
  // Exact cases are separate processes and sequential. Raw failures are never persisted.
  for (const name of names) {
    const result = run('cargo', [...base, name, '--', '--exact', '--ignored', '--test-threads=1'], env);
    const counts = /test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored/.exec(result.output);
    const passed = result.code === 0 && counts?.[1] === '1' && counts[2] === '0' && counts[3] === '0';
    const skipped = result.code === 0 && counts?.[3] === '1';
    report[passed ? 'passed' : skipped ? 'skipped' : 'failed']++;
    report.tests.push({ name, status: passed ? 'passed' : skipped ? 'skipped' : 'failed' });
  }
  report.status = report.failed || report.skipped ? 'failed' : 'passed';
  return report;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const report = runSuite();
  mkdirSync('target/test-results', { recursive: true });
  const evidence = JSON.stringify(report, null, 2) + '\n';
  writeFileSync('target/test-results/database.json', evidence);
  writeFileSync('target/test-results/database-' + report.at.replace(/[:.]/g, '-') + '.json', evidence);
  console.log(JSON.stringify(report, null, 2));
  process.exitCode = report.status === 'passed' ? 0 : 2;
}
