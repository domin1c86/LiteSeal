import { build } from 'esbuild';
import { mkdir, mkdtemp, writeFile, readFile } from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import { spawn, spawnSync } from 'node:child_process';
import { stopTree } from './process.mjs';
const types = spawnSync(process.execPath, ['node_modules/typescript/bin/tsc', '-p', 'ui/tsconfig.tests.json'], { stdio: 'inherit', windowsHide: true });
if (types.status !== 0) process.exit(1);
await mkdir('target/test-results', { recursive: true });
const directory = await mkdtemp(path.resolve('target/test-results/ui-style-'));
for (const [name, source] of [['app', 'style'], ['groups', 'groups']]) {
  await build({ entryPoints: [`ui/tests/${source}-harness.tsx`], bundle: true, outfile: path.join(directory, `${name}.js`), platform: 'browser', jsx: 'automatic', define: { 'process.env.NODE_ENV': '"development"' } });
  await writeFile(path.join(directory, `${name}.html`), `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"><link rel="stylesheet" href="${name}.css"></head><body><div id="root"></div><script src="${name}.js"></script></body></html>`);
}
const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
const electron = createRequire(import.meta.url)('electron');
const child = spawn(electron, [path.resolve('scripts/style-ui-electron.cjs'), directory], { env, stdio: 'ignore', windowsHide: true });
let timedOut = false;
const timer = setTimeout(() => { timedOut = true; void stopTree(child); }, 300000);
const code = await new Promise(resolve => { child.once('error', () => resolve(1)); child.once('exit', code => resolve(code)); });
clearTimeout(timer);
try {
  const report = JSON.parse(await readFile(path.join(directory, 'result.json'), 'utf8'));
  console.log(JSON.stringify({ status: report.status, screenshots: report.screens.length, checks: report.checks, errors: report.errors }, null, 2));
} catch { console.log(timedOut ? 'Style runner timed out' : 'Style runner did not produce a result'); }
console.log('UI style evidence: ' + directory);
process.exitCode = code === 0 && !timedOut ? 0 : 1;
