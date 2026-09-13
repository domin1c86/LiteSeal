const readline = require('node:readline');
const mode = process.argv[2];
process.stdout.write('{"ready":tr');
setTimeout(() => process.stdout.write('ue,"version":1}\n'), 5);
readline.createInterface({ input: process.stdin }).on('line', line => {
  const { id } = JSON.parse(line);
  if (mode === 'hang') return;
  if (mode === 'crash') return process.exit(2);
  if (mode === 'malformed') return process.stdout.write('{bad}\n');
  if (mode === 'business') return process.stdout.write(JSON.stringify({ id, error: '邀请码无效' }) + '\n');
  // Intentionally return responses out of order and split UTF-8 across chunks.
  setTimeout(() => {
    const bytes = Buffer.from(JSON.stringify({ id, result: `中文-${id}` }) + '\n');
    const cut = bytes.indexOf(Buffer.from('中')) + 1;
    process.stdout.write(bytes.subarray(0, cut));
    process.stdout.write(bytes.subarray(cut));
  }, id === 1 ? 30 : 1);
}).on('close', () => process.exit(0));
