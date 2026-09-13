import { createRequire } from "node:module";
import { createServer } from "vite";
import { npm, run, stopTree } from "./process.mjs";
const require = createRequire(import.meta.url);
let vite, desktop, building;
let closing = false;
async function cleanup() {
  if (closing) return;
  closing = true;
  await stopTree(building);
  await stopTree(desktop);
  await vite?.close();
}
for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => { void cleanup().then(() => process.exit(0)); });
try {
  for (const [command, args] of [["cargo", ["build", "--locked", "-p", "liteseal-desktop"]], [npm, ["run", "build:electron"]]]) {
    const task = run(command, args); building = task.child; await task.done;
  }
  building = undefined;
  vite = await createServer({ configFile: "ui/vite.config.ts", root: "ui" });
  await vite.listen(); vite.printUrls();
  const task = run(require("electron"), ["."]);
  desktop = task.child;
  await task.done;
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
} finally { await cleanup(); }
