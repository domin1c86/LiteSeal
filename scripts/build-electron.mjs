import { build } from "esbuild";
await build({ entryPoints: { main: "electron/main.ts", preload: "electron/preload.ts", bridge: "electron/bridge.ts", contracts: "electron/contracts.ts" },
  outdir: "dist-electron", outExtension: { ".js": ".cjs" }, bundle: true,
  platform: "node", target: "node24", format: "cjs", external: ["electron"], sourcemap: false });
