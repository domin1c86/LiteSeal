import { npm, run } from "./process.mjs";
if (process.platform !== "win32" || process.arch !== "x64") {
  throw new Error("请在 Windows x64 环境运行打包命令，确保 Rust 子进程与安装包架构一致。");
}
await run(npm, ["run", "build"]).done;
await run(npm, ["exec", "--", "electron-builder", "--win", "--x64", "--publish", "never"]).done;
await import("./verify-package.mjs");
