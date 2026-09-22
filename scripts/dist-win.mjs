import { npm, run } from "./process.mjs";
if (process.platform !== "win32" || process.arch !== "x64") {
  throw new Error("请在 Windows x64 环境运行打包命令，确保 Rust 子进程与安装包架构一致。");
}
await run(npm, ["run", "build"]).done;
const signed = process.env.LITESEAL_SIGNED_RELEASE === "1";
if (signed && !process.env.CSC_LINK) throw new Error("签名发布需要 CSC_LINK 和对应证书凭据，不输出未签名替代包。");
await run(npm, ["exec", "--", "electron-builder", "--win", "--x64", "--publish", "never",
  ...(signed ? ["--config.forceCodeSigning=true", "--config.win.signAndEditExecutable=true"] : [])]).done;
await import("./verify-package.mjs");
