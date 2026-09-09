import { spawn } from "node:child_process";
export const npm = process.platform === "win32" ? "npm.cmd" : "npm";
export function run(command, args, options = {}) {
  // Only fixed script-owned arguments are passed to cmd.exe for npm on Windows.
  const child = spawn(command, args, { stdio: "inherit", shell: process.platform === "win32" && command.endsWith(".cmd"), ...options });
  return { child, done: new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => code === 0 ? resolve() : reject(new Error(`${command} exited (${code ?? signal})`)));
  }) };
}
export async function stopTree(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  if (process.platform === "win32") {
    await new Promise(resolve => {
      const killer = spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
      killer.once("error", resolve); killer.once("exit", resolve);
    });
  } else {
    child.kill("SIGTERM");
  }
}
