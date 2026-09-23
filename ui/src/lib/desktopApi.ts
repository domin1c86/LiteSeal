import type { DesktopApi } from "../../../electron/contracts";

/** Desktop commands are unavailable in a plain browser preview. */
export function getDesktopApi(): DesktopApi {
  if (!window.desktop) {
    throw new Error("请通过 Electron 桌面应用使用此功能；浏览器仅支持界面预览");
  }
  return window.desktop;
}
