import { useEffect, useRef, useState } from "react";

export interface Organizer {
  version: 1;
  aliases: Record<string, string>;
  lists: { id: string; name: string; peers: string[] }[];
  favorites: { messageId: string; peerId: string }[];
  notes: string;
}
const empty = (): Organizer => ({ version: 1, aliases: {}, lists: [], favorites: [], notes: "" });

export function useOrganizer(userId?: string) {
  const [value, setValue] = useState<Organizer>(empty);
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const current = useRef(value);
  const saving = useRef(false);
  const generation = useRef(0);
  useEffect(() => {
    const run = ++generation.current;
    setReady(false); setValue(empty()); setError("");
    if (!userId) return;
    void window.desktop.get_personal_organizer({}).then(raw => {
      const parsed: Organizer = raw ? JSON.parse(raw) : empty();
      if (parsed.version !== 1 || !parsed.aliases || !Array.isArray(parsed.lists) || !Array.isArray(parsed.favorites) || typeof parsed.notes !== "string") throw new Error("本机整理数据格式不支持");
      if (run !== generation.current) return;
      current.current = parsed; setValue(parsed); setReady(true);
    }).catch(failure => { if (run === generation.current) setError(String(failure)); });
    return () => { generation.current++; };
  }, [userId]);
  useEffect(() => {
    const guard = (event: BeforeUnloadEvent) => { if (saving.current) { event.preventDefault(); event.returnValue = ""; } };
    window.addEventListener("beforeunload", guard);
    return () => window.removeEventListener("beforeunload", guard);
  }, []);
  async function update(change: (previous: Organizer) => Organizer) {
    if (!ready || saving.current) throw new Error("请等待本机数据读取或保存完成");
    const run = generation.current;
    saving.current = true; setBusy(true);
    try {
      const next = change(current.current);
      await window.desktop.save_personal_organizer({ content: JSON.stringify(next) });
      if (run === generation.current) { current.current = next; setValue(next); setError(""); }
    } catch (failure) { if (run === generation.current) setError(String(failure)); throw failure; }
    finally { saving.current = false; if (run === generation.current) setBusy(false); }
  }
  return { value, ready, busy, error, update };
}
