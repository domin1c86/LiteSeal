import { useEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";

/** Shared modal surface; native dialog contains focus and makes the workspace inert. */
export default function PanelDialog({ label, children, onClose, busy = false, wide = false }: {
  label: string; children: ReactNode; onClose: () => void; busy?: boolean; wide?: boolean;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current!;
    const previous = document.activeElement as HTMLElement | null;
    element.showModal();
    return () => { element.close(); if (previous?.isConnected) previous.focus(); };
  }, []);
  return createPortal(<dialog ref={dialog} role="dialog" aria-modal="true" aria-label={label}
    className={`panel-dialog${wide ? " panel-dialog-wide" : ""}`}
    onKeyDown={event => { if (event.key === "Escape") event.stopPropagation(); }}
    onCancel={event => { event.preventDefault(); if (!busy) onClose(); }}>
    <header className="panel-dialog-heading"><h2>{label}</h2>
      <button type="button" aria-label="关闭对话框" disabled={busy} onClick={onClose}>×</button>
    </header>
    <div className="panel-dialog-body">{children}</div>
  </dialog>, document.body);
}
