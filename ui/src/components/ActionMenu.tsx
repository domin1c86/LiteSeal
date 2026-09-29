import { useEffect, useRef, type ReactNode } from "react";

/** Native disclosure keeps secondary actions keyboard accessible without crowding rows. */
export default function ActionMenu({ label, children, caption = "···" }: {
  label: string; children: ReactNode; caption?: string;
}) {
  const menu = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    const dismiss = (event: PointerEvent) => {
      if (menu.current && !menu.current.contains(event.target as Node)) menu.current.open = false;
    };
    document.addEventListener("pointerdown", dismiss);
    return () => document.removeEventListener("pointerdown", dismiss);
  }, []);
  return <details ref={menu} className="action-menu" onToggle={() => {
    const element = menu.current;
    if (!element?.open) return;
    delete element.dataset.below;
    const scrollArea = element.closest(".chat-messages");
    const items = element.querySelector(".action-menu-items");
    if (scrollArea && items && items.getBoundingClientRect().top < scrollArea.getBoundingClientRect().top) {
      element.dataset.below = "true";
    }
  }} onKeyDown={event => {
    if (event.key === "Escape" && menu.current?.open) {
      event.stopPropagation(); menu.current.open = false;
      menu.current.querySelector("summary")?.focus();
    }
  }}>
    <summary aria-label={label} title={label}>{caption}</summary>
    <div className="action-menu-items" onClick={event => {
      const button = (event.target as Element).closest("button");
      if (button && !button.disabled && menu.current) {
        menu.current.open = false;
        menu.current.querySelector("summary")?.focus();
      }
    }}>{children}</div>
  </details>;
}
