"use client";

import { useState, useSyncExternalStore } from "react";

const noop = () => () => {};

/**
 * Copies `text` to the clipboard. Rendered only after hydration, so without
 * JavaScript the page shows the command text alone (it stays selectable).
 */
export function CopyButton({ text, label }: { text: string; label: string }) {
  const hydrated = useSyncExternalStore(noop, () => true, () => false);
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  if (!hydrated) return null;
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setState("copied");
        } catch {
          setState("failed");
        }
        setTimeout(() => setState("idle"), 2000);
      }}
      className="rounded border border-zinc-400 px-2 py-1 text-xs focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 dark:border-zinc-600 dark:focus-visible:outline-blue-400"
    >
      {state === "copied" ? "Copied" : state === "failed" ? "Copy failed" : label}
      <span className="sr-only" role="status">
        {state === "copied" ? "Copied to clipboard" : ""}
      </span>
    </button>
  );
}
