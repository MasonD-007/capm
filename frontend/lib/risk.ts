// Display mapping for risk labels (manifest/risk.go). Labels describe exposure
// declared in the manifest; they are not a review and their absence is not an
// endorsement. Colour is never the only signal: every style carries a word.
import type { RiskLabel } from "./api";

export type RiskDisplay = { word: string; className: string };

const BASE = "inline-block rounded border px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wide";

const DISPLAY: Record<string, RiskDisplay> = {
  high: {
    word: "high",
    className: `${BASE} border-red-500 bg-red-50 text-red-800 dark:border-red-400 dark:bg-red-950 dark:text-red-200`,
  },
  caution: {
    word: "caution",
    className: `${BASE} border-amber-500 bg-amber-50 text-amber-900 dark:border-amber-400 dark:bg-amber-950 dark:text-amber-200`,
  },
  info: {
    word: "info",
    className: `${BASE} border-zinc-400 bg-zinc-50 text-zinc-700 dark:border-zinc-500 dark:bg-zinc-900 dark:text-zinc-300`,
  },
};

const RANK: Record<string, number> = { high: 3, caution: 2, info: 1 };

/** Word and style for a severity; null for "" or anything unknown (never echoed). */
export function riskDisplay(severity: string | undefined | null): RiskDisplay | null {
  if (typeof severity !== "string" || !Object.hasOwn(DISPLAY, severity)) return null;
  return DISPLAY[severity];
}

/** Well-formed labels only, ordered high, caution, info, then id (the server's order). */
export function sortRiskLabels(labels: RiskLabel[]): RiskLabel[] {
  return labels
    .filter(
      (l) =>
        l && typeof l.id === "string" && typeof l.reason === "string" && riskDisplay(l.severity) !== null,
    )
    .sort((a, b) => RANK[b.severity] - RANK[a.severity] || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}
