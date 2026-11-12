import { clean } from "./text";

/** UTC calendar date (YYYY-MM-DD) of an ISO timestamp; "" if missing or invalid. */
export function formatDate(iso: string | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString().slice(0, 10);
}

const isCount = (n: unknown): n is number => typeof n === "number" && Number.isInteger(n) && n >= 0;

/**
 * "12 downloads" (zero is "0 downloads", never blank); "" when the registry
 * sent no usable count. Counts are raw request counts that anyone can inflate.
 */
export function formatDownloads(n: number | undefined): string {
  if (!isCount(n)) return "";
  return `${n.toLocaleString("en-US")} ${n === 1 ? "download" : "downloads"}`;
}

/**
 * Bundle totals from its versions' counts, removed versions left out; null
 * when the registry sent no counts at all (older server).
 */
export function downloadTotals(
  vs: { downloads?: number; downloads30d?: number; removed?: boolean }[],
): { total: number; last30d: number } | null {
  if (!vs.some((v) => isCount(v.downloads))) return null;
  let total = 0;
  let last30d = 0;
  for (const v of vs) {
    if (v.removed === true) continue;
    if (isCount(v.downloads)) total += v.downloads;
    if (isCount(v.downloads30d)) last30d += v.downloads30d;
  }
  return { total, last30d };
}

/** "sha256:" plus the first 12 hex characters, cleaned and bounded. */
export function shortDigest(d: string | undefined): string {
  const c = clean(d);
  const i = c.indexOf(":");
  if (i < 0) return c.slice(0, 19);
  return c.slice(0, i + 1 + 12);
}

export type VersionState = { kind: "live" | "yanked" | "removed"; label: string };

const MAX_REASON = 120;

/** Release state for the history table; a removal reason is admin text, so cleaned and bounded. */
export function versionState(v: { yanked: boolean; removed?: boolean; removedReason?: string }): VersionState {
  if (v.removed === true) {
    const reason = Array.from(clean(v.removedReason)).slice(0, MAX_REASON).join("");
    return { kind: "removed", label: `removed: ${reason || "(no reason given)"}` };
  }
  if (v.yanked) return { kind: "yanked", label: "yanked" };
  return { kind: "live", label: "live" };
}
