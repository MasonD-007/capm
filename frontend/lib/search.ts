// Home-page search helpers. The API caps q at 100 characters (runes) and
// pages at limit/offset; these mirror that so the page never sends a request
// the API would reject.

export const MAX_QUERY = 100;
export const PAGE_SIZE = 50;
const MAX_OFFSET = 1_000_000;

type Param = string | string[] | undefined;

const first = (p: Param): string | undefined => (Array.isArray(p) ? p[0] : p);

/** Trim, cap at MAX_QUERY code points, trim again. */
export function normalizeQuery(raw: Param): string {
  const s = (first(raw) ?? "").trim();
  return Array.from(s).slice(0, MAX_QUERY).join("").trim();
}

/** A non-negative integer offset; anything else is 0. */
export function parseOffset(raw: Param): number {
  const s = first(raw);
  if (s === undefined || !/^\d{1,7}$/.test(s)) return 0;
  const n = Number(s);
  return n <= MAX_OFFSET ? n : 0;
}

/** A full page came back, so another may exist. */
export function hasNextPage(count: number): boolean {
  return count >= PAGE_SIZE;
}

export function prevOffset(offset: number): number {
  return Math.max(0, offset - PAGE_SIZE);
}

/** The orders the list endpoint offers; "name" (A to Z) is the default. */
export type SortMode = "name" | "recent" | "downloads";

/** The home-page views, in display order. Download counts are raw request counts, not a quality signal. */
export const SORT_VIEWS: { mode: SortMode; label: string }[] = [
  { mode: "name", label: "A to Z" },
  { mode: "recent", label: "Recently published" },
  { mode: "downloads", label: "Most downloaded (30 days)" },
];

/** The sort query parameter; anything unknown (or absent) is the default order. */
export function parseSort(raw: Param): SortMode {
  const s = first(raw);
  return s === "recent" || s === "downloads" ? s : "name";
}

/** Home-page URL for a query, offset and order; q, sort and offset are omitted when empty/default/zero. */
export function homeHref(q: string, offset: number, sort: SortMode = "name"): string {
  const p = new URLSearchParams();
  if (q) p.set("q", q);
  if (sort !== "name") p.set("sort", sort);
  if (offset > 0) p.set("offset", String(offset));
  const s = p.toString();
  return s ? `/?${s}` : "/";
}

/** Link that switches the home page to a view, keeping the query and restarting at the first page. */
export function sortHref(q: string, sort: SortMode): string {
  return homeHref(q, 0, sort);
}
