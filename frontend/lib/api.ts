// Typed client for the capm registry API. Server-side only: it reads API_URL,
// which is not NEXT_PUBLIC_ and so is never bundled for the browser. Everything
// returned is untrusted registry data; callers must render it as text.

export type Mount = { path: string; mode: string };
export type Secret = { name: string; description?: string };
export type MCPEntry = { name: string; url: string; host: string; secret?: string };

/** A shared caveat from manifest/notices.go; render `text` verbatim. */
export type Notice = { section: "network" | "baseAgent" | "context" | string; text: string };

// Mirrors manifest.Summary (manifest/summary.go).
export type Summary = {
  egress: string[];
  mounts: Mount[];
  secrets: Secret[];
  mcp: MCPEntry[];
  base: { agent: string; version?: string };
  model: unknown;
  context: string[];
  /** The base agent kit's own egress; empty with baseHostsBroad when not enumerated. */
  baseHosts?: string[];
  baseHostsBroad?: boolean;
  notices?: Notice[];
};

/** Texts of the summary's notices for one section, in server order. */
export function noticeTexts(s: Summary, section: string): string[] {
  return (s.notices ?? []).filter((n) => n?.section === section).map((n) => n.text);
}

export type BundleListItem = {
  ownerId: number;
  owner: string;
  name: string;
  /** Latest non-yanked version; empty when every version is yanked. */
  latest: string;
  /** Author's description of that version (unverified). */
  description: string;
};

export type BundleVersion = {
  version: string;
  digest: string;
  yanked: boolean;
  createdAt: string;
  /**
   * An admin took this version down. The registry withholds its manifest, so
   * `manifest` and `summary` are empty for removed versions: never render
   * install commands or permissions for them. Absent on older servers.
   */
  removed?: boolean;
  /** The admin's reason; untrusted text. */
  removedReason?: string;
  manifest: { metadata: { name: string; version: string; description?: string } };
  summary: Summary;
};

/** True when an admin removed the version (false on servers that predate removal). */
export function isRemoved(v: { removed?: boolean }): boolean {
  return v.removed === true;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
  get notFound() {
    return this.status === 404;
  }
}

const TIMEOUT_MS = 5000;

function baseUrl(): string {
  const u =
    process.env.API_URL ?? process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
  return u.replace(/\/+$/, "");
}

async function get<T>(path: string): Promise<T> {
  let res: Response;
  try {
    res = await fetch(baseUrl() + path, {
      cache: "no-store",
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { Accept: "application/json" },
    });
  } catch {
    throw new ApiError(0, "registry unreachable");
  }
  if (!res.ok) {
    throw new ApiError(res.status, `registry returned ${res.status}`);
  }
  try {
    return (await res.json()) as T;
  } catch {
    throw new ApiError(502, "registry returned invalid JSON");
  }
}

export function listBundles(): Promise<BundleListItem[]> {
  return get<BundleListItem[]>("/v1/bundles");
}

const SEGMENT = /^[A-Za-z0-9._-]+$/;

/** Owner/name must be plain path segments: `.`/`..` would collapse onto other API routes. */
function validSegment(s: string): boolean {
  return SEGMENT.test(s) && s !== "." && s !== "..";
}

export async function getBundle(owner: string, name: string): Promise<BundleVersion[]> {
  if (!validSegment(owner) || !validSegment(name)) {
    throw new ApiError(404, "bundle not found");
  }
  return get<BundleVersion[]>(
    `/v1/bundles/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`,
  );
}

type Parsed = { nums: number[]; pre: string[] };

function parse(v: string): Parsed | null {
  const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$/.exec(v);
  if (!m) return null;
  return { nums: [+m[1], +m[2], +m[3]], pre: m[4] ? m[4].split(".") : [] };
}

function cmp(a: Parsed, b: Parsed): number {
  for (let i = 0; i < 3; i++) if (a.nums[i] !== b.nums[i]) return a.nums[i] - b.nums[i];
  if (!a.pre.length || !b.pre.length) return b.pre.length - a.pre.length;
  for (let i = 0; i < Math.max(a.pre.length, b.pre.length); i++) {
    const x = a.pre[i], y = b.pre[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xn = /^\d+$/.test(x), yn = /^\d+$/.test(y);
    if (xn && yn) { if (+x !== +y) return +x - +y; }
    else if (xn !== yn) return xn ? -1 : 1;
    else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** Highest non-yanked, non-removed version, releases before prereleases (as the registry's /resolve does). */
export function latestNonYanked<T extends { version: string; yanked: boolean; removed?: boolean }>(
  vs: T[],
): T | undefined {
  let rel: [T, Parsed] | undefined;
  let pre: [T, Parsed] | undefined;
  for (const v of vs) {
    if (v.yanked || isRemoved(v)) continue;
    const p = parse(v.version);
    if (!p) continue;
    if (p.pre.length === 0) {
      if (!rel || cmp(p, rel[1]) > 0) rel = [v, p];
    } else if (!pre || cmp(p, pre[1]) > 0) pre = [v, p];
  }
  return (rel ?? pre)?.[0];
}
