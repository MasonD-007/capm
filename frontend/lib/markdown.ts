// Pure helpers for rendering an author-supplied README. The README is
// untrusted text: it is never HTML (raw HTML is not enabled in the renderer),
// links keep only http(s) and mailto destinations, and images are never loaded.
import { cleanMultiline } from "./text";

/** The registry stores at most 64 KiB; this is a client-side bound on top of that. */
export const MAX_README_CHARS = 66_000;

const TRUNCATED = "\n\n[README truncated in this display]\n";

const ALLOWED_PROTOCOLS = new Set(["http:", "https:", "mailto:"]);

// C0 controls, space, DEL and C1 controls.
const OUTER = /^[\u0000- \u007f-\u009f]+|[\u0000- \u007f-\u009f]+$/g;
const INNER = /[\u0000- \u007f-\u009f]/;

/**
 * The normalised URL when raw is an absolute http:, https: or mailto: URL;
 * null for everything else (javascript:, data:, vbscript:, file:, relative and
 * protocol-relative references, fragments, malformed input).
 */
export function safeUrl(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  // Browsers ignore leading control characters and spaces, so do the same
  // here; anything left inside the URL that is not a plain character is out.
  const s = raw.replace(OUTER, "");
  if (s === "" || INNER.test(s)) return null;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  return ALLOWED_PROTOCOLS.has(u.protocol) ? u.href : null;
}

/** Cleaned README text, bounded for display. */
export function capReadme(text: unknown): string {
  const s = cleanMultiline(text);
  if (s.length <= MAX_README_CHARS) return s;
  let end = MAX_README_CHARS;
  const last = s.charCodeAt(end - 1);
  if (last >= 0xd800 && last <= 0xdbff) end--; // do not split a surrogate pair
  return s.slice(0, end) + TRUNCATED;
}
