// Server-side half of "Report this bundle": form parsing, the visitor IP, and
// the call to the registry. Reads API_URL, so it must never reach the browser.
import { isIP } from "node:net";
import { baseUrl, validSegment } from "./api";
import { DETAILS_MAX, REASONS, VERSION_MAX } from "./report-shared";
import type { Reason, ReportField, ReportState } from "./report-shared";

export { DETAILS_MAX, REASONS } from "./report-shared";

export type ReportBody = { version: string; reason: Reason; details: string };

export type Parsed =
  | { ok: true; body: ReportBody }
  | { ok: false; errors: Partial<Record<ReportField, string>> };

const FIELD_TEXT: Record<ReportField, string> = {
  reason: "Choose a reason.",
  version: "That version does not exist for this bundle.",
  details: `Details are required when the reason is "Something else", and must be at most ${DETAILS_MAX} characters.`,
};

// Same shape the CLI accepts for a version (cli/ref.go), including + build metadata.
const VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]*$/;

function str(v: FormDataEntryValue | null): string {
  return typeof v === "string" ? v : "";
}

/** Validates the form with the registry's own rules and builds the API body. */
export function parseReportForm(f: FormData): Parsed {
  const reason = str(f.get("reason"));
  const version = str(f.get("version")).trim();
  const details = str(f.get("details")).trim();
  const errors: Partial<Record<ReportField, string>> = {};
  if (!(REASONS as readonly string[]).includes(reason)) errors.reason = FIELD_TEXT.reason;
  if (version && (version.length > VERSION_MAX || !VERSION_RE.test(version) || version.includes(".."))) errors.version = FIELD_TEXT.version;
  if (Array.from(details).length > DETAILS_MAX || (reason === "other" && details === "")) {
    errors.details = FIELD_TEXT.details;
  }
  if (Object.keys(errors).length > 0) return { ok: false, errors };
  return { ok: true, body: { version, reason: reason as Reason, details } };
}

/**
 * The visitor's address, from the one header the CDN in front of the site sets
 * itself (default CF-Connecting-IP), or null. X-Forwarded-For is never read: a
 * visitor can put anything in it. Only a single, syntactically valid IP is
 * accepted, so the value is safe to put in a header.
 */
export function visitorIp(get: (name: string) => string | null, header = "cf-connecting-ip"): string | null {
  const v = (get(header) ?? "").trim();
  return v !== "" && isIP(v) !== 0 ? v : null;
}

/** The header name to read; CLIENT_IP_HEADER is the backend's own knob. */
export function ipHeaderName(): string {
  return (process.env.CLIENT_IP_HEADER ?? "").trim() || "cf-connecting-ip";
}

const TIMEOUT_MS = 5000;

/**
 * POSTs the report to the registry from the server. When the visitor's IP is
 * known it is sent as the only X-Forwarded-For entry (the backend with
 * TRUSTED_PROXY=true keys its limiter on the rightmost entry) and as
 * CF-Connecting-IP (for a backend configured with CLIENT_IP_HEADER). Without
 * it nothing is sent, so the backend sees this server's own address and the
 * limit becomes one shared bucket for the whole site.
 */
export async function sendReportDetailed(
  owner: string,
  name: string,
  body: ReportBody,
  ip: string | null,
): Promise<{ status: number; error: string }> {
  if (!validSegment(owner) || !validSegment(name)) return { status: 404, error: "" };
  const headers: Record<string, string> = { "Content-Type": "application/json", Accept: "application/json" };
  if (ip) {
    headers["X-Forwarded-For"] = ip;
    headers["CF-Connecting-IP"] = ip;
  }
  try {
    const res = await fetch(`${baseUrl()}/v1/bundles/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/report`, {
      method: "POST",
      cache: "no-store",
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers,
      body: JSON.stringify(body),
    });
    let error = "";
    if (res.status === 400) {
      try {
        error = String(((await res.json()) as { error?: unknown }).error ?? "");
      } catch {}
    }
    return { status: res.status, error };
  } catch {
    return { status: 0, error: "" };
  }
}

export async function sendReport(owner: string, name: string, body: ReportBody, ip: string | null): Promise<number> {
  return (await sendReportDetailed(owner, name, body, ip)).status;
}

export const OK_TEXT = "Thanks. The registry operator will review this.";

/**
 * Maps the registry's status to what the page shows. Fixed texts only: a
 * registry error message selects a field but is never displayed.
 */
export function messageFor(status: number, registryError = ""): ReportState {
  if (status === 201 || status === 202) return { status: "ok", message: OK_TEXT };
  if (status === 429) {
    return { status: "error", message: "Too many reports from your network. Please try again later." };
  }
  if (status === 400) {
    const field = (["reason", "details", "version"] as const).find((f) => registryError.startsWith(f)) ?? "version";
    return { status: "error", message: "Please check the form.", errors: { [field]: FIELD_TEXT[field] } };
  }
  if (status === 404) return { status: "error", message: "Reporting is not available for this bundle right now." };
  return { status: "error", message: "Could not send the report. Please try again later." };
}
