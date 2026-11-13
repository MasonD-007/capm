// Constants and types shared by the report form (a client component) and the
// server-side report code. Nothing here may import server-only modules.

/** Reasons the registry accepts (backend/internal/api/report.go). */
export const REASONS = ["malware", "secrets-exposed", "impersonation", "other"] as const;
export type Reason = (typeof REASONS)[number];

export const REASON_LABELS: Record<Reason, string> = {
  malware: "Malware or a malicious bundle",
  "secrets-exposed": "Exposes secrets or credentials",
  impersonation: "Impersonates someone else",
  other: "Something else (describe it below)",
};

/** Characters allowed in the details text. */
export const DETAILS_MAX = 2000;
/** Longest version string the registry will look up. */
export const VERSION_MAX = 128;

export type ReportField = "reason" | "version" | "details";

/** What the form shows after a submit. Never contains anything the visitor typed. */
export type ReportState = {
  status: "idle" | "ok" | "error";
  message: string;
  errors?: Partial<Record<ReportField, string>>;
};

export const IDLE: ReportState = { status: "idle", message: "" };
