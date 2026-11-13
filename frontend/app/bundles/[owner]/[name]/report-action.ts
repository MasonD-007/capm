"use server";

import { headers } from "next/headers";
import { ipHeaderName, messageFor, parseReportForm, sendReportDetailed, visitorIp } from "@/lib/report";
import type { ReportState } from "@/lib/report-shared";

/**
 * Server Action behind the "Report this bundle" form. owner and name are bound
 * by the page (and re-validated before any request); everything in formData is
 * untrusted. The result carries fixed texts only: nothing the visitor typed,
 * and nothing the registry said, is sent back to the page.
 *
 * CSRF: Next.js only runs a Server Action for a POST whose Origin matches the
 * Host / X-Forwarded-Host (serverActions.allowedOrigins is not configured, so
 * same origin only); see docs/security-notes.md.
 */
export async function submitReport(
  owner: string,
  name: string,
  _prev: ReportState,
  formData: FormData,
): Promise<ReportState> {
  const parsed = parseReportForm(formData);
  if (!parsed.ok) {
    return { status: "error", message: "Please check the form.", errors: parsed.errors };
  }
  const h = await headers();
  const ip = visitorIp((n) => h.get(n), ipHeaderName());
  const { status, error } = await sendReportDetailed(owner, name, parsed.body, ip);
  return messageFor(status, error);
}
