"use client";

import { useActionState, useState } from "react";
import { DETAILS_MAX, IDLE, REASONS, REASON_LABELS, VERSION_MAX } from "@/lib/report-shared";
import type { ReportState } from "@/lib/report-shared";

const field =
  "mt-1 w-full rounded border border-zinc-400 bg-transparent px-2 py-1 text-sm focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 dark:border-zinc-600 dark:focus-visible:outline-blue-400";

/**
 * "Report this bundle". A native <details> disclosure around a form whose
 * action is a Server Action, so it also submits without JavaScript (the page
 * is then re-rendered with the result). Typed text lives only in the browser;
 * the result shown afterwards is a fixed message.
 */
export function ReportForm({
  action,
  defaultVersion,
}: {
  action: (prev: ReportState, formData: FormData) => Promise<ReportState>;
  defaultVersion: string;
}) {
  const [state, formAction, pending] = useActionState(action, IDLE);
  const [details, setDetails] = useState("");
  const e = state.errors ?? {};
  const done = state.status === "ok";
  return (
    <section className="mt-10" aria-labelledby="report-heading">
      <details open={state.status !== "idle" || undefined} className="rounded border border-zinc-300 p-4 dark:border-zinc-700">
        <summary
          id="report-heading"
          className="cursor-pointer text-sm font-semibold focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600"
        >
          Report this bundle
        </summary>
        <p className="mt-3 text-sm text-zinc-600 dark:text-zinc-400">
          Tell the registry operator about malware, exposed secrets or impersonation. A report is reviewed by
          hand and removes nothing by itself. You do not need an account.
        </p>
        <div aria-live="polite" role="status">
          {state.message && (
            <p
              className={
                "mt-3 rounded border p-2 text-sm " +
                (done
                  ? "border-green-600 text-green-800 dark:text-green-300"
                  : "border-red-400 text-red-800 dark:text-red-300")
              }
            >
              {state.message}
            </p>
          )}
        </div>
        {!done && (
          <form action={formAction} className="mt-4 space-y-4">
            <div>
              <label htmlFor="report-reason" className="text-sm font-medium">
                Reason
              </label>
              <select
                id="report-reason"
                name="reason"
                required
                defaultValue=""
                aria-invalid={e.reason ? true : undefined}
                aria-describedby={e.reason ? "report-reason-err" : undefined}
                className={field}
              >
                <option value="" disabled>
                  Choose a reason
                </option>
                {REASONS.map((r) => (
                  <option key={r} value={r}>
                    {REASON_LABELS[r]}
                  </option>
                ))}
              </select>
              {e.reason && (
                <p id="report-reason-err" className="mt-1 text-sm text-red-800 dark:text-red-300">
                  {e.reason}
                </p>
              )}
            </div>
            <div>
              <label htmlFor="report-version" className="text-sm font-medium">
                Version <span className="font-normal text-zinc-500">(optional; empty means the whole bundle)</span>
              </label>
              <input
                id="report-version"
                name="version"
                type="text"
                defaultValue={defaultVersion}
                maxLength={VERSION_MAX}
                autoComplete="off"
                aria-invalid={e.version ? true : undefined}
                aria-describedby={e.version ? "report-version-err" : undefined}
                className={field + " font-mono"}
              />
              {e.version && (
                <p id="report-version-err" className="mt-1 text-sm text-red-800 dark:text-red-300">
                  {e.version}
                </p>
              )}
            </div>
            <div>
              <label htmlFor="report-details" className="text-sm font-medium">
                Details <span className="font-normal text-zinc-500">(required for &quot;Something else&quot;)</span>
              </label>
              <textarea
                id="report-details"
                name="details"
                rows={5}
                value={details}
                onChange={(ev) => setDetails(ev.target.value)}
                aria-invalid={e.details ? true : undefined}
                aria-describedby={"report-details-hint" + (e.details ? " report-details-err" : "")}
                className={field}
              />
              <p id="report-details-hint" className="mt-1 text-xs text-zinc-500">
                Up to {DETAILS_MAX} characters.{" "}
                <span aria-hidden="true">
                  {Array.from(details).length} / {DETAILS_MAX}
                </span>
              </p>
              {e.details && (
                <p id="report-details-err" className="mt-1 text-sm text-red-800 dark:text-red-300">
                  {e.details}
                </p>
              )}
            </div>
            <button
              type="submit"
              disabled={pending}
              className="rounded border border-zinc-500 px-3 py-1 text-sm font-medium focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 disabled:opacity-60 dark:border-zinc-500 dark:focus-visible:outline-blue-400"
            >
              {pending ? "Sending..." : "Send report"}
            </button>
          </form>
        )}
      </details>
    </section>
  );
}
