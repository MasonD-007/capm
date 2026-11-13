import Link from "next/link";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { ApiError, getBundle, getVersionDetail, isRemoved, latestNonYanked, noticeTexts } from "@/lib/api";
import type { BundleVersion, RiskLabel } from "@/lib/api";
import { cliCommands } from "@/lib/commands";
import { downloadTotals, formatDate, formatDownloads, shortDigest, versionState } from "@/lib/format";
import { Readme } from "@/lib/readme";
import { riskDisplay, sortRiskLabels } from "@/lib/risk";
import { clean } from "@/lib/text";
import { CopyButton } from "../../../_components/copy-button";
import { ownerHref } from "../../../_components/bundle-rows";
import { ReportForm } from "../../../_components/report-form";
import { submitReport } from "./report-action";

type Props = {
  params: Promise<{ owner: string; name: string }>;
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
};

export default function BundlePage(props: Props) {
  return (
    <main className="mx-auto w-full max-w-3xl px-6 py-12">
      <Link href="/" className="text-sm text-zinc-500 hover:underline">
        &larr; All bundles
      </Link>
      <Suspense fallback={<p className="mt-8 text-zinc-500">Loading bundle...</p>}>
        <Detail {...props} />
      </Suspense>
    </main>
  );
}

async function Detail({ params, searchParams }: Props) {
  const { owner, name } = await params;
  const sp = await searchParams;
  const wanted = typeof sp.v === "string" ? sp.v : undefined;

  let versions: BundleVersion[];
  try {
    versions = await getBundle(owner, name);
  } catch (e) {
    if (e instanceof ApiError && e.notFound) notFound();
    return (
      <p role="alert" className="mt-8 rounded border border-red-300 p-4 text-red-700 dark:text-red-400">
        Could not load this bundle from the registry. Try again shortly.
      </p>
    );
  }
  if (versions.length === 0) notFound();

  // An explicit ?v= that matches nothing is a not-found for that version, never
  // a silent fallback to another one. Without ?v=, the latest installable
  // version (what `capm run` resolves), else the newest listed.
  const latest = latestNonYanked(versions);
  const selected = wanted ? versions.find((v) => v.version === wanted) : (latest ?? versions[versions.length - 1]);
  if (!selected) return <VersionNotFound owner={owner} name={name} wanted={wanted!} />;

  const removed = isRemoved(selected);
  const description = clean(selected.manifest?.metadata?.description);
  // A removed version has no manifest to show, and must never be offered for
  // install: skip the command block, description, permissions and README.
  const detail = removed ? null : await getVersionDetail(owner, name, selected.version);
  const riskLabels = detail?.riskLabels ?? null;
  const readme = detail?.readme ?? "";
  const cmd = removed ? null : cliCommands(owner, name, selected.version);
  return (
    <>
      <h1 className="mt-4 break-all font-mono text-3xl font-semibold tracking-tight">
        <Link href={ownerHref(owner)} className="underline-offset-2 hover:underline">
          {clean(owner)}
        </Link>
        /{clean(name)}
      </h1>

      <DownloadTotals versions={versions} />

      {removed && (
        <section role="alert" className="mt-6 rounded border border-red-400 p-4 text-red-800 dark:text-red-300">
          <h2 className="font-semibold">
            Version {clean(selected.version)} was removed by the registry
          </h2>
          <p className="mt-1 whitespace-pre-wrap text-sm">
            Reason (written by a registry admin): {clean(selected.removedReason) || "(none given)"}
          </p>
          <p className="mt-1 text-sm">It cannot be installed, and its version number cannot be reused.</p>
        </section>
      )}

      {cmd && (
        <section className="mt-6" aria-labelledby="commands-heading">
          <h2 id="commands-heading" className="text-sm font-semibold uppercase tracking-wide text-zinc-500">
            Inspect, then run (version {clean(selected.version)})
          </h2>
          <pre className="mt-2 overflow-x-auto rounded bg-zinc-100 p-3 font-mono text-sm dark:bg-zinc-900">
            <code>
              {cmd.inspect}
              {"\n"}
              {cmd.run}
            </code>
          </pre>
          <div className="mt-2 flex flex-wrap gap-2">
            <CopyButton text={cmd.inspect} label="Copy inspect command" />
            <CopyButton text={cmd.run} label="Copy run command" />
          </div>
          <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
            Pinned to this exact version. <code className="font-mono">capm run</code> needs your own
            model endpoint, and <code className="font-mono">--allow-unenforced-egress</code> to accept
            the egress status shown under Network below.
          </p>
        </section>
      )}

      <History versions={versions} selected={selected} latest={latest} />

      {selected.yanked && !removed && (
        <p className="mt-3 rounded border border-amber-400 p-3 text-sm text-amber-800 dark:text-amber-300">
          This version has been yanked by its owner and is not offered by default. Pinning it
          exactly still works.
        </p>
      )}
      <p className="mt-3 break-all font-mono text-xs text-zinc-500">
        Version {clean(selected.version)}, digest {clean(selected.digest)}
      </p>

      {riskLabels && <RiskLabels labels={riskLabels} />}

      {!removed && <Permissions s={selected.summary} />}

      {!removed && description && (
        <section className="mt-10 rounded border border-dashed border-zinc-300 p-4 dark:border-zinc-700">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-500">
            Author&apos;s description (unverified)
          </h2>
          <p className="mt-2 whitespace-pre-wrap text-zinc-700 dark:text-zinc-300">{description}</p>
        </section>
      )}

      {!removed && readme && (
        <section
          className="mt-10 rounded border border-dashed border-zinc-300 p-4 dark:border-zinc-700"
          aria-labelledby="readme-heading"
        >
          <h2 id="readme-heading" className="text-sm font-semibold uppercase tracking-wide text-zinc-500">
            README: from the author, unverified
          </h2>
          <p className="mt-1 text-xs text-zinc-500">
            Written by the bundle&apos;s author and not checked by the registry. Links go to other sites,
            and images are not loaded.
          </p>
          <div className="mt-2 text-zinc-800 dark:text-zinc-200">
            <Readme text={readme} />
          </div>
        </section>
      )}

      <ReportForm action={submitReport.bind(null, owner, name)} defaultVersion={clean(selected.version)} />
    </>
  );
}

// Totals across the bundle's versions that have not been removed. Nothing is
// shown for a registry that does not send counts.
function DownloadTotals({ versions }: { versions: BundleVersion[] }) {
  const t = downloadTotals(versions);
  if (!t) return null;
  return (
    <section className="mt-4" aria-labelledby="downloads-heading">
      <h2 id="downloads-heading" className="sr-only">
        Downloads
      </h2>
      <p className="text-sm text-zinc-700 dark:text-zinc-300">
        <span className="font-medium">{formatDownloads(t.last30d)}</span> in the last 30 days,{" "}
        <span className="font-medium">{formatDownloads(t.total)}</span> all time.
      </p>
      <p className="mt-1 text-xs text-zinc-500">Download counts are raw request counts.</p>
    </section>
  );
}

function VersionNotFound({ owner, name, wanted }: { owner: string; name: string; wanted: string }) {
  return (
    <section role="alert" className="mt-8 rounded border border-amber-400 p-4">
      <h1 className="text-xl font-semibold">Version not found</h1>
      <p className="mt-2">
        <span className="font-mono">
          {clean(owner)}/{clean(name)}
        </span>{" "}
        has no version <q className="font-mono">{Array.from(clean(wanted)).slice(0, 64).join("")}</q>.
      </p>
      <p className="mt-2 text-sm">
        <Link
          href={`/bundles/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`}
          className="underline underline-offset-2"
        >
          Show the latest version and the version history
        </Link>
      </p>
    </section>
  );
}

const STATE_CLASS = {
  live: "",
  yanked: "text-amber-800 dark:text-amber-300",
  removed: "text-red-800 dark:text-red-300",
} as const;

// Facts the registry holds about each release. The digest is shortened here;
// the selected version's full digest is shown below the table.
function History({
  versions,
  selected,
  latest,
}: {
  versions: BundleVersion[];
  selected: BundleVersion;
  latest: BundleVersion | undefined;
}) {
  const rows = [...versions].reverse();
  return (
    <section className="mt-8" aria-labelledby="history-heading">
      <h2 id="history-heading" className="text-sm font-semibold uppercase tracking-wide text-zinc-500">
        Version history
      </h2>
      <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
        Showing version <span className="font-mono">{clean(selected.version)}</span>
        {selected.version === latest?.version ? " (latest installable)" : ""}. Choose a version to see
        its permissions and pinned commands.
      </p>
      <div
        className="mt-2 overflow-x-auto rounded border border-zinc-200 focus-visible:outline-2 focus-visible:outline-blue-600 dark:border-zinc-800"
        role="region"
        aria-label="Version history table"
        tabIndex={0}
      >
        <table className="w-full min-w-max text-left text-sm">
          <thead className="border-b border-zinc-200 text-zinc-500 dark:border-zinc-800">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">Version</th>
              <th scope="col" className="px-3 py-2 font-medium">Published</th>
              <th scope="col" className="px-3 py-2 font-medium">State</th>
              <th scope="col" className="px-3 py-2 font-medium">Downloads</th>
              <th scope="col" className="px-3 py-2 font-medium">Digest</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
            {rows.map((v) => {
              const st = versionState(v);
              const current = v.version === selected.version;
              return (
                <tr key={v.version} className={current ? "bg-zinc-100 dark:bg-zinc-900" : ""}>
                  <td className="px-3 py-2 font-mono">
                    <Link
                      href={`?v=${encodeURIComponent(v.version)}`}
                      aria-current={current ? "page" : undefined}
                      className="underline underline-offset-2 focus-visible:outline-2 focus-visible:outline-blue-600"
                    >
                      {clean(v.version)}
                    </Link>
                  </td>
                  <td className="px-3 py-2 whitespace-nowrap">{formatDate(v.createdAt)}</td>
                  <td className="px-3 py-2">
                    <span className={STATE_CLASS[st.kind]}>{st.label}</span>
                  </td>
                  <td className="px-3 py-2 whitespace-nowrap tabular-nums">
                    {v.removed === true ? "-" : (v.downloads?.toLocaleString("en-US") ?? "")}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs whitespace-nowrap">{shortDigest(v.digest)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Block({ title, items, notes = [] }: { title: string; items: string[]; notes?: string[] }) {
  return (
    <div className="mt-5">
      <h3 className="font-medium">{title}</h3>
      <Notes texts={notes} />
      {items.length === 0 ? (
        <p className="mt-1 pl-4 text-zinc-500">(none)</p>
      ) : (
        <ul className="mt-1 pl-4 font-mono text-sm">
          {items.map((it, i) => (
            <li key={i} className="break-all">
              {it}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Notes({ texts }: { texts: string[] }) {
  return (
    <>
      {texts.map((t, i) => (
        <p
          key={i}
          role="note"
          className="mt-1 ml-4 rounded border border-amber-400 px-2 py-1 text-sm text-amber-800 dark:text-amber-300"
        >
          {clean(t)}
        </p>
      ))}
    </>
  );
}

// Same sections as manifest.Summary.Render() (manifest/summary.go). Only the
// API's `summary` field is rendered here, and every caveat comes from its
// `notices` (manifest/notices.go); never hand-copy those texts here.
function Permissions({ s }: { s: BundleVersion["summary"] }) {
  const base = clean(s.base?.agent) + (s.base?.version ? " " + clean(s.base.version) : "");
  const baseHosts = (s.baseHosts ?? []).map(clean);
  return (
    <section className="mt-10">
      <h2 className="text-xl font-semibold">Declared permissions</h2>
      <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
        This is what the bundle declares. <code className="font-mono">capm inspect</code> shows the
        same summary locally.
      </p>

      <Block
        title="Network (declared bundle egress, port 443; the base agent's hosts and your model endpoint are listed separately below)"
        notes={noticeTexts(s, "network")}
        items={s.egress.map(clean)}
      />
      <Block
        title="Files (mounted from your machine)"
        items={s.mounts.map((m) => `${clean(m.path)} (${clean(m.mode)})`)}
      />
      <Block
        title="Secrets (you will be asked to provide these)"
        items={s.secrets.map((x) =>
          x.description ? `${clean(x.name)}: ${clean(x.description)}` : clean(x.name),
        )}
      />
      <Block
        title="MCP servers (reached via the host MCP gateway, not sandbox egress)"
        items={s.mcp.map(
          (c) =>
            `${clean(c.name)}: ${clean(c.url)} (host ${clean(c.host)})` +
            (c.secret ? ` using secret ${clean(c.secret)}` : ""),
        )}
      />

      <Block
        title={`Base agent: ${base} (its own sbx egress, in addition to the bundle's)`}
        notes={noticeTexts(s, "baseAgent")}
        items={
          baseHosts.length > 0
            ? baseHosts
            : s.baseHostsBroad
              ? ["(a broad list, not enumerated by capm)"]
              : []
        }
      />

      <p className="mt-5">
        <span className="font-medium">Context files (read by the agent; not verified): </span>
        <span className="font-mono text-sm break-all">
          {s.context.length === 0 ? "(none)" : s.context.map(clean).join(", ")}
        </span>
      </p>
      {s.context.length > 0 && <Notes texts={noticeTexts(s, "context")} />}
      <p className="mt-2 font-medium">
        Model endpoint: supplied by you (not part of the egress list)
      </p>
    </section>
  );
}

// Labels are computed by the registry from the declared manifest
// (manifest/risk.go); `capm inspect` recomputes them locally. They state
// exposure, not a review, and an empty list is not an endorsement.
function RiskLabels({ labels }: { labels: RiskLabel[] }) {
  const sorted = sortRiskLabels(labels);
  return (
    <section className="mt-10" aria-labelledby="risk-labels-heading">
      <h2 id="risk-labels-heading" className="text-xl font-semibold">
        Risk labels
      </h2>
      <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
        Computed from the declared manifest; not a review. They describe how much the bundle says it
        can reach, and what is declared is not enforced yet. <code className="font-mono">capm inspect</code>{" "}
        recomputes them locally.
      </p>
      {sorted.length === 0 ? (
        <p className="mt-3 text-zinc-500">(no risk labels apply; this is not an endorsement)</p>
      ) : (
        <ul className="mt-3 space-y-2">
          {sorted.map((l, i) => {
            const d = riskDisplay(l.severity)!;
            return (
              <li key={`${l.id}-${i}`} className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                <span className={d.className}>{d.word}</span>
                <span className="font-mono text-sm text-zinc-500">{clean(l.id)}</span>
                <span className="break-words">{clean(l.reason)}</span>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
