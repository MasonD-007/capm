import Link from "next/link";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { ApiError, getBundle, latestNonYanked, noticeTexts } from "@/lib/api";
import type { BundleVersion } from "@/lib/api";
import { cliCommands } from "@/lib/commands";
import { clean } from "@/lib/text";

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

  const selected = wanted
    ? versions.find((v) => v.version === wanted)
    : (latestNonYanked(versions) ?? versions[0]);
  if (!selected) notFound();

  const id = `${clean(owner)}/${clean(name)}`;
  const description = clean(selected.manifest?.metadata?.description);
  const cmd = cliCommands(owner, name, selected.version);
  return (
    <>
      <h1 className="mt-4 font-mono text-3xl font-semibold tracking-tight">{id}</h1>

      <section className="mt-6">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-500">
          Inspect, then run (version {clean(selected.version)})
        </h2>
        <pre className="mt-2 overflow-x-auto rounded bg-zinc-100 p-3 font-mono text-sm dark:bg-zinc-900">
          <code>
            {cmd.inspect}
            {"\n"}
            {cmd.run}
          </code>
        </pre>
        <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
          <code className="font-mono">capm run</code> needs your own model endpoint, and{" "}
          <code className="font-mono">--allow-unenforced-egress</code> to accept the egress status
          shown under Network below.
        </p>
      </section>

      <section className="mt-8">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-500">Versions</h2>
        <ul className="mt-2 flex flex-wrap gap-2">
          {versions.map((v) => (
            <li key={v.version}>
              <Link
                href={`?v=${encodeURIComponent(v.version)}`}
                aria-current={v.version === selected.version ? "page" : undefined}
                className={`inline-block rounded border px-2 py-1 font-mono text-sm ${
                  v.version === selected.version
                    ? "border-zinc-900 bg-zinc-900 text-white dark:border-zinc-100 dark:bg-zinc-100 dark:text-black"
                    : "border-zinc-300 dark:border-zinc-700"
                } ${v.yanked ? "line-through" : ""}`}
              >
                {clean(v.version)}
                {v.yanked && <span className="ml-1 no-underline">(yanked)</span>}
              </Link>
            </li>
          ))}
        </ul>
        {selected.yanked && (
          <p className="mt-3 rounded border border-amber-400 p-3 text-sm text-amber-800 dark:text-amber-300">
            This version has been yanked by its owner and is not offered by default. Pinning it
            exactly still works.
          </p>
        )}
        <p className="mt-3 break-all font-mono text-xs text-zinc-500">
          Version {clean(selected.version)}, digest {clean(selected.digest)}
        </p>
      </section>

      {description && (
        <section className="mt-8 rounded border border-dashed border-zinc-300 p-4 dark:border-zinc-700">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-500">
            Author&apos;s description (unverified)
          </h2>
          <p className="mt-2 whitespace-pre-wrap text-zinc-700 dark:text-zinc-300">{description}</p>
        </section>
      )}

      <Permissions s={selected.summary} />
    </>
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
