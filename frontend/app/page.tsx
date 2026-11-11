import Link from "next/link";
import { Suspense } from "react";
import { ApiError, listBundles } from "@/lib/api";
import { clean } from "@/lib/text";

export default function Home() {
  return (
    <main className="mx-auto w-full max-w-3xl px-6 py-12">
      <h1 className="text-3xl font-semibold tracking-tight">capm</h1>
      <p className="mt-2 text-zinc-600 dark:text-zinc-400">
        A registry for agent bundles. Browse what a bundle declares before you run it.
      </p>
      <Suspense fallback={<p className="mt-8 text-zinc-500">Loading bundles...</p>}>
        <BundleList />
      </Suspense>
    </main>
  );
}

async function BundleList() {
  let bundles;
  try {
    bundles = await listBundles();
  } catch (e) {
    const detail = e instanceof ApiError && e.status > 0 ? ` (status ${e.status})` : "";
    return (
      <p role="alert" className="mt-8 rounded border border-red-300 p-4 text-red-700 dark:text-red-400">
        Could not load bundles from the registry{detail}. Try again shortly.
      </p>
    );
  }
  if (bundles.length === 0) {
    return <p className="mt-8 text-zinc-500">No bundles have been published yet.</p>;
  }
  return (
    <ul className="mt-8 divide-y divide-zinc-200 dark:divide-zinc-800">
      {bundles.map((b) => (
        <li key={`${b.owner}/${b.name}`} className="py-4">
          <Link
            href={`/bundles/${encodeURIComponent(b.owner)}/${encodeURIComponent(b.name)}`}
            className="font-mono text-lg font-medium underline-offset-2 hover:underline"
          >
            {clean(b.owner)}/{clean(b.name)}
          </Link>
          <span className="ml-3 text-sm text-zinc-500">
            {b.latest ? `latest ${clean(b.latest)}` : "no installable version (all yanked)"}
          </span>
          {b.description && (
            <p className="mt-1 text-zinc-700 dark:text-zinc-300">{clean(b.description)}</p>
          )}
        </li>
      ))}
    </ul>
  );
}
