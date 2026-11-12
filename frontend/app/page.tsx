import Link from "next/link";
import { Suspense } from "react";
import { ApiError, listBundles } from "@/lib/api";
import {
  MAX_QUERY,
  PAGE_SIZE,
  hasNextPage,
  homeHref,
  normalizeQuery,
  parseOffset,
  parseSort,
  prevOffset,
} from "@/lib/search";
import { clean } from "@/lib/text";
import { BundleRows, LoadError, Pager, SortNav } from "./_components/bundle-rows";

type Props = {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
};

export default function Home(props: Props) {
  return (
    <main className="mx-auto w-full max-w-3xl px-6 py-12">
      <h1 className="text-3xl font-semibold tracking-tight">capm</h1>
      <p className="mt-2 text-zinc-600 dark:text-zinc-400">
        A registry for agent bundles. Browse what a bundle declares before you run it.
      </p>
      <pre className="mt-4 overflow-x-auto rounded bg-zinc-100 p-3 font-mono text-sm dark:bg-zinc-900">
        <code>curl -fsSL https://capm.masondrake.dev/install.sh | sh</code>
      </pre>
      {/* A plain GET form: works without JavaScript. It sits outside the
          Suspense boundary so it is part of the static shell. */}
      <form action="/" method="get" role="search" className="mt-6 flex gap-2">
        <label htmlFor="q" className="sr-only">
          Search bundles by owner, name or description
        </label>
        <input
          id="q"
          name="q"
          type="search"
          maxLength={MAX_QUERY}
          autoComplete="off"
          placeholder="Search bundles"
          className="min-w-0 flex-1 rounded border border-zinc-400 bg-transparent px-3 py-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 dark:border-zinc-600 dark:focus-visible:outline-blue-400"
        />
        <button
          type="submit"
          className="rounded border border-zinc-900 bg-zinc-900 px-4 py-2 text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 dark:border-zinc-100 dark:bg-zinc-100 dark:text-black dark:focus-visible:outline-blue-400"
        >
          Search
        </button>
      </form>
      <Suspense fallback={<p className="mt-8 text-zinc-500">Loading bundles...</p>}>
        <Results {...props} />
      </Suspense>
    </main>
  );
}

async function Results({ searchParams }: Props) {
  const sp = await searchParams;
  const q = normalizeQuery(sp.q);
  const offset = parseOffset(sp.offset);
  // An unknown ?sort= falls back to the default A to Z view (and is marked as such).
  const sort = parseSort(sp.sort);

  let bundles;
  try {
    bundles = await listBundles({ q, sort, limit: PAGE_SIZE, offset });
  } catch (e) {
    return <LoadError detail={e instanceof ApiError && e.status > 0 ? ` (status ${e.status})` : ""} />;
  }

  const prev = offset > 0 ? homeHref(q, prevOffset(offset), sort) : null;
  const next = hasNextPage(bundles.length) ? homeHref(q, offset + PAGE_SIZE, sort) : null;
  const views = <SortNav q={q} sort={sort} />;

  if (bundles.length === 0) {
    if (offset > 0) {
      return (
        <>
          {views}
          <p className="mt-8 text-zinc-500">No more results.</p>
          <Pager prev={prev} next={null} />
        </>
      );
    }
    return q ? (
      <>
        {views}
        <div className="mt-8" role="status">
          <p className="text-zinc-700 dark:text-zinc-300">
            No bundles match <q className="font-mono">{clean(q)}</q>.
          </p>
          <p className="mt-2 text-sm text-zinc-500">
            Search looks at owner, bundle name and the latest version&apos;s description.{" "}
            <Link href="/" className="underline underline-offset-2">
              Show all bundles
            </Link>
          </p>
        </div>
      </>
    ) : (
      <p className="mt-8 text-zinc-500">No bundles have been published yet.</p>
    );
  }
  return (
    <>
      {views}
      {q && (
        <p className="mt-8 text-sm text-zinc-600 dark:text-zinc-400" role="status">
          {offset > 0 ? `Results ${offset + 1} to ${offset + bundles.length}` : "Results"} for{" "}
          <q className="font-mono">{clean(q)}</q>.{" "}
          <Link href="/" className="underline underline-offset-2">
            Clear search
          </Link>
        </p>
      )}
      <BundleRows bundles={bundles} />
      {bundles.some((b) => b.downloads30d !== undefined) && (
        <p className="mt-4 text-xs text-zinc-500">
          Download counts are raw request counts: anyone can inflate them, and they say nothing about a
          bundle&apos;s safety or quality.
        </p>
      )}
      <Pager prev={prev} next={next} />
    </>
  );
}
