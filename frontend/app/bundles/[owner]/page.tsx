import Link from "next/link";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { ApiError, listBundles } from "@/lib/api";
import { PAGE_SIZE, hasNextPage, parseOffset, prevOffset } from "@/lib/search";
import { clean } from "@/lib/text";
import { BundleRows, LoadError, Pager, ownerHref } from "../../_components/bundle-rows";

type Props = {
  params: Promise<{ owner: string }>;
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
};

export default function OwnerPage(props: Props) {
  return (
    <main className="mx-auto w-full max-w-3xl px-6 py-12">
      <Link href="/" className="text-sm text-zinc-500 hover:underline">
        &larr; All bundles
      </Link>
      <Suspense fallback={<p className="mt-8 text-zinc-500">Loading bundles...</p>}>
        <OwnerBundles {...props} />
      </Suspense>
    </main>
  );
}

async function OwnerBundles({ params, searchParams }: Props) {
  const { owner } = await params;
  const offset = parseOffset((await searchParams).offset);

  let bundles;
  try {
    bundles = await listBundles({ owner, limit: PAGE_SIZE, offset });
  } catch (e) {
    return <LoadError detail={e instanceof ApiError && e.status > 0 ? ` (status ${e.status})` : ""} />;
  }
  // The API answers an unknown owner with an empty list. An owner that
  // exists always has at least one bundle on its first page.
  if (bundles.length === 0 && offset === 0) notFound();

  // The API matches the login case-insensitively; show its canonical spelling.
  const login = clean(bundles[0]?.owner ?? owner);
  const base = ownerHref(bundles[0]?.owner ?? owner);
  const prev = offset > 0 ? (prevOffset(offset) > 0 ? `${base}?offset=${prevOffset(offset)}` : base) : null;
  const next = hasNextPage(bundles.length) ? `${base}?offset=${offset + PAGE_SIZE}` : null;
  return (
    <>
      <h1 className="mt-4 font-mono text-3xl font-semibold tracking-tight">{login}</h1>
      <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">Bundles published by this GitHub user.</p>
      {bundles.length === 0 ? <p className="mt-8 text-zinc-500">No more results.</p> : <BundleRows bundles={bundles} />}
      <Pager prev={prev} next={next} />
    </>
  );
}
