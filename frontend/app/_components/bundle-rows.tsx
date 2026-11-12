import Link from "next/link";
import type { BundleListItem } from "@/lib/api";
import { riskDisplay } from "@/lib/risk";
import { clean } from "@/lib/text";

export function ownerHref(owner: string): string {
  return `/bundles/${encodeURIComponent(owner)}`;
}

/** The list row shared by the home page, search results and owner pages. */
export function BundleRows({ bundles }: { bundles: BundleListItem[] }) {
  return (
    <ul className="mt-6 divide-y divide-zinc-200 dark:divide-zinc-800">
      {bundles.map((b) => {
        const risk = riskDisplay(b.risk);
        return (
          <li key={`${b.owner}/${b.name}`} className="py-4">
            <span className="font-mono text-lg font-medium">
              <Link href={ownerHref(b.owner)} className="underline-offset-2 hover:underline">
                {clean(b.owner)}
              </Link>
              /
              <Link
                href={`/bundles/${encodeURIComponent(b.owner)}/${encodeURIComponent(b.name)}`}
                className="underline-offset-2 hover:underline"
              >
                {clean(b.name)}
              </Link>
            </span>
            <span className="ml-3 text-sm text-zinc-500">
              {b.latest ? `latest ${clean(b.latest)}` : "no installable version (all yanked)"}
            </span>
            {risk && (
              <span
                className={`ml-3 align-middle ${risk.className}`}
                title="Highest risk label, computed by the registry from the declared manifest; not a review. Open the bundle for the full list."
              >
                risk: {risk.word}
              </span>
            )}
            {b.description && (
              <p className="mt-1 text-zinc-700 dark:text-zinc-300">{clean(b.description)}</p>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/** Previous / Next links; Next only when a full page came back. */
export function Pager({ prev, next }: { prev: string | null; next: string | null }) {
  if (!prev && !next) return null;
  return (
    <nav aria-label="Pagination" className="mt-6 flex justify-between text-sm">
      {prev ? (
        <Link href={prev} rel="prev" className="rounded px-2 py-1 underline underline-offset-2">
          &larr; Previous
        </Link>
      ) : (
        <span />
      )}
      {next && (
        <Link href={next} rel="next" className="rounded px-2 py-1 underline underline-offset-2">
          Next &rarr;
        </Link>
      )}
    </nav>
  );
}

export function LoadError({ detail = "" }: { detail?: string }) {
  return (
    <p role="alert" className="mt-8 rounded border border-red-300 p-4 text-red-700 dark:text-red-400">
      Could not load bundles from the registry{detail}. Try again shortly.
    </p>
  );
}
