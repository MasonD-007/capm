// Where a version was published from. Mirrors manifest.ParseRepository and
// manifest.RepositoryMatches (manifest/repository.go); keep them in step.
//
// "Verified" here is the registry's statement that the version was published
// by a GitHub Actions workflow of the repository the manifest names. It says
// where the version was published from. It is not a review of the bundle and
// says nothing about whether its contents match the repository.
import { clean } from "./text";

const PREFIX = "https://github.com/";
const OWNER = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/;
const REPO = /^[A-Za-z0-9._-]{1,100}$/;

function validParts(owner: string, repo: string): boolean {
  return (
    OWNER.test(owner) &&
    REPO.test(repo) &&
    repo !== "." &&
    repo !== ".." &&
    !repo.toLowerCase().endsWith(".git")
  );
}

export type ParsedRepository = { owner: string; repo: string; url: string };

/**
 * Accepts exactly https://github.com/<owner>/<repo>: https, host github.com
 * (lower case, ASCII), two path segments of characters GitHub allows, no
 * trailing slash, no ".git", no query, fragment, userinfo or port. Anything
 * else (including every non-string) is null, so a link is only ever built
 * from a value that passed this check.
 */
export function parseRepository(s: unknown): ParsedRepository | null {
  if (typeof s !== "string" || s.length > 200 || !s.startsWith(PREFIX)) return null;
  const rest = s.slice(PREFIX.length);
  const i = rest.indexOf("/");
  if (i < 0) return null;
  const owner = rest.slice(0, i);
  const repo = rest.slice(i + 1);
  if (!validParts(owner, repo)) return null;
  return { owner, repo, url: `${PREFIX}${owner}/${repo}` };
}

/** The manifest's claim against the "owner/repo" a CI identity certified; case-insensitive. */
export function repositoryMatches(claim: unknown, ciRepository: unknown): boolean {
  const c = parseRepository(claim);
  if (!c || typeof ciRepository !== "string") return false;
  const i = ciRepository.indexOf("/");
  if (i < 0) return false;
  const owner = ciRepository.slice(0, i);
  const repo = ciRepository.slice(i + 1);
  if (!validParts(owner, repo)) return false;
  return c.owner.toLowerCase() === owner.toLowerCase() && c.repo.toLowerCase() === repo.toLowerCase();
}

export type Provenance =
  | { kind: "verified"; repo: string; url: string; workflowRef: string; commit: string }
  | { kind: "claim"; repo: string; url: string };

type VersionLike = {
  manifest?: { metadata?: { repository?: unknown } };
  repositoryVerified?: boolean;
  publishedVia?: { repository?: unknown; workflowRef?: unknown; sha?: unknown };
};

/**
 * What to show about a version's repository: nothing, the author's claim, or
 * "published from". The verified state needs the registry's flag AND its own
 * provenance record naming the same repository as the manifest, so an
 * inconsistent reply is shown as a claim, never as a verified one. The URL is
 * only ever the re-built, validated one.
 */
export function provenanceOf(v: VersionLike): Provenance | null {
  const claim = parseRepository(v.manifest?.metadata?.repository);
  if (!claim) return null;
  const repo = `${claim.owner}/${claim.repo}`;
  const via = v.publishedVia;
  if (v.repositoryVerified === true && via && repositoryMatches(claim.url, via.repository)) {
    return {
      kind: "verified",
      repo,
      url: claim.url,
      workflowRef: clean(via.workflowRef).slice(0, 300),
      commit: clean(via.sha).slice(0, 7),
    };
  }
  return { kind: "claim", repo, url: claim.url };
}

/** "organisation" for an organisation's namespace; empty for users and for registries that do not say. */
export function ownerKindLabel(kind: unknown): string {
  return kind === "org" ? "organisation" : "";
}

/** The member who published a version of an organisation's bundle (cleaned); empty otherwise. */
export function publishedByLabel(v: { ownerKind?: unknown; publishedBy?: unknown }): string {
  return v.ownerKind === "org" ? clean(v.publishedBy).slice(0, 80) : "";
}
