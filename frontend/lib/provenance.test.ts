import { describe, expect, it } from "vitest";
import { ownerKindLabel, parseRepository, provenanceOf, publishedByLabel, repositoryMatches } from "./provenance";

describe("parseRepository", () => {
  it("accepts exactly https://github.com/<owner>/<repo>", () => {
    expect(parseRepository("https://github.com/MasonD-007/capm")).toEqual({
      owner: "MasonD-007",
      repo: "capm",
      url: "https://github.com/MasonD-007/capm",
    });
    expect(parseRepository("https://github.com/acme/.github")?.repo).toBe(".github");
    expect(parseRepository("https://github.com/acme/my.repo_name-2")?.repo).toBe("my.repo_name-2");
  });

  it.each([
    ["javascript:alert(1)"],
    ["JavaScript:alert(1)"],
    ["data:text/html,<script>alert(1)</script>"],
    ["vbscript:x"],
    ["//github.com/a/b"],
    ["http://github.com/a/b"],
    ["HTTPS://github.com/a/b"],
    ["https://GitHub.com/a/b"],
    ["https://www.github.com/a/b"],
    ["https://github.com.evil.example/a/b"],
    ["https://gitlab.com/a/b"],
    ["https://evil.example/https://github.com/a/b"],
    ["https://user@github.com/a/b"],
    ["https://user:pw@github.com/a/b"],
    ["https://github.com@evil.example/a/b"],
    ["https://github.com:443/a/b"],
    ["https://gıthub.com/a/b"], // dotless i look-alike host
    ["https://github.com/а/b"], // Cyrillic a in the owner
    ["https://github.com/a/b/"],
    ["https://github.com/a/b.git"],
    ["https://github.com/a/b/tree/main"],
    ["https://github.com/a"],
    ["https://github.com/"],
    ["https://github.com//b"],
    ["https://github.com/a/b?x=1"],
    ["https://github.com/a/b#readme"],
    ["https://github.com/a/b%2Fc"],
    ["https://github.com/a/b c"],
    ["https://github.com/a/b\n"],
    ["https://github.com/a/b​"],
    [" https://github.com/a/b"],
    ["https://github.com/-a/b"],
    ["https://github.com/a/.."],
    [""],
  ])("rejects %j", (s) => {
    expect(parseRepository(s)).toBeNull();
  });

  it("rejects non-strings and over-long values", () => {
    expect(parseRepository(undefined)).toBeNull();
    expect(parseRepository(null)).toBeNull();
    expect(parseRepository(42)).toBeNull();
    expect(parseRepository({ toString: () => "https://github.com/a/b" })).toBeNull();
    expect(parseRepository("https://github.com/a/" + "b".repeat(101))).toBeNull();
    expect(parseRepository("https://github.com/" + "a".repeat(40) + "/b")).toBeNull();
  });
});

describe("repositoryMatches", () => {
  it("compares owner and repo case-insensitively", () => {
    expect(repositoryMatches("https://github.com/Alice/X", "alice/x")).toBe(true);
    expect(repositoryMatches("https://github.com/alice/x", "ALICE/X")).toBe(true);
  });
  it("is false for anything that is not the same repository", () => {
    for (const [claim, ci] of [
      ["https://github.com/alice/x", "alice/y"],
      ["https://github.com/alice/x", "bob/x"],
      ["https://github.com/alice/x/", "alice/x"],
      ["https://github.com/alice/x.git", "alice/x"],
      ["https://gitlab.com/alice/x", "alice/x"],
      ["https://github.com/alice/x", "alice/x/extra"],
      ["https://github.com/alice/x", "alice"],
      ["https://github.com/alice/x", ""],
      ["", "alice/x"],
    ] as const) {
      expect(repositoryMatches(claim, ci)).toBe(false);
    }
    expect(repositoryMatches("https://github.com/alice/x", undefined)).toBe(false);
  });
});

const sha = "0123456789abcdef0123456789abcdef01234567";
const base = {
  manifest: { metadata: { repository: "https://github.com/alice/x" } },
  repositoryVerified: true,
  publishedVia: { repository: "alice/x", workflowRef: "alice/x/.github/workflows/p.yml@refs/heads/main", sha },
};

describe("provenanceOf", () => {
  it("is verified only when the registry says so and its own record agrees with the manifest", () => {
    expect(provenanceOf(base)).toEqual({
      kind: "verified",
      repo: "alice/x",
      url: "https://github.com/alice/x",
      workflowRef: "alice/x/.github/workflows/p.yml@refs/heads/main",
      commit: "0123456",
    });
  });
  it("shows an unverified claim as a claim", () => {
    expect(provenanceOf({ manifest: base.manifest, repositoryVerified: false })).toEqual({
      kind: "claim",
      repo: "alice/x",
      url: "https://github.com/alice/x",
    });
    expect(provenanceOf({ manifest: base.manifest })).toMatchObject({ kind: "claim" });
  });
  it("downgrades an inconsistent verified flag to a claim", () => {
    for (const v of [
      { ...base, publishedVia: { ...base.publishedVia, repository: "mallory/other" } },
      { ...base, publishedVia: undefined },
      { ...base, publishedVia: { workflowRef: "x" } },
    ]) {
      expect(provenanceOf(v)).toMatchObject({ kind: "claim", url: "https://github.com/alice/x" });
    }
  });
  it("is empty without a repository claim, even when the registry says verified", () => {
    expect(provenanceOf({ manifest: { metadata: {} }, repositoryVerified: true, publishedVia: base.publishedVia })).toBeNull();
    expect(provenanceOf({ manifest: { metadata: { repository: "" } } })).toBeNull();
    expect(provenanceOf({})).toBeNull();
  });
  it("never produces a link for a claim that is not a plain github.com repository URL", () => {
    for (const bad of ["javascript:alert(1)", "https://evil.example/a/b", "https://user@github.com/a/b", "https://gıthub.com/a/b"]) {
      expect(provenanceOf({ manifest: { metadata: { repository: bad } }, repositoryVerified: true, publishedVia: base.publishedVia })).toBeNull();
    }
  });
  it("cleans the workflow ref and commit it shows", () => {
    const p = provenanceOf({
      ...base,
      publishedVia: { ...base.publishedVia, workflowRef: "a‮b\u001b[31m", sha: "ab\u0007cdef0123" },
    });
    expect(p).toMatchObject({ kind: "verified" });
    if (p?.kind === "verified") {
      expect(p.workflowRef).not.toMatch(/[‮\u001b]/);
      expect(p.commit).not.toMatch(/[\u0007]/);
      expect(p.commit.length).toBeLessThanOrEqual(7);
    }
  });
});

describe("ownerKindLabel", () => {
  it("labels organisations only", () => {
    expect(ownerKindLabel("org")).toBe("organisation");
    expect(ownerKindLabel("user")).toBe("");
    expect(ownerKindLabel(undefined)).toBe(""); // older registries
    expect(ownerKindLabel("ORG")).toBe("");
    expect(ownerKindLabel({})).toBe("");
  });
});

describe("publishedByLabel", () => {
  it("shows the publishing member only for an organisation's bundle", () => {
    expect(publishedByLabel({ ownerKind: "org", publishedBy: "alice" })).toBe("alice");
    expect(publishedByLabel({ ownerKind: "org" })).toBe("");
    expect(publishedByLabel({ ownerKind: "user", publishedBy: "alice" })).toBe("");
    expect(publishedByLabel({ publishedBy: "alice" })).toBe("");
  });
  it("cleans the login", () => {
    expect(publishedByLabel({ ownerKind: "org", publishedBy: "al\u202eice\u001b" })).not.toMatch(/[\u202e\u001b]/);
  });
});
