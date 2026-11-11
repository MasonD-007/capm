// C1: the website must render the shared notices from the API summary, not a
// hand-copied duplicate of manifest/notices.go that could drift from what the
// CLI prints.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(__dirname, "..");

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    if (e === "node_modules" || e.startsWith(".")) continue;
    const p = join(dir, e);
    if (statSync(p).isDirectory()) out.push(...sources(p));
    else if (/\.(ts|tsx)$/.test(e) && !/\.test\.ts$/.test(e)) out.push(p);
  }
  return out;
}

// Every string literal piece of the Go notice constants.
function goNoticeLiterals(): string[] {
  const go = readFileSync(join(root, "..", "manifest", "notices.go"), "utf8");
  const lits = [...go.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
  return lits.filter((s) => s.length >= 20);
}

describe("shared notices", () => {
  const files = [...sources(join(root, "app")), ...sources(join(root, "lib"))];

  it("finds the Go notice constants", () => {
    expect(goNoticeLiterals().length).toBeGreaterThanOrEqual(5);
  });

  it("are not hand-copied into the website", () => {
    for (const f of files) {
      const src = readFileSync(f, "utf8").replace(/\s+/g, " ");
      for (const lit of goNoticeLiterals()) {
        const piece = lit.replace(/\s+/g, " ").trim();
        expect(src.includes(piece), `${f} hand-copies "${piece}"`).toBe(false);
      }
      for (const stale of ["not listed here", "set by sbx and not listed", "Egress enforcement", "prompt-injection"]) {
        expect(src.includes(stale), `${f} contains "${stale}"`).toBe(false);
      }
    }
  });

  it("are rendered from the API summary on the bundle page", () => {
    const page = readFileSync(join(root, "app", "bundles", "[owner]", "[name]", "page.tsx"), "utf8");
    expect(page).toMatch(/noticeTexts\(s, "network"\)/);
    expect(page).toMatch(/noticeTexts\(s, "baseAgent"\)/);
    expect(page).toMatch(/baseHosts/);
  });
});
