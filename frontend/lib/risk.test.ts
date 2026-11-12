import { afterEach, describe, expect, it, vi } from "vitest";
import { getRiskLabels } from "./api";
import { riskDisplay, sortRiskLabels } from "./risk";

afterEach(() => vi.unstubAllGlobals());

describe("riskDisplay", () => {
  it("always carries a word, not only a colour", () => {
    for (const s of ["high", "caution", "info"]) {
      const d = riskDisplay(s)!;
      expect(d.word.length).toBeGreaterThan(0);
      expect(d.className).toContain("dark:");
    }
    expect(riskDisplay("high")!.word).toBe("high");
    expect(riskDisplay("caution")!.word).toBe("caution");
    expect(riskDisplay("info")!.word).toBe("info");
  });

  it("shows nothing for no severity and never echoes unknown strings", () => {
    expect(riskDisplay("")).toBeNull();
    expect(riskDisplay(undefined)).toBeNull();
    expect(riskDisplay("<script>")).toBeNull();
  });

  it("uses distinct styles per severity", () => {
    const cls = new Set(["high", "caution", "info"].map((s) => riskDisplay(s)!.className));
    expect(cls.size).toBe(3);
  });
});

describe("sortRiskLabels", () => {
  it("orders high, caution, info then id, and drops malformed entries", () => {
    const out = sortRiskLabels([
      { id: "b", severity: "info", reason: "r" },
      { id: "z", severity: "high", reason: "r" },
      { id: "a", severity: "caution", reason: "r" },
      { id: "a", severity: "high", reason: "r" },
      { id: "x", severity: "weird", reason: "r" },
      null,
      { id: 3 },
    ] as never);
    expect(out.map((l) => l.id)).toEqual(["a", "z", "a", "b"]);
  });
});

describe("getRiskLabels", () => {
  it("reads riskLabels from the exact-version metadata", async () => {
    const f = vi.fn(async () => new Response(JSON.stringify({ riskLabels: [{ id: "i", severity: "info", reason: "r" }] })));
    vi.stubGlobal("fetch", f);
    const out = await getRiskLabels("alice", "x", "1.0.0");
    expect(out).toEqual([{ id: "i", severity: "info", reason: "r" }]);
    expect(String((f.mock.calls[0] as unknown[])[0])).toMatch(/\/v1\/bundles\/alice\/x\/1\.0\.0$/);
  });

  it("is null when the server predates labels or the call fails", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ version: "1.0.0" }))));
    expect(await getRiskLabels("alice", "x", "1.0.0")).toBeNull();
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 500 })));
    expect(await getRiskLabels("alice", "x", "1.0.0")).toBeNull();
    expect(await getRiskLabels("..", "x", "1.0.0")).toBeNull();
  });

  it("keeps an empty list distinct from missing", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ riskLabels: [] }))));
    expect(await getRiskLabels("alice", "x", "1.0.0")).toEqual([]);
  });
});
