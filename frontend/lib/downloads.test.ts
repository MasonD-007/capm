import { afterEach, describe, expect, it, vi } from "vitest";
import { listBundles } from "./api";
import { downloadTotals, formatDownloads } from "./format";

describe("formatDownloads", () => {
  it("always says the number, including zero", () => {
    expect(formatDownloads(0)).toBe("0 downloads");
    expect(formatDownloads(1)).toBe("1 download");
    expect(formatDownloads(2)).toBe("2 downloads");
    expect(formatDownloads(1234567)).toBe("1,234,567 downloads");
  });
  it("is empty when the registry sent no count (older server) or garbage", () => {
    expect(formatDownloads(undefined)).toBe("");
    expect(formatDownloads(NaN)).toBe("");
    expect(formatDownloads(-3)).toBe("");
    expect(formatDownloads(1.5)).toBe("");
    expect(formatDownloads("12" as unknown as number)).toBe("");
  });
});

describe("downloadTotals", () => {
  it("sums the versions that are not removed", () => {
    const vs = [
      { downloads: 3, downloads30d: 1 },
      { downloads: 10, downloads30d: 10 },
      { downloads: 7, downloads30d: 7, removed: true },
    ];
    expect(downloadTotals(vs)).toEqual({ total: 13, last30d: 11 });
  });
  it("is zero for a bundle with no counted downloads", () => {
    expect(downloadTotals([{ downloads: 0, downloads30d: 0 }])).toEqual({ total: 0, last30d: 0 });
  });
  it("is null when the registry sends no counts", () => {
    expect(downloadTotals([{}, {}])).toBeNull();
    expect(downloadTotals([])).toBeNull();
  });
  it("ignores non-numeric values rather than propagating NaN", () => {
    expect(downloadTotals([{ downloads: 2, downloads30d: "x" as unknown as number }])).toEqual({ total: 2, last30d: 0 });
  });
});

describe("listBundles sort option", () => {
  afterEach(() => vi.unstubAllGlobals());
  async function url(o: Parameters<typeof listBundles>[0]) {
    vi.stubEnv("API_URL", "http://backend:8080");
    const f = vi.fn(async () => new Response("[]", { status: 200 }));
    vi.stubGlobal("fetch", f);
    await listBundles(o);
    return (f.mock.calls[0] as unknown as [string])[0];
  }
  it("sends sort for recent and downloads, after q", async () => {
    expect(await url({ q: "a", sort: "recent", limit: 50 })).toBe("http://backend:8080/v1/bundles?q=a&sort=recent&limit=50");
    expect(await url({ sort: "downloads", offset: 50 })).toBe("http://backend:8080/v1/bundles?sort=downloads&offset=50");
  });
  it("leaves the default order out so older servers see the old request", async () => {
    expect(await url({ sort: "name", limit: 50 })).toBe("http://backend:8080/v1/bundles?limit=50");
  });
});
