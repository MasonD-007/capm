import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, getBundle, getVersionDetail, isRemoved, listBundles, latestNonYanked } from "./api";

function mockFetch(status: number, body: unknown) {
  const f = vi.fn(async () => new Response(JSON.stringify(body), { status }));
  vi.stubGlobal("fetch", f);
  return f;
}

afterEach(() => vi.unstubAllGlobals());

describe("listBundles", () => {
  it("returns typed data and fetches uncached from API_URL", async () => {
    vi.stubEnv("API_URL", "http://backend:8080");
    const f = mockFetch(200, [
      { ownerId: 1, owner: "alice", name: "x", latest: "1.0.0", description: "d" },
    ]);
    const out = await listBundles();
    expect(out[0].owner).toBe("alice");
    expect(out[0].latest).toBe("1.0.0");
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("http://backend:8080/v1/bundles");
    expect(init.cache).toBe("no-store");
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it("throws ApiError on non-2xx", async () => {
    mockFetch(500, { error: "internal error" });
    await expect(listBundles()).rejects.toMatchObject({ status: 500 });
  });
});

describe("getBundle", () => {
  it("returns versions for a well-formed owner/name", async () => {
    const f = mockFetch(200, [{ version: "1.0.0", yanked: false }]);
    const out = await getBundle("Al-ice_1", "x.y");
    expect(out[0].version).toBe("1.0.0");
    expect((f.mock.calls[0] as unknown as [string])[0]).toContain("/v1/bundles/Al-ice_1/x.y");
  });

  it.each([
    [".", "x"],
    ["..", "x"],
    ["a", ".."],
    ["a", "."],
    ["al ice", "x"],
    ["a/b", "x"],
    ["a", "x%2f"],
    ["", "x"],
    ["~1", "x"],
  ])("rejects owner %j name %j as not found without fetching", async (owner, name) => {
    const f = mockFetch(200, []);
    const err = await getBundle(owner, name).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.notFound).toBe(true);
    expect(f).not.toHaveBeenCalled();
  });

  it("maps 404 to a distinct not-found error", async () => {
    mockFetch(404, { error: "bundle not found" });
    const err = await getBundle("a", "b").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.notFound).toBe(true);
  });

  it("does not flag other failures as not-found", async () => {
    mockFetch(502, {});
    const err = await getBundle("a", "b").catch((e) => e);
    expect(err.notFound).toBe(false);
  });
});

describe("listBundles options", () => {
  it("passes q, owner, limit and offset, encoded", async () => {
    vi.stubEnv("API_URL", "http://backend:8080");
    const f = mockFetch(200, []);
    await listBundles({ q: "a b&c", owner: "alice", limit: 50, offset: 100 });
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("http://backend:8080/v1/bundles?q=a+b%26c&owner=alice&limit=50&offset=100");
    expect(init.cache).toBe("no-store");
  });
  it("omits empty options", async () => {
    vi.stubEnv("API_URL", "http://backend:8080");
    const f = mockFetch(200, []);
    await listBundles({ q: "", limit: 50, offset: 0 });
    expect((f.mock.calls[0] as unknown as [string])[0]).toBe("http://backend:8080/v1/bundles?limit=50");
  });
});

describe("getVersionDetail", () => {
  it("returns risk labels and readme from the metadata endpoint", async () => {
    const f = mockFetch(200, { riskLabels: [{ id: "x", severity: "high", reason: "r" }], readme: "# hi" });
    const d = await getVersionDetail("alice", "x", "1.0.0");
    expect(d).toEqual({ riskLabels: [{ id: "x", severity: "high", reason: "r" }], readme: "# hi" });
    expect((f.mock.calls[0] as unknown as [string])[0]).toContain("/v1/bundles/alice/x/1.0.0");
  });
  it("defaults readme to empty and tolerates an older server", async () => {
    mockFetch(200, {});
    expect(await getVersionDetail("alice", "x", "1.0.0")).toEqual({ riskLabels: null, readme: "" });
  });
  it("ignores a non-string readme", async () => {
    mockFetch(200, { readme: { a: 1 }, riskLabels: [] });
    expect(await getVersionDetail("alice", "x", "1.0.0")).toEqual({ riskLabels: [], readme: "" });
  });
  it("is null on failure or for non-segment arguments, without fetching", async () => {
    const f = mockFetch(410, { removed: true });
    expect(await getVersionDetail("alice", "x", "1.0.0")).toBeNull();
    f.mockClear();
    expect(await getVersionDetail("alice", "x", "../1")).toBeNull();
    expect(f).not.toHaveBeenCalled();
  });
});

describe("latestNonYanked", () => {
  const v = (version: string, yanked: boolean) => ({ version, yanked });
  it("skips yanked and picks highest release over prerelease", () => {
    expect(latestNonYanked([v("1.0.0", false), v("2.0.0", true), v("1.2.0", false), v("3.0.0-rc.1", false)])?.version).toBe("1.2.0");
  });
  it("is undefined when all yanked", () => {
    expect(latestNonYanked([v("1.0.0", true)])).toBeUndefined();
  });
});

describe("removed versions", () => {
  it("getBundle passes removed and removedReason through", async () => {
    mockFetch(200, [
      { version: "1.0.0", yanked: false, removed: false, removedReason: "" },
      { version: "1.1.0", yanked: false, removed: true, removedReason: "malware" },
    ]);
    const out = await getBundle("alice", "x");
    expect(out[1].removed).toBe(true);
    expect(out[1].removedReason).toBe("malware");
    expect(isRemoved(out[1])).toBe(true);
    expect(isRemoved(out[0])).toBe(false);
  });

  it("isRemoved is false for an older server that omits the field", () => {
    const v: { removed?: boolean } = {};
    expect(isRemoved(v)).toBe(false);
  });

  it("latestNonYanked skips removed versions", () => {
    const vs = [
      { version: "1.0.0", yanked: false, removed: false },
      { version: "2.0.0", yanked: false, removed: true },
    ];
    expect(latestNonYanked(vs)?.version).toBe("1.0.0");
    expect(latestNonYanked([{ version: "1.0.0", yanked: false, removed: true }])).toBeUndefined();
  });
});
