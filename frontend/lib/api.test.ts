import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, getBundle, listBundles, latestNonYanked } from "./api";

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

describe("latestNonYanked", () => {
  const v = (version: string, yanked: boolean) => ({ version, yanked });
  it("skips yanked and picks highest release over prerelease", () => {
    expect(latestNonYanked([v("1.0.0", false), v("2.0.0", true), v("1.2.0", false), v("3.0.0-rc.1", false)])?.version).toBe("1.2.0");
  });
  it("is undefined when all yanked", () => {
    expect(latestNonYanked([v("1.0.0", true)])).toBeUndefined();
  });
});
