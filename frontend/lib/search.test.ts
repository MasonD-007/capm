import { describe, expect, it } from "vitest";
import { MAX_QUERY, PAGE_SIZE, hasNextPage, homeHref, normalizeQuery, parseOffset, prevOffset } from "./search";

describe("normalizeQuery", () => {
  it("trims and treats empty or missing as empty", () => {
    expect(normalizeQuery("  review  ")).toBe("review");
    expect(normalizeQuery("")).toBe("");
    expect(normalizeQuery("   ")).toBe("");
    expect(normalizeQuery(undefined)).toBe("");
  });
  it("uses the first value of a repeated parameter", () => {
    expect(normalizeQuery(["a", "b"])).toBe("a");
    expect(normalizeQuery([])).toBe("");
  });
  it("caps at 100 characters (code points, like the API)", () => {
    expect(MAX_QUERY).toBe(100);
    expect(normalizeQuery("x".repeat(150))).toHaveLength(100);
    const emoji = normalizeQuery("\u{1F600}".repeat(150));
    expect(Array.from(emoji)).toHaveLength(100);
  });
  it("trims after capping so the API never sees leading or trailing space", () => {
    const q = normalizeQuery("a".repeat(99) + " " + "b".repeat(10));
    expect(q).toBe("a".repeat(99));
  });
});

describe("parseOffset", () => {
  it.each([
    ["0", 0],
    ["50", 50],
    ["150", 150],
    [undefined, 0],
    ["", 0],
    ["-1", 0],
    ["1.5", 0],
    ["abc", 0],
    ["1e3", 0],
    ["0x10", 0],
    ["99999999999999999999", 0],
  ])("parses %j as %j", (raw, want) => {
    expect(parseOffset(raw)).toBe(want);
  });
  it("uses the first value of a repeated parameter", () => {
    expect(parseOffset(["50", "100"])).toBe(50);
  });
});

describe("paging", () => {
  it("page size is 50", () => expect(PAGE_SIZE).toBe(50));
  it("shows Next only when a full page came back", () => {
    expect(hasNextPage(50)).toBe(true);
    expect(hasNextPage(49)).toBe(false);
    expect(hasNextPage(0)).toBe(false);
  });
  it("previous offset never goes below zero", () => {
    expect(prevOffset(100)).toBe(50);
    expect(prevOffset(50)).toBe(0);
    expect(prevOffset(20)).toBe(0);
    expect(prevOffset(0)).toBe(0);
  });
});

describe("homeHref", () => {
  it("is the bare home page without a query or offset", () => {
    expect(homeHref("", 0)).toBe("/");
  });
  it("encodes the query", () => {
    expect(homeHref("a b&c=d/é", 0)).toBe("/?q=a+b%26c%3Dd%2F%C3%A9");
  });
  it("adds offset only when positive", () => {
    expect(homeHref("x", 50)).toBe("/?q=x&offset=50");
    expect(homeHref("", 50)).toBe("/?offset=50");
  });
});
