import { describe, expect, it } from "vitest";
import { SORT_VIEWS, homeHref, parseSort, sortHref } from "./search";

describe("parseSort", () => {
  it.each([
    ["recent", "recent"],
    ["downloads", "downloads"],
    ["name", "name"],
  ])("accepts %j", (raw, want) => expect(parseSort(raw)).toBe(want));

  it.each([undefined, "", "bogus", "Recent", "downloads30d", " recent", "recent,name", "__proto__"])(
    "falls back to the default order for %j",
    (raw) => expect(parseSort(raw)).toBe("name"),
  );
  it("uses the first value of a repeated parameter", () => {
    expect(parseSort(["downloads", "recent"])).toBe("downloads");
    expect(parseSort([])).toBe("name");
  });
});

describe("SORT_VIEWS", () => {
  it("lists the three views in display order with their labels", () => {
    expect(SORT_VIEWS).toEqual([
      { mode: "name", label: "A to Z" },
      { mode: "recent", label: "Recently published" },
      { mode: "downloads", label: "Most downloaded (30 days)" },
    ]);
  });
});

describe("homeHref with sort", () => {
  it("leaves the default order out of the URL (existing URLs unchanged)", () => {
    expect(homeHref("", 0)).toBe("/");
    expect(homeHref("x", 50)).toBe("/?q=x&offset=50");
    expect(homeHref("x", 50, "name")).toBe("/?q=x&offset=50");
  });
  it("adds sort for the other views, between q and offset", () => {
    expect(homeHref("", 0, "recent")).toBe("/?sort=recent");
    expect(homeHref("", 0, "downloads")).toBe("/?sort=downloads");
    expect(homeHref("a b", 0, "downloads")).toBe("/?q=a+b&sort=downloads");
    expect(homeHref("a b", 100, "recent")).toBe("/?q=a+b&sort=recent&offset=100");
    expect(homeHref("", 50, "recent")).toBe("/?sort=recent&offset=50");
  });
});

describe("sortHref", () => {
  it("switches the view, keeps the query and restarts paging", () => {
    expect(sortHref("review", "recent")).toBe("/?q=review&sort=recent");
    expect(sortHref("review", "downloads")).toBe("/?q=review&sort=downloads");
    expect(sortHref("review", "name")).toBe("/?q=review");
    expect(sortHref("", "name")).toBe("/");
  });
});
