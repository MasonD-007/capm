import { describe, expect, it } from "vitest";
import { SIGNED_CAPTION, formatDate, shortDigest, signedLabel, versionState } from "./format";

describe("formatDate", () => {
  it("renders the UTC calendar date", () => {
    expect(formatDate("2026-11-12T21:04:58Z")).toBe("2026-11-12");
    expect(formatDate("2026-11-12T23:59:59-05:00")).toBe("2026-11-13");
  });
  it("is empty for missing or invalid input", () => {
    expect(formatDate(undefined)).toBe("");
    expect(formatDate("")).toBe("");
    expect(formatDate("not a date")).toBe("");
  });
});

describe("shortDigest", () => {
  it("keeps the algorithm and 12 hex characters", () => {
    expect(shortDigest("sha256:" + "ab12".repeat(16))).toBe("sha256:ab12ab12ab12");
  });
  it("cleans control characters and bounds length for odd input", () => {
    expect(shortDigest("sha256:ab\ncd")).toBe("sha256:ab�cd");
    expect(shortDigest("x".repeat(100))).toHaveLength(19);
    expect(shortDigest(undefined)).toBe("");
  });
});

describe("versionState", () => {
  it("removed beats yanked beats live", () => {
    expect(versionState({ yanked: false })).toEqual({ kind: "live", label: "live" });
    expect(versionState({ yanked: true })).toEqual({ kind: "yanked", label: "yanked" });
    expect(versionState({ yanked: true, removed: true, removedReason: "malware" })).toEqual({
      kind: "removed",
      label: "removed: malware",
    });
  });
  it("cleans and bounds the admin's reason", () => {
    const s = versionState({ yanked: false, removed: true, removedReason: "a‮b" + "z".repeat(300) });
    expect(s.kind).toBe("removed");
    expect(s.label).not.toContain("‮");
    expect(s.label.length).toBeLessThanOrEqual(8 + 120 + 1);
  });
  it("says so when no reason was given", () => {
    expect(versionState({ yanked: false, removed: true }).label).toBe("removed: (no reason given)");
  });
});

describe("signedLabel", () => {
  it("is plain text, nothing more", () => {
    expect(signedLabel({ signed: true })).toBe("signed");
    expect(signedLabel({ signed: false })).toBe("unsigned");
  });
  it("is empty when the registry did not say, and for removed versions", () => {
    expect(signedLabel({})).toBe("");
    expect(signedLabel({ signed: "yes" as unknown as boolean })).toBe("");
    expect(signedLabel({ signed: true, removed: true })).toBe("");
  });
  it("has a caption that says the registry does not verify", () => {
    expect(SIGNED_CAPTION).toBe(
      "Signed means a signature file was uploaded. The registry does not verify it; capm verifies it when you pull or run.",
    );
  });
});
