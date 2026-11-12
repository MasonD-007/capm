import { describe, expect, it } from "vitest";
import { clean, cleanMultiline } from "./text";

describe("clean", () => {
  it("replaces control and bidi characters, including newlines", () => {
    expect(clean("a\nb‮c")).toBe("a�b�c");
    expect(clean(42)).toBe("");
  });
});

describe("cleanMultiline", () => {
  it("keeps newlines and tabs but replaces other control and bidi characters", () => {
    expect(cleanMultiline("a\nb\tc")).toBe("a\nb\tc");
    expect(cleanMultiline("a\x00b\x1bc‮d⁦e\x7f")).toBe("a�b�c�d�e�");
  });
  it("normalises carriage returns to newlines", () => {
    expect(cleanMultiline("a\r\nb\rc")).toBe("a\nb\nc");
  });
  it("is empty for non-strings", () => {
    expect(cleanMultiline(undefined)).toBe("");
    expect(cleanMultiline(null)).toBe("");
  });
});
