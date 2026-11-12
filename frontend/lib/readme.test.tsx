import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { MAX_README_CHARS, capReadme, safeUrl } from "./markdown";
import { Readme } from "./readme";

const html = (md: string) => renderToStaticMarkup(<Readme text={md} />);

describe("safeUrl", () => {
  it.each([
    ["https://example.com/a?b=1#c", "https://example.com/a?b=1#c"],
    ["http://example.com", "http://example.com/"],
    ["mailto:me@example.com", "mailto:me@example.com"],
    ["  https://example.com/  ", "https://example.com/"],
  ])("allows %j", (raw, want) => {
    expect(safeUrl(raw)).toBe(want);
  });

  it.each([
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    " javascript:alert(1)",
    "java\tscript:alert(1)",
    "java\nscript:alert(1)",
    "\u0001javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:image/png;base64,AAAA",
    "vbscript:msgbox(1)",
    "file:///etc/passwd",
    "ftp://example.com/",
    "blob:https://example.com/x",
    "//evil.example.com/x",
    "/relative/path",
    "relative.md",
    "#fragment",
    "",
    "https:",
    "http://",
    "https://exa mple.com",
  ])("rejects %j", (raw) => {
    expect(safeUrl(raw)).toBeNull();
  });

  it("rejects non-strings", () => {
    expect(safeUrl(undefined)).toBeNull();
    expect(safeUrl(null)).toBeNull();
    expect(safeUrl(5)).toBeNull();
  });
});

describe("Readme rendering", () => {
  it("renders ordinary Markdown", () => {
    const out = html("# Title\n\nSome *emphasis*, **strong** and `code`.\n\n- a\n- b\n\n```js\nlet x = 1;\n```\n");
    expect(out).toContain("<em>emphasis</em>");
    expect(out).toContain("<strong>strong</strong>");
    expect(out).toContain("<code");
    expect(out).toContain("<li>a</li>");
    expect(out).toContain("let x = 1;");
  });

  it("demotes headings so the page keeps its own h1 and h2", () => {
    const out = html("# One\n\n## Two\n\n### Three\n\n###### Six");
    expect(out).not.toMatch(/<h[12][ >]/);
    expect(out).toMatch(/<h3[^>]*>One<\/h3>/);
  });

  it("does not emit a script element for <script>", () => {
    const out = html("hello\n\n<script>alert(1)</script>\n\nafter <script>alert(2)</script> inline");
    expect(out).not.toMatch(/<script/i);
    expect(out).toContain("&lt;script&gt;");
    expect(out).toContain("hello");
    expect(out).toContain("after");
  });

  it("does not pass raw HTML through", () => {
    const out = html(
      [
        '<div onclick="steal()" style="position:fixed;inset:0">overlay</div>',
        "",
        '<iframe src="https://evil.example/"></iframe>',
        "",
        '<img src="https://track.example/p.gif" onerror="x()">',
        "",
        '<a href="javascript:alert(1)">raw</a>',
        "",
        "<style>body{display:none}</style>",
        "",
        '<svg onload="x()"></svg> and <b style="color:red">bold</b>',
      ].join("\n"),
    );
    expect(out).not.toMatch(/<(div|iframe|img|svg|style|b|a)[\s>]/i);
    expect(out).not.toMatch(/<[^>]*\sstyle=/i);
    expect(out).not.toMatch(/<[^>]*\son\w+=/i);
    expect(out).not.toMatch(/<[^>]*javascript:/i);
  });

  it.each([
    "[x](javascript:alert(1))",
    "[x](JaVaScRiPt:alert(1))",
    "[x](&#106;avascript:alert(1))",
    "[x](jav&#x09;ascript:alert(1))",
    "[x][r]\n\n[r]: javascript:alert(1)",
    "[x](data:text/html;base64,PHNjcmlwdD4=)",
    "[x](vbscript:run)",
    "[x](//evil.example/)",
    "[x](relative/path.md)",
    "<javascript:alert(1)>",
  ])("drops the destination of %j and keeps no link", (md) => {
    const out = html(md);
    expect(out).not.toMatch(/<a[\s>]/i);
    expect(out).not.toMatch(/href=/i);
    expect(out).not.toMatch(/javascript:\S*"/i);
  });

  it("keeps the text of a link whose destination is dropped", () => {
    expect(html("[click me](javascript:alert(1))")).toContain("click me");
  });

  it("renders a normal link with nofollow noopener noreferrer and no target", () => {
    const out = html("See [the docs](https://example.com/docs?a=1&b=2) and <https://example.org/x> or [mail](mailto:a@example.com).");
    expect(out).toContain('href="https://example.com/docs?a=1&amp;b=2"');
    expect(out).toContain('href="https://example.org/x"');
    expect(out).toContain('href="mailto:a@example.com"');
    const anchors = out.match(/<a [^>]*>/g) ?? [];
    expect(anchors).toHaveLength(3);
    for (const a of anchors) {
      expect(a).toContain('rel="nofollow noopener noreferrer"');
      expect(a).not.toContain("target=");
    }
  });

  it("never loads an image: it becomes a text link to the image URL", () => {
    const out = html("![a logo](https://example.com/logo.png) and ![](https://example.com/b.png)");
    expect(out).not.toMatch(/<img/i);
    expect(out).not.toMatch(/\ssrc=/i);
    expect(out).toMatch(/<a [^>]*href="https:\/\/example\.com\/logo\.png"[^>]*>[^<]*a logo[^<]*<\/a>/);
    expect(out).toContain('rel="nofollow noopener noreferrer"');
    expect(out).toContain("https://example.com/b.png");
  });

  it("shows an image with an unsafe source as plain text only", () => {
    const out = html("![pwn](javascript:alert(1)) ![d](data:image/svg+xml;base64,AAAA)");
    expect(out).not.toMatch(/<img|<a[\s>]|href=|src=/i);
    expect(out).toContain("pwn");
  });

  it("does not nest a link inside a linked image", () => {
    const out = html("[![badge](https://example.com/b.svg)](https://example.com/page)");
    expect(out).not.toMatch(/<img/i);
    const anchors = out.match(/<a[\s>]/g) ?? [];
    expect(anchors).toHaveLength(1);
    expect(out).toContain('href="https://example.com/page"');
    expect(out).toContain("badge");
  });

  it("replaces control and bidi characters but keeps line structure", () => {
    const out = html("line one‮EVIL\n\nline two\u0000x");
    expect(out).not.toContain("‮");
    expect(out).not.toContain("\u0000");
    expect(out).toMatch(/<p[^>]*>line one�EVIL<\/p>/);
    expect(out).toContain("line two");
  });

  it("renders no html or javascript in code blocks as markup", () => {
    const out = html("```html\n<script>alert(1)</script>\n```");
    expect(out).not.toMatch(/<script/i);
    expect(out).toContain("&lt;script&gt;");
  });

  it("caps a long README and says so", () => {
    expect(capReadme("x".repeat(10))).toBe("x".repeat(10));
    const long = "para\n\n".repeat(100_000); // 600k chars
    const capped = capReadme(long);
    expect(capped.length).toBeLessThanOrEqual(MAX_README_CHARS + 100);
    expect(capped).toContain("[README truncated");
    const t0 = Date.now();
    const out = html(long);
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(out.length).toBeLessThan(MAX_README_CHARS * 12);
    expect(out).toContain("README truncated");
  });

  it("handles deeply nested and malformed input without throwing", () => {
    expect(() => html("> ".repeat(500) + "deep")).not.toThrow();
    expect(() => html("[".repeat(5000))).not.toThrow();
    expect(() => html("![](".repeat(1000))).not.toThrow();
  });
});
