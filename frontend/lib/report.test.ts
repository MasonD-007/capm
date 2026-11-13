import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DETAILS_MAX,
  REASONS,
  messageFor,
  parseReportForm,
  sendReport,
  visitorIp,
} from "./report";
import type { ReportBody } from "./report";

afterEach(() => vi.unstubAllGlobals());

function form(o: Record<string, string>): FormData {
  const f = new FormData();
  for (const [k, v] of Object.entries(o)) f.set(k, v);
  return f;
}

describe("parseReportForm", () => {
  it("builds the API body", () => {
    const r = parseReportForm(form({ reason: "malware", version: " 1.0.0 ", details: "  bad  " }));
    expect(r).toEqual({ ok: true, body: { version: "1.0.0", reason: "malware", details: "bad" } });
  });
  it("allows no version and no details unless the reason is other", () => {
    expect(parseReportForm(form({ reason: "secrets-exposed", version: "", details: "" }))).toMatchObject({ ok: true });
    expect(parseReportForm(form({ reason: "impersonation" }))).toMatchObject({ ok: true });
  });
  it("rejects a missing or unknown reason", () => {
    for (const reason of ["", "spam", "Malware", "__proto__"]) {
      expect(parseReportForm(form({ reason }))).toEqual({ ok: false, errors: { reason: expect.any(String) } });
    }
    expect(parseReportForm(new FormData())).toMatchObject({ ok: false });
  });
  it("requires details for other", () => {
    expect(parseReportForm(form({ reason: "other", details: "  " }))).toMatchObject({ ok: false, errors: { details: expect.any(String) } });
  });
  it("counts characters, not UTF-16 units, against the 2000 limit", () => {
    expect(parseReportForm(form({ reason: "malware", details: "😀".repeat(DETAILS_MAX) }))).toMatchObject({ ok: true });
    expect(parseReportForm(form({ reason: "malware", details: "😀".repeat(DETAILS_MAX + 1) }))).toMatchObject({
      ok: false,
      errors: { details: expect.any(String) },
    });
  });
  it("rejects a malformed or oversized version", () => {
    for (const version of ["../x", "a b", "1.0.0/../..", "x".repeat(129)]) {
      expect(parseReportForm(form({ reason: "malware", version }))).toMatchObject({ ok: false, errors: { version: expect.any(String) } });
    }
  });
  it("ignores non-string form values (files)", () => {
    const f = new FormData();
    f.set("reason", new File(["x"], "x.txt"));
    expect(parseReportForm(f)).toMatchObject({ ok: false });
  });
  it("exposes the same reasons as the registry", () => {
    expect([...REASONS]).toEqual(["malware", "secrets-exposed", "impersonation", "other"]);
  });
});

describe("visitorIp", () => {
  const h = (m: Record<string, string>) => (n: string) => m[n.toLowerCase()] ?? null;
  it("takes the single valid IP in the trusted header", () => {
    expect(visitorIp(h({ "cf-connecting-ip": "203.0.113.9" }), "CF-Connecting-IP")).toBe("203.0.113.9");
    expect(visitorIp(h({ "cf-connecting-ip": " 2001:db8::1 " }), "cf-connecting-ip")).toBe("2001:db8::1");
  });
  it("ignores everything else: no header, junk, lists, and the spoofable X-Forwarded-For", () => {
    expect(visitorIp(h({}), "cf-connecting-ip")).toBeNull();
    for (const v of ["", "nope", "1.2.3.4, 5.6.7.8", "1.2.3.4\r\nX: y", "999.1.1.1", "1.2.3.4:80"]) {
      expect(visitorIp(h({ "cf-connecting-ip": v }), "cf-connecting-ip")).toBeNull();
    }
    expect(visitorIp(h({ "x-forwarded-for": "6.6.6.6" }), "cf-connecting-ip")).toBeNull();
  });
});

describe("sendReport", () => {
  const body: ReportBody = { version: "1.0.0", reason: "malware", details: "x" };
  function mock(status: number) {
    const f = vi.fn(async () => new Response("{}", { status }));
    vi.stubGlobal("fetch", f);
    return f;
  }
  it("posts JSON to API_URL, server-side, forwarding the visitor IP", async () => {
    vi.stubEnv("API_URL", "http://backend:8080");
    const f = mock(202);
    expect(await sendReport("alice", "x.y", body, "203.0.113.9")).toBe(202);
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("http://backend:8080/v1/bundles/alice/x.y/report");
    expect(init.method).toBe("POST");
    expect(init.cache).toBe("no-store");
    expect(init.signal).toBeInstanceOf(AbortSignal);
    expect(JSON.parse(init.body as string)).toEqual(body);
    const hdr = init.headers as Record<string, string>;
    expect(hdr["Content-Type"]).toBe("application/json");
    expect(hdr["X-Forwarded-For"]).toBe("203.0.113.9");
    expect(hdr["CF-Connecting-IP"]).toBe("203.0.113.9");
  });
  it("sends no forwarding headers when the visitor IP is unknown", async () => {
    const f = mock(202);
    await sendReport("alice", "x", body, null);
    const hdr = (f.mock.calls[0] as unknown as [string, RequestInit])[1].headers as Record<string, string>;
    expect(Object.keys(hdr).map((k) => k.toLowerCase())).not.toContain("x-forwarded-for");
    expect(Object.keys(hdr).map((k) => k.toLowerCase())).not.toContain("cf-connecting-ip");
  });
  it("never calls the API for a path-like owner or name", async () => {
    const f = mock(202);
    for (const [o, n] of [["..", "x"], ["a", "../b"], ["a/b", "x"], ["", "x"]]) {
      expect(await sendReport(o, n, body, null)).toBe(404);
    }
    expect(f).not.toHaveBeenCalled();
  });
  it("returns 0 when the registry is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("down"); }));
    expect(await sendReport("a", "x", body, null)).toBe(0);
  });
});

describe("messageFor", () => {
  it("shows the same neutral text for every success", () => {
    const ok = "Thanks. The registry operator will review this.";
    expect(messageFor(202)).toEqual({ status: "ok", message: ok });
    expect(messageFor(201)).toEqual({ status: "ok", message: ok });
  });
  it("explains the rate limit", () => {
    expect(messageFor(429).message).toMatch(/too many reports from your network/i);
  });
  it("maps a 400 to a fixed field message, never registry text", () => {
    for (const f of ["reason", "details", "version"] as const) {
      const m = messageFor(400, `${f}: something <script>`);
      expect(m.status).toBe("error");
      expect(m.errors?.[f]).toBeTruthy();
      expect(JSON.stringify(m)).not.toContain("script");
    }
  });
  it("is generic for everything else", () => {
    for (const s of [0, 404, 413, 415, 500, 502]) {
      expect(messageFor(s).status).toBe("error");
      expect(messageFor(s).message).toBeTruthy();
    }
  });
});
