import { describe, it, expect, vi, beforeEach } from "vitest";
import worker from "./index";
import type { Env } from "./index";

const env: Env = {
  SPYDERBAT_API_URL: "https://api.spyderbat.com",
  SPYDERBAT_API_TOKEN: "test-token",
  SPYDERBAT_ORG_UID: "org-123",
  AUTH_SECRET: "supersecret",
  CF_API_TOKEN: "cf-token",
  CF_ACCOUNT_ID: "acct-123",
  CF_ZONE_ID: "zone-123",
  CF_IP_LIST_ID: "list-abc",
  SPYDERBAT_WEBHOOK_SECRET: "webhook-secret",
  CF_AI_GATEWAY_ID: "gw-123",
};

function makeRequest(method: string, path: string, body?: string, headers?: Record<string, string>): Request {
  return new Request(`https://worker.example.com${path}`, {
    method,
    body,
    headers: { "Content-Type": "application/x-ndjson", ...headers },
  });
}

// Build a valid HMAC-SHA256 signature for Spyderbat reverse webhook tests
async function hmacSign(body: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(body));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

// ── Health ────────────────────────────────────────────────────────────────
describe("health endpoint", () => {
  it("returns 200 with status ok and version", async () => {
    const res = await worker.fetch(makeRequest("GET", "/health"), env, {} as ExecutionContext);
    expect(res.status).toBe(200);
    const body = await res.json() as { status: string; version: string };
    expect(body.status).toBe("ok");
    expect(body.version).toBe("2.0");
  });
});

// ── Logpush ingest (POST /) ───────────────────────────────────────────────
describe("auth validation", () => {
  it("returns 401 when X-Auth-Secret is missing", async () => {
    const res = await worker.fetch(makeRequest("POST", "/", '{"Action":"block"}'), env, {} as ExecutionContext);
    expect(res.status).toBe(401);
  });

  it("returns 401 when X-Auth-Secret is wrong", async () => {
    const res = await worker.fetch(makeRequest("POST", "/", '{"Action":"block"}', { "X-Auth-Secret": "wrong" }), env, {} as ExecutionContext);
    expect(res.status).toBe(401);
  });

  it("accepts secret with surrounding whitespace", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 200 })));
    const res = await worker.fetch(makeRequest("POST", "/", '{"Action":"block","ClientIP":"1.1.1.1"}', { "X-Auth-Secret": "  supersecret  " }), env, {} as ExecutionContext);
    expect(res.status).not.toBe(401);
  });
});

describe("NDJSON ingestion", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 200 }))); });

  it("returns forwarded count", async () => {
    const ndjson = [
      JSON.stringify({ Action: "block", ClientIP: "1.1.1.1", Source: "waf", WAFRuleID: "R1", EdgeStartTimestamp: 1748476800000000000 }),
      JSON.stringify({ Action: "challenge", ClientIP: "2.2.2.2", BotScore: 5, BotScoreSrc: "Heuristics" }),
    ].join("\n");
    const res = await worker.fetch(makeRequest("POST", "/", ndjson, { "X-Auth-Secret": "supersecret" }), env, {} as ExecutionContext);
    expect(res.status).toBe(200);
    const body = await res.json() as { forwarded: number };
    expect(body.forwarded).toBe(2);
  });

  it("skips malformed lines", async () => {
    const ndjson = ["BAD_JSON", JSON.stringify({ Action: "block", ClientIP: "3.3.3.3" })].join("\n");
    const res = await worker.fetch(makeRequest("POST", "/", ndjson, { "X-Auth-Secret": "supersecret" }), env, {} as ExecutionContext);
    const body = await res.json() as { forwarded: number };
    expect(body.forwarded).toBe(1);
  });

  it("handles CRLF line endings", async () => {
    const ndjson = JSON.stringify({ Action: "block", ClientIP: "4.4.4.4" }) + "\r\n" + JSON.stringify({ Action: "log", ClientIP: "5.5.5.5" });
    const res = await worker.fetch(makeRequest("POST", "/", ndjson, { "X-Auth-Secret": "supersecret" }), env, {} as ExecutionContext);
    const body = await res.json() as { forwarded: number };
    expect(body.forwarded).toBe(2);
  });

  it("returns forwarded:0 for empty body", async () => {
    const res = await worker.fetch(makeRequest("POST", "/", "", { "X-Auth-Secret": "supersecret" }), env, {} as ExecutionContext);
    const body = await res.json() as { forwarded: number };
    expect(body.forwarded).toBe(0);
  });

  it("enriches events with country and ASN tags", async () => {
    const capture = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", capture);
    const payload = JSON.stringify({ Action: "block", ClientIP: "1.1.1.1", ClientCountry: "CN", ClientASN: 63949, ClientASNDescription: "LINODE-AP", Source: "waf", WAFRuleID: "R1" });
    await worker.fetch(makeRequest("POST", "/", payload, { "X-Auth-Secret": "supersecret" }), env, {} as ExecutionContext);
    const sent = JSON.parse(capture.mock.calls[0][1].body as string);
    expect(sent.tags).toContain("country:CN");
    expect(sent.description).toContain("asn:LINODE-AP");
  });
});

describe("severity mapping", () => {
  beforeEach(() => { vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 200 }))); });

  it("block → severity 8", async () => {
    const capture = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", capture);
    await worker.fetch(makeRequest("POST", "/", JSON.stringify({ Action: "block", ClientIP: "1.1.1.1" }), { "X-Auth-Secret": "supersecret" }), env, {} as ExecutionContext);
    expect(JSON.parse(capture.mock.calls[0][1].body as string).severity).toBe(8);
  });

  it("challenge + bot score < 30 → severity 7", async () => {
    const capture = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", capture);
    await worker.fetch(makeRequest("POST", "/", JSON.stringify({ Action: "challenge", ClientIP: "1.1.1.1", BotScore: 10 }), { "X-Auth-Secret": "supersecret" }), env, {} as ExecutionContext);
    expect(JSON.parse(capture.mock.calls[0][1].body as string).severity).toBe(7);
  });
});

// ── Reverse webhook (POST /spyderbat-alert) ───────────────────────────────
describe("reverse webhook: Spyderbat → Cloudflare block", () => {
  it("returns 401 when signature header missing", async () => {
    const res = await worker.fetch(makeRequest("POST", "/spyderbat-alert", '{}'), env, {} as ExecutionContext);
    expect(res.status).toBe(401);
  });

  it("returns 401 when HMAC signature is invalid", async () => {
    const res = await worker.fetch(makeRequest("POST", "/spyderbat-alert", '{}', { "X-Spyderbat-Signature": "invalidsig" }), env, {} as ExecutionContext);
    expect(res.status).toBe(401);
  });

  it("blocks IP when valid Spyderbat alert arrives", async () => {
    const body = JSON.stringify({ id: "alert-1", policy_name: "high-severity-ssh", severity: 9, src_ip: "10.0.0.1" });
    const sig = await hmacSign(body, "webhook-secret");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response('{"result":{"id":"item-1"}}', { status: 200 })));
    const res = await worker.fetch(makeRequest("POST", "/spyderbat-alert", body, { "X-Spyderbat-Signature": sig }), env, {} as ExecutionContext);
    expect(res.status).toBe(200);
    const result = await res.json() as { action: string; ip: string };
    expect(result.action).toBe("blocked");
    expect(result.ip).toBe("10.0.0.1");
  });

  it("returns noop when alert has no src_ip", async () => {
    const body = JSON.stringify({ id: "alert-2", policy_name: "anomaly", severity: 5 });
    const sig = await hmacSign(body, "webhook-secret");
    const res = await worker.fetch(makeRequest("POST", "/spyderbat-alert", body, { "X-Spyderbat-Signature": sig }), env, {} as ExecutionContext);
    const result = await res.json() as { action: string };
    expect(result.action).toBe("noop");
  });
});

// ── Spyderbat error handling ──────────────────────────────────────────────
describe("Spyderbat error handling", () => {
  it("returns 502 when Spyderbat returns non-2xx", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("error", { status: 500 })));
    const res = await worker.fetch(makeRequest("POST", "/", JSON.stringify({ Action: "block", ClientIP: "1.1.1.1" }), { "X-Auth-Secret": "supersecret" }), env, {} as ExecutionContext);
    expect(res.status).toBe(502);
  });

  it("returns 502 when Spyderbat is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network error")));
    const res = await worker.fetch(makeRequest("POST", "/", JSON.stringify({ Action: "block", ClientIP: "1.1.1.1" }), { "X-Auth-Secret": "supersecret" }), env, {} as ExecutionContext);
    expect(res.status).toBe(502);
  });
});
