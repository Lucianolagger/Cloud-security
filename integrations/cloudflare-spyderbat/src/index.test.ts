import { describe, it, expect, vi, beforeEach } from "vitest";
import worker from "./index";
import { Governance, CIRCUIT_THRESHOLD } from "./governance";
import type { Env } from "./index";

// ── Minimal in-memory KV mock ─────────────────────────────────────────────
function makeKV(): KVNamespace {
  const store = new Map<string, { value: string; expiry?: number }>();
  return {
    async get(key: string) {
      const entry = store.get(key);
      if (!entry) return null;
      if (entry.expiry && Date.now() > entry.expiry) { store.delete(key); return null; }
      return entry.value;
    },
    async put(key: string, value: string, opts?: { expirationTtl?: number }) {
      store.set(key, { value, expiry: opts?.expirationTtl ? Date.now() + opts.expirationTtl * 1000 : undefined });
    },
    async delete(key: string) { store.delete(key); },
    async list(opts?: { prefix?: string; limit?: number }) {
      const keys = [...store.keys()]
        .filter((k) => !opts?.prefix || k.startsWith(opts.prefix))
        .slice(0, opts?.limit ?? 1000)
        .map((name) => ({ name }));
      return { keys, list_complete: true, cursor: "" };
    },
  } as unknown as KVNamespace;
}

function makeEnv(overrides: Partial<Env> = {}): Env {
  return {
    SPYDERBAT_API_URL: "https://api.spyderbat.com",
    SPYDERBAT_API_TOKEN: "tok",
    SPYDERBAT_ORG_UID: "org-1",
    AUTH_SECRET: "supersecret",
    CF_API_TOKEN: "cf-tok",
    CF_ACCOUNT_ID: "acct-1",
    CF_ZONE_ID: "zone-1",
    CF_IP_LIST_ID: "list-1",
    SPYDERBAT_WEBHOOK_SECRET: "wh-secret",
    CF_AI_GATEWAY_ID: "gw-1",
    GOV_KV: makeKV(),
    GOV_ADMIN_SECRET: "admin-secret",
    ...overrides,
  };
}

async function hmacSign(body: string, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(body));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

function req(method: string, path: string, body?: string, headers?: Record<string, string>): Request {
  return new Request(`https://worker.test${path}`, {
    method, body,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

// ── Health ────────────────────────────────────────────────────────────────
describe("GET /health", () => {
  it("returns 200 with governance stats", async () => {
    const res = await worker.fetch(req("GET", "/health"), makeEnv(), {} as ExecutionContext);
    expect(res.status).toBe(200);
    const b = await res.json() as { status: string; governance: { circuit_open: boolean } };
    expect(b.status).toBe("ok");
    expect(b.governance.circuit_open).toBe(false);
  });
});

// ── Governance endpoints ──────────────────────────────────────────────────
describe("GET /gov/stats", () => {
  it("returns 401 without admin secret", async () => {
    const res = await worker.fetch(req("GET", "/gov/stats"), makeEnv(), {} as ExecutionContext);
    expect(res.status).toBe(401);
  });

  it("returns stats with admin secret", async () => {
    const res = await worker.fetch(req("GET", "/gov/stats", undefined, { "X-Gov-Admin-Secret": "admin-secret" }), makeEnv(), {} as ExecutionContext);
    expect(res.status).toBe(200);
    const b = await res.json() as { circuit_open: boolean; circuit_threshold: number };
    expect(b.circuit_open).toBe(false);
    expect(b.circuit_threshold).toBe(CIRCUIT_THRESHOLD);
  });
});

describe("GET /gov/audit", () => {
  it("returns empty audit log initially", async () => {
    const res = await worker.fetch(req("GET", "/gov/audit", undefined, { "X-Gov-Admin-Secret": "admin-secret" }), makeEnv(), {} as ExecutionContext);
    const b = await res.json() as { count: number };
    expect(b.count).toBe(0);
  });

  it("audit log grows after an event is forwarded", async () => {
    const env = makeEnv();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 200 })));
    await worker.fetch(
      req("POST", "/", JSON.stringify({ Action: "block", ClientIP: "1.1.1.1", Source: "waf", WAFRuleID: "R1" }), { "X-Auth-Secret": "supersecret", "Content-Type": "application/x-ndjson" }),
      env, {} as ExecutionContext,
    );
    const res = await worker.fetch(req("GET", "/gov/audit", undefined, { "X-Gov-Admin-Secret": "admin-secret" }), env, {} as ExecutionContext);
    const b = await res.json() as { count: number; decisions: Array<{ action: string }> };
    expect(b.count).toBeGreaterThan(0);
    expect(b.decisions[0].action).toBe("forwarded");
  });
});

describe("POST /gov/whitelist", () => {
  it("adds IP to whitelist and subsequent block is skipped", async () => {
    const env = makeEnv();

    // Add to whitelist
    const wlRes = await worker.fetch(
      req("POST", "/gov/whitelist", JSON.stringify({ ip: "10.0.0.1", reason: "Internal scanner", by: "admin@corp.com" }), { "X-Gov-Admin-Secret": "admin-secret" }),
      env, {} as ExecutionContext,
    );
    expect((await wlRes.json() as { whitelisted: string }).whitelisted).toBe("10.0.0.1");

    // Block attempt should be skipped
    const body = JSON.stringify({ id: "a1", policy_name: "test", severity: 9, src_ip: "10.0.0.1" });
    const sig = await hmacSign(body, "wh-secret");
    vi.stubGlobal("fetch", vi.fn());
    const blockRes = await worker.fetch(
      req("POST", "/spyderbat-alert", body, { "X-Spyderbat-Signature": sig }),
      env, {} as ExecutionContext,
    );
    const b = await blockRes.json() as { action: string };
    expect(b.action).toBe("skipped_whitelist");
    // CF API should NOT have been called
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });
});

describe("DELETE /gov/whitelist", () => {
  it("removes IP from whitelist", async () => {
    const env = makeEnv();
    await worker.fetch(req("POST", "/gov/whitelist", JSON.stringify({ ip: "9.9.9.9", reason: "test", by: "admin" }), { "X-Gov-Admin-Secret": "admin-secret" }), env, {} as ExecutionContext);
    const res = await worker.fetch(req("DELETE", "/gov/whitelist", JSON.stringify({ ip: "9.9.9.9" }), { "X-Gov-Admin-Secret": "admin-secret" }), env, {} as ExecutionContext);
    const b = await res.json() as { removed: string };
    expect(b.removed).toBe("9.9.9.9");
  });
});

describe("POST /gov/unblock", () => {
  it("calls CF API to remove IP and clears block TTL", async () => {
    const env = makeEnv();
    const cfUnblock = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", cfUnblock);
    const res = await worker.fetch(req("POST", "/gov/unblock", JSON.stringify({ ip: "5.5.5.5" }), { "X-Gov-Admin-Secret": "admin-secret" }), env, {} as ExecutionContext);
    expect(res.status).toBe(200);
    const b = await res.json() as { unblocked: string };
    expect(b.unblocked).toBe("5.5.5.5");
    expect(cfUnblock).toHaveBeenCalled();
  });
});

// ── Circuit breaker ───────────────────────────────────────────────────────
describe("circuit breaker", () => {
  it("opens after CIRCUIT_THRESHOLD blocks and holds subsequent alerts", async () => {
    const env = makeEnv();
    const gov = new Governance(env.GOV_KV, "admin-secret");

    // Pre-load counter to threshold
    const hour = new Date().toISOString().slice(0, 13);
    await env.GOV_KV.put(`gov:circuit:${hour}`, String(CIRCUIT_THRESHOLD));

    const body = JSON.stringify({ id: "cb-1", policy_name: "test", severity: 9, src_ip: "7.7.7.7" });
    const sig = await hmacSign(body, "wh-secret");
    vi.stubGlobal("fetch", vi.fn());

    const res = await worker.fetch(req("POST", "/spyderbat-alert", body, { "X-Spyderbat-Signature": sig }), env, {} as ExecutionContext);
    const b = await res.json() as { action: string };
    expect(b.action).toBe("held_circuit");
    expect(vi.mocked(fetch)).not.toHaveBeenCalled(); // CF API not called
  });
});

// ── Duplicate block skip ──────────────────────────────────────────────────
describe("duplicate block skip", () => {
  it("skips if IP already blocked within TTL window", async () => {
    const env = makeEnv();
    const gov = new Governance(env.GOV_KV, "admin-secret");
    await gov.trackBlock("8.8.8.8", "already-blocked");

    const body = JSON.stringify({ id: "dup-1", policy_name: "test", severity: 9, src_ip: "8.8.8.8" });
    const sig = await hmacSign(body, "wh-secret");
    vi.stubGlobal("fetch", vi.fn());

    const res = await worker.fetch(req("POST", "/spyderbat-alert", body, { "X-Spyderbat-Signature": sig }), env, {} as ExecutionContext);
    const b = await res.json() as { action: string };
    expect(b.action).toBe("duplicate_skip");
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });
});

// ── Happy path block with governance metadata ─────────────────────────────
describe("successful block with governance", () => {
  it("returns decision_id and expires_in", async () => {
    const env = makeEnv();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response('{"result":{"id":"x"}}', { status: 200 })));
    const body = JSON.stringify({ id: "ok-1", policy_name: "waf-critical", severity: 9, src_ip: "203.0.113.1" });
    const sig = await hmacSign(body, "wh-secret");
    const res = await worker.fetch(req("POST", "/spyderbat-alert", body, { "X-Spyderbat-Signature": sig }), env, {} as ExecutionContext);
    const b = await res.json() as { action: string; decision_id: string; expires_in: string };
    expect(b.action).toBe("blocked");
    expect(b.decision_id).toBeTruthy();
    expect(b.expires_in).toBe("24h");
  });
});

// ── Logpush: gov metadata attached to Spyderbat events ───────────────────
describe("governance metadata on forwarded events", () => {
  it("each event contains gov.decision_id and gov.auto_action", async () => {
    const env = makeEnv();
    const capture = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", capture);
    await worker.fetch(
      req("POST", "/", JSON.stringify({ Action: "block", ClientIP: "6.6.6.6", Source: "waf", WAFRuleID: "R2" }),
        { "X-Auth-Secret": "supersecret", "Content-Type": "application/x-ndjson" }),
      env, {} as ExecutionContext,
    );
    const sent = JSON.parse(capture.mock.calls[0][1].body as string) as { gov: { decision_id: string; auto_action: boolean } };
    expect(sent.gov.decision_id).toBeTruthy();
    expect(sent.gov.auto_action).toBe(true);
  });
});
