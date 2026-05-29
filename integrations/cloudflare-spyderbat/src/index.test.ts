import { describe, it, expect, vi, beforeEach } from "vitest";
import worker from "./index";
import type { Env } from "./index";

const env: Env = {
  SPYDERBAT_API_URL: "https://api.spyderbat.com",
  SPYDERBAT_API_TOKEN: "test-token",
  SPYDERBAT_ORG_UID: "org-123",
  AUTH_SECRET: "supersecret",
};

function makeRequest(method: string, path: string, body?: string, headers?: Record<string, string>): Request {
  return new Request(`https://worker.example.com${path}`, {
    method,
    body,
    headers: {
      "Content-Type": "application/x-ndjson",
      ...headers,
    },
  });
}

describe("health endpoint", () => {
  it("returns 200 with status ok", async () => {
    const req = makeRequest("GET", "/health");
    const res = await worker.fetch(req, env, {} as ExecutionContext);
    expect(res.status).toBe(200);
    const body = await res.json() as { status: string };
    expect(body.status).toBe("ok");
  });
});

describe("auth validation", () => {
  it("returns 401 when X-Auth-Secret is missing", async () => {
    const req = makeRequest("POST", "/", '{"Action":"block","ClientIP":"1.2.3.4"}');
    const res = await worker.fetch(req, env, {} as ExecutionContext);
    expect(res.status).toBe(401);
  });

  it("returns 401 when X-Auth-Secret is wrong", async () => {
    const req = makeRequest("POST", "/", '{"Action":"block"}', { "X-Auth-Secret": "wrong" });
    const res = await worker.fetch(req, env, {} as ExecutionContext);
    expect(res.status).toBe(401);
  });

  it("accepts request with correct secret (trimmed)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 200 })));
    const req = makeRequest("POST", "/", '{"Action":"block","ClientIP":"1.2.3.4"}', {
      "X-Auth-Secret": "  supersecret  ",
    });
    const res = await worker.fetch(req, env, {} as ExecutionContext);
    expect(res.status).not.toBe(401);
  });
});

describe("NDJSON ingestion", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 200 })));
  });

  it("returns forwarded count on valid NDJSON", async () => {
    const ndjson = [
      JSON.stringify({ Action: "block", ClientIP: "1.1.1.1", Source: "waf", WAFRuleID: "100001A" }),
      JSON.stringify({ Action: "challenge", ClientIP: "2.2.2.2", BotScore: 5, BotScoreSrc: "Heuristics" }),
    ].join("\n");

    const req = makeRequest("POST", "/", ndjson, { "X-Auth-Secret": "supersecret" });
    const res = await worker.fetch(req, env, {} as ExecutionContext);
    expect(res.status).toBe(200);
    const body = await res.json() as { forwarded: number };
    expect(body.forwarded).toBe(2);
  });

  it("skips malformed lines and processes valid ones", async () => {
    const ndjson = ["not-json", JSON.stringify({ Action: "block", ClientIP: "3.3.3.3" })].join("\n");
    const req = makeRequest("POST", "/", ndjson, { "X-Auth-Secret": "supersecret" });
    const res = await worker.fetch(req, env, {} as ExecutionContext);
    const body = await res.json() as { forwarded: number };
    expect(body.forwarded).toBe(1);
  });

  it("handles CRLF line endings", async () => {
    const ndjson = JSON.stringify({ Action: "block", ClientIP: "4.4.4.4" }) + "\r\n" +
                   JSON.stringify({ Action: "log", ClientIP: "5.5.5.5" });
    const req = makeRequest("POST", "/", ndjson, { "X-Auth-Secret": "supersecret" });
    const res = await worker.fetch(req, env, {} as ExecutionContext);
    const body = await res.json() as { forwarded: number };
    expect(body.forwarded).toBe(2);
  });

  it("returns 200 with forwarded:0 for empty body", async () => {
    const req = makeRequest("POST", "/", "", { "X-Auth-Secret": "supersecret" });
    const res = await worker.fetch(req, env, {} as ExecutionContext);
    expect(res.status).toBe(200);
    const body = await res.json() as { forwarded: number };
    expect(body.forwarded).toBe(0);
  });
});

describe("severity mapping", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 200 })));
  });

  it("assigns severity 8 for block action", async () => {
    const capturedFetch = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", capturedFetch);

    const req = makeRequest("POST", "/",
      JSON.stringify({ Action: "block", ClientIP: "1.1.1.1" }),
      { "X-Auth-Secret": "supersecret" }
    );
    await worker.fetch(req, env, {} as ExecutionContext);

    const callBody = capturedFetch.mock.calls[0][1].body as string;
    const event = JSON.parse(callBody);
    expect(event.severity).toBe(8);
  });

  it("bumps severity +1 for bot score < 30", async () => {
    const capturedFetch = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", capturedFetch);

    const req = makeRequest("POST", "/",
      JSON.stringify({ Action: "challenge", ClientIP: "1.1.1.1", BotScore: 10 }),
      { "X-Auth-Secret": "supersecret" }
    );
    await worker.fetch(req, env, {} as ExecutionContext);

    const callBody = capturedFetch.mock.calls[0][1].body as string;
    const event = JSON.parse(callBody);
    // challenge=6, bot bump → 7
    expect(event.severity).toBe(7);
  });
});

describe("Spyderbat error handling", () => {
  it("returns 502 when Spyderbat returns non-2xx", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("error", { status: 500 })));
    const req = makeRequest("POST", "/",
      JSON.stringify({ Action: "block", ClientIP: "1.1.1.1" }),
      { "X-Auth-Secret": "supersecret" }
    );
    const res = await worker.fetch(req, env, {} as ExecutionContext);
    expect(res.status).toBe(502);
  });

  it("returns 502 when Spyderbat is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network error")));
    const req = makeRequest("POST", "/",
      JSON.stringify({ Action: "block", ClientIP: "1.1.1.1" }),
      { "X-Auth-Secret": "supersecret" }
    );
    const res = await worker.fetch(req, env, {} as ExecutionContext);
    expect(res.status).toBe(502);
  });
});
