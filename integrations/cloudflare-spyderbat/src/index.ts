import { Governance } from "./governance";
import type { GovDecision } from "./governance";

export interface Env {
  // ── Spyderbat ingest ─────────────────────────────────────────────────────
  SPYDERBAT_API_URL: string;
  SPYDERBAT_API_TOKEN: string;
  SPYDERBAT_ORG_UID: string;
  // ── Logpush auth ─────────────────────────────────────────────────────────
  AUTH_SECRET: string;
  // ── Cloudflare API (reverse block) ───────────────────────────────────────
  CF_API_TOKEN: string;
  CF_ACCOUNT_ID: string;
  CF_ZONE_ID: string;
  CF_IP_LIST_ID: string;
  // ── Spyderbat webhook auth ───────────────────────────────────────────────
  SPYDERBAT_WEBHOOK_SECRET: string;
  // ── AI Gateway Shadow AI polling ─────────────────────────────────────────
  CF_AI_GATEWAY_ID: string;
  // ── Governance ───────────────────────────────────────────────────────────
  GOV_KV: KVNamespace;        // KV namespace for audit log, whitelist, stats
  GOV_ADMIN_SECRET: string;   // Secret for admin governance endpoints
}

// ── Field schemas ─────────────────────────────────────────────────────────
interface CFLogEntry {
  Action?: string;
  ClientIP?: string;
  ClientRequestHost?: string;
  ClientRequestMethod?: string;
  ClientRequestPath?: string;
  ClientRequestQuery?: string;
  ClientRequestUserAgent?: string;
  ClientCountry?: string;
  ClientASN?: number;
  ClientASNDescription?: string;
  EdgeStartTimestamp?: number;
  EdgeResponseStatus?: number;
  RayID?: string;
  RuleID?: string;
  Source?: string;
  BotScore?: number;
  BotScoreSrc?: string;
  BotTags?: string[];
  WAFAction?: string;
  WAFRuleID?: string;
  WAFRuleMessage?: string;
  WAFMatchedVar?: string;
  FirewallMatchesActions?: string[];
  FirewallMatchesRuleIDs?: string[];
  FirewallMatchesSources?: string[];
  ZoneName?: string;
}

interface AIGatewayLog {
  id: string;
  provider: string;
  model?: string;
  request_type?: string;
  status_code?: number;
  success?: boolean;
  created_at?: string;
  tokens_in?: number;
  tokens_out?: number;
  cf_connecting_ip?: string;
  cf_ray?: string;
  metadata?: Record<string, unknown>;
}

interface SpyderbatAlert {
  id: string;
  policy_name: string;
  severity: number;
  src_ip?: string;
  description?: string;
  tags?: string[];
  time?: number;
}

interface SpyderbatEvent {
  schema: "cloudflare_security_event";
  time: number;
  id: string;
  class: string;
  action: string;
  severity: number;
  src_ip: string;
  description: string;
  details: Record<string, unknown>;
  tags: string[];
  cf_ray?: string;
  // Governance metadata attached to every event Spyderbat receives
  gov: {
    decision_id: string;
    reviewed: boolean;
    auto_action: boolean;
    circuit_count: number;
  };
}

// ── Lookup tables ─────────────────────────────────────────────────────────
const ACTION_SEVERITY: Record<string, number> = {
  block: 8, drop: 8,
  challenge: 6, jschallenge: 6,
  managed_challenge: 5,
  log: 3, allow: 3,
};

const SHADOW_AI_PROVIDERS = new Set([
  "openai", "anthropic", "google-ai", "cohere", "mistral",
  "perplexity", "groq", "azure-openai",
]);

const MAX_BODY_BYTES = 10 * 1024 * 1024;

// ── Transform: Logpush firewall event ─────────────────────────────────────
function toSpyderbatEvent(log: CFLogEntry, cfRay: string, govMeta: SpyderbatEvent["gov"]): SpyderbatEvent {
  const action = (log.Action ?? log.WAFAction ?? "unknown").toLowerCase();
  let severity = ACTION_SEVERITY[action] ?? 4;
  if (typeof log.BotScore === "number" && log.BotScore < 30) severity = Math.min(10, severity + 1);

  let eventClass = "security_event";
  if (log.Source === "waf" || log.WAFRuleID) eventClass = "waf_event";
  else if (typeof log.BotScore === "number" && log.BotScore < 30) eventClass = "bot_event";
  else if (log.FirewallMatchesSources?.includes("ddos")) eventClass = "ddos_event";
  else if (log.FirewallMatchesSources?.length) eventClass = "firewall_event";

  const descParts = [`action:${action}`, `ip:${log.ClientIP ?? "?"}`];
  if (log.WAFRuleMessage) descParts.push(`waf:${log.WAFRuleMessage}`);
  if (log.WAFMatchedVar) descParts.push(`matched:${log.WAFMatchedVar}`);
  if (typeof log.BotScore === "number") descParts.push(`bot_score:${log.BotScore}`);
  if (log.ClientCountry) descParts.push(`country:${log.ClientCountry}`);
  if (log.ClientASNDescription) descParts.push(`asn:${log.ClientASNDescription}`);

  const tags = ["cloudflare", eventClass, `action:${action}`];
  if (log.Source) tags.push(`source:${log.Source}`);
  if (log.ClientCountry) tags.push(`country:${log.ClientCountry}`);
  if (log.BotTags?.length) tags.push(...log.BotTags.map((t) => `bot:${t.toLowerCase()}`));
  if (log.ZoneName) tags.push(`zone:${log.ZoneName}`);

  return {
    schema: "cloudflare_security_event",
    // EdgeStartTimestamp is in nanoseconds per Cloudflare Logpush docs
    time: log.EdgeStartTimestamp ? Math.floor(log.EdgeStartTimestamp / 1e9) : Math.floor(Date.now() / 1000),
    id: crypto.randomUUID(),
    class: eventClass,
    action,
    severity,
    src_ip: log.ClientIP ?? "",
    description: descParts.join(" | "),
    details: { ...log },
    tags,
    cf_ray: cfRay || undefined,
    gov: govMeta,
  };
}

// ── Transform: AI Gateway log ─────────────────────────────────────────────
function aiGatewayToSpyderbatEvent(log: AIGatewayLog, govMeta: SpyderbatEvent["gov"]): SpyderbatEvent {
  const isShadow = SHADOW_AI_PROVIDERS.has(log.provider?.toLowerCase());
  return {
    schema: "cloudflare_security_event",
    time: log.created_at ? Math.floor(new Date(log.created_at).getTime() / 1000) : Math.floor(Date.now() / 1000),
    id: log.id ?? crypto.randomUUID(),
    class: "shadow_ai_event",
    action: log.success ? "allowed" : "blocked",
    severity: isShadow ? (log.success ? 6 : 8) : 3,
    src_ip: log.cf_connecting_ip ?? "",
    description: `Shadow AI: ${log.provider} model:${log.model ?? "?"} tokens_in:${log.tokens_in ?? 0} tokens_out:${log.tokens_out ?? 0}`,
    details: { ...log },
    tags: [
      "cloudflare", "shadow_ai_event", "ai-gateway",
      `provider:${log.provider}`,
      ...(log.model ? [`model:${log.model}`] : []),
      isShadow ? "shadow_ai" : "authorized_ai",
    ],
    cf_ray: log.cf_ray,
    gov: govMeta,
  };
}

// ── Cloudflare API: block IP ──────────────────────────────────────────────
async function blockIpInCloudflare(ip: string, comment: string, env: Env): Promise<void> {
  const url = `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/rules/lists/${env.CF_IP_LIST_ID}/items`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.CF_API_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify([{ ip, comment: comment.slice(0, 500) }]),
  });
  if (!res.ok) {
    const err = await res.text().catch(() => "");
    console.log(JSON.stringify({ level: "error", msg: "cf_block_failed", ip, status: res.status, err: err.slice(0, 200) }));
    throw new Error(`CF block failed: ${res.status}`);
  }
}

// ── Cloudflare API: unblock IP ────────────────────────────────────────────
async function unblockIpInCloudflare(ip: string, env: Env): Promise<void> {
  const url = `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/rules/lists/${env.CF_IP_LIST_ID}/items`;
  const res = await fetch(url, {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${env.CF_API_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ items: [{ ip }] }),
  });
  if (!res.ok) {
    console.log(JSON.stringify({ level: "warn", msg: "cf_unblock_failed", ip, status: res.status }));
  }
}

// ── Spyderbat ingest ──────────────────────────────────────────────────────
async function sendToSpyderbat(events: SpyderbatEvent[], env: Env, cfRay = ""): Promise<Response> {
  const ingestUrl = `${env.SPYDERBAT_API_URL}/api/v1/source/ingest/${env.SPYDERBAT_ORG_UID}`;
  const body = events.map((e) => JSON.stringify(e)).join("\n");
  let res: Response;
  try {
    res = await fetch(ingestUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.SPYDERBAT_API_TOKEN}`,
        "Content-Type": "application/x-ndjson",
        "X-CF-Ray": cfRay,
      },
      body,
    });
  } catch (err) {
    console.log(JSON.stringify({ level: "error", msg: "spyderbat_unreachable", error: String(err), cf_ray: cfRay }));
    return new Response("Bad Gateway", { status: 502 });
  }
  if (!res.ok) {
    const errText = await res.text().catch(() => "");
    console.log(JSON.stringify({ level: "error", msg: "spyderbat_error", status: res.status, body: errText.slice(0, 200), cf_ray: cfRay }));
    return new Response("Bad Gateway", { status: 502 });
  }
  console.log(JSON.stringify({ level: "info", msg: "forwarded", count: events.length, cf_ray: cfRay }));
  return Response.json({ forwarded: events.length });
}

// ── HMAC verification ─────────────────────────────────────────────────────
async function verifyHmac(body: string, signature: string, secret: string): Promise<boolean> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const sigBytes = Uint8Array.from(atob(signature), (c) => c.charCodeAt(0));
  return crypto.subtle.verify("HMAC", key, sigBytes, enc.encode(body));
}

// ── Admin auth ────────────────────────────────────────────────────────────
function isAdmin(request: Request, env: Env): boolean {
  return (request.headers.get("X-Gov-Admin-Secret") ?? "").trim() === env.GOV_ADMIN_SECRET.trim();
}

// ── Main ──────────────────────────────────────────────────────────────────
export default {
  // ── Cron: poll AI Gateway every 5 minutes ────────────────────────────────
  async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
    const gov = new Governance(env.GOV_KV, env.GOV_ADMIN_SECRET);
    const since = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const url = `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/ai-gateway/gateways/${env.CF_AI_GATEWAY_ID}/logs?start=${since}&order_by=created_at&direction=asc&per_page=100`;

    let logsRes: Response;
    try {
      logsRes = await fetch(url, { headers: { Authorization: `Bearer ${env.CF_API_TOKEN}` } });
    } catch (err) {
      console.log(JSON.stringify({ level: "error", msg: "ai_gateway_poll_failed", error: String(err) }));
      return;
    }
    if (!logsRes.ok) return;

    const data = await logsRes.json() as { result?: AIGatewayLog[] };
    const logs = data.result ?? [];
    if (logs.length === 0) return;

    const circuitCount = await gov.getCircuitCount();
    const events: SpyderbatEvent[] = [];

    for (const l of logs) {
      const decisionId = crypto.randomUUID();
      const govMeta: SpyderbatEvent["gov"] = {
        decision_id: decisionId,
        reviewed: false,
        auto_action: true,
        circuit_count: circuitCount,
      };
      const event = aiGatewayToSpyderbatEvent(l, govMeta);

      await gov.logDecision({
        id: decisionId,
        ts: Date.now(),
        type: "shadow_ai_flag",
        src_ip: l.cf_connecting_ip ?? "",
        severity: event.severity,
        event_class: "shadow_ai_event",
        action: "forwarded",
        reason: `AI Gateway: provider=${l.provider} model=${l.model ?? "?"} tokens_in=${l.tokens_in ?? 0}`,
        reviewed: false,
      } satisfies GovDecision);

      events.push(event);
    }

    console.log(JSON.stringify({ level: "info", msg: "ai_gateway_polled", count: events.length }));
    await sendToSpyderbat(events, env);
  },

  async fetch(request: Request, env: Env, _ctx?: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const cfRay = request.headers.get("CF-Ray") ?? "";
    const gov = new Governance(env.GOV_KV, env.GOV_ADMIN_SECRET);

    // ── Health ───────────────────────────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/health") {
      const stats = await gov.getStats();
      return Response.json({ status: "ok", service: "cloudflare-spyderbat-worker", version: "3.0", governance: stats });
    }

    // ════════════════════════════════════════════════════════════════════
    // GOVERNANCE ENDPOINTS — require X-Gov-Admin-Secret header
    // ════════════════════════════════════════════════════════════════════

    // GET /gov/stats — AI usage and decision metrics for current hour
    if (request.method === "GET" && url.pathname === "/gov/stats") {
      if (!isAdmin(request, env)) return new Response("Unauthorized", { status: 401 });
      return Response.json(await gov.getStats());
    }

    // GET /gov/audit?limit=20 — recent AI decisions
    if (request.method === "GET" && url.pathname === "/gov/audit") {
      if (!isAdmin(request, env)) return new Response("Unauthorized", { status: 401 });
      const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "20", 10), 100);
      const decisions = await gov.getAuditLog(limit);
      return Response.json({ count: decisions.length, decisions });
    }

    // POST /gov/whitelist — add IP to permanent whitelist (never auto-block)
    if (request.method === "POST" && url.pathname === "/gov/whitelist") {
      if (!isAdmin(request, env)) return new Response("Unauthorized", { status: 401 });
      const { ip, reason, by } = await request.json() as { ip: string; reason: string; by: string };
      if (!ip || !reason) return new Response("ip and reason required", { status: 400 });
      await gov.addWhitelist(ip, reason, by ?? "admin");
      console.log(JSON.stringify({ level: "info", msg: "gov_whitelist_add", ip, reason, by }));
      return Response.json({ whitelisted: ip, reason });
    }

    // DELETE /gov/whitelist — remove IP from whitelist
    if (request.method === "DELETE" && url.pathname === "/gov/whitelist") {
      if (!isAdmin(request, env)) return new Response("Unauthorized", { status: 401 });
      const { ip } = await request.json() as { ip: string };
      await gov.removeWhitelist(ip);
      console.log(JSON.stringify({ level: "info", msg: "gov_whitelist_remove", ip }));
      return Response.json({ removed: ip });
    }

    // POST /gov/unblock — manually unblock an IP in Cloudflare + clear TTL
    if (request.method === "POST" && url.pathname === "/gov/unblock") {
      if (!isAdmin(request, env)) return new Response("Unauthorized", { status: 401 });
      const { ip } = await request.json() as { ip: string };
      await Promise.all([
        unblockIpInCloudflare(ip, env),
        gov.clearBlock(ip),
      ]);
      console.log(JSON.stringify({ level: "info", msg: "gov_manual_unblock", ip }));
      return Response.json({ unblocked: ip });
    }

    // ════════════════════════════════════════════════════════════════════
    // REVERSE WEBHOOK — Spyderbat alert → Cloudflare block
    // ════════════════════════════════════════════════════════════════════
    if (request.method === "POST" && url.pathname === "/spyderbat-alert") {
      const rawBody = await request.text().catch(() => "");
      const signature = request.headers.get("X-Spyderbat-Signature") ?? "";
      if (!signature) return new Response("Unauthorized", { status: 401 });

      const valid = await verifyHmac(rawBody, signature, env.SPYDERBAT_WEBHOOK_SECRET).catch(() => false);
      if (!valid) {
        console.log(JSON.stringify({ level: "warn", msg: "spyderbat_invalid_hmac" }));
        return new Response("Unauthorized", { status: 401 });
      }

      let alert: SpyderbatAlert;
      try { alert = JSON.parse(rawBody) as SpyderbatAlert; }
      catch { return new Response("Bad Request", { status: 400 }); }

      const decisionId = crypto.randomUUID();
      const ip = alert.src_ip ?? "";

      if (!ip) {
        return Response.json({ action: "noop", reason: "no src_ip", decision_id: decisionId });
      }

      // ── Governance gate ──────────────────────────────────────────────
      const [whitelisted, circuitOpen, alreadyBlocked] = await Promise.all([
        gov.isWhitelisted(ip),
        gov.isCircuitOpen(),
        gov.isAlreadyBlocked(ip),
      ]);

      const baseDecision: Omit<GovDecision, "action" | "reason"> = {
        id: decisionId,
        ts: Date.now(),
        type: "cf_auto_block",
        src_ip: ip,
        severity: alert.severity,
        event_class: "spyderbat_alert",
        policy: alert.policy_name,
        expires_at: Date.now() + 86_400_000,
        reviewed: false,
      };

      if (whitelisted) {
        const entry = await gov.getWhitelistEntry(ip);
        await gov.logDecision({ ...baseDecision, action: "skipped_whitelist", reason: `Whitelisted: ${entry?.reason ?? "?"}` });
        console.log(JSON.stringify({ level: "info", msg: "gov_whitelist_skip", ip, decision_id: decisionId }));
        return Response.json({ action: "skipped_whitelist", ip, decision_id: decisionId });
      }

      if (alreadyBlocked) {
        await gov.logDecision({ ...baseDecision, action: "duplicate_skip", reason: "IP already in active block window" });
        return Response.json({ action: "duplicate_skip", ip, decision_id: decisionId });
      }

      if (circuitOpen) {
        await gov.logDecision({ ...baseDecision, action: "held_circuit", reason: `Circuit breaker open: >${50} blocks/hour — human review required` });
        console.log(JSON.stringify({ level: "warn", msg: "gov_circuit_open", ip, decision_id: decisionId }));
        return Response.json({ action: "held_circuit", ip, decision_id: decisionId, message: "Circuit breaker open. Review /gov/audit and unblock manually if needed." });
      }

      // ── Approved — execute block ─────────────────────────────────────
      const comment = `spyderbat:${alert.policy_name ?? "?"} sev:${alert.severity} gov:${decisionId}`;
      try {
        await blockIpInCloudflare(ip, comment, env);
        await Promise.all([
          gov.trackBlock(ip, comment),
          gov.incrementCircuit(),
          gov.logDecision({ ...baseDecision, action: "blocked", reason: comment }),
        ]);
        console.log(JSON.stringify({ level: "info", msg: "gov_block_executed", ip, policy: alert.policy_name, decision_id: decisionId }));
        return Response.json({ action: "blocked", ip, policy: alert.policy_name, decision_id: decisionId, expires_in: "24h" });
      } catch {
        return new Response("Failed to block IP", { status: 502 });
      }
    }

    // ════════════════════════════════════════════════════════════════════
    // LOGPUSH WEBHOOK — Cloudflare security events → Spyderbat
    // ════════════════════════════════════════════════════════════════════
    if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

    const incomingSecret = (request.headers.get("X-Auth-Secret") ?? "").trim();
    if (!incomingSecret || incomingSecret !== env.AUTH_SECRET.trim()) {
      console.log(JSON.stringify({ level: "warn", msg: "unauthorized", cf_ray: cfRay }));
      return new Response("Unauthorized", { status: 401 });
    }

    const contentLength = parseInt(request.headers.get("Content-Length") ?? "0", 10);
    if (contentLength > MAX_BODY_BYTES) return new Response("Payload Too Large", { status: 413 });

    let body: string;
    try { body = await request.text(); } catch { return new Response("Bad Request", { status: 400 }); }
    if (body.length > MAX_BODY_BYTES) return new Response("Payload Too Large", { status: 413 });

    const circuitCount = await gov.getCircuitCount();
    const events: SpyderbatEvent[] = [];

    for (const line of body.split(/\r?\n/).filter(Boolean)) {
      let log: CFLogEntry;
      try { log = JSON.parse(line) as CFLogEntry; } catch {
        console.log(JSON.stringify({ level: "warn", msg: "skipped_malformed_line", cf_ray: cfRay }));
        continue;
      }

      const decisionId = crypto.randomUUID();
      const govMeta: SpyderbatEvent["gov"] = {
        decision_id: decisionId,
        reviewed: false,
        auto_action: true,
        circuit_count: circuitCount,
      };

      const event = toSpyderbatEvent(log, cfRay, govMeta);

      // Determine decision type for audit
      const typeMap: Record<string, GovDecision["type"]> = {
        waf_event: "waf_forward",
        bot_event: "bot_forward",
        ddos_event: "ddos_forward",
      };

      await gov.logDecision({
        id: decisionId,
        ts: Date.now(),
        type: typeMap[event.class] ?? "generic_forward",
        src_ip: event.src_ip,
        severity: event.severity,
        event_class: event.class,
        action: "forwarded",
        reason: event.description,
        cf_ray: cfRay,
        reviewed: false,
      } satisfies GovDecision);

      events.push(event);
    }

    if (events.length === 0) return Response.json({ forwarded: 0 });
    return sendToSpyderbat(events, env, cfRay);
  },
};
