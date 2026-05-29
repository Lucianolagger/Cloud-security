export interface Env {
  SPYDERBAT_API_URL: string;
  SPYDERBAT_API_TOKEN: string;
  SPYDERBAT_ORG_UID: string;
  AUTH_SECRET: string;
  // Reverse webhook: Cloudflare API credentials
  CF_API_TOKEN: string;
  CF_ACCOUNT_ID: string;
  CF_ZONE_ID: string;
  CF_IP_LIST_ID: string;      // ID of a Cloudflare IP List used as blocklist
  SPYDERBAT_WEBHOOK_SECRET: string; // HMAC secret Spyderbat signs its webhooks with
  // AI Gateway polling (used by cron handler)
  CF_AI_GATEWAY_ID: string;
}

// ── Cloudflare Logpush firewall-events field schema (partial) ──────────────
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

// ── Cloudflare AI Gateway log entry ──────────────────────────────────────
interface AIGatewayLog {
  id: string;
  provider: string;       // "openai" | "anthropic" | "workers-ai" | ...
  model?: string;
  request_type?: string;
  status_code?: number;
  success?: boolean;
  created_at?: string;
  tokens_in?: number;
  tokens_out?: number;
  metadata?: Record<string, unknown>;
  // Custom headers forwarded through AI Gateway
  cf_connecting_ip?: string;
  cf_ray?: string;
}

// ── Spyderbat webhook alert (reverse direction) ───────────────────────────
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
}

// ── Lookup tables ─────────────────────────────────────────────────────────
const ACTION_SEVERITY: Record<string, number> = {
  block: 8,
  drop: 8,
  challenge: 6,
  jschallenge: 6,
  managed_challenge: 5,
  log: 3,
  allow: 3,
};

// Shadow AI: known unauthorized AI providers to flag
const SHADOW_AI_PROVIDERS = new Set([
  "openai", "anthropic", "google-ai", "cohere", "mistral",
  "perplexity", "groq", "azure-openai",
]);

const MAX_BODY_BYTES = 10 * 1024 * 1024;

// ── Transform: Logpush firewall event → Spyderbat ─────────────────────────
function toSpyderbatEvent(log: CFLogEntry, cfRay: string): SpyderbatEvent {
  const action = (log.Action ?? log.WAFAction ?? "unknown").toLowerCase();
  let severity = ACTION_SEVERITY[action] ?? 4;
  if (typeof log.BotScore === "number" && log.BotScore < 30) severity = Math.min(10, severity + 1);

  // Priority: waf > bot > ddos > firewall > generic
  let eventClass = "security_event";
  if (log.Source === "waf" || log.WAFRuleID) eventClass = "waf_event";
  else if (typeof log.BotScore === "number" && log.BotScore < 30) eventClass = "bot_event";
  else if (log.FirewallMatchesSources?.includes("ddos")) eventClass = "ddos_event";
  else if (log.FirewallMatchesSources?.length) eventClass = "firewall_event";

  const descParts: string[] = [`action:${action}`, `ip:${log.ClientIP ?? "?"}`];
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
  };
}

// ── Transform: AI Gateway log → Spyderbat shadow_ai_event ─────────────────
function aiGatewayToSpyderbatEvent(log: AIGatewayLog): SpyderbatEvent {
  const isShadow = SHADOW_AI_PROVIDERS.has(log.provider?.toLowerCase());
  return {
    schema: "cloudflare_security_event",
    time: log.created_at ? Math.floor(new Date(log.created_at).getTime() / 1000) : Math.floor(Date.now() / 1000),
    id: log.id ?? crypto.randomUUID(),
    class: "shadow_ai_event",
    action: log.success ? "allowed" : "blocked",
    // Shadow AI usage is medium severity; failed calls (unauthorized model) are higher
    severity: isShadow ? (log.success ? 6 : 8) : 3,
    src_ip: log.cf_connecting_ip ?? "",
    description: `Shadow AI: ${log.provider} model:${log.model ?? "?"} tokens_in:${log.tokens_in ?? 0} tokens_out:${log.tokens_out ?? 0}`,
    details: { ...log },
    tags: [
      "cloudflare", "shadow_ai_event", "ai-gateway",
      `provider:${log.provider}`,
      ...(log.model ? [`model:${log.model}`] : []),
      ...(isShadow ? ["shadow_ai"] : ["authorized_ai"]),
    ],
    cf_ray: log.cf_ray,
  };
}

// ── Cloudflare API: add IP to blocklist ───────────────────────────────────
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
    console.log(JSON.stringify({ level: "error", msg: "cf_ip_block_failed", ip, status: res.status, err: err.slice(0, 200) }));
    throw new Error(`CF block failed: ${res.status}`);
  }
  console.log(JSON.stringify({ level: "info", msg: "cf_ip_blocked", ip, comment }));
}

// ── Spyderbat ingest helper ───────────────────────────────────────────────
async function sendToSpyderbat(events: SpyderbatEvent[], env: Env, cfRay = ""): Promise<Response> {
  const ingestUrl = `${env.SPYDERBAT_API_URL}/api/v1/source/ingest/${env.SPYDERBAT_ORG_UID}`;
  const body = events.map((e) => JSON.stringify(e)).join("\n");

  let spyderbatRes: Response;
  try {
    spyderbatRes = await fetch(ingestUrl, {
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

  if (!spyderbatRes.ok) {
    const errText = await spyderbatRes.text().catch(() => "");
    console.log(JSON.stringify({ level: "error", msg: "spyderbat_error", status: spyderbatRes.status, body: errText.slice(0, 200), cf_ray: cfRay }));
    return new Response("Bad Gateway", { status: 502 });
  }

  console.log(JSON.stringify({ level: "info", msg: "forwarded", count: events.length, cf_ray: cfRay }));
  return Response.json({ forwarded: events.length });
}

// ── HMAC verification for Spyderbat webhooks ──────────────────────────────
async function verifySpyderbatHmac(body: string, signature: string, secret: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["verify"]
  );
  const sigBytes = Uint8Array.from(atob(signature), (c) => c.charCodeAt(0));
  return crypto.subtle.verify("HMAC", key, sigBytes, encoder.encode(body));
}

// ── Main fetch handler ────────────────────────────────────────────────────
export default {
  // ── Cron: poll AI Gateway logs for Shadow AI ────────────────────────────
  async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
    const since = new Date(Date.now() - 5 * 60 * 1000).toISOString(); // last 5 min
    const url = `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/ai-gateway/gateways/${env.CF_AI_GATEWAY_ID}/logs?start=${since}&order_by=created_at&direction=asc&per_page=100`;

    let logsRes: Response;
    try {
      logsRes = await fetch(url, {
        headers: { Authorization: `Bearer ${env.CF_API_TOKEN}` },
      });
    } catch (err) {
      console.log(JSON.stringify({ level: "error", msg: "ai_gateway_poll_failed", error: String(err) }));
      return;
    }

    if (!logsRes.ok) {
      console.log(JSON.stringify({ level: "warn", msg: "ai_gateway_poll_non200", status: logsRes.status }));
      return;
    }

    const data = await logsRes.json() as { result?: AIGatewayLog[] };
    const logs = data.result ?? [];
    if (logs.length === 0) return;

    const events = logs.map((l) => aiGatewayToSpyderbatEvent(l));
    console.log(JSON.stringify({ level: "info", msg: "ai_gateway_events_polled", count: events.length }));
    await sendToSpyderbat(events, env);
  },

  async fetch(request: Request, env: Env, _ctx?: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const cfRay = request.headers.get("CF-Ray") ?? "";

    // ── Health ────────────────────────────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/health") {
      return Response.json({ status: "ok", service: "cloudflare-spyderbat-worker", version: "2.0" });
    }

    // ── POST /spyderbat-alert — reverse webhook: Spyderbat → Cloudflare ──
    if (request.method === "POST" && url.pathname === "/spyderbat-alert") {
      const rawBody = await request.text().catch(() => "");
      const signature = request.headers.get("X-Spyderbat-Signature") ?? "";

      if (!signature) return new Response("Unauthorized", { status: 401 });

      const valid = await verifySpyderbatHmac(rawBody, signature, env.SPYDERBAT_WEBHOOK_SECRET).catch(() => false);
      if (!valid) {
        console.log(JSON.stringify({ level: "warn", msg: "spyderbat_webhook_invalid_hmac" }));
        return new Response("Unauthorized", { status: 401 });
      }

      let alert: SpyderbatAlert;
      try {
        alert = JSON.parse(rawBody) as SpyderbatAlert;
      } catch {
        return new Response("Bad Request", { status: 400 });
      }

      if (!alert.src_ip) {
        return Response.json({ action: "noop", reason: "no src_ip in alert" });
      }

      const comment = `spyderbat:${alert.policy_name ?? "unknown"} sev:${alert.severity} id:${alert.id}`;
      try {
        await blockIpInCloudflare(alert.src_ip, comment, env);
        return Response.json({ action: "blocked", ip: alert.src_ip, policy: alert.policy_name });
      } catch {
        return new Response("Failed to block IP", { status: 502 });
      }
    }

    // ── POST / — Logpush webhook: Cloudflare → Spyderbat ─────────────────
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

    const events: SpyderbatEvent[] = [];
    for (const line of body.split(/\r?\n/).filter(Boolean)) {
      try {
        events.push(toSpyderbatEvent(JSON.parse(line) as CFLogEntry, cfRay));
      } catch {
        console.log(JSON.stringify({ level: "warn", msg: "skipped_malformed_line", cf_ray: cfRay }));
      }
    }

    if (events.length === 0) return Response.json({ forwarded: 0 });
    return sendToSpyderbat(events, env, cfRay);
  },
};
