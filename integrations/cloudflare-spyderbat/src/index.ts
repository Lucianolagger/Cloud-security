export interface Env {
  SPYDERBAT_API_URL: string;   // e.g. https://api.spyderbat.com
  SPYDERBAT_API_TOKEN: string; // Bearer token
  SPYDERBAT_ORG_UID: string;   // Organization UID
  AUTH_SECRET: string;         // Shared secret for X-Auth-Secret header
}

// ── Cloudflare Logpush firewall-events field schema (partial) ──────────────
interface CFLogEntry {
  Action?: string;
  ClientIP?: string;
  ClientRequestHost?: string;
  ClientRequestMethod?: string;
  ClientRequestPath?: string;
  ClientRequestUserAgent?: string;
  // Nanosecond Unix timestamp per Cloudflare Logpush docs
  EdgeStartTimestamp?: number;
  RuleID?: string;
  Source?: string;
  BotScore?: number;
  BotScoreSrc?: string;
  WAFAction?: string;
  WAFRuleID?: string;
  WAFRuleMessage?: string;
  FirewallMatchesActions?: string[];
  FirewallMatchesRuleIDs?: string[];
  FirewallMatchesSources?: string[];
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

const MAX_BODY_BYTES = 10 * 1024 * 1024; // 10 MB guard

// ── Transform ─────────────────────────────────────────────────────────────
function toSpyderbatEvent(log: CFLogEntry, cfRay: string): SpyderbatEvent {
  const action = (log.Action ?? log.WAFAction ?? "unknown").toLowerCase();
  let severity = ACTION_SEVERITY[action] ?? 4;
  // Low bot score (< 30) means likely automated/malicious — raise severity by 1
  if (typeof log.BotScore === "number" && log.BotScore < 30) severity = Math.min(10, severity + 1);

  // Priority: waf > bot > ddos > firewall > generic
  let eventClass = "security_event";
  if (log.Source === "waf" || log.WAFRuleID) eventClass = "waf_event";
  else if (typeof log.BotScore === "number" && log.BotScore < 30) eventClass = "bot_event";
  else if (log.FirewallMatchesSources?.includes("ddos")) eventClass = "ddos_event";
  else if (log.FirewallMatchesSources?.length) eventClass = "firewall_event";

  const descParts: string[] = [`action:${action}`, `ip:${log.ClientIP ?? "?"}`];
  if (log.WAFRuleMessage) descParts.push(`waf:${log.WAFRuleMessage}`);
  if (typeof log.BotScore === "number") descParts.push(`bot_score:${log.BotScore}(${log.BotScoreSrc ?? "?"})`);
  if (log.FirewallMatchesRuleIDs?.length) descParts.push(`fw_rules:${log.FirewallMatchesRuleIDs.join(",")}`);

  const tags = ["cloudflare", eventClass, `action:${action}`];
  if (log.Source) tags.push(`source:${log.Source}`);

  return {
    schema: "cloudflare_security_event",
    // EdgeStartTimestamp is nanoseconds per Cloudflare Logpush docs → convert to Unix seconds
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

// ── Request handler ───────────────────────────────────────────────────────
export default {
  async fetch(request: Request, env: Env, _ctx?: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const cfRay = request.headers.get("CF-Ray") ?? "";

    // Health check
    if (request.method === "GET" && url.pathname === "/health") {
      return Response.json({ status: "ok", service: "cloudflare-spyderbat-worker" });
    }

    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    // Auth — constant-string comparison; trim to avoid whitespace surprises
    const incomingSecret = (request.headers.get("X-Auth-Secret") ?? "").trim();
    if (!incomingSecret || incomingSecret !== env.AUTH_SECRET.trim()) {
      console.log(JSON.stringify({ level: "warn", msg: "unauthorized request", cf_ray: cfRay }));
      return new Response("Unauthorized", { status: 401 });
    }

    // Payload size guard
    const contentLength = parseInt(request.headers.get("Content-Length") ?? "0", 10);
    if (contentLength > MAX_BODY_BYTES) {
      return new Response("Payload Too Large", { status: 413 });
    }

    let body: string;
    try {
      body = await request.text();
    } catch {
      return new Response("Bad Request", { status: 400 });
    }

    if (body.length > MAX_BODY_BYTES) {
      return new Response("Payload Too Large", { status: 413 });
    }

    // Parse NDJSON — handle both LF and CRLF line endings
    const events: SpyderbatEvent[] = [];
    for (const line of body.split(/\r?\n/).filter(Boolean)) {
      try {
        events.push(toSpyderbatEvent(JSON.parse(line) as CFLogEntry, cfRay));
      } catch {
        // Skip malformed lines; Logpush guarantees one JSON object per line
        // but partial batches can arrive during edge failures
        console.log(JSON.stringify({ level: "warn", msg: "skipped malformed line", cf_ray: cfRay }));
      }
    }

    if (events.length === 0) {
      return Response.json({ forwarded: 0 });
    }

    // Forward to Spyderbat
    const ingestUrl = `${env.SPYDERBAT_API_URL}/api/v1/source/ingest/${env.SPYDERBAT_ORG_UID}`;
    const ndjsonBody = events.map((e) => JSON.stringify(e)).join("\n");

    let spyderbatRes: Response;
    try {
      spyderbatRes = await fetch(ingestUrl, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.SPYDERBAT_API_TOKEN}`,
          "Content-Type": "application/x-ndjson",
          "X-CF-Ray": cfRay,
        },
        body: ndjsonBody,
      });
    } catch (err) {
      console.log(JSON.stringify({ level: "error", msg: "spyderbat fetch failed", error: String(err), cf_ray: cfRay }));
      // Return 502 so Cloudflare Logpush retries the batch
      return new Response("Bad Gateway", { status: 502 });
    }

    if (!spyderbatRes.ok) {
      const errText = await spyderbatRes.text().catch(() => "");
      console.log(JSON.stringify({
        level: "error",
        msg: "spyderbat ingest error",
        status: spyderbatRes.status,
        body: errText.slice(0, 200),
        cf_ray: cfRay,
      }));
      return new Response("Bad Gateway", { status: 502 });
    }

    console.log(JSON.stringify({ level: "info", msg: "forwarded", count: events.length, cf_ray: cfRay }));
    return Response.json({ forwarded: events.length });
  },
};
