# Cloudflare → Spyderbat Security Event Worker

A Cloudflare Worker that receives security events from Cloudflare Logpush (WAF, Bot, DDoS, Firewall) and forwards them to Spyderbat in real time for correlation and policy monitoring.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Cloudflare Edge                          │
│                                                                 │
│  WAF ──┐                                                        │
│  Bot ──┼──► Logpush (firewall_events) ──► POST /  ┐            │
│  DDoS ─┘         (NDJSON batch)                   │            │
│  FW ───┘                                          ▼            │
│                                    cloudflare-spyderbat-worker  │
│                                           │                     │
│                                           │ normalize + forward  │
└───────────────────────────────────────────┼─────────────────────┘
                                            │
                                            ▼
                              ┌─────────────────────────┐
                              │  Spyderbat Ingest API   │
                              │  /api/v1/source/ingest  │
                              └─────────────────────────┘
```

**Flow:**
1. Cloudflare Logpush delivers batches of security events as NDJSON to the Worker URL.
2. The Worker validates the `X-Auth-Secret` header, parses each event, and maps it to Spyderbat's schema.
3. The normalized batch is POSTed to the Spyderbat ingest endpoint.
4. On Spyderbat failure the Worker returns `502`, causing Logpush to retry automatically.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Cloudflare account | Pro plan or higher for Logpush |
| Spyderbat account | API token + Org UID from the Spyderbat dashboard |
| Node.js ≥ 18 | For Wrangler CLI |
| Wrangler CLI | `npm install -g wrangler` |

---

## Setup

### 1 — Clone and install dependencies

```bash
git clone https://github.com/lucianolagger/cloud-security.git
cd cloud-security/integrations/cloudflare-spyderbat
npm install
```

### 2 — Authenticate Wrangler

```bash
wrangler login
```

### 3 — Set secrets

```bash
wrangler secret put SPYDERBAT_API_URL
# Enter: https://api.spyderbat.com

wrangler secret put SPYDERBAT_API_TOKEN
# Enter: <your Spyderbat API token>

wrangler secret put SPYDERBAT_ORG_UID
# Enter: <your Spyderbat Org UID>

wrangler secret put AUTH_SECRET
# Enter: <random 32+ character string — keep this, you'll need it for Logpush>
```

> **Generate a strong secret:**
> ```bash
> openssl rand -hex 32
> ```

### 4 — Configure the route in `wrangler.toml`

Uncomment and update the `[[routes]]` block:

```toml
[[routes]]
pattern = "security-ingest.yourdomain.com/*"
zone_name = "yourdomain.com"
```

Or use a `workers.dev` subdomain (no route config needed) for quick testing.

---

## Configure Cloudflare Logpush

Go to **Cloudflare Dashboard → Analytics & Logs → Logpush → Create a job**.

| Setting | Value |
|---|---|
| Dataset | **Firewall events** |
| Destination | **HTTP** |
| URL | `https://security-ingest.yourdomain.com/` |
| Header name | `X-Auth-Secret` |
| Header value | *(the `AUTH_SECRET` you set above)* |

### Recommended Logpush fields (firewall events)

```
Action, ClientIP, ClientRequestHost, ClientRequestMethod,
ClientRequestPath, ClientRequestUserAgent, EdgeStartTimestamp,
RuleID, Source, BotScore, BotScoreSrc,
WAFAction, WAFRuleID, WAFRuleMessage,
FirewallMatchesActions, FirewallMatchesRuleIDs, FirewallMatchesSources
```

---

## Local Development & Testing

### Start local dev server

```bash
# Copy example vars
cp .env.example .dev.vars   # edit .dev.vars with real or test values

wrangler dev
# Worker runs at http://localhost:8787
```

### Test with curl

**Health check:**
```bash
curl http://localhost:8787/health
# {"status":"ok","service":"cloudflare-spyderbat-worker"}
```

**Single WAF block event:**
```bash
curl -X POST http://localhost:8787/ \
  -H "Content-Type: application/x-ndjson" \
  -H "X-Auth-Secret: your-auth-secret" \
  -d '{"Action":"block","ClientIP":"198.51.100.1","ClientRequestHost":"example.com","ClientRequestMethod":"GET","ClientRequestPath":"/admin","EdgeStartTimestamp":1748476800000000000,"Source":"waf","WAFRuleID":"100001A","WAFRuleMessage":"SQL Injection Attempt","WAFAction":"block"}'
# {"forwarded":1}
```

**Multiple events (NDJSON batch):**
```bash
curl -X POST http://localhost:8787/ \
  -H "Content-Type: application/x-ndjson" \
  -H "X-Auth-Secret: your-auth-secret" \
  --data-binary $'{"Action":"block","ClientIP":"198.51.100.1","Source":"waf","WAFRuleID":"100001A","WAFRuleMessage":"XSS","EdgeStartTimestamp":1748476800000000000}\n{"Action":"challenge","ClientIP":"203.0.113.42","BotScore":5,"BotScoreSrc":"Heuristics","EdgeStartTimestamp":1748476801000000000}'
# {"forwarded":2}
```

**Auth failure test:**
```bash
curl -X POST http://localhost:8787/ \
  -H "X-Auth-Secret: wrong-secret" \
  -d '{}'
# HTTP 401 Unauthorized
```

### Run unit tests

```bash
npm test
```

---

## Deployment

```bash
wrangler deploy
```

Verify the deployment:

```bash
curl https://security-ingest.yourdomain.com/health
```

---

## Event Schema

Each event forwarded to Spyderbat has this structure:

```json
{
  "schema": "cloudflare_security_event",
  "time": 1748476800,
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "class": "waf_event",
  "action": "block",
  "severity": 8,
  "src_ip": "198.51.100.1",
  "description": "action:block | ip:198.51.100.1 | waf:SQL Injection Attempt",
  "details": { ...original Cloudflare log fields... },
  "tags": ["cloudflare", "waf_event", "action:block", "source:waf"],
  "cf_ray": "7d3f4e5a6b7c8d9e-IAD"
}
```

### Event classes

| Class | Condition |
|---|---|
| `waf_event` | `Source === "waf"` or `WAFRuleID` present |
| `bot_event` | `BotScore < 30` (and not waf) |
| `ddos_event` | `FirewallMatchesSources` includes `"ddos"` |
| `firewall_event` | Other firewall rule matches |
| `security_event` | Fallback |

### Severity scale

| Severity | Trigger |
|---|---|
| 8 | `block` or `drop` |
| 7 | `challenge`/`jschallenge` + bot score < 30 |
| 6 | `challenge` or `jschallenge` |
| 5 | `managed_challenge` |
| 4 | Unknown action |
| 3 | `log` or `allow` |

Bot score < 30 adds +1 to the action-derived severity (capped at 10).

---

## Monitoring & Troubleshooting

### View live logs

```bash
wrangler tail
```

Logs are structured JSON:
```json
{"level":"info","msg":"forwarded","count":12,"cf_ray":"7d3f..."}
{"level":"error","msg":"spyderbat ingest error","status":500,"body":"...","cf_ray":"7d3f..."}
```

### Common issues

| Symptom | Cause | Fix |
|---|---|---|
| All requests return 401 | Wrong `X-Auth-Secret` in Logpush config | Re-check the header value matches `AUTH_SECRET` secret |
| Requests return 502 | Spyderbat API unreachable or token expired | Verify `SPYDERBAT_API_TOKEN` and `SPYDERBAT_ORG_UID` |
| `forwarded: 0` on every request | No matching log lines in body | Check Logpush field selection matches expected schema |
| Logpush job shows failures | Worker returning 5xx | Check `wrangler tail` for error details |

### Secret rotation

To rotate `AUTH_SECRET`:
1. Run `wrangler secret put AUTH_SECRET` with the new value.
2. Update the `X-Auth-Secret` header value in your Cloudflare Logpush job.
3. Both changes should be applied within the same deployment window to avoid downtime.

---

## Security Notes

- The `AUTH_SECRET` prevents unauthorized parties from injecting fake security events into Spyderbat.
- Never log the value of `AUTH_SECRET` or `SPYDERBAT_API_TOKEN`.
- The Worker does not store or cache event data — it forwards in memory only.
- Spyderbat API calls include the `CF-Ray` ID for end-to-end traceability.
