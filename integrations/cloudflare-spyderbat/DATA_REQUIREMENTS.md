# Data Requirements — Cloudflare ↔ Spyderbat Integration

**Document purpose:** Each stakeholder listed below must provide the data in their section before production deployment can proceed. Fields marked **REQUIRED** block deployment. Fields marked **GOVERNANCE CRITICAL** block the AI governance layer from operating.

**How to submit:** Fill in the "Your value" column and hand this document to the DevOps team. Do not share this document over email — use an encrypted channel or a secrets manager.

---

## Priority Order for Collection

> AI Governance data must be collected **first**. Without it the system runs without safety controls.

1. 🔴 **Security / Governance Team** — controls all automated AI actions
2. 🟠 **Cloudflare Administrator** — platform credentials and infrastructure
3. 🟠 **Spyderbat Administrator** — destination platform credentials
4. 🟡 **IT / Network Team** — routing and DNS
5. 🟢 **Development / DevOps Team** — environment setup

---

## 1. 🔴 Security / Governance Team

> These values control **who can authorize automated AI actions**, what the limits are, and which IPs are protected from auto-blocking. Collect these before any other section.

| Variable | Format | Where to find / how to generate | Why needed | Status |
|---|---|---|---|---|
| `GOV_ADMIN_SECRET` | 64-char hex string | Run: `openssl rand -hex 32` | Authenticates all `/gov/*` admin endpoints (audit log, whitelist, unblock) | ☐ |
| `AUTH_SECRET` | 64-char hex string | Run: `openssl rand -hex 32` | Authenticates Cloudflare Logpush → Worker webhook | ☐ |
| `SPYDERBAT_WEBHOOK_SECRET` | 64-char hex string | Run: `openssl rand -hex 32` (share also with Spyderbat Admin) | HMAC key for verifying Spyderbat → Worker alerts | ☐ |

### Governance Policy Decisions (no code changes needed — confirm values)

| Parameter | Default | Confirmed value | Who decides |
|---|---|---|---|
| Circuit breaker threshold (max auto-blocks/hour) | **50** | _______ | Security Team Lead |
| Block TTL (auto-expiry of IP blocks) | **24 hours** | _______ | Security Team Lead |
| Minimum severity for auto-block | **7 / 10** | _______ | Security Team Lead |
| Audit log retention | **30 days** | _______ | Compliance / Legal |
| False-positive SLA (max hours to review held blocks) | *(not set)* | _______ | Security Team Lead |

### Initial IP Whitelist

> IPs added here are **permanently exempt** from auto-blocking. Include: internal vulnerability scanners, partner monitoring IPs, uptime monitors, CDN health-check IPs.

| IP Address | Owner / Purpose | Added by |
|---|---|---|
| _____________ | __________________________ | _________ |
| _____________ | __________________________ | _________ |
| _____________ | __________________________ | _________ |

### Escalation Contact (when circuit breaker opens)

> When the circuit breaker opens (> threshold blocks/hour), no automatic blocks occur until a human reviews `/gov/audit`. Define who gets notified and how.

| Role | Name | Contact (Slack / email / phone) |
|---|---|---|
| Primary on-call | _________________ | ________________________________ |
| Secondary on-call | _________________ | ________________________________ |
| Decision authority | _________________ | ________________________________ |

---

## 2. 🟠 Cloudflare Administrator

> Required to: deploy the Worker, create the blocklist, configure Logpush, and enable AI Gateway.

| Variable | Format | Where to find | Why needed | Your value |
|---|---|---|---|---|
| `CF_ACCOUNT_ID` | 32-char hex | Dashboard URL: `dash.cloudflare.com/**{id}**/...` or any Zone → Overview → right sidebar | Scope all Cloudflare API calls | |
| `CF_ZONE_ID` | 32-char hex | Zone → Overview → right sidebar → "Zone ID" | Scope firewall and DNS actions to the correct zone | |
| `CF_API_TOKEN` | ~40-char string | My Profile → API Tokens → Create Token (see permissions below) | Authenticate all Cloudflare API calls from the Worker | |
| `CF_IP_LIST_ID` | 32-char hex | Security → WAF → Tools → IP Lists → create `spyderbat_blocklist` → copy ID from URL | ID of the dynamic blocklist the Worker updates | |
| `CF_AI_GATEWAY_ID` | string (slug) | AI → AI Gateway → Create Gateway → copy the gateway name | Identify which gateway to poll for Shadow AI events | |

### Required CF_API_TOKEN permissions

Create at: **My Profile → API Tokens → Create Token → Custom Token**

| Permission type | Resource | Level |
|---|---|---|
| Account | AI Gateway | Read |
| Account | Account Filter Lists | Edit |
| Zone | Firewall Services | Edit |
| Zone | Zone | Read |

### Pre-deployment tasks for Cloudflare Admin

- [ ] Create IP List named `spyderbat_blocklist` (Type: IP) → copy ID
- [ ] Create WAF Custom Rule: `ip.src in $spyderbat_blocklist` → Block, Priority 1
- [ ] Create AI Gateway named `corporate-ai-gateway`
- [ ] Verify API Token works: `curl -H "Authorization: Bearer TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify`

---

## 3. 🟠 Spyderbat Administrator

> Required to: configure the ingest source and set up the reverse webhook so Spyderbat alerts trigger Cloudflare blocks.

| Variable | Format | Where to find | Why needed | Your value |
|---|---|---|---|---|
| `SPYDERBAT_API_URL` | URL | Always: `https://api.spyderbat.com` | Base URL for ingest and API calls | `https://api.spyderbat.com` |
| `SPYDERBAT_API_TOKEN` | Bearer token string | Spyderbat Dashboard → Settings → API Keys → Create Key | Authenticate event ingestion | |
| `SPYDERBAT_ORG_UID` | UUID format | Spyderbat Dashboard → Settings → Organization → UID | Scope ingest to the correct organization | |
| `SPYDERBAT_WEBHOOK_SECRET` | 64-char hex | Receive from **Security Team** (they generate it) | Sign Spyderbat → Worker webhook payloads for HMAC verification | |

### Pre-deployment tasks for Spyderbat Admin

- [ ] Create API key with ingest permissions → provide token
- [ ] Note the Organization UID → provide it
- [ ] Configure Response Action Webhook:
  - URL: `https://{worker-domain}/spyderbat-alert`
  - Header: `X-Spyderbat-Signature` (HMAC-SHA256, signed with `SPYDERBAT_WEBHOOK_SECRET`)
- [ ] Create policies that trigger the webhook (coordinate thresholds with Security Team):

| Policy name | Condition | Action |
|---|---|---|
| CF Auto-Block Critical | `class = "waf_event" AND severity >= 8` | Webhook → cloudflare-block |
| CF Auto-Block Bot Storm | `class = "bot_event" AND count(src_ip, 5min) > 50` | Webhook → cloudflare-block |
| Shadow AI High Risk | `class = "shadow_ai_event" AND tokens_in > 5000` | Alert (no auto-block) |
| CF Auto-Block Multi-Vector | same IP in waf_event + bot_event within 60s | Webhook → cloudflare-block |

---

## 4. 🟡 IT / Network Team

> Required to: route the Worker domain, create the KV namespace, and update DNS.

| Item | Format | How to obtain | Why needed | Your value |
|---|---|---|---|---|
| Worker domain / route | `subdomain.yourdomain.com` | Decide which subdomain will host the Worker endpoint | Cloudflare Logpush and Spyderbat must POST to this URL | |
| KV Namespace ID | 32-char hex | Run: `npx wrangler kv namespace create GOV_KV` → copy `id` from output | Stores governance audit log, whitelist, circuit breaker state | |
| KV Preview ID | 32-char hex | Same command output → copy `preview_id` | Required for `wrangler dev` local testing | |
| DNS CNAME record | CNAME to `{worker}.workers.dev` | Create in DNS after Worker is deployed | Route the chosen subdomain to the Cloudflare Worker | |

### KV Namespace creation command

```bash
npx wrangler kv namespace create GOV_KV
# Output example:
# { binding: 'GOV_KV', id: 'abc123...', preview_id: 'def456...' }
```

Paste both IDs into `wrangler.toml` under `[[kv_namespaces]]` before deploying.

---

## 5. 🟢 Development / DevOps Team

> Required to: deploy the Worker and load all secrets into Cloudflare.

| Requirement | Minimum version | Verify with | Status |
|---|---|---|---|
| Node.js | 18.x or higher | `node --version` | ☐ |
| npm | 9.x or higher | `npm --version` | ☐ |
| Wrangler CLI | 3.x | `npx wrangler --version` | ☐ |
| Git access to `lucianolagger/cloud-security` | read + write | `git remote -v` | ☐ |
| Cloudflare account login | — | `npx wrangler login` | ☐ |

### Deployment checklist (run only after all sections above are complete)

```bash
cd integrations/cloudflare-spyderbat
npm install

# Load all secrets (one per command — Wrangler prompts for the value)
npx wrangler secret put GOV_ADMIN_SECRET
npx wrangler secret put AUTH_SECRET
npx wrangler secret put SPYDERBAT_API_URL
npx wrangler secret put SPYDERBAT_API_TOKEN
npx wrangler secret put SPYDERBAT_ORG_UID
npx wrangler secret put SPYDERBAT_WEBHOOK_SECRET
npx wrangler secret put CF_API_TOKEN
npx wrangler secret put CF_ACCOUNT_ID
npx wrangler secret put CF_ZONE_ID
npx wrangler secret put CF_IP_LIST_ID
npx wrangler secret put CF_AI_GATEWAY_ID

# Update wrangler.toml with KV namespace IDs (from IT Team)
# [[kv_namespaces]]
# id = "{KV Namespace ID from IT Team}"
# preview_id = "{KV Preview ID from IT Team}"

# Run tests (must be 12/12 before deploying)
npm test

# Deploy
npx wrangler deploy

# Verify health
curl https://{worker-domain}/health
```

---

## Governance KPIs to Monitor Post-Deploy

| KPI | Endpoint | Target |
|---|---|---|
| Blocks this hour | `GET /gov/stats` → `blocks_this_hour` | < 50 (circuit threshold) |
| Circuit breaker state | `GET /gov/stats` → `circuit_open` | `false` |
| Shadow AI flags / hour | `GET /gov/stats` → `shadow_ai_flags_this_hour` | Track baseline |
| Events forwarded / hour | `GET /gov/stats` → `total_forwarded_this_hour` | Track baseline |
| Recent decisions | `GET /gov/audit?limit=20` | Review daily |
| False positive rate | Manual: count `gov/unblock` calls vs total blocks | Target < 2% |

### Governance admin commands (require `GOV_ADMIN_SECRET`)

```bash
BASE="https://{worker-domain}"
ADMIN="your-gov-admin-secret"

# Check live AI governance stats
curl "$BASE/gov/stats" -H "X-Gov-Admin-Secret: $ADMIN"

# Review last 20 AI decisions
curl "$BASE/gov/audit?limit=20" -H "X-Gov-Admin-Secret: $ADMIN"

# Whitelist an IP (internal scanner, partner, etc.)
curl -X POST "$BASE/gov/whitelist" \
  -H "X-Gov-Admin-Secret: $ADMIN" \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.0.0.5","reason":"Internal Qualys scanner","by":"security-team@corp.com"}'

# Manually unblock an IP (false positive remediation)
curl -X POST "$BASE/gov/unblock" \
  -H "X-Gov-Admin-Secret: $ADMIN" \
  -H "Content-Type: application/json" \
  -d '{"ip":"198.51.100.1"}'
```

---

## Data Retention & Privacy Note

The governance audit log stores IP addresses, which may constitute **personal data** under GDPR/CCPA in some jurisdictions. Current retention: **30 days** (configurable in `governance.ts`). Review with your legal/compliance team before go-live.

---

## Summary Checklist

| Section | Owner | Complete |
|---|---|---|
| Governance secrets + policy decisions + whitelist | **Security Team Lead** | ☐ |
| Escalation contacts defined | **Security Team Lead** | ☐ |
| Cloudflare token + IP List + AI Gateway created | **Cloudflare Admin** | ☐ |
| Spyderbat API key + UID + webhook + policies | **Spyderbat Admin** | ☐ |
| Worker domain + KV namespace IDs + DNS | **IT / Network Team** | ☐ |
| Node/Wrangler ready + all secrets loaded + deploy | **DevOps Team** | ☐ |
