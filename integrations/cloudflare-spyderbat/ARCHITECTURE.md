# Arquitectura de Integración: Cloudflare ↔ Spyderbat

## 1. Árbol de Conectores

```
cloudflare-spyderbat-integration
│
├── CAPA A — FUENTES (Cloudflare Edge)
│   │
│   ├── [A1] WAF Engine
│   │   ├── Managed Ruleset (OWASP Top 10, CF-managed)
│   │   ├── Custom Rules (reglas propias por path/método)
│   │   ├── Rate Limiting Rules
│   │   └── → emite: Action, WAFRuleID, WAFRuleMessage, WAFMatchedVar, WAFAction
│   │
│   ├── [A2] Bot Management
│   │   ├── Heuristic Engine
│   │   ├── Machine Learning Score (0–100)
│   │   ├── Verified Bots Allowlist (Googlebot, etc.)
│   │   ├── Challenge Platform (JS, CAPTCHA, Managed)
│   │   └── → emite: BotScore, BotScoreSrc, BotTags, Action
│   │
│   ├── [A3] DDoS Protection
│   │   ├── L3/L4 (Magic Transit — volumétrico)
│   │   ├── L7 HTTP DDoS (rate heuristics)
│   │   ├── Adaptive DDoS Protection
│   │   └── → emite: FirewallMatchesSources["ddos"], Action["block"]
│   │
│   ├── [A4] Firewall Rules (Custom + IP Access)
│   │   ├── IP Access Rules (bloqueo por ASN, país, IP)
│   │   ├── Custom Firewall Rules (expresiones avanzadas)
│   │   ├── Managed IP Lists (Tor, VPN, Bogon)
│   │   └── → emite: FirewallMatchesRuleIDs, FirewallMatchesSources
│   │
│   └── [A5] AI Gateway (Shadow AI)
│       ├── OpenAI proxy       /v1/openai/...
│       ├── Anthropic proxy    /v1/anthropic/...
│       ├── Google AI proxy    /v1/google-ai-studio/...
│       ├── Azure OpenAI proxy /v1/azure-openai/...
│       ├── Mistral proxy      /v1/mistral/...
│       ├── Groq proxy         /v1/groq/...
│       ├── Workers AI         /v1/workers-ai/...
│       └── → emite: provider, model, tokens_in, tokens_out, success, cf_connecting_ip
│
├── CAPA B — TRANSPORTE (Cloudflare Logpush)
│   │
│   ├── [B1] Job: firewall_events
│   │   ├── Dataset: Firewall Events
│   │   ├── Trigger: real-time (cada batch ~1 seg)
│   │   ├── Formato: NDJSON (un objeto JSON por línea)
│   │   ├── Destino: POST https://worker.yourdomain.com/
│   │   └── Auth: Header X-Auth-Secret
│   │
│   └── [B2] Cron trigger (Workers scheduled)
│       ├── Frecuencia: */5 * * * * (cada 5 min)
│       ├── Acción: GET Cloudflare AI Gateway logs API
│       └── Ventana: últimos 5 minutos
│
├── CAPA C — PROCESAMIENTO (Cloudflare Worker)
│   │
│   ├── [C1] POST /  ← Logpush webhook
│   │   ├── Valida X-Auth-Secret (HMAC trim)
│   │   ├── Guard: Content-Length > 10MB → 413
│   │   ├── Parse NDJSON (/\r?\n/ split)
│   │   ├── toSpyderbatEvent() por cada línea
│   │   │   ├── Determina event class (prioridad: waf > bot > ddos > fw > generic)
│   │   │   ├── Calcula severity (tabla + bot bump)
│   │   │   └── Agrega country, ASN, BotTags, ZoneName, RayID
│   │   ├── sendToSpyderbat() batch NDJSON
│   │   └── 502 si Spyderbat falla → Logpush reintenta
│   │
│   ├── [C2] POST /spyderbat-alert  ← reverse webhook
│   │   ├── Verifica X-Spyderbat-Signature (HMAC-SHA256)
│   │   ├── Parsea alerta (id, policy_name, severity, src_ip)
│   │   ├── blockIpInCloudflare() → CF IP Lists API
│   │   └── 200 {action:"blocked", ip} ó {action:"noop"}
│   │
│   ├── [C3] GET /health
│   │   └── 200 {status:"ok", version:"2.0"}
│   │
│   └── [C4] scheduled()  ← cron cada 5 min
│       ├── GET CF AI Gateway logs (últimos 5 min)
│       ├── aiGatewayToSpyderbatEvent() por cada log
│       │   ├── Detecta SHADOW_AI_PROVIDERS (openai, anthropic, etc.)
│       │   └── Clasifica: shadow_ai_event, severity 6-8
│       └── sendToSpyderbat() batch
│
├── CAPA D — DESTINO (Spyderbat Platform)
│   │
│   ├── [D1] Ingest API
│   │   ├── Endpoint: POST /api/v1/source/ingest/{org_uid}
│   │   ├── Auth: Bearer token
│   │   ├── Formato: NDJSON con schema "cloudflare_security_event"
│   │   └── Recibe todos los eventos de C1, C2, C4
│   │
│   ├── [D2] AI Engine (Spyderbat ML)
│   │   ├── Correlaciona eventos externos (Cloudflare) con comportamiento interno
│   │   ├── Baseline de actividad normal por IP, path, método
│   │   ├── Detecta patrones multi-vector (misma IP en WAF + Bot + DDoS)
│   │   └── Genera score de riesgo por entidad
│   │
│   ├── [D3] Spyder Graph
│   │   ├── Visualiza relaciones: IP → host → path → regla WAF
│   │   ├── Linea de tiempo de ataques por IP
│   │   └── Exportable para generar reglas WAF específicas
│   │
│   └── [D4] Policy Engine → Webhooks
│       ├── Trigger: severity ≥ umbral configurado
│       ├── Acción: POST /spyderbat-alert en el Worker
│       └── Firma: HMAC-SHA256 con SPYDERBAT_WEBHOOK_SECRET
│
└── CAPA E — ACCIÓN (Cloudflare API — reverse)
    │
    ├── [E1] IP Lists API
    │   ├── Agrega src_ip del alert al spyderbat_blocklist
    │   └── WAF Custom Rule ya configurada bloquea esa lista
    │
    └── [E2] (futuro) WAF Custom Rules API
        └── Crear reglas dinámicas basadas en Spyder Graph
```

---

## 2. Arquitectura General — Zoom Out (visión de 10.000 pies)

```
╔══════════════════════════════════════════════════════════════════════╗
║                         INTERNET                                    ║
║   Atacantes, bots, usuarios con Shadow AI, tráfico legítimo         ║
╚══════════════════════════╤═══════════════════════════════════════════╝
                           │ tráfico HTTP/S
                           ▼
╔══════════════════════════════════════════════════════════════════════╗
║               CLOUDFLARE EDGE  (200+ ciudades)                      ║
║                                                                      ║
║  ┌─────────┐  ┌──────────┐  ┌────────────┐  ┌──────────────────┐   ║
║  │   WAF   │  │   Bot    │  │    DDoS    │  │   AI Gateway     │   ║
║  │ [A1]    │  │ Mgmt [A2]│  │  Prot [A3] │  │  Shadow AI [A5]  │   ║
║  └────┬────┘  └────┬─────┘  └─────┬──────┘  └────────┬─────────┘   ║
║       └────────────┴──────────────┴──────────────────┘             ║
║                              │ Logpush NDJSON [B1] + Cron [B2]      ║
╚══════════════════════════════╪═════════════════════════════════════╝
                               │
                               ▼
╔══════════════════════════════════════════════════════════════════════╗
║          CLOUDFLARE WORKER  (cloudflare-spyderbat-worker)           ║
║                                                                      ║
║   POST /  →  transform  →  sendToSpyderbat()    [C1]                ║
║   POST /spyderbat-alert  →  blockIpInCloudflare()  [C2]             ║
║   scheduled()  →  AI Gateway poll  →  shadow_ai_event  [C4]         ║
╚═════════════════╤════════════════════════════╤═══════════════════════╝
                  │ eventos NDJSON             │ IP block CF API
                  ▼                            ▲
╔══════════════════════════════╗    ╔══════════════════════════════════╗
║     SPYDERBAT PLATFORM       ║    ║     CLOUDFLARE IP LIST           ║
║                              ║    ║     spyderbat_blocklist          ║
║  Ingest API  [D1]            ║    ║  → WAF Custom Rule bloquea       ║
║  AI Engine   [D2]  ─────────────►║     toda IP en la lista          ║
║  Spyder Graph [D3]           ║    ╚══════════════════════════════════╝
║  Policy Engine [D4] ─────────╫──► POST /spyderbat-alert (webhook)
╚══════════════════════════════╝
```

---

## 3. Arquitectura Detallada — Zoom In (evento por evento)

### Flujo A: WAF block event → Spyderbat

```
1. Request maliciosa llega al edge de Cloudflare
   │  GET /login?id=1 UNION SELECT * FROM users--
   │  IP: 185.220.101.45  Country: RU  ASN: 60280 (AS-DIGI-HOST)
   ▼
2. WAF Managed Rule "100001A" hace match
   │  WAFRuleMessage: "SQL Injection Attack Detected"
   │  WAFMatchedVar: "ARGS:id"
   │  Action: "block"  → HTTP 403 devuelto al atacante
   ▼
3. Logpush empaqueta el evento en NDJSON (batch ~1s)
   │  {
   │    "Action":"block", "ClientIP":"185.220.101.45",
   │    "ClientCountry":"RU", "ClientASN":60280,
   │    "ClientASNDescription":"AS-DIGI-HOST",
   │    "WAFRuleID":"100001A", "WAFRuleMessage":"SQL Injection",
   │    "WAFMatchedVar":"ARGS:id",
   │    "EdgeStartTimestamp":1748476800000000000,
   │    "RayID":"7d3f4e5a6b7c8d9e", "ZoneName":"example.com"
   │  }
   ▼
4. POST https://worker.yourdomain.com/
   Header: X-Auth-Secret: <secreto>
   Body: NDJSON
   ▼
5. Worker valida secreto → parsea NDJSON → toSpyderbatEvent()
   │  {
   │    "schema": "cloudflare_security_event",
   │    "class": "waf_event",          ← Source="waf" + WAFRuleID → prioridad #1
   │    "action": "block",
   │    "severity": 8,                 ← block=8, sin bot bump
   │    "src_ip": "185.220.101.45",
   │    "description": "action:block | ip:185.220.101.45 | waf:SQL Injection | matched:ARGS:id | country:RU | asn:AS-DIGI-HOST",
   │    "tags": ["cloudflare","waf_event","action:block","source:waf","country:RU","zone:example.com"],
   │    "cf_ray": "7d3f4e5a6b7c8d9e"
   │  }
   ▼
6. POST https://api.spyderbat.com/api/v1/source/ingest/{org_uid}
   Authorization: Bearer <token>
   ▼
7. Spyderbat AI Engine recibe → correlaciona con:
   - ¿Esta IP atacó otros hosts internos?
   - ¿Aparece en feeds de threat intel?
   - ¿Mismo ASN que ataques previos?
   ▼
8. Spyderbat Policy: severity ≥ 8 → dispara webhook
   POST https://worker.yourdomain.com/spyderbat-alert
   {
     "id":"alert-xyz", "policy_name":"waf-critical-block",
     "severity":9, "src_ip":"185.220.101.45"
   }
   ▼
9. Worker verifica HMAC → llama Cloudflare IP Lists API
   POST /accounts/{acct}/rules/lists/{list_id}/items
   [{"ip":"185.220.101.45", "comment":"spyderbat:waf-critical-block sev:9"}]
   ▼
10. WAF Custom Rule bloquea 185.220.101.45 en TODO el edge
    → próximos requests de esa IP → 403 instantáneo sin llegar al WAF
```

### Flujo B: Shadow AI detection (cron)

```
1. Desarrollador interno llama directamente a OpenAI API
   desde su máquina (sin pasar por AI Gateway corporativo)
   → OpenAI responde directamente
   → NO aparece en AI Gateway logs
   → Shadow AI no detectado en este flujo ← LIMITACIÓN

   ─────────────────────────────────────────

   Alternativa configurada correctamente:
   Developer usa: https://gateway.ai.cloudflare.com/v1/{acct}/{gw_id}/openai/v1/chat/completions
   (endpoint corporativo que proxea a OpenAI a través de AI Gateway)

2. AI Gateway registra el log:
   {
     "id": "log-abc",
     "provider": "openai",
     "model": "gpt-4o",
     "request_type": "chat.completion",
     "tokens_in": 1200,
     "tokens_out": 450,
     "success": true,
     "created_at": "2026-05-29T04:30:00Z",
     "cf_connecting_ip": "10.0.0.42"   ← IP del desarrollador interno
   }

3. Cron Worker (*/5 min) hace GET a AI Gateway API
   → Filtra: provider in SHADOW_AI_PROVIDERS
   → openai ∈ {openai, anthropic, google-ai, ...} → shadow_ai_event

4. aiGatewayToSpyderbatEvent() produce:
   {
     "schema": "cloudflare_security_event",
     "class": "shadow_ai_event",
     "action": "allowed",
     "severity": 6,             ← proveedor shadow + éxito = 6
     "src_ip": "10.0.0.42",
     "description": "Shadow AI: openai model:gpt-4o tokens_in:1200 tokens_out:450",
     "tags": ["cloudflare","shadow_ai_event","ai-gateway","provider:openai","model:gpt-4o","shadow_ai"]
   }

5. Spyderbat correlaciona:
   - 10.0.0.42 = ¿qué proceso hizo la llamada? (si hay agente Spyderbat en ese host)
   - ¿Qué datos se enviaron? (tokens_in alto = posible fuga de datos)
   - ¿Frecuencia de uso fuera de horario laboral?
```

---

## 4. Datos Recolectados — Enumeración Completa

### Grupo 1 — Identificación del atacante (7 datos)
```
 1. ClientIP              → IP de origen del request
 2. ClientCountry         → País (código ISO: "RU", "CN", "US")
 3. ClientASN             → Número de sistema autónomo (ej: 60280)
 4. ClientASNDescription  → Nombre del ISP/hosting (ej: "AS-DIGI-HOST")
 5. RayID                 → ID único de Cloudflare para el request
 6. CF-Ray                → Mismo RayID, propagado al Worker
 7. EdgeStartTimestamp    → Timestamp nanosegundos → convertido a Unix seconds
```

### Grupo 2 — Detalle del request HTTP (6 datos)
```
 8. ClientRequestHost     → Dominio atacado (ej: "api.example.com")
 9. ClientRequestMethod   → Método HTTP (GET, POST, PUT...)
10. ClientRequestPath     → Path del request (ej: "/admin/login")
11. ClientRequestQuery    → Query string (ej: "id=1 UNION SELECT...")
12. ClientRequestUserAgent → User-Agent (ej: "sqlmap/1.7", "python-requests")
13. EdgeResponseStatus    → HTTP status devuelto (403, 200, 429...)
```

### Grupo 3 — WAF (5 datos)
```
14. WAFAction             → Acción del WAF ("block", "log", "challenge")
15. WAFRuleID             → ID de la regla que hizo match (ej: "100001A")
16. WAFRuleMessage        → Descripción (ej: "SQL Injection Attack Detected")
17. WAFMatchedVar         → Variable que disparó la regla (ej: "ARGS:id")
18. Source                → Fuente del evento ("waf", "firewallrules", "bots")
```

### Grupo 4 — Bot Management (4 datos)
```
19. BotScore              → Puntuación 0-100 (0=casi certeza de bot, 100=humano)
20. BotScoreSrc           → Motor que lo detectó ("Heuristics", "ML", "Verified Bot")
21. BotTags               → Clasificación ["AUTOMATED", "VERIFIED_BOT", "TOR", "VPN"]
22. Action (bot)          → "challenge", "managed_challenge", "block", "allow"
```

### Grupo 5 — DDoS y Firewall Rules (4 datos)
```
23. FirewallMatchesActions   → ["block", "challenge", "log"]
24. FirewallMatchesRuleIDs   → IDs de reglas activadas ["custom-rule-1", "ddos-l7"]
25. FirewallMatchesSources   → Fuentes ["ddos", "firewallrules", "waf"]
26. ZoneName                 → Zona de Cloudflare afectada ("example.com")
```

### Grupo 6 — AI Gateway / Shadow AI (8 datos)
```
27. provider              → Proveedor de AI ("openai", "anthropic", "google-ai")
28. model                 → Modelo usado ("gpt-4o", "claude-3-5-sonnet", "gemini-pro")
29. request_type          → Tipo de operación ("chat.completion", "embedding", "image")
30. tokens_in             → Tokens enviados al modelo (posible fuga de datos)
31. tokens_out            → Tokens recibidos (tamaño de respuesta)
32. success               → Si la llamada fue exitosa (bool)
33. created_at            → Timestamp ISO de la llamada
34. cf_connecting_ip      → IP interna del usuario que usó la AI
```

### Grupo 7 — Metadatos del evento (Spyderbat schema) (5 datos)
```
35. schema                → "cloudflare_security_event" (fijo)
36. id                    → UUID único por evento (generado por Worker)
37. class                 → "waf_event" | "bot_event" | "ddos_event" | "firewall_event" | "shadow_ai_event" | "security_event"
38. severity              → 1-10 (calculado según tabla)
39. tags                  → Array de etiquetas para filtrado en Spyderbat
```

### Grupo 8 — Alertas de Spyderbat (reverse webhook) (5 datos)
```
40. alert.id              → ID único de la alerta
41. alert.policy_name     → Nombre de la política que disparó ("waf-critical-block")
42. alert.severity        → Severidad asignada por Spyderbat (1-10)
43. alert.src_ip          → IP a bloquear en Cloudflare
44. alert.description     → Descripción del incidente detectado
```

**Total: 44 datos recolectados y procesados en el pipeline**

---

## 5. Paso a Paso con Resultados Esperados

### PASO 1 — Crear API Token en Cloudflare
**Acción:** Dashboard → My Profile → API Tokens → Create Token (Custom)
```
Permisos:
  Zone → Firewall Services: Edit
  Zone → Zone: Read
  Account → AI Gateway: Read
  Account → Lists: Edit
  Account → Logs: Read
```
**Resultado:** Token string (ej: `Gq7Js9Kf2pX...`). Lo guardas como `CF_API_TOKEN`.

**Verificación:**
```bash
curl -H "Authorization: Bearer TU_TOKEN" \
  https://api.cloudflare.com/client/v4/user/tokens/verify
# Esperado: {"result":{"status":"active"}}
```

---

### PASO 2 — Crear IP List (blocklist dinámica)
**Acción:** Security → WAF → Tools → IP Lists → Create List
```
Name: spyderbat_blocklist
Type: IP
```
**Resultado:** `CF_IP_LIST_ID` = string de 32 chars hex (ej: `a1b2c3d4e5f6...`).

Luego crear WAF Custom Rule:
```
Expression: (ip.src in $spyderbat_blocklist)
Action: Block
Priority: 1  ← primera en ejecutarse
```
**Resultado esperado:** Cualquier IP que Spyderbat detecte como amenaza queda bloqueada en <1 segundo en todos los edges de Cloudflare.

---

### PASO 3 — Configurar Cloudflare AI Gateway
**Acción:** AI → AI Gateway → Create Gateway
```
Name: corporate-ai-gateway
```
**Resultado:** URL del gateway: `https://gateway.ai.cloudflare.com/v1/{account_id}/corporate-ai-gateway/`
`CF_AI_GATEWAY_ID` = `corporate-ai-gateway`

**Configurar en la organización:**
```
Antes: developers llaman → https://api.openai.com/v1/chat/completions
Después: developers llaman → https://gateway.ai.cloudflare.com/v1/{acct}/corporate-ai-gateway/openai/v1/chat/completions
```
**Resultado:** Todo uso de AI queda logueado. Shadow AI = uso que NO pasa por este gateway.

---

### PASO 4 — Configurar webhook en Spyderbat
**Acción:** Spyderbat Dashboard → Policies → Response Actions → Add Webhook
```
URL: https://security-ingest.yourdomain.com/spyderbat-alert
Method: POST
Header: X-Spyderbat-Signature: <HMAC generado automáticamente>
Secret: openssl rand -hex 32  → guarda como SPYDERBAT_WEBHOOK_SECRET
Trigger: severity >= 7
```
**Resultado:** Cuando Spyderbat detecta una amenaza crítica, el Worker recibe el alert y bloquea la IP en Cloudflare automáticamente.

---

### PASO 5 — Desplegar el Worker
**Acción:**
```bash
cd integrations/cloudflare-spyderbat

wrangler secret put SPYDERBAT_API_URL       # https://api.spyderbat.com
wrangler secret put SPYDERBAT_API_TOKEN     # paso previo en Spyderbat
wrangler secret put SPYDERBAT_ORG_UID       # Settings → Organization
wrangler secret put AUTH_SECRET             # openssl rand -hex 32
wrangler secret put CF_API_TOKEN            # paso 1
wrangler secret put CF_ACCOUNT_ID           # de la URL del dashboard
wrangler secret put CF_ZONE_ID              # Zone → Overview
wrangler secret put CF_IP_LIST_ID           # paso 2
wrangler secret put SPYDERBAT_WEBHOOK_SECRET # paso 4
wrangler secret put CF_AI_GATEWAY_ID        # paso 3

wrangler deploy
```
**Resultado esperado:**
```
✓ Deployed cloudflare-spyderbat-worker
  https://cloudflare-spyderbat-worker.YOURNAME.workers.dev

Workers Deployed:
  cloudflare-spyderbat-worker
  Schedule: */5 * * * *
```

**Verificación:**
```bash
curl https://cloudflare-spyderbat-worker.YOURNAME.workers.dev/health
# {"status":"ok","service":"cloudflare-spyderbat-worker","version":"2.0"}
```

---

### PASO 6 — Configurar Logpush
**Acción:** Analytics & Logs → Logpush → Create a job
```
Dataset: Firewall Events
Destination: HTTP
URL: https://cloudflare-spyderbat-worker.YOURNAME.workers.dev/
Header: X-Auth-Secret = <tu AUTH_SECRET>

Campos:
  Action, ClientASN, ClientASNDescription, ClientCountry,
  ClientIP, ClientRequestHost, ClientRequestMethod, ClientRequestPath,
  ClientRequestQuery, ClientRequestUserAgent, EdgeStartTimestamp,
  EdgeResponseStatus, BotScore, BotScoreSrc, BotTags,
  WAFAction, WAFRuleID, WAFRuleMessage, WAFMatchedVar,
  FirewallMatchesActions, FirewallMatchesRuleIDs, FirewallMatchesSources,
  RayID, Source, ZoneName
```
**Resultado esperado:** En `wrangler tail` verás logs como:
```json
{"level":"info","msg":"forwarded","count":3,"cf_ray":"7d3f4e5a6b7c8d9e"}
```
Y en Spyderbat → Sources → tu source → eventos con schema `cloudflare_security_event`.

---

### PASO 7 — Verificar el loop completo end-to-end

**Test A — WAF event → Spyderbat:**
```bash
# Simula un WAF block (en wrangler dev local)
curl -X POST http://localhost:8787/ \
  -H "X-Auth-Secret: TU_SECRET" \
  -H "Content-Type: application/x-ndjson" \
  -d '{"Action":"block","ClientIP":"198.51.100.1","ClientCountry":"RU","WAFRuleID":"SQL001","WAFRuleMessage":"SQL Injection","WAFMatchedVar":"ARGS:q","Source":"waf","EdgeStartTimestamp":1748476800000000000}'
```
**Resultado:** `{"forwarded":1}` + evento visible en Spyderbat en <5 segundos.

**Test B — Reverse block (Spyderbat → Cloudflare):**
```bash
# Genera HMAC del body
BODY='{"id":"test-1","policy_name":"test-policy","severity":9,"src_ip":"198.51.100.1"}'
SIG=$(echo -n "$BODY" | openssl dgst -sha256 -hmac "TU_WEBHOOK_SECRET" -binary | base64)

curl -X POST http://localhost:8787/spyderbat-alert \
  -H "Content-Type: application/json" \
  -H "X-Spyderbat-Signature: $SIG" \
  -d "$BODY"
```
**Resultado:** `{"action":"blocked","ip":"198.51.100.1","policy":"test-policy"}` + IP aparece en tu IP List en Cloudflare.

**Test C — Shadow AI (cron manual):**
```bash
# Triggerear el cron manualmente en dev
wrangler dev --test-scheduled
# En otra terminal:
curl "http://localhost:8787/__scheduled?cron=*+*+*+*+*"
```
**Resultado:** En `wrangler tail` verás:
```json
{"level":"info","msg":"ai_gateway_events_polled","count":5}
{"level":"info","msg":"forwarded","count":5}
```

---

### PASO 8 — Crear políticas en Spyderbat
**Acción:** Spyderbat → Policies → Create Policy
```
Política 1: WAF Critical
  Trigger: class = "waf_event" AND severity >= 8
  Action: Webhook → /spyderbat-alert (bloqueo automático)

Política 2: Bot Storm
  Trigger: class = "bot_event" AND count(src_ip, 5min) > 50
  Action: Alert + Webhook

Política 3: Shadow AI High Exfiltration Risk
  Trigger: class = "shadow_ai_event" AND tokens_in > 5000
  Action: Alert to security team

Política 4: Multi-vector Attack
  Trigger: misma src_ip en waf_event + bot_event en <60s
  Action: Webhook (bloqueo inmediato)
```
**Resultado esperado:** El loop completo opera de forma autónoma — Cloudflare detecta, Spyderbat correlaciona y evalúa, el Worker ejecuta el bloqueo, Cloudflare protege.

---

## 6. Resultados Esperados por Fase

| Fase | Acción completada | Resultado medible |
|---|---|---|
| Pasos 1-2 | Token + IP List creados | API calls funcionan, lista visible en dashboard |
| Paso 3 | AI Gateway configurado | Logs de uso de AI visibles en CF dashboard |
| Paso 4 | Webhook Spyderbat | Alerts disparan POST al Worker |
| Paso 5 | Worker desplegado | `/health` devuelve 200, cron activo cada 5min |
| Paso 6 | Logpush activo | Eventos WAF/Bot/DDoS llegan a Spyderbat en <5s |
| Paso 7 | Tests end-to-end | Loop completo verificado, 44 datos fluyendo |
| Paso 8 | Políticas en Spyderbat | Bloqueos automáticos sin intervención humana |

**Estado final del sistema:**
- Latencia Cloudflare → Spyderbat: **< 2 segundos** por batch
- Latencia Spyderbat → bloqueo en CF edge: **< 5 segundos** (webhook + API + propagación)
- Cobertura de eventos: **WAF + Bot + DDoS + Firewall + Shadow AI** (44 campos)
- Bloqueos automáticos: **0 intervención humana** para amenazas con severity ≥ 7
