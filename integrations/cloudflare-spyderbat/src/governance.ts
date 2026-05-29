// Governance layer: audit log, circuit breaker, whitelist, stats
// Sits between every AI decision and every automated action.

export interface GovDecision {
  id: string;
  ts: number;
  type:
    | "cf_auto_block"     // Spyderbat alert → CF blocks IP
    | "shadow_ai_flag"    // AI Gateway → Shadow AI detected
    | "waf_forward"       // WAF event → forwarded to Spyderbat
    | "bot_forward"       // Bot event → forwarded to Spyderbat
    | "ddos_forward"      // DDoS event → forwarded to Spyderbat
    | "generic_forward";  // Other security event
  src_ip: string;
  severity: number;
  event_class: string;
  action:
    | "blocked"            // IP blocked in Cloudflare
    | "forwarded"          // Event sent to Spyderbat
    | "held_circuit"       // Circuit breaker open — action paused
    | "skipped_whitelist"  // IP is whitelisted — action skipped
    | "duplicate_skip";    // IP already blocked — skip
  reason: string;
  policy?: string;
  cf_ray?: string;
  expires_at?: number;     // Unix timestamp when block expires (24h default)
  reviewed: boolean;       // Human reviewed this decision
}

export interface GovStats {
  hour: string;
  blocks_this_hour: number;
  circuit_open: boolean;
  circuit_threshold: number;
  total_forwarded_this_hour: number;
  shadow_ai_flags_this_hour: number;
}

// Auto-blocks expire after 24h by default
const BLOCK_TTL_SECONDS = 86_400;
// Max automated IP blocks per hour before circuit opens
export const CIRCUIT_THRESHOLD = 50;

export class Governance {
  constructor(private kv: KVNamespace, public adminSecret: string) {}

  // ── Helpers ──────────────────────────────────────────────────────────────
  private hourKey(): string {
    // "2026-05-29T04" — resets automatically each hour
    return new Date().toISOString().slice(0, 13);
  }

  // ── Circuit breaker ──────────────────────────────────────────────────────
  // Prevents AI from autonomously blocking more than CIRCUIT_THRESHOLD IPs/hour.
  // When open, blocks are held and humans are alerted instead of acting.
  async isCircuitOpen(): Promise<boolean> {
    const count = parseInt((await this.kv.get(`gov:circuit:${this.hourKey()}`)) ?? "0", 10);
    return count >= CIRCUIT_THRESHOLD;
  }

  async incrementCircuit(): Promise<number> {
    const key = `gov:circuit:${this.hourKey()}`;
    const current = parseInt((await this.kv.get(key)) ?? "0", 10);
    const next = current + 1;
    await this.kv.put(key, String(next), { expirationTtl: 3_600 });
    return next;
  }

  async getCircuitCount(): Promise<number> {
    return parseInt((await this.kv.get(`gov:circuit:${this.hourKey()}`)) ?? "0", 10);
  }

  // ── Whitelist — IPs that must never be auto-blocked ───────────────────────
  async isWhitelisted(ip: string): Promise<boolean> {
    return (await this.kv.get(`gov:whitelist:${ip}`)) !== null;
  }

  async addWhitelist(ip: string, reason: string, by: string): Promise<void> {
    await this.kv.put(
      `gov:whitelist:${ip}`,
      JSON.stringify({ added_at: Date.now(), reason, by }),
    );
  }

  async removeWhitelist(ip: string): Promise<void> {
    await this.kv.delete(`gov:whitelist:${ip}`);
  }

  async getWhitelistEntry(ip: string): Promise<{ added_at: number; reason: string; by: string } | null> {
    const val = await this.kv.get(`gov:whitelist:${ip}`);
    return val ? (JSON.parse(val) as { added_at: number; reason: string; by: string }) : null;
  }

  // ── Block TTL — track auto-blocks so they auto-expire ────────────────────
  async trackBlock(ip: string, reason: string): Promise<void> {
    await this.kv.put(
      `gov:block_ttl:${ip}`,
      JSON.stringify({ blocked_at: Date.now(), reason }),
      { expirationTtl: BLOCK_TTL_SECONDS },
    );
  }

  async isAlreadyBlocked(ip: string): Promise<boolean> {
    return (await this.kv.get(`gov:block_ttl:${ip}`)) !== null;
  }

  async clearBlock(ip: string): Promise<void> {
    await this.kv.delete(`gov:block_ttl:${ip}`);
  }

  // ── Audit log — immutable record of every AI decision ───────────────────
  async logDecision(d: GovDecision): Promise<void> {
    // Key sorts by timestamp descending for easy recent-first listing
    await this.kv.put(`gov:audit:${d.ts}:${d.id}`, JSON.stringify(d), {
      expirationTtl: 30 * 86_400, // keep 30 days
    });

    // Lightweight per-hour counters for stats
    const h = this.hourKey();
    if (d.action === "forwarded") {
      await this._incr(`gov:stats:fwd:${h}`, 3_600);
    }
    if (d.type === "shadow_ai_flag") {
      await this._incr(`gov:stats:shadow:${h}`, 3_600);
    }
  }

  private async _incr(key: string, ttl: number): Promise<void> {
    const v = parseInt((await this.kv.get(key)) ?? "0", 10);
    await this.kv.put(key, String(v + 1), { expirationTtl: ttl });
  }

  // ── Stats ─────────────────────────────────────────────────────────────────
  async getStats(): Promise<GovStats> {
    const h = this.hourKey();
    const [circuitRaw, fwdRaw, shadowRaw] = await Promise.all([
      this.kv.get(`gov:circuit:${h}`),
      this.kv.get(`gov:stats:fwd:${h}`),
      this.kv.get(`gov:stats:shadow:${h}`),
    ]);
    const blocks = parseInt(circuitRaw ?? "0", 10);
    return {
      hour: h,
      blocks_this_hour: blocks,
      circuit_open: blocks >= CIRCUIT_THRESHOLD,
      circuit_threshold: CIRCUIT_THRESHOLD,
      total_forwarded_this_hour: parseInt(fwdRaw ?? "0", 10),
      shadow_ai_flags_this_hour: parseInt(shadowRaw ?? "0", 10),
    };
  }

  // ── Audit log retrieval ───────────────────────────────────────────────────
  async getAuditLog(limit = 20): Promise<GovDecision[]> {
    // KV list returns keys alphabetically; gov:audit:{ts}:{id} sorts by time
    const list = await this.kv.list({ prefix: "gov:audit:", limit });
    const entries = await Promise.all(
      [...list.keys].reverse().map(async (k) => {
        const v = await this.kv.get(k.name);
        return v ? (JSON.parse(v) as GovDecision) : null;
      }),
    );
    return entries.filter(Boolean) as GovDecision[];
  }
}
