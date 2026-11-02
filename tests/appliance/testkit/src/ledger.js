"use strict";

// Local ground-truth ledger. The simulator drives one request at a time, reads
// the exact upstream calls each request produced from the mock's call log, and
// records the resulting spend/tokens/requests here under the SAME series keys the
// appliance's telemetry uses. Reconciliation then compares this ledger to the
// appliance's `/v1/telemetry/series` window sums.
//
// It also keeps running per-member and per-team grand-total usage so the
// simulator can predict, before each call, whether the appliance should enforce
// a monthly cap (HTTP 429) — exercising the TeamUsageTracker enforcement path.

// ---- series key builders (kept in lockstep with src/telemetry/mod.rs) ----
const k = {
  all: () => "surfaces:all",
  surface: (id) => `surface:${id}`,
  surfaceStage: (id, stage) => `surface:${id}:stage:${stage}`,
  member: (id) => `member:${id}`,
  memberSurface: (mid, sid) => `member:${mid}:surface:${sid}`,
  team: (id) => `team:${id}`,
};

// ---- rejection SCOPE builders (the prefix the /telemetry/rejections endpoint
// takes; it sums the per-category series under the scope and returns `total`).
// Kept in lockstep with src/telemetry/mod.rs and is_valid_rejection_scope. ----
const rk = {
  all: () => "rejection:all",
  surface: (id) => `rejection:surface:${id}`,
  surfaceStage: (id, stage) => `rejection:surface:${id}:stage:${stage}`,
  member: (id) => `rejection:member:${id}`,
  team: (id) => `rejection:team:${id}`,
};

function emptyBucket() {
  return { cost: 0, tokens: 0, requests: 0 };
}

class Ledger {
  constructor() {
    this.series = new Map(); // key -> {cost, tokens, requests}
    this.memberUsage = new Map(); // memberId -> {cost, tokens}
    this.teamUsage = new Map(); // teamId -> {cost, tokens}
    this.rejections = new Map(); // rejection scope -> expected total count
  }

  _bucket(key) {
    let b = this.series.get(key);
    if (!b) {
      b = emptyBucket();
      this.series.set(key, b);
    }
    return b;
  }

  add(key, cost, tokens, requests = 1) {
    const b = this._bucket(key);
    b.cost += cost;
    b.tokens += tokens;
    b.requests += requests;
  }

  get(key) {
    return this.series.get(key) || emptyBucket();
  }

  keys() {
    return Array.from(this.series.keys());
  }

  // Running grand-total usage used for cap prediction.
  memberTotals(memberId) {
    return this.memberUsage.get(memberId) || { cost: 0, tokens: 0 };
  }
  teamTotals(teamId) {
    return this.teamUsage.get(teamId) || { cost: 0, tokens: 0 };
  }

  // Record one SUCCESSFUL execution. `grand` is the sum across all stages;
  // `llm` is the main-LLM stage only (== response.usage); `stages` optionally
  // carries judge/jury sub-totals for stage-key attribution.
  recordSuccess({ surfaceId, memberId, teamIds, grand, llm, stages }) {
    // Grand-total scopes.
    this.add(k.all(), grand.cost, grand.tokens, 1);
    this.add(k.surface(surfaceId), grand.cost, grand.tokens, 1);
    this.add(k.member(memberId), grand.cost, grand.tokens, 1);
    this.add(k.memberSurface(memberId, surfaceId), grand.cost, grand.tokens, 1);
    for (const t of teamIds) this.add(k.team(t), grand.cost, grand.tokens, 1);

    // Stage scopes.
    this.add(k.surfaceStage(surfaceId, "llm"), llm.cost, llm.tokens, 1);
    if (stages) {
      for (const [stage, v] of Object.entries(stages)) {
        if (v && (v.cost > 0 || v.tokens > 0)) {
          this.add(k.surfaceStage(surfaceId, stage), v.cost, v.tokens, 1);
        }
      }
    }

    // Running usage for cap prediction.
    const m = this.memberUsage.get(memberId) || { cost: 0, tokens: 0 };
    m.cost += grand.cost;
    m.tokens += grand.tokens;
    this.memberUsage.set(memberId, m);
    for (const t of teamIds) {
      const tu = this.teamUsage.get(t) || { cost: 0, tokens: 0 };
      tu.cost += grand.cost;
      tu.tokens += grand.tokens;
      this.teamUsage.set(t, tu);
    }
  }

  // Record one BLOCKED execution (judge/jury content rejection -> HTTP 403).
  // A blocked request records ONLY rejection telemetry, never usage telemetry,
  // so this deliberately does not touch the usage series or running totals.
  recordRejection({ surfaceId, stage, memberId, teamIds }) {
    this._rej(rk.all());
    this._rej(rk.surface(surfaceId));
    if (stage) this._rej(rk.surfaceStage(surfaceId, stage));
    if (memberId) this._rej(rk.member(memberId));
    for (const t of teamIds || []) this._rej(rk.team(t));
  }

  _rej(scope) {
    this.rejections.set(scope, (this.rejections.get(scope) || 0) + 1);
  }

  rejectionScopes() {
    return Array.from(this.rejections.keys());
  }
  rejectionCount(scope) {
    return this.rejections.get(scope) || 0;
  }
}

module.exports = { Ledger, keys: k, rejectionKeys: rk };
