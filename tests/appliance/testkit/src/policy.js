"use strict";

const { info, warn } = require("./log");
const { config } = require("./config");
const { buildPipe } = require("./surfaces");

// A black-box drill for the OPA policy system. It provisions reusable policy
// definitions + policy-bound surfaces + a dedicated uncapped caller, then drives
// real traffic and management-API calls to assert, end to end:
//
//   - per-surface allow / deny (a header-gated `llm.policy`);
//   - multi-policy deny-overrides (two policies, one denies);
//   - fail-closed eviction (deleting a referenced definition flips allow → deny);
//   - appliance-wide (global) enforcement + monitor-only rollout;
//   - the dry-run (simulate), blast-radius (impact), and version-history APIs.
//
// It is reconciliation-safe: a policy 403 accrues no usage and no rejection
// telemetry (the appliance records only a governance entry), and every 200 is
// priced from the mock's per-nonce call log and recorded into the ledger exactly
// like any other surface. The global-assignment window is opened and always
// restored inside this phase (try/finally), so it never leaks onto other traffic.

// Header the gated policy keys on. Lowercase — the appliance lowercases header
// names before handing `input.http.headers` to Rego.
const POLICY_HEADER = "x-tk-policy";
const ALLOW_HEADERS = { [POLICY_HEADER]: "allow" };

// Allow only when the caller presents `x-tk-policy: allow`; default deny.
const REGO_ALLOW_HEADER = [
  "package llm.policy",
  "import rego.v1",
  "default allow := false",
  `allow if input.http.headers["${POLICY_HEADER}"] == "allow"`,
  "",
].join("\n");

// Always deny (a constant baseline used for deny-overrides + global tests).
const REGO_DENY_ALL = ["package llm.policy", "import rego.v1", "default allow := false", ""].join("\n");

// Always allow (used to prove a draft body + version update are honoured).
const REGO_ALLOW_ALL = ["package llm.policy", "import rego.v1", "default allow := true", ""].join("\n");

function policyDef(id, rego) {
  return {
    id,
    name: id,
    description: "testkit policy fixture",
    policy_type: "llm",
    policy: rego,
    enabled: true,
    created_at: new Date().toISOString(),
  };
}

// A plain email LLM surface bound to the given `opa_policy` block. Reuses the
// shared surface builder so the wire shape matches every other testkit surface.
function policySurface(key, ctx, opaPolicy) {
  const built = buildPipe(
    { key, identity: "email", route: `/llm/${key}`, model: "mock-small", description: `testkit policy surface ${key}` },
    ctx,
  );
  built.pipe.opa_policy = opaPolicy;
  return built;
}

// A recon-facing surface descriptor. Policy surfaces have no judge/jury, so they
// contribute no stage keys; their per-surface usage series still reconciles.
function descriptor(built) {
  return {
    pipeId: built.pipeId,
    route: built.route,
    identity: "email",
    model: built.model,
    hasJudge: false,
    jurors: 0,
    moderated: false,
  };
}

// Provision definitions, policy-bound surfaces, and a dedicated uncapped caller.
// The caller carries no `surfaces` so the load/coverage phases never touch it;
// it is exercised only by this drill. Pushed into the shared members/teams so
// teardown removes it.
async function setupPolicy(appliance, ctx, members, teams) {
  const defs = {
    allow: policyDef("tk-pol-allow", REGO_ALLOW_HEADER),
    deny: policyDef("tk-pol-deny", REGO_DENY_ALL),
    fc: policyDef("tk-pol-fc", REGO_ALLOW_HEADER),
    ver: policyDef("tk-pol-ver", REGO_DENY_ALL),
  };
  // Delete-then-create so a prior run's definition (definitions are not
  // test-surface flagged) can't collide, and the version history starts at 1.
  for (const d of Object.values(defs)) {
    try {
      await appliance.deletePolicyDefinition(d.id);
    } catch (e) {
      warn(`policy setup: pre-delete ${d.id} skipped: ${e.message || e}`);
    }
    await appliance.createPolicyDefinition(d);
  }

  const single = policySurface("tk-policy-single", ctx, { enabled: true, policy_definition_id: defs.allow.id });
  const multi = policySurface("tk-policy-multi", ctx, {
    enabled: true,
    policy_definition_id: defs.allow.id,
    policy_definition_ids: [defs.deny.id],
  });
  const fc = policySurface("tk-policy-fc", ctx, { enabled: true, policy_definition_id: defs.fc.id });
  for (const s of [single, multi, fc]) await appliance.createPipe(s.pipe);

  const team = await appliance.createTeam({ id: "", name: "Testkit Policy Caller" });
  const teamRec = { id: team.id, name: team.name, memberIds: [], drill: true };
  teams.push(teamRec);
  const email = `policy-${Date.now()}@testkit.local`;
  const createdMember = await appliance.createMember({
    id: "",
    name: "Policy caller",
    identifier: { kind: "email", email },
  });
  const caller = {
    id: createdMember.id,
    flavor: "email",
    teamId: teamRec.id,
    cred: { flavor: "email", email },
    surfaces: [],
    signer: null,
  };
  members.push(caller);
  teamRec.memberIds.push(caller.id);
  await appliance.addTeamMember(teamRec.id, caller.id);

  const surfaceDescriptors = [descriptor(single), descriptor(multi), descriptor(fc)];
  info(`policy drill ready: 4 definitions, 3 surfaces, dedicated caller`);
  return {
    enabled: true,
    allowId: defs.allow.id,
    denyId: defs.deny.id,
    fcId: defs.fc.id,
    verId: defs.ver.id,
    defIds: Object.values(defs).map((d) => d.id),
    single: surfaceDescriptors[0],
    multi: surfaceDescriptors[1],
    fc: surfaceDescriptors[2],
    caller,
    surfaceDescriptors,
  };
}

// Appliance-wide (global) enforcement + monitor-only. The original assignments
// are captured and always restored, so the global deny window is fully contained
// within this phase and never blocks other traffic.
async function runGlobalChecks(appliance, pol, driveStatuses, allAre, ok, fail) {
  let saved = null;
  try {
    const cur = await appliance.getPolicyAssignments();
    if (cur.status === 403) {
      info("policy drill: global-assignment checks skipped (caller lacks policies.publish)");
      return;
    }
    if (!cur.ok) {
      fail("global-setup", `GET policy-assignments -> ${cur.status}`);
      return;
    }
    saved = (cur.json && cur.json.assignments) || {};

    // (a) Enforced global deny → every llm surface denies, even a header-passing one.
    const put1 = await appliance.setPolicyAssignments({
      assignments: { ...saved, llm: [{ policy_id: pol.denyId, monitor_only: false }] },
    });
    if (!put1.ok) {
      fail("global-deny-set", `PUT -> ${put1.status}: ${(put1.text || "").slice(0, 160)}`);
    } else {
      const s = await driveStatuses(pol.single, ALLOW_HEADERS);
      if (allAre(s, 403)) ok("global-deny-enforced");
      else fail("global-deny-enforced", `expected all 403 under global deny, got ${s.join(",")}`);
    }

    // (b) Monitor-only global deny → recorded but never blocks.
    const put2 = await appliance.setPolicyAssignments({
      assignments: { ...saved, llm: [{ policy_id: pol.denyId, monitor_only: true }] },
    });
    if (!put2.ok) {
      fail("global-monitor-set", `PUT -> ${put2.status}`);
    } else {
      const s = await driveStatuses(pol.single, ALLOW_HEADERS);
      if (allAre(s, 200)) ok("global-monitor-only");
      else fail("global-monitor-only", `expected all 200 under monitor-only, got ${s.join(",")}`);
    }

    // (c) Restore → enforcement clears and the surface allows again.
    const restore = await appliance.setPolicyAssignments({ assignments: saved });
    saved = null;
    if (!restore.ok) {
      fail("global-restore", `PUT restore -> ${restore.status}`);
    } else {
      const s = await driveStatuses(pol.single, ALLOW_HEADERS);
      if (allAre(s, 200)) ok("global-cleared");
      else fail("global-cleared", `expected all 200 after clearing global, got ${s.join(",")}`);
    }
  } catch (e) {
    fail("global-checks", `error: ${e.message || e}`);
  } finally {
    if (saved) {
      try {
        await appliance.setPolicyAssignments({ assignments: saved });
      } catch (e) {
        warn(`policy drill: failed to restore global assignments: ${e.message || e}`);
      }
    }
  }
}

// Read-only management surface: dry-run (with a draft-type override and a bounds
// rejection), blast radius, and immutable version history.
async function runManagementChecks(appliance, pol, ok, fail) {
  const inputWith = { http: { method: "POST", path: "/v1/chat/completions", headers: { [POLICY_HEADER]: "allow" } } };
  const inputWithout = { http: { method: "POST", path: "/v1/chat/completions", headers: {} } };

  const simA = await appliance.simulatePolicy(pol.allowId, { input: inputWith });
  if (simA.ok && simA.json && simA.json.allow === true) ok("simulate-allow");
  else fail("simulate-allow", `expected allow:true, got ${simA.status}:${JSON.stringify(simA.json)}`);

  const simD = await appliance.simulatePolicy(pol.allowId, { input: inputWithout });
  if (simD.ok && simD.json && simD.json.allow === false) ok("simulate-deny");
  else fail("simulate-deny", `expected allow:false, got ${simD.status}:${JSON.stringify(simD.json)}`);

  // A draft allow-all body evaluated under an explicit type must allow even the
  // header-absent input the stored (header-gated) policy would deny — proving the
  // draft body + type override are honoured.
  const simDraft = await appliance.simulatePolicy(pol.allowId, {
    input: inputWithout,
    policy: REGO_ALLOW_ALL,
    policy_type: "llm",
  });
  if (simDraft.ok && simDraft.json && simDraft.json.allow === true) ok("simulate-draft-type");
  else fail("simulate-draft-type", `expected draft allow:true, got ${simDraft.status}:${JSON.stringify(simDraft.json)}`);

  // The dry-run is bounded: an oversized sample input is rejected (HTTP 400).
  const bigInput = { http: { headers: { [POLICY_HEADER]: "x".repeat(300 * 1024) } } };
  const simBig = await appliance.simulatePolicy(pol.allowId, { input: bigInput });
  if (simBig.status === 400) ok("simulate-bounds");
  else fail("simulate-bounds", `expected 400 for oversized input, got ${simBig.status}`);

  // Blast radius: the allow policy backs the single + multi surfaces.
  try {
    const impact = await appliance.policyImpact(pol.allowId);
    if (impact && impact.pipes >= 2) ok("impact-count");
    else fail("impact-count", `expected pipes>=2, got ${JSON.stringify(impact)}`);
  } catch (e) {
    fail("impact-count", `error: ${e.message || e}`);
  }

  // Version history: updating a definition appends an immutable, newest-first
  // version (create = v1, update = v2).
  try {
    await appliance.updatePolicyDefinition(policyDef(pol.verId, REGO_ALLOW_ALL));
    const versions = await appliance.listPolicyVersions(pol.verId);
    const ordered =
      Array.isArray(versions) &&
      versions.length >= 2 &&
      versions[0].version > versions[versions.length - 1].version;
    if (ordered) ok("versions-history");
    else fail("versions-history", `expected >=2 versions newest-first, got ${JSON.stringify(versions)}`);
  } catch (e) {
    fail("versions-history", `error: ${e.message || e}`);
  }
}

// Drive the whole policy drill for one round. Traffic checks send
// `config.policyRequests` calls each and assert every status matches.
async function policyPhase(deps, appliance, world, ledger, pricer, rng, roundIdx, stats) {
  const { executeOnce, recordExecution } = deps;
  const out = { enabled: false, checks: [], pass: true };
  const pol = world.policy;
  if (!config.policyDrill || !pol || !pol.enabled) return out;
  out.enabled = true;

  const n = config.policyRequests;
  const caller = pol.caller;
  const fail = (name, detail) => {
    out.checks.push({ name, ok: false, detail });
    out.pass = false;
    stats.policyFailures.push({ name, detail });
    warn(`policy drill: ${name} FAILED — ${detail}`);
  };
  const ok = (name) => out.checks.push({ name, ok: true });
  const allAre = (statuses, code) => statuses.length > 0 && statuses.every((s) => s === code);

  // Drive n calls; record every 200's priced usage so reconciliation stays exact
  // (a 403 records nothing — matching the appliance, which meters no usage for a
  // policy block).
  const driveStatuses = async (surface, extraHeaders) => {
    const statuses = [];
    for (let i = 0; i < n; i += 1) {
      const r = await executeOnce(appliance, pricer, caller, surface, { roundIdx, rng, headers: extraHeaders });
      statuses.push(r.status);
      if (r.status === 200) {
        recordExecution(ledger, {
          surfaceId: surface.pipeId,
          memberId: caller.id,
          teamIds: caller.teamIds || [caller.teamId],
          grand: r.grand,
          llm: r.llm,
        });
      }
    }
    return statuses;
  };

  // 1. Single header-gated policy: allow with the header, deny without it.
  const a1 = await driveStatuses(pol.single, ALLOW_HEADERS);
  if (allAre(a1, 200)) ok("single-allow");
  else fail("single-allow", `expected all 200, got ${a1.join(",")}`);
  const d1 = await driveStatuses(pol.single, null);
  if (allAre(d1, 403)) ok("single-deny");
  else fail("single-deny", `expected all 403, got ${d1.join(",")}`);

  // 2. Multi-policy deny-overrides: the header satisfies policy A, but policy B
  // (deny-all) denies — so the request is blocked regardless.
  const m1 = await driveStatuses(pol.multi, ALLOW_HEADERS);
  if (allAre(m1, 403)) ok("multi-deny-overrides");
  else fail("multi-deny-overrides", `expected all 403 (deny-overrides), got ${m1.join(",")}`);

  // 3. Fail-closed: the fc surface allows with the header, but deleting its
  // referenced definition must evict the engine and flip it to a deny.
  const fcBefore = await driveStatuses(pol.fc, ALLOW_HEADERS);
  if (allAre(fcBefore, 200)) ok("failclosed-before");
  else fail("failclosed-before", `expected all 200 before delete, got ${fcBefore.join(",")}`);
  try {
    await appliance.deletePolicyDefinition(pol.fcId);
    const fcAfter = await driveStatuses(pol.fc, ALLOW_HEADERS);
    if (allAre(fcAfter, 403)) ok("failclosed-after-delete");
    else fail("failclosed-after-delete", `expected all 403 after delete (fail-closed), got ${fcAfter.join(",")}`);
  } catch (e) {
    fail("failclosed-after-delete", `delete/probe error: ${e.message || e}`);
  }

  // 4. Appliance-wide global enforcement + monitor-only (window always restored).
  await runGlobalChecks(appliance, pol, driveStatuses, allAre, ok, fail);

  // 5. Management endpoints: dry-run, blast radius, version history.
  await runManagementChecks(appliance, pol, ok, fail);

  info(
    `policy drill: ${out.checks.filter((c) => c.ok).length}/${out.checks.length} checks passed${
      out.pass ? "" : ` (${stats.policyFailures.length} failure(s))`
    }`,
  );
  return out;
}

module.exports = { setupPolicy, policyPhase };
