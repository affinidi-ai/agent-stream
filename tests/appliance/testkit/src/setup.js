"use strict";

const fs = require("fs");
const path = require("path");

const { config } = require("./config");
const { info, randInt } = require("./log");
const { makeJwtSigner } = require("./identities");
const { buildApiKeyHolder, buildSurface } = require("./surfaces");
const { setupEnrolment } = require("./enrolment");
const { setupPolicy } = require("./policy");

// Load the surface definitions from the config folder. Each file is either a
// compact template or a full PipeConfig (detected per file); the raw text is
// kept so full configs can have their runtime placeholders substituted.
function loadSurfaceDefs() {
  const dir = config.surfacesDir;
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => ({ name: f, text: fs.readFileSync(path.join(dir, f), "utf8") }));
}

const FLAVORS = ["email", "jwt", "apikey"];

// Roughly a third of members and teams get a deliberately tiny cap so the run
// trips real enforcement (HTTP 429); the rest stay uncapped.
function maybeMemberCap(rng) {
  if (rng() > 0.35) return {};
  if (rng() < 0.5) return { monthly_token_cap: randInt(rng, 400, 2500) };
  return { monthly_budget_usd: Number((0.001 + rng() * 0.02).toFixed(6)) };
}
function maybeTeamCap(rng) {
  if (rng() > 0.4) return {};
  if (rng() < 0.5) return { monthly_token_cap: randInt(rng, 2000, 12000) };
  return { monthly_budget_usd: Number((0.005 + rng() * 0.05).toFixed(6)) };
}

function hasCap(o) {
  return o.monthly_token_cap != null || o.monthly_budget_usd != null;
}

// Pick the cheapest plain email surface (no judge/jury) for the cap drill so
// each call accrues usage through exactly one upstream LLM call — keeping the
// success→cap transition easy to reason about.
function pickDrillSurface(surfacesByFlavor) {
  const email = surfacesByFlavor.email || [];
  const plain = email.find((s) => !s.hasJudge && s.jurors === 0 && !s.moderated);
  return plain || email[0] || null;
}

// Build deterministic fixtures whose caps are tiny enough that a single (or
// second) call trips real enforcement, plus an uncapped control that must never
// be blocked. These drive the cap-enforcement drill in the simulator. All
// members/teams created here are also pushed into the shared members/teams
// arrays so teardown removes them.
async function buildCapDrill(appliance, surfacesByFlavor, signer, members, teams) {
  const surface = pickDrillSurface(surfacesByFlavor);
  if (!surface) {
    info("cap drill skipped: no email surface available");
    return null;
  }
  let idx = 0;
  const mkEmailMember = async (label, caps) => {
    const email = `cap-${label}-${Date.now()}-${idx}@testkit.local`;
    idx += 1;
    const created = await appliance.createMember({
      id: "",
      name: `Cap drill ${label}`,
      identifier: { kind: "email", email },
      ...caps,
    });
    const member = {
      id: created.id,
      flavor: "email",
      teamId: null,
      cred: { flavor: "email", email },
      monthly_budget_usd: caps.monthly_budget_usd,
      monthly_token_cap: caps.monthly_token_cap,
      surfaces: [surface],
      signer,
      drill: true,
    };
    members.push(member);
    return member;
  };

  // Host team is uncapped so member caps are the only constraint.
  const hostTeam = await appliance.createTeam({ id: "", name: "Testkit Cap Drill Host" });
  const host = { id: hostTeam.id, name: hostTeam.name, memberIds: [], drill: true };
  teams.push(host);

  const control = await mkEmailMember("control", {});
  const memberToken = await mkEmailMember("member-token", { monthly_token_cap: 50 });
  const memberBudget = await mkEmailMember("member-budget", { monthly_budget_usd: 0.0005 });
  for (const m of [control, memberToken, memberBudget]) {
    m.teamId = host.id;
    host.memberIds.push(m.id);
    await appliance.addTeamMember(host.id, m.id);
  }

  // Tiny-budget team with two individually-uncapped members: usage from either
  // trips the *team* cap.
  const capTeamRec = await appliance.createTeam({
    id: "",
    name: "Testkit Cap Drill Team",
    monthly_budget_usd: 0.0008,
  });
  const capTeam = {
    id: capTeamRec.id,
    name: capTeamRec.name,
    monthly_budget_usd: 0.0008,
    memberIds: [],
    drill: true,
  };
  teams.push(capTeam);
  const teamMemberA = await mkEmailMember("team-a", {});
  const teamMemberB = await mkEmailMember("team-b", {});
  for (const m of [teamMemberA, teamMemberB]) {
    m.teamId = capTeam.id;
    capTeam.memberIds.push(m.id);
    await appliance.addTeamMember(capTeam.id, m.id);
  }

  info("created cap-drill fixtures (control + member/team caps)");
  return {
    surface,
    control,
    targets: [
      { kind: "member-token", member: memberToken, scope: "member" },
      { kind: "member-budget", member: memberBudget, scope: "member" },
      { kind: "team-budget", member: teamMemberA, scope: "team", team: capTeam },
      { kind: "team-budget", member: teamMemberB, scope: "team", team: capTeam },
    ],
  };
}

// Mint an uncapped member of the given flavor on a dedicated uncapped team, so
// the rejection drill always has a caller that reaches the judge/jury guard
// (rather than being short-circuited by a member/team quota). Pushed into the
// shared members/teams arrays so teardown removes it.
async function ensureRejectionCaller(appliance, flavor, signer, surfacesByFlavor, members, teams) {
  const surfacesForFlavor = surfacesByFlavor[flavor] || [];
  if (surfacesForFlavor.length === 0) return null;

  const team = await appliance.createTeam({ id: "", name: `Testkit Rejection Caller (${flavor})` });
  const teamRec = { id: team.id, name: team.name, memberIds: [], drill: true };
  teams.push(teamRec);

  const tag = `${flavor}-${Date.now()}`;
  const cred = { flavor };
  let identifier;
  if (flavor === "email") {
    const email = `reject-${tag}@testkit.local`;
    identifier = { kind: "email", email };
    cred.email = email;
  } else if (flavor === "jwt") {
    const subject = `reject-${tag}`;
    identifier = { kind: "subject", subject };
    cred.subject = subject;
  } else {
    const created = await appliance.createApiKey(config.apiKeyAgentId, `reject-${tag}`);
    identifier = { kind: "api_key", key_name: created.key_id };
    cred.keyId = created.key_id;
    cred.secret = created.secret;
  }

  const createdMember = await appliance.createMember({
    id: "",
    name: `Rejection caller ${flavor}`,
    identifier,
  });
  const member = {
    id: createdMember.id,
    flavor,
    teamId: teamRec.id,
    cred,
    surfaces: surfacesForFlavor,
    signer,
  };
  members.push(member);
  teamRec.memberIds.push(member.id);
  await appliance.addTeamMember(teamRec.id, member.id);
  info(`created guaranteed uncapped ${flavor} rejection caller`);
  return member;
}

// Identify members/teams left behind by a previous (possibly crashed) run.
// Member identifiers are deterministic (`m{n}@testkit.local`, `subj-{n}`, …) so
// a fresh run would otherwise collide with leftovers (HTTP 409). Names are the
// stable signal across every flavor: every member/team this kit creates is
// named with a "Testkit"/"Member"/"Cap drill"/"Rejection caller" prefix.
const LEFTOVER_TEAM_RE = /^Testkit /;
const LEFTOVER_MEMBER_RE = /^(Member \d|Cap drill |Rejection caller )/;

function memberEmail(m) {
  return (m && m.identifier && m.identifier.email) || "";
}

// Remove any residue from a prior run so deterministic identifiers are free.
// Teams are deleted first (which drops their membership references), then the
// now-unreferenced members. Best-effort: never fails the run.
async function cleanupLeftovers(appliance) {
  let teams = [];
  let members = [];
  try {
    teams = (await appliance.listTeams()) || [];
  } catch (e) {
    info(`leftover team scan skipped: ${e.message}`);
  }
  try {
    members = (await appliance.listMembers()) || [];
  } catch (e) {
    info(`leftover member scan skipped: ${e.message}`);
  }

  let removedTeams = 0;
  for (const t of teams) {
    if (t.system || !LEFTOVER_TEAM_RE.test(t.name || "")) continue;
    try {
      await appliance.deleteTeam(t.id);
      removedTeams += 1;
    } catch (e) {
      info(`leftover team delete ${t.id} failed: ${e.message}`);
    }
  }

  let removedMembers = 0;
  for (const m of members) {
    if (m.system) continue;
    const stale = LEFTOVER_MEMBER_RE.test(m.name || "") || memberEmail(m).endsWith("@testkit.local");
    if (!stale) continue;
    try {
      await appliance.deleteMember(m.id);
      removedMembers += 1;
    } catch (e) {
      info(`leftover member delete ${m.id} failed: ${e.message}`);
    }
  }

  if (removedTeams || removedMembers) {
    info(`cleaned ${removedTeams} leftover team(s) and ${removedMembers} leftover member(s)`);
  }
}

async function setup(appliance, rng) {
  const surfaceDefs = loadSurfaceDefs();

  // 0. Clear any test surfaces left behind by a previous (possibly crashed)
  // run, so a fresh run starts from a clean slate. Best-effort: the bulk
  // endpoint is debug/test-mode only, so a release appliance returns 404.
  try {
    const cleaned = await appliance.deleteTestSurfaces();
    if (cleaned && cleaned.deleted) info(`cleaned ${cleaned.deleted} leftover test surface(s)`);
  } catch (e) {
    info(`leftover test-surface cleanup skipped: ${e.message}`);
  }

  // Also clear leftover members/teams from a prior run so the deterministic
  // member identifiers (m{n}@testkit.local, subj-{n}, …) don't collide (409).
  await cleanupLeftovers(appliance);

  // 1. JWT verification strategy from a freshly generated RSA keypair.
  const signer = makeJwtSigner();
  const strategy = await appliance.createJwtStrategy({
    name: "testkit-rs256",
    expected_issuer: signer.issuer,
    jwks_source: { type: "static", jwks: [signer.publicJwk] },
  });
  const jwtStrategyId = strategy.id;
  info(`created JWT strategy ${jwtStrategyId}`);

  // 2. Surfaces (one pipe per template).
  // Resolve the first host listener AND the first pipe path prefix so each
  // surface carries a `listen_address` and a route of the form
  // `{prefix}/{suffix}` — both are needed for the dashboard access-point node to
  // render as fully configured. An empty listen address, or a route that
  // doesn't start with a configured pipe path prefix (so the dashboard can't
  // decompose it into prefix + custom path), is what makes the access-point node
  // show the "unconfigured" marching ants.
  let listenAddress = "";
  let pathPrefix = "";
  try {
    const routing = await appliance.surfaceRoutingConfig();
    listenAddress = (routing && routing.available_listen_addresses && routing.available_listen_addresses[0]) || "";
    pathPrefix = (routing && routing.pipe_path_prefix && routing.pipe_path_prefix[0] && routing.pipe_path_prefix[0].prefix) || "";
    if (listenAddress) info(`resolved surface listen address ${listenAddress}`);
    if (pathPrefix) info(`resolved pipe path prefix ${pathPrefix}`);
  } catch (e) {
    info(`surface-routing config lookup skipped: ${e.message}`);
  }
  const ctx = {
    mockInternalUrl: config.mockInternalUrl,
    jwtStrategyId,
    apiKeyAgentId: config.apiKeyAgentId,
    listenAddress,
    pathPrefix,
  };
  const apiKeyHolder = buildApiKeyHolder(ctx);
  await appliance.createPipe(apiKeyHolder);
  info(`created API-key holder surface ${apiKeyHolder.id}`);

  const surfaces = [];
  const surfacesByFlavor = { email: [], jwt: [], apikey: [] };
  for (const def of surfaceDefs) {
    const built = buildSurface(def.text, ctx);
    await appliance.createPipe(built.pipe);
    const surface = {
      key: built.pipeId,
      pipeId: built.pipeId,
      route: built.route,
      identity: built.identity,
      model: built.model,
      hasJudge: built.hasJudge,
      jurors: built.jurors,
      moderated: built.moderated,
      drift: built.drift,
    };
    surfaces.push(surface);
    surfacesByFlavor[built.identity].push(surface);
    info(`created surface ${built.pipeId} (${def.name}) on ${built.route}`);
  }
  // 3. Teams with random caps.
  const teams = [];
  for (let t = 0; t < config.numTeams; t += 1) {
    const cap = maybeTeamCap(rng);
    const created = await appliance.createTeam({
      id: "",
      name: `Testkit Team ${t + 1}`,
      ...cap,
    });
    teams.push({
      id: created.id,
      name: created.name,
      monthly_budget_usd: cap.monthly_budget_usd,
      monthly_token_cap: cap.monthly_token_cap,
      memberIds: [],
    });
  }
  info(`created ${teams.length} teams`);

  // 4. Members (round-robin flavor) with random caps; api-key members get a key.
  // Identifiers carry a per-run id: member soft-delete leaves a tombstone that
  // still reserves the identifier (the appliance's duplicate check scans deleted
  // members too), so deterministic ids would collide (409) on a later run.
  const runId = Date.now().toString(36);
  const members = [];
  let globalIdx = 0;
  for (let t = 0; t < teams.length; t += 1) {
    const team = teams[t];
    for (let i = 0; i < config.membersPerTeam; i += 1) {
      const flavor = FLAVORS[globalIdx % FLAVORS.length];
      const cap = maybeMemberCap(rng);
      let identifier;
      const cred = { flavor };

      if (flavor === "email") {
        const email = `m${globalIdx}-${runId}@testkit.local`;
        identifier = { kind: "email", email };
        cred.email = email;
      } else if (flavor === "jwt") {
        const subject = `subj-${globalIdx}-${runId}`;
        identifier = { kind: "subject", subject };
        cred.subject = subject;
      } else {
        const created = await appliance.createApiKey(config.apiKeyAgentId, `client-${globalIdx}-${runId}`);
        identifier = { kind: "api_key", key_name: created.key_id };
        cred.keyId = created.key_id;
        cred.secret = created.secret;
      }

      const createdMember = await appliance.createMember({
        id: "",
        name: `Member ${globalIdx}`,
        identifier,
        ...cap,
      });

      const member = {
        id: createdMember.id,
        flavor,
        teamId: team.id,
        cred,
        monthly_budget_usd: cap.monthly_budget_usd,
        monthly_token_cap: cap.monthly_token_cap,
        surfaces: surfacesByFlavor[flavor],
        signer,
      };
      members.push(member);
      team.memberIds.push(member.id);
      await appliance.addTeamMember(team.id, member.id);
      globalIdx += 1;
    }
  }
  info(`created ${members.length} members and assigned team membership`);

  // 5. Deterministic cap-enforcement drill fixtures (tiny-capped members/teams
  // plus an uncapped control). Pushed into members/teams so teardown cleans up.
  const capDrill = config.capDrill
    ? await buildCapDrill(appliance, surfacesByFlavor, signer, members, teams)
    : null;

  // Map of team id -> whether that team carries a cap, to find load-safe members.
  const teamCapped = new Map(teams.map((t) => [t.id, hasCap(t)]));

  // Members that have at least one compatible surface to call.
  const callableMembers = members.filter((m) => m.surfaces.length > 0);

  // "Load" members are uncapped individually AND on an uncapped team, and are not
  // drill fixtures — so the concurrent load phase never trips a cap, keeping
  // token/cost reconciliation exact.
  const loadMembers = callableMembers.filter(
    (m) => !m.drill && !hasCap(m) && !teamCapped.get(m.teamId),
  );

  // Moderated surfaces (judge/jury that reject the mock's BLOCKED trigger) used
  // by the rejection drill, paired with the email members that can call them.
  const moderatedSurfaces = surfaces.filter((s) => s.moderated);

  // Guarantee the rejection drill always has an uncapped caller of the right
  // flavor: in a small or heavily-capped random population every email member
  // can end up capped, which would silently skip the drill. Mint a dedicated
  // uncapped member (on an uncapped team) per moderated-surface flavor.
  if (config.rejectionDrill && moderatedSurfaces.length > 0) {
    const flavorsNeeded = new Set(moderatedSurfaces.map((s) => s.identity));
    for (const flavor of flavorsNeeded) {
      const have = loadMembers.some((m) => m.flavor === flavor);
      if (have) continue;
      const created = await ensureRejectionCaller(appliance, flavor, signer, surfacesByFlavor, members, teams);
      if (created) {
        loadMembers.push(created);
        callableMembers.push(created);
      }
    }
  }

  info(
    `partitioned ${loadMembers.length} load members, ${
      capDrill ? capDrill.targets.length : 0
    } cap-drill targets, ${moderatedSurfaces.length} moderated surfaces`,
  );

  // 6. Enrolment (member auto-provisioning) infrastructure: novel identities,
  // mTLS PKI + CA, three auto-provisioning surfaces, and the appliance
  // provisioning config. Runs on top of the full population/quotas/rejection/
  // load test — it is purely additive. The enrolment surfaces are registered in
  // `surfaces` (for teardown + stage-consistency reconciliation) but kept out of
  // the per-flavor pools so only the enrolment drill drives them.
  let enrolment = { enabled: false };
  if (config.enrolmentDrill) {
    try {
      const built = await setupEnrolment(
        appliance,
        {
          runId,
          signer,
          mockInternalUrl: config.mockInternalUrl,
          jwtStrategyId,
          apiKeyAgentId: config.apiKeyAgentId,
          listenAddress,
          pathPrefix,
        },
        rng,
      );
      enrolment = built.context;
      for (const desc of built.surfaceDescriptors) surfaces.push(desc);
      info(`enrolment ready: ${built.surfaceDescriptors.length} surfaces, provisioning config applied`);
    } catch (e) {
      info(`enrolment setup failed (drill will be skipped): ${e && e.message ? e.message : e}`);
      enrolment = { enabled: false, setupError: e && e.message ? e.message : String(e) };
    }
  }

  // 7. Policy enforcement drill: reusable policy definitions + policy-bound
  // surfaces + a dedicated uncapped caller. Additive; the surfaces are
  // registered for teardown + reconciliation but kept out of the general pools
  // so only this drill drives them.
  let policy = { enabled: false };
  if (config.policyDrill) {
    try {
      policy = await setupPolicy(appliance, ctx, members, teams);
      for (const desc of policy.surfaceDescriptors) surfaces.push(desc);
    } catch (e) {
      info(`policy drill setup failed (drill will be skipped): ${e && e.message ? e.message : e}`);
      policy = { enabled: false, setupError: e && e.message ? e.message : String(e) };
    }
  }

  return {
    jwtStrategyId,
    signer,
    apiKeyHolderId: apiKeyHolder.id,
    surfaces,
    teams,
    members,
    callableMembers,
    loadMembers,
    capDrill,
    moderatedSurfaces,
    enrolment,
    policy,
  };
}

module.exports = { setup };
