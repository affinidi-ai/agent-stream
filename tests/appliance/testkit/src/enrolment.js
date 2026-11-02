"use strict";

// Member auto-provisioning (enrolment) drill.
//
// Exercises the appliance's first-sight member provisioning across all three
// VERIFIED identity kinds — JWT claims, API key, and mTLS client certificate —
// and then drives real, priced LLM traffic through the newly-enrolled members so
// their spend/tokens reconcile against the local ledger exactly like the rest of
// the population.
//
// Setup (once, in setup.js): generate novel per-run identities, build a
// throwaway CA + client cert (openssl), upload the CA, create three
// auto-provisioning surfaces, and PUT the appliance provisioning config.
//
// Phase (each round, from simulate.js): preview the rules (write-free), present
// each novel identity so a member is minted on first sight, assert the member +
// its identifiers + its team memberships (fixed + templated `ensure_team`), then
// drive N priced calls per enrolled member and record them. A round-1 guardrail
// sub-scenario asserts `max_auto_provisioned_members` refuses a further mint.
//
// mTLS presentation uses the forwarded-client-cert path over plain HTTP, so the
// appliance must trust the runner as a forwarded proxy (see
// tests/appliance/config/managed.config.toml [tls.client_auth]). When mTLS cannot be exercised the
// run FAILS unless ENROLMENT_MTLS=optional downgrades it to a logged skip.

const { config } = require("./config");
const { info, warn } = require("./log");
const { makeMtlsPki, opensslAvailable } = require("./identities");
const { buildPipe } = require("./surfaces");
const { spinner, isStopRequested } = require("./progress");

// The appliance's built-in anonymous member/team an unrecognised (or
// provisioning-refused) verified caller falls back to. Kept in lockstep with
// src/members/types.rs / src/teams/types.rs.
const ANON_MEMBER = "anonymous";
const ANON_TEAM = "anonymous";

// Normalise an identifier value the way the appliance does (trim + lowercase),
// so a runner-side lookup matches the store's identifier index.
function norm(v) {
  return String(v == null ? "" : v)
    .trim()
    .toLowerCase();
}

// The concrete value carried by a stored MemberIdentifier of any kind.
function identifierValue(id) {
  if (!id) return "";
  return String(id.email || id.subject || id.key_name || id.value || "").trim();
}

// Find the (single) member carrying an identifier equal to `value`, tolerating
// the legacy singular `identifier` field alongside the `identifiers` array.
async function findMemberByIdentifier(appliance, value) {
  const want = norm(value);
  const members = (await appliance.listMembers()) || [];
  return members.find((m) => {
    const ids = Array.isArray(m.identifiers) ? m.identifiers.slice() : [];
    if (m.identifier) ids.push(m.identifier);
    return ids.some((id) => norm(identifierValue(id)) === want);
  });
}

// The team ids (slugs) a member currently belongs to.
async function teamsForMember(appliance, memberId) {
  const teams = (await appliance.listTeams()) || [];
  return teams.filter((t) => Array.isArray(t.members) && t.members.includes(memberId)).map((t) => t.id);
}

// The appliance-level provisioning config for a run. Rules cover every verified
// source; team rules assign a shared "enrolled" team to everyone, an
// "engineering" team to JWT callers in that group, and a per-tenant team
// created on demand from a claim. Team ids are PER-RUN slugs so a tombstoned
// team from a prior run can never poison `ensure_team` on a later run.
function buildProvisioningConfig(runId, opts) {
  const enrolled = `tk-enrolled-${runId}`;
  const eng = `tk-eng-${runId}`;
  return {
    enabled: true,
    identifier_rules: [
      { source: { type: "jwt_subject" }, as_kind: "subject" },
      { source: { type: "jwt_claim", claim: "email" }, as_kind: "email" },
      { source: { type: "mtls_subject_cn" }, as_kind: "custom" },
      { source: { type: "mtls_email_san" }, as_kind: "email" },
      { source: { type: "api_key_name" }, as_kind: "api_key" },
    ],
    name_claim: "name",
    member_defaults: {}, // uncapped — enrolled members must be load-safe
    team_rules: [
      { team_id_template: enrolled, ensure_team: true, team_name_template: `Enrolled ${runId}` },
      {
        when: { type: "claim_contains", claim: "groups", contains: opts.group },
        team_id_template: eng,
        ensure_team: true,
        team_name_template: `Engineering ${runId}`,
      },
      {
        when: { type: "claim_present", claim: "tid" },
        team_id_template: "tenant-{{claim.tid}}",
        ensure_team: true,
        team_name_template: "Tenant {{claim.tid}}",
      },
    ],
    max_auto_provisioned_members: 100000,
    creations_per_minute: 100000,
  };
}

// Build a surface descriptor (the shape simulate.js's executeOnce + reconcile
// expect) from buildPipe's returned metadata.
function surfaceDescriptor(built) {
  return {
    key: built.pipeId,
    pipeId: built.pipeId,
    route: built.route,
    identity: built.identity,
    model: built.model,
    hasJudge: false,
    jurors: 0,
    moderated: false,
  };
}

// One-time enrolment setup: novel identities, mTLS PKI + CA upload, surfaces,
// and the appliance provisioning config. Returns the enrolment context (stored
// on `world.enrolment`) plus the surface descriptors to register in
// `world.surfaces`. Never throws — on a hard problem it returns a context whose
// per-kind checks fail loudly during the phase.
async function setupEnrolment(appliance, ctx, rng) {
  const runId = ctx.runId;
  const group = "engineering";
  const tenantTid = `testkitco-${runId}`;
  const teamSlugs = {
    enrolled: `tk-enrolled-${runId}`,
    eng: `tk-eng-${runId}`,
    tenant: `tenant-${tenantTid}`.toLowerCase(),
  };

  // ── Novel per-run identities (unknown to the member store) ─────────────────
  const jwtSubject = `enrol-jwt-${runId}`;
  const jwtNovel = {
    flavor: "jwt",
    signer: ctx.signer,
    cred: {
      subject: jwtSubject,
      claims: {
        email: `${jwtSubject}@testkit.local`,
        name: `Enrol JWT ${runId}`,
        groups: [group],
        tid: tenantTid,
      },
    },
  };

  const apiKeyRec = await appliance.createApiKey(ctx.apiKeyAgentId, `enrol-key-${runId}`);
  const apikeyNovel = {
    flavor: "apikey",
    cred: { keyId: apiKeyRec.key_id, secret: apiKeyRec.secret },
  };

  // The guardrail sub-scenario needs its own novel (API-key) identity so it can
  // be refused without disturbing the three primary enrolments.
  const guardRec = await appliance.createApiKey(ctx.apiKeyAgentId, `enrol-guard-${runId}`);
  const guardNovel = {
    flavor: "apikey",
    cred: { keyId: guardRec.key_id, secret: guardRec.secret },
  };

  // ── mTLS PKI + CA trust anchor (optional) ─────────────────────────────────
  let mtlsAvailable = false;
  let mtlsSkipReason = null;
  let mtlsNovel = null;
  let caCertId = null;
  let mtlsSurface = null;

  if (!opensslAvailable()) {
    mtlsSkipReason =
      "openssl CLI not found on the runner — cannot generate the mTLS client certificate. " +
      "Install openssl (the managed docker runner does this automatically) or set ENROLMENT_MTLS=optional.";
  } else {
    try {
      const cn = `enrol-mtls-${runId}`;
      const email = `${cn}@testkit.local`;
      const pki = makeMtlsPki({ cn, email });
      const caCert = await appliance.createCertificate({
        name: `testkit-enrol-ca-${runId}`,
        description: "Throwaway CA for testkit mTLS enrolment drill.",
        kind: "ca",
        certificate_pem: pki.caPem,
      });
      caCertId = caCert.id;
      mtlsNovel = {
        flavor: "mtls",
        cred: { cn, email, clientCertPem: pki.clientCertPem },
      };
      mtlsAvailable = true;
    } catch (e) {
      mtlsSkipReason = `mTLS PKI/CA setup failed: ${e && e.message ? e.message : e}`;
    }
  }

  // ── Auto-provisioning surfaces ────────────────────────────────────────────
  const surfaceDescriptors = [];
  const surfaces = {};
  const mkSurface = async (flavor, extraCtx) => {
    const template = {
      key: `enrol-${flavor}-${runId}`,
      identity: flavor,
      model: "mock-small",
      route: `/tk-enrol-${flavor}-${runId}`,
      autoProvision: true,
    };
    const built = buildPipe(template, {
      mockInternalUrl: ctx.mockInternalUrl,
      jwtStrategyId: ctx.jwtStrategyId,
      apiKeyAgentId: ctx.apiKeyAgentId,
      listenAddress: ctx.listenAddress,
      pathPrefix: ctx.pathPrefix,
      ...extraCtx,
    });
    await appliance.createPipe(built.pipe);
    const desc = surfaceDescriptor(built);
    surfaceDescriptors.push(desc);
    info(`created enrolment surface ${built.pipeId} (${flavor}) on ${built.route}`);
    return desc;
  };

  surfaces.jwt = await mkSurface("jwt");
  surfaces.apikey = await mkSurface("apikey");
  if (mtlsAvailable) {
    mtlsSurface = await mkSurface("mtls", { enrolCaCertId: caCertId });
    surfaces.mtls = mtlsSurface;
  }

  // ── Provisioning config ───────────────────────────────────────────────────
  const provisioningConfig = buildProvisioningConfig(runId, { group });
  await appliance.setProvisioningConfig(provisioningConfig);
  info(
    `enrolment configured: provisioning enabled, ${mtlsAvailable ? "mTLS armed" : `mTLS unavailable (${mtlsSkipReason})`}`,
  );

  return {
    context: {
      enabled: true,
      runId,
      group,
      tenantTid,
      teamSlugs,
      surfaces,
      caCertId,
      mtlsAvailable,
      mtlsSkipReason,
      provisioningConfig,
      novel: { jwt: jwtNovel, apikey: apikeyNovel, mtls: mtlsNovel, guard: guardNovel },
      // Provisioned members/teams discovered during the phase, for teardown.
      registered: false,
    },
    surfaceDescriptors,
  };
}

// Register a freshly-enrolled member (and its ensure-created teams) into the
// shared world arrays so the existing teardown removes them. Idempotent across
// rounds (the same identity resolves the same member id every round).
function registerForTeardown(world, memberObj, teamIds) {
  if (!world.members.some((m) => m.id === memberObj.id)) world.members.push(memberObj);
  for (const slug of teamIds) {
    let team = world.teams.find((t) => t.id === slug);
    if (!team) {
      team = { id: slug, name: slug, memberIds: [], enrolment: true };
      world.teams.push(team);
    }
    if (!team.memberIds.includes(memberObj.id)) team.memberIds.push(memberObj.id);
  }
}

// Assert + record one identity kind: preview, first-sight provisioning, member +
// identifier + team assertions, idempotency, and N priced accrual calls.
async function runEnrolmentKind(deps, appliance, world, ledger, pricer, rng, roundIdx, stats, enr, kd, sp) {
  const rec = {
    kind: kd.kind,
    provisioned: false,
    memberId: null,
    identifiers: [],
    teamIds: [],
    expectedTeams: kd.expectedTeams,
    calls: 0,
    previewOk: false,
    idempotentOk: false,
    skipped: false,
    pass: true,
    reason: null,
  };
  const fail = (reason) => {
    rec.pass = false;
    rec.reason = reason;
    stats.enrolmentFailures.push({ kind: kd.kind, reason });
  };

  // 1. Preview (write-free) — the rules must resolve to a provisioned member.
  try {
    const preview = await appliance.previewProvisioning(kd.preview);
    const idValues = (preview.identifiers || []).map((i) => norm(i.value));
    const teamIds = (preview.teams || []).map((t) => t.team_id);
    const identifiersOk = kd.expectedIdentifiers.every((v) => idValues.includes(norm(v)));
    const teamsOk = kd.expectedTeams.every((slug) => teamIds.includes(slug));
    rec.previewOk = !!preview.would_provision && identifiersOk && teamsOk;
    if (!rec.previewOk) {
      fail(
        `preview mismatch (would_provision=${preview.would_provision}, identifiers=${JSON.stringify(idValues)}, teams=${JSON.stringify(teamIds)}, reason=${preview.reason || "n/a"})`,
      );
    }
  } catch (e) {
    fail(`preview request failed: ${e && e.message ? e.message : e}`);
  }

  // 2. First-sight provisioning call.
  const idValue = kd.idValue;
  const existedBefore = !!(await findMemberByIdentifier(appliance, idValue));
  const first = await deps.executeOnce(appliance, pricer, kd.novel, kd.surface, { roundIdx, rng });
  if (first.status !== 200) {
    const diag =
      kd.kind === "mtls"
        ? `mTLS enrolment call returned ${first.status} (expected 200). The appliance likely does not trust the runner as a forwarded-cert proxy — set [tls.client_auth].trusted_proxies + forwarded_header.format="url_encoded_pem" in its config (the managed testkit config does this), or set ENROLMENT_MTLS=optional to skip.`
        : `enrolment call returned ${first.status} (expected 200)${first.body ? `: ${first.body}` : ""}`;
    if (!kd.mandatory) {
      rec.skipped = true;
      rec.pass = true;
      info(`enrolment ${kd.kind}: skipped (${diag})`);
      return rec;
    }
    fail(diag);
    return rec;
  }
  rec.calls += 1;

  // 3. Discover the (possibly freshly-minted) member + its teams.
  const member = await findMemberByIdentifier(appliance, idValue);
  if (!member) {
    fail("provisioning call succeeded but no member could be found for the identity");
    return rec;
  }
  rec.provisioned = true;
  rec.memberId = member.id;
  rec.identifiers = (member.identifiers || []).map(identifierValue).filter(Boolean);
  if (!existedBefore && roundIdx === 1 && member.auto_provisioned !== true) {
    fail("newly-created member is not flagged auto_provisioned");
  }
  for (const want of kd.expectedIdentifiers) {
    if (!rec.identifiers.some((v) => norm(v) === norm(want))) {
      fail(`member is missing expected identifier '${want}' (has ${JSON.stringify(rec.identifiers)})`);
    }
  }
  const teamIds = await teamsForMember(appliance, member.id);
  rec.teamIds = teamIds;
  for (const slug of kd.expectedTeams) {
    if (!teamIds.includes(slug)) {
      fail(`member is missing expected team '${slug}' (has ${JSON.stringify(teamIds)})`);
    }
  }

  // Register for teardown, and pin the resolved id/teams onto the novel member
  // so accrual calls (and any later round) attribute correctly.
  const memberObj = {
    id: member.id,
    flavor: kd.novel.flavor,
    signer: kd.novel.signer,
    cred: kd.novel.cred,
    teamIds,
    enrolment: true,
  };
  registerForTeardown(world, memberObj, teamIds);

  // 4. Record the first call's spend, then drive N-1 accrual calls.
  deps.recordExecution(ledger, {
    surfaceId: kd.surface.pipeId,
    memberId: member.id,
    teamIds,
    grand: first.grand,
    llm: first.llm,
  });
  for (let i = 1; i < config.enrolmentCalls; i += 1) {
    if (isStopRequested()) break;
    const r = await deps.executeOnce(appliance, pricer, memberObj, kd.surface, { roundIdx, rng });
    if (r.status === 200) {
      deps.recordExecution(ledger, {
        surfaceId: kd.surface.pipeId,
        memberId: member.id,
        teamIds,
        grand: r.grand,
        llm: r.llm,
      });
      rec.calls += 1;
    } else {
      fail(`accrual call ${i} returned ${r.status} (expected 200 — member should now resolve)`);
      break;
    }
    if (sp) sp.set({ kind: kd.kind, calls: rec.calls, member: member.id.slice(0, 8) });
  }

  // 5. Idempotency: the identity must map to exactly ONE member.
  const members = (await appliance.listMembers()) || [];
  const matches = members.filter((m) => {
    const ids = Array.isArray(m.identifiers) ? m.identifiers.slice() : [];
    if (m.identifier) ids.push(m.identifier);
    return ids.some((id) => norm(identifierValue(id)) === norm(idValue));
  });
  rec.idempotentOk = matches.length === 1;
  if (!rec.idempotentOk) fail(`expected exactly one member for the identity, found ${matches.length}`);

  return rec;
}

// Round-1 guardrail: cap `max_auto_provisioned_members` at the current count and
// assert a further novel identity is REFUSED (falls back to anonymous, no new
// member). The refused call still attributes usage to the anonymous member/team,
// so it is recorded to keep reconciliation exact. Restores the config always.
async function runGuardrail(deps, appliance, ledger, pricer, rng, roundIdx, stats, enr) {
  const out = { ran: true, pass: true, reason: null };
  let autoCount;
  try {
    const members = (await appliance.listMembers()) || [];
    autoCount = members.filter((m) => m.auto_provisioned && m.status !== "deleted").length;
  } catch (e) {
    out.ran = false;
    out.reason = `could not list members: ${e && e.message ? e.message : e}`;
    return out;
  }

  const capped = { ...enr.provisioningConfig, max_auto_provisioned_members: autoCount };
  const guard = enr.novel.guard;
  try {
    await appliance.setProvisioningConfig(capped);
    const before = await findMemberByIdentifier(appliance, guard.cred.keyId);
    const r = await deps.executeOnce(appliance, pricer, guard, enr.surfaces.apikey, { roundIdx, rng });
    if (r.status === 200) {
      // Provisioning refused ⇒ attributed to the anonymous member/team.
      deps.recordExecution(ledger, {
        surfaceId: enr.surfaces.apikey.pipeId,
        memberId: ANON_MEMBER,
        teamIds: [ANON_TEAM],
        grand: r.grand,
        llm: r.llm,
      });
    }
    const after = await findMemberByIdentifier(appliance, guard.cred.keyId);
    if (after && !before) {
      out.pass = false;
      out.reason = "guardrail breached: a member was provisioned despite max_auto_provisioned_members";
      stats.enrolmentFailures.push({ kind: "guardrail", reason: out.reason });
    }
  } catch (e) {
    out.ran = false;
    out.reason = `guardrail scenario errored: ${e && e.message ? e.message : e}`;
  } finally {
    try {
      await appliance.setProvisioningConfig(enr.provisioningConfig);
    } catch (e) {
      warn(`restoring provisioning config after guardrail failed: ${e && e.message ? e.message : e}`);
    }
  }
  return out;
}

// The enrolment phase, invoked once per round from simulate.js. `deps` carries
// the shared { executeOnce, recordExecution } so we never duplicate the
// nonce/pricing plumbing (and avoids a require cycle with simulate.js).
async function enrolmentPhase(deps, appliance, world, ledger, pricer, rng, roundIdx, stats) {
  const enr = world.enrolment;
  const out = { enabled: false, sent: 0, kinds: [], guardrail: null, mtls: null, pass: true };
  if (!enr || !enr.enabled) return out;
  out.enabled = true;
  out.mtls = { available: enr.mtlsAvailable, skipReason: enr.mtlsSkipReason };

  // mTLS mandatory-when-run policy: openssl/PKI unavailable is a hard failure
  // unless explicitly downgraded to optional.
  if (!enr.mtlsAvailable) {
    if (config.enrolmentMtlsOptional) {
      info(`enrolment: mTLS skipped (${enr.mtlsSkipReason})`);
    } else {
      stats.enrolmentFailures.push({ kind: "mtls", reason: enr.mtlsSkipReason });
      out.pass = false;
    }
  }

  const kinds = [
    {
      kind: "jwt",
      surface: enr.surfaces.jwt,
      novel: enr.novel.jwt,
      idValue: enr.novel.jwt.cred.subject,
      expectedIdentifiers: [enr.novel.jwt.cred.subject, enr.novel.jwt.cred.claims.email],
      expectedTeams: [enr.teamSlugs.enrolled, enr.teamSlugs.eng, enr.teamSlugs.tenant],
      preview: { type: "jwt", subject: enr.novel.jwt.cred.subject, claims: enr.novel.jwt.cred.claims },
      mandatory: true,
    },
    {
      kind: "apikey",
      surface: enr.surfaces.apikey,
      novel: enr.novel.apikey,
      idValue: enr.novel.apikey.cred.keyId,
      expectedIdentifiers: [enr.novel.apikey.cred.keyId],
      expectedTeams: [enr.teamSlugs.enrolled],
      preview: { type: "api_key", key_name: enr.novel.apikey.cred.keyId },
      mandatory: true,
    },
  ];
  if (enr.mtlsAvailable) {
    kinds.push({
      kind: "mtls",
      surface: enr.surfaces.mtls,
      novel: enr.novel.mtls,
      idValue: enr.novel.mtls.cred.cn,
      expectedIdentifiers: [enr.novel.mtls.cred.cn, enr.novel.mtls.cred.email],
      expectedTeams: [enr.teamSlugs.enrolled],
      preview: {
        type: "mtls",
        subject_dn: `CN=${enr.novel.mtls.cred.cn}`,
        sans: { email: [enr.novel.mtls.cred.email] },
      },
      mandatory: !config.enrolmentMtlsOptional,
    });
  }

  const sp = spinner("enrolment drill");
  for (const kd of kinds) {
    if (isStopRequested()) break;
    const rec = await runEnrolmentKind(deps, appliance, world, ledger, pricer, rng, roundIdx, stats, enr, kd, sp);
    if (!rec.pass) out.pass = false;
    out.sent += rec.calls;
    out.kinds.push(rec);
  }
  enr.registered = true;

  if (config.enrolmentGuardrail && roundIdx === 1 && !isStopRequested()) {
    out.guardrail = await runGuardrail(deps, appliance, ledger, pricer, rng, roundIdx, stats, enr);
    if (out.guardrail && out.guardrail.ran && !out.guardrail.pass) out.pass = false;
  }
  sp.stop();

  info(
    `enrolment drill: ${out.kinds.filter((k) => k.pass && !k.skipped).length}/${out.kinds.length} kinds provisioned` +
      `${out.kinds.some((k) => k.skipped) ? ` (${out.kinds.filter((k) => k.skipped).length} skipped)` : ""}` +
      `; guardrail=${out.guardrail ? (out.guardrail.pass ? "pass" : "FAIL") : "n/a"}`,
  );
  return out;
}

// Enrolment-specific teardown: drop the CA trust anchor and disable the
// appliance provisioning config so a leftover run can't keep minting members.
// The provisioned members + ensure-created teams are cleaned up by the generic
// teardown (they were registered into world.members / world.teams).
async function enrolmentTeardown(appliance, world) {
  const enr = world.enrolment;
  if (!enr || !enr.enabled) return;
  try {
    await appliance.setProvisioningConfig({ enabled: false, identifier_rules: [] });
  } catch (e) {
    warn(`disabling provisioning config failed: ${e && e.message ? e.message : e}`);
  }
  if (enr.caCertId) {
    try {
      await appliance.deleteCertificate(enr.caCertId);
    } catch (e) {
      warn(`deleting enrolment CA cert failed: ${e && e.message ? e.message : e}`);
    }
  }
}

module.exports = { setupEnrolment, enrolmentPhase, enrolmentTeardown };
