"use strict";

const { info, warn } = require("./log");
const { enrolmentTeardown } = require("./enrolment");

// Tear down everything the run created, in dependency order, while leaving the
// recorded statistics intact: telemetry series are only GC'd for the entities
// we delete, and the appliance-wide `surfaces:all` aggregate is never removed.
// The retained run report (written by main) plus the surviving aggregate are
// the "stats" the user asked to keep.
async function teardown(appliance, world) {
  // 0. Disable member auto-provisioning and drop the enrolment CA trust anchor
  // first, so nothing can be auto-minted while the rest of teardown runs. The
  // enrolled members + ensure-created teams themselves are registered into
  // world.members / world.teams and cleaned up by the generic steps below.
  await enrolmentTeardown(appliance, world);

  // 1. Drop team memberships (member delete is refused while referenced).
  for (const team of world.teams) {
    for (const memberId of team.memberIds) {
      try {
        await appliance.removeTeamMember(team.id, memberId);
      } catch (e) {
        warn(`removeTeamMember ${team.id}/${memberId} failed: ${e}`);
      }
    }
  }

  // 2. Delete members.
  for (const member of world.members) {
    try {
      await appliance.deleteMember(member.id);
    } catch (e) {
      warn(`deleteMember ${member.id} failed: ${e}`);
    }
  }

  // 3. Delete teams.
  for (const team of world.teams) {
    try {
      await appliance.deleteTeam(team.id);
    } catch (e) {
      warn(`deleteTeam ${team.id} failed: ${e}`);
    }
  }

  // 4. Delete surfaces.
  for (const surface of world.surfaces) {
    try {
      await appliance.deletePipe(surface.pipeId);
    } catch (e) {
      warn(`deletePipe ${surface.pipeId} failed: ${e}`);
    }
  }

  // The API-key holder goes last: every api-key Surface names it.
  if (world.apiKeyHolderId) {
    try {
      await appliance.deletePipe(world.apiKeyHolderId);
    } catch (e) {
      warn(`deletePipe ${world.apiKeyHolderId} failed: ${e}`);
    }
  }

  // 4b. Delete the policy drill's reusable definitions (the surfaces that
  // referenced them are gone by now). Best-effort: the fail-closed sub-test may
  // have already deleted one (404), and a non-test appliance never created them.
  if (world.policy && Array.isArray(world.policy.defIds)) {
    for (const id of world.policy.defIds) {
      try {
        await appliance.deletePolicyDefinition(id);
      } catch (e) {
        warn(`deletePolicyDefinition ${id} failed: ${e.message || e}`);
      }
    }
  }

  // 5. Safety net: bulk-delete any test surface this run missed (e.g. one that
  // never made it into `world.surfaces` because setup crashed partway).
  // Best-effort — the bulk endpoint is debug/test-mode only.
  try {
    const cleaned = await appliance.deleteTestSurfaces();
    if (cleaned && cleaned.deleted) info(`bulk-removed ${cleaned.deleted} stray test surface(s)`);
  } catch (e) {
    warn(`bulk test-surface cleanup failed: ${e.message}`);
  }

  info("teardown complete (statistics retained)");
}

module.exports = { teardown };
