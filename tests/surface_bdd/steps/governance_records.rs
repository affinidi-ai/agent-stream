use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then, when};

#[given(expr = "governance recording is enabled with body capture for LLM Surface {string}")]
async fn governance_recording_is_enabled_with_body_capture(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    configure_governance_recording(world, &surface_name, true, true).await;
}

#[given(expr = "governance recording is enabled without body capture for LLM Surface {string}")]
async fn governance_recording_is_enabled_without_body_capture(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    configure_governance_recording(world, &surface_name, false, true).await;
}

#[given(expr = "governance recording includes streamed interactions for LLM Surface {string}")]
async fn governance_recording_includes_streamed_interactions(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    configure_governance_recording(world, &surface_name, true, true).await;
}

#[given(expr = "the caller has completed chat prompt {string} through LLM Surface {string}")]
async fn caller_has_completed_chat_prompt(
    world: &mut SurfaceWorld,
    prompt: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    send_chat_prompt(world, &route, &prompt).await;
    assert_caller_success(world, "governance-recorded request");
    world.expected_governance_records += 1;
}

#[given(expr = "the caller has been rejected after sending chat prompt {string} to LLM Surface {string}")]
async fn caller_has_been_rejected_after_sending_chat_prompt(
    world: &mut SurfaceWorld,
    prompt: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    send_chat_prompt(world, &route, &prompt).await;
    let response = caller_response(world);
    assert_eq!(response.status, 403, "expected Prompt Guard rejection, got {}: {}", response.status, response.text);
    assert_eq!(response.body["error"]["type"], "prompt_guard_violation");
    world.expected_governance_records += 1;
}

#[given(expr = "the caller has completed streamed chat prompt {string} through LLM Surface {string}")]
async fn caller_has_completed_streamed_chat_prompt(
    world: &mut SurfaceWorld,
    prompt: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    send_streaming_chat_prompt(world, &route, &prompt).await;
    let response = caller_response(world);
    assert_eq!(
        response.status, 200,
        "expected streamed governance-recorded request to succeed, got {}: {}",
        response.status, response.text
    );
    assert!(
        response
            .text
            .contains("chat.completion.chunk"),
        "expected an event stream, got {}",
        response.text
    );
    world.expected_governance_records += 1;
}

#[given(expr = "the caller has completed a chat interaction through LLM Surface {string}")]
async fn caller_has_completed_chat_interaction(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    send_chat_completion_to_surface(world, &surface_name).await;
    assert_caller_success(world, "unrecorded request");
}

#[when(expr = "the operator reviews the latest governance record for LLM Surface {string}")]
async fn operator_reviews_latest_governance_record(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let surface_id = surface_id(&surface_name);
    world.admin_response = Some(poll_governance_records(world, &surface_id, world.expected_governance_records).await);
}

#[when(expr = "the operator verifies the governance record chain for LLM Surface {string}")]
async fn operator_verifies_governance_record_chain(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let surface_id = surface_id(&surface_name);
    world.admin_response =
        Some(poll_governance_verification(world, &surface_id, world.expected_governance_records).await);
}

#[when(expr = "the operator lists LLM Surfaces with governance records")]
async fn operator_lists_llm_surfaces_with_governance_records(world: &mut SurfaceWorld) {
    world.admin_response = Some(
        world
            .admin_client()
            .get_admin_json("/v1/governance/surfaces")
            .await,
    );
}

#[then(expr = "the governance record request succeeds")]
async fn governance_record_request_succeeds(world: &mut SurfaceWorld) {
    assert_admin_response_status(world, 200, "governance record request");
    assert!(!governance_records(world).is_empty(), "expected at least one governance record");
}

#[then(expr = "the latest governance record reports a successful interaction")]
async fn latest_governance_record_reports_success(world: &mut SurfaceWorld) {
    let record = latest_record(world);
    let stages = record["stages"]
        .as_array()
        .expect("governance record should include stages");
    assert!(
        stages
            .iter()
            .any(|stage| stage["stage"] == "llm_call" && stage["outcome"] == "observed"),
        "expected a completed LLM call stage, got {record}"
    );
    assert!(
        stages
            .iter()
            .all(|stage| stage["outcome"] != "block" && stage["outcome"] != "error"),
        "successful interaction should not contain blocked or failed stages: {record}"
    );
}

#[then(expr = "the latest governance record contains prompt {string}")]
async fn latest_governance_record_contains_prompt(
    world: &mut SurfaceWorld,
    prompt: String,
) {
    assert_eq!(latest_record(world)["prompt"], format!("user: {prompt}"));
}

#[then(expr = "the latest governance record contains completion {string}")]
async fn latest_governance_record_contains_completion(
    world: &mut SurfaceWorld,
    completion: String,
) {
    assert_eq!(latest_record(world)["completion"], completion);
}

#[then(expr = "the latest governance record is signed by the appliance")]
async fn latest_governance_record_is_signed_by_appliance(world: &mut SurfaceWorld) {
    let stored = latest_stored_record(world);
    let signed_vc = &stored["signed_vc"];
    let issuer = signed_vc["issuer"]
        .as_str()
        .expect("signed governance credential should identify its issuer");
    assert!(issuer.starts_with("did:"), "expected appliance DID issuer, got {issuer:?}");
    assert!(
        signed_vc["type"]
            .as_array()
            .is_some_and(|types| types
                .iter()
                .any(|value| value == "AIGovernanceRecordCredential")),
        "expected governance credential type, got {signed_vc}"
    );
    assert!(signed_vc["proof"].is_object(), "expected signed credential proof, got {signed_vc}");
    let subject = &signed_vc["credentialSubject"];
    assert_eq!(
        subject["record_id"], stored["record"]["record_id"],
        "signed credential should identify the returned record"
    );
    assert_eq!(
        subject["content_hash"], stored["record"]["content_hash"],
        "signed credential should attest the returned record hash"
    );
}

#[then(expr = "governance chain verification succeeds")]
async fn governance_chain_verification_succeeds(world: &mut SurfaceWorld) {
    assert_admin_response_status(world, 200, "governance chain verification");
    assert_eq!(admin_response(world).body["valid"], true, "expected valid governance chain");
}

#[then(expr = "the governance record chain contains {int} records")]
async fn governance_record_chain_contains_records(
    world: &mut SurfaceWorld,
    expected_count: u64,
) {
    assert_eq!(
        admin_response(world).body["count"],
        expected_count,
        "unexpected governance record count: {}",
        admin_response(world).text
    );
}

#[then(expr = "the latest governance record reports a Prompt Guard blocked interaction")]
async fn latest_governance_record_reports_prompt_guard_block(world: &mut SurfaceWorld) {
    let record = latest_record(world);
    let stages = record["stages"]
        .as_array()
        .expect("governance record should include stages");
    assert!(
        stages
            .iter()
            .any(|stage| stage["stage"] == "regex_request" && stage["outcome"] == "block"),
        "expected blocked request Prompt Guard stage, got {record}"
    );
    assert!(record["completion"].is_null(), "blocked interaction should not contain a completion: {record}");
}

#[then(expr = "the latest governance record contains blocked prompt {string}")]
async fn latest_governance_record_contains_blocked_prompt(
    world: &mut SurfaceWorld,
    prompt: String,
) {
    assert_eq!(latest_record(world)["prompt"], format!("user: {prompt}"));
}

#[then(expr = "the latest governance record contains a prompt digest")]
async fn latest_governance_record_contains_prompt_digest(world: &mut SurfaceWorld) {
    let call = latest_llm_call(world);
    assert_sha256_digest(&call["request_digest"], "prompt");
}

#[then(expr = "the latest governance record contains a completion digest")]
async fn latest_governance_record_contains_completion_digest(world: &mut SurfaceWorld) {
    let call = latest_llm_call(world);
    assert_sha256_digest(&call["response_digest"], "completion");
}

#[then(expr = "the latest governance record does not retain prompt {string}")]
async fn latest_governance_record_does_not_retain_prompt(
    world: &mut SurfaceWorld,
    prompt: String,
) {
    let stored = latest_stored_record(world);
    assert!(stored["record"]["prompt"].is_null(), "prompt body should be omitted: {stored}");
    assert!(
        !stored
            .to_string()
            .contains(&prompt),
        "prompt body should not appear in the stored record"
    );
}

#[then(expr = "the latest governance record does not retain completion {string}")]
async fn latest_governance_record_does_not_retain_completion(
    world: &mut SurfaceWorld,
    completion: String,
) {
    let stored = latest_stored_record(world);
    assert!(stored["record"]["completion"].is_null(), "completion body should be omitted: {stored}");
    assert!(
        !stored
            .to_string()
            .contains(&completion),
        "completion body should not appear in the stored record"
    );
}

#[then(expr = "the recorded Surface list request succeeds")]
async fn recorded_surface_list_request_succeeds(world: &mut SurfaceWorld) {
    assert_admin_response_status(world, 200, "recorded Surface list request");
    assert!(
        admin_response(world)
            .body
            .is_array(),
        "expected recorded Surface list"
    );
}

#[then(expr = "LLM Surface {string} is absent from the governance record list")]
async fn llm_surface_is_absent_from_governance_record_list(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let surface_id = surface_id(&surface_name);
    let surfaces = admin_response(world)
        .body
        .as_array()
        .expect("governance Surface response should be an array");
    assert!(
        surfaces
            .iter()
            .all(|surface| surface["surface_id"] != surface_id && surface["surface_name"] != surface_name),
        "LLM Surface {surface_name:?} should not have governance records: {surfaces:?}"
    );
}
