use crate::bdd_support::admin_client::RecordedResponse;
use crate::world::SurfaceWorld;
use serde_json::{Value, json};
use std::time::Duration;

use super::update_surface;

const GOVERNANCE_POLL_ATTEMPTS: usize = 50;
const GOVERNANCE_POLL_INTERVAL: Duration = Duration::from_millis(100);

pub(crate) async fn configure_governance_recording(
    world: &mut SurfaceWorld,
    surface_name: &str,
    capture_bodies: bool,
    include_streaming: bool,
) {
    update_surface(
        world,
        surface_name,
        |pipe| {
            pipe["governance_recording"] = json!({
                "enabled": true,
                "capture_bodies": capture_bodies,
                "include_streaming": include_streaming,
                "retention_days": 0
            });
        },
        "governance recording",
    )
    .await;
}

pub(crate) async fn poll_governance_records(
    world: &SurfaceWorld,
    surface_id: &str,
    expected_count: usize,
) -> RecordedResponse {
    let path = format!("/v1/governance/records?surface_id={surface_id}");
    let minimum = expected_count.max(1);
    let mut response = world
        .admin_client()
        .get_admin_json(&path)
        .await;
    for _ in 0..GOVERNANCE_POLL_ATTEMPTS {
        if response.status != 200
            || response
                .body
                .as_array()
                .is_some_and(|records| records.len() >= minimum)
        {
            return response;
        }
        tokio::time::sleep(GOVERNANCE_POLL_INTERVAL).await;
        response = world
            .admin_client()
            .get_admin_json(&path)
            .await;
    }
    response
}

pub(crate) async fn poll_governance_verification(
    world: &SurfaceWorld,
    surface_id: &str,
    expected_count: usize,
) -> RecordedResponse {
    let path = format!("/v1/governance/verify?surface_id={surface_id}");
    let mut response = world
        .admin_client()
        .get_admin_json(&path)
        .await;
    for _ in 0..GOVERNANCE_POLL_ATTEMPTS {
        if response.status != 200
            || response.body["count"]
                .as_u64()
                .is_some_and(|count| count >= expected_count as u64)
        {
            return response;
        }
        tokio::time::sleep(GOVERNANCE_POLL_INTERVAL).await;
        response = world
            .admin_client()
            .get_admin_json(&path)
            .await;
    }
    response
}

pub(crate) fn admin_response(world: &SurfaceWorld) -> &RecordedResponse {
    world
        .admin_response
        .as_ref()
        .expect("operator response should be recorded")
}

pub(crate) fn assert_admin_response_status(
    world: &SurfaceWorld,
    expected_status: u16,
    request_name: &str,
) {
    let response = admin_response(world);
    assert_eq!(
        response.status, expected_status,
        "expected {request_name} to return {expected_status}, got {}: {}",
        response.status, response.text
    );
}

pub(crate) fn governance_records(world: &SurfaceWorld) -> &[Value] {
    admin_response(world)
        .body
        .as_array()
        .expect("governance records response should be an array")
}

pub(crate) fn latest_stored_record(world: &SurfaceWorld) -> &Value {
    governance_records(world)
        .last()
        .expect("latest governance record should be available")
}

pub(crate) fn latest_record(world: &SurfaceWorld) -> &Value {
    &latest_stored_record(world)["record"]
}

pub(crate) fn latest_llm_call(world: &SurfaceWorld) -> &Value {
    latest_record(world)["stages"]
        .as_array()
        .and_then(|stages| {
            stages
                .iter()
                .find_map(|stage| stage.get("llm_call"))
                .filter(|call| !call.is_null())
        })
        .expect("governance record should contain an LLM call")
}

pub(crate) fn assert_sha256_digest(
    value: &Value,
    body_name: &str,
) {
    let digest = value
        .as_str()
        .unwrap_or_else(|| panic!("{body_name} digest should be a string, got {value}"));
    assert_eq!(digest.len(), 71, "{body_name} digest should contain a SHA-256 value");
    assert!(digest.starts_with("sha256:"), "unexpected {body_name} digest: {digest}");
}
