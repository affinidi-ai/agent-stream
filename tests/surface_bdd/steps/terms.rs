use cucumber::{given, then, when};
use serde_json::{Value, json};
use std::time::Duration;

use super::support::{create_access_token, latest_client, login_human_user};
use crate::bdd_support::admin_client::AdminClient;
use crate::world::SurfaceWorld;

async fn accept_current_terms(client: &AdminClient) {
    let response = client
        .accept_current_terms()
        .await;
    assert_eq!(response.status, 200, "Terms acceptance should succeed: {}", response.text);
}

async fn save_customer_draft(
    client: &AdminClient,
    version: &str,
    url: &str,
    requires_reconsent: bool,
) {
    let response = client
        .put_admin_json(
            "/v1/terms/customer/draft",
            json!({
                "version": version,
                "title": format!("Customer Terms {version}"),
                "url": url,
                "requires_reconsent": requires_reconsent,
            }),
        )
        .await;
    assert_eq!(response.status, 200, "Customer Terms draft should be saved: {}", response.text);
}

async fn publish_customer_terms(client: &AdminClient) -> crate::bdd_support::admin_client::RecordedResponse {
    client
        .post_admin_json("/v1/terms/customer/publish", Value::Null)
        .await
}

async fn accepted_customer_terms(
    world: &mut SurfaceWorld,
    username: &str,
    version: &str,
) -> AdminClient {
    let client = login_human_user(world, username, "administrator").await;
    accept_current_terms(&client).await;
    save_customer_draft(&client, version, &format!("https://example.com/terms/{version}"), true).await;
    let publication = publish_customer_terms(&client).await;
    assert_eq!(publication.status, 201, "Customer Terms version should publish: {}", publication.text);
    accept_current_terms(&client).await;
    client
}

async fn publish_customer_terms_version(
    world: &mut SurfaceWorld,
    username: &str,
    version: &str,
) {
    let client = latest_client(world, username);
    save_customer_draft(&client, version, &format!("https://example.com/terms/{version}"), true).await;
    let publication = publish_customer_terms(&client).await;
    assert_eq!(publication.status, 201, "Customer Terms version should publish: {}", publication.text);
}

async fn create_management_token(
    world: &mut SurfaceWorld,
    name: &str,
    username: &str,
) {
    let client = if world
        .human_clients
        .contains_key(username)
    {
        latest_client(world, username)
    } else {
        login_human_user(world, username, "administrator").await
    };
    let status = client
        .get_admin_json("/v1/terms/status")
        .await;
    let was_pending = status.body["consent_required"]
        .as_bool()
        .unwrap_or(false);
    if was_pending {
        accept_current_terms(&client).await;
    }
    let token = create_access_token(&client, name, &["settings.view"]).await;
    world
        .management_tokens
        .insert(name.to_string(), token);

    if was_pending {
        save_customer_draft(&client, "pat-reconsent", "https://example.com/terms/pat-reconsent", true).await;
        let publication = publish_customer_terms(&client).await;
        assert_eq!(publication.status, 201, "replacement Customer Terms should publish: {}", publication.text);
    }
}

#[given("Terms consent is enabled")]
fn terms_consent_is_enabled(world: &mut SurfaceWorld) {
    world.terms_enabled = true;
    world.affinidi_cache_seeded = true;
}

#[given(expr = "Affinidi Terms version {string} is current")]
fn affinidi_terms_version_is_current(
    world: &mut SurfaceWorld,
    version: String,
) {
    world.affinidi_terms_manifest["version_id"] = json!(format!("affinidi:{version}"));
    world.affinidi_terms_manifest["version"] = json!(version);
}

#[given(expr = "Affinidi Terms version {string} was received from Affinidi Well")]
fn affinidi_terms_version_was_received(
    world: &mut SurfaceWorld,
    version: String,
) {
    world.affinidi_terms_manifest["version_id"] = json!(format!("affinidi:{version}"));
    world.affinidi_terms_manifest["version"] = json!(version);
    world.affinidi_cache_seeded = true;
}

#[given("Affinidi Well is unavailable before the appliance has received metadata")]
fn affinidi_well_is_unavailable_before_first_fetch(world: &mut SurfaceWorld) {
    world.affinidi_cache_seeded = false;
    world.affinidi_well_available = false;
}

#[given("Affinidi Well is unavailable")]
async fn affinidi_well_is_unavailable(world: &mut SurfaceWorld) {
    world.affinidi_well_available = false;
    if let Some(well) = world.affinidi_well.as_ref() {
        let request_count = well.request_count().await;
        well.set_available(false)
            .await;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if well.request_count().await > request_count {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the appliance should retry Affinidi Well");
    }
}

#[given(expr = "administrator {string} accepted all applicable Terms")]
async fn administrator_accepted_all_terms(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = login_human_user(world, &username, "administrator").await;
    accept_current_terms(&client).await;
}

#[given(expr = "human user {string} accepted Affinidi Terms version {string}")]
async fn human_user_accepted_affinidi_terms(
    world: &mut SurfaceWorld,
    username: String,
    version: String,
) {
    world.affinidi_terms_manifest["version_id"] = json!(format!("affinidi:{version}"));
    world.affinidi_terms_manifest["version"] = json!(version);
    let client = login_human_user(world, &username, "administrator").await;
    accept_current_terms(&client).await;
}

#[given(expr = "Affinidi Well publishes version {string} requiring re-consent")]
async fn affinidi_well_publishes_version(
    world: &mut SurfaceWorld,
    version: String,
) {
    let next_sequence = world.affinidi_terms_manifest["publication_sequence"]
        .as_u64()
        .expect("publication sequence should be numeric")
        + 1;
    world.affinidi_terms_manifest["publication_sequence"] = json!(next_sequence);
    world.affinidi_terms_manifest["version_id"] = json!(format!("affinidi:{version}"));
    world.affinidi_terms_manifest["version"] = json!(version);
    world.affinidi_terms_manifest["requires_reconsent"] = json!(true);
    world
        .affinidi_well
        .as_ref()
        .expect("Affinidi Well should be running")
        .set_metadata(
            world
                .affinidi_terms_manifest
                .clone(),
        )
        .await;
}

async fn wait_for_affinidi_well_request(
    world: &SurfaceWorld,
    previous_request_count: usize,
) {
    let well = world
        .affinidi_well
        .as_ref()
        .expect("Affinidi Well should be running");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if well.request_count().await > previous_request_count {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the appliance should refresh Affinidi Terms metadata");
}

#[given("the appliance has refreshed Affinidi Terms metadata")]
async fn appliance_refreshed_affinidi_terms(world: &mut SurfaceWorld) {
    let appliance = &world
        .infra
        .as_ref()
        .expect("scenario infrastructure should exist")
        ._appliance;
    let expected_version = world.affinidi_terms_manifest["version"].clone();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut observed = Value::Null;
    while tokio::time::Instant::now() < deadline {
        let response = reqwest::get(format!("{}/v1/terms/applicable", appliance.base_url()))
            .await
            .expect("applicable Terms request should complete");
        let status = response.status();
        let body = response
            .text()
            .await
            .expect("applicable Terms response should be readable");
        observed = json!({ "status": status.as_u16(), "body": body });
        if status.is_success() {
            let body = serde_json::from_str::<Value>(&body).expect("applicable Terms should be JSON");
            if body["terms"]
                .as_array()
                .is_some_and(|terms| {
                    terms
                        .iter()
                        .any(|term| term["version"] == expected_version)
                })
            {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let request_count = world
        .affinidi_well
        .as_ref()
        .expect("Affinidi Well should be running")
        .request_count()
        .await;
    panic!(
        "the appliance did not refresh Affinidi Terms after {request_count} Well requests; last response: {observed}"
    );
}

#[given("Affinidi Well serves an invalid publication")]
async fn affinidi_well_serves_invalid_publication(world: &mut SurfaceWorld) {
    let well = world
        .affinidi_well
        .as_ref()
        .expect("Affinidi Well should be running");
    let request_count = well.request_count().await;
    let mut invalid = world
        .affinidi_terms_manifest
        .clone();
    invalid["schema_version"] = json!(999);
    well.set_metadata(invalid)
        .await;
    wait_for_affinidi_well_request(world, request_count).await;
}

#[given("Affinidi Well serves a rollback publication")]
async fn affinidi_well_serves_rollback_publication(world: &mut SurfaceWorld) {
    let well = world
        .affinidi_well
        .as_ref()
        .expect("Affinidi Well should be running");
    let request_count = well.request_count().await;
    let mut rollback = world
        .affinidi_terms_manifest
        .clone();
    rollback["publication_sequence"] = json!(1);
    rollback["version_id"] = json!("affinidi:3.2");
    rollback["version"] = json!("3.2");
    well.set_metadata(rollback)
        .await;
    wait_for_affinidi_well_request(world, request_count).await;
}

#[when("the caller requests Affinidi Terms provider health")]
async fn caller_requests_affinidi_terms_provider_health(world: &mut SurfaceWorld) {
    world.ensure_operator().await;
    let appliance = &world
        .infra
        .as_ref()
        .expect("scenario infrastructure should exist")
        ._appliance;
    let response = reqwest::get(format!("{}/v1/terms/provider-health", appliance.base_url()))
        .await
        .expect("provider health request should complete");
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect();
    let text = response
        .text()
        .await
        .expect("provider health response should be readable");
    let body = serde_json::from_str(&text).expect("provider health response should be JSON");
    world.caller_response = Some(crate::bdd_support::admin_client::RecordedResponse { status, body, text, headers });
}

#[then("the Affinidi Terms provider health state is unavailable")]
fn affinidi_terms_provider_health_is_unavailable(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("provider health response should exist");
    assert_eq!(response.body["state"], "unavailable");
}

#[when(expr = "human user {string} signs in")]
async fn human_user_signs_in(
    world: &mut SurfaceWorld,
    username: String,
) {
    login_human_user(world, &username, "administrator").await;
}

#[then("authentication succeeds")]
fn authentication_succeeds(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("authentication response should exist");
    assert_eq!(response.status, 200, "expected successful authentication, got {}", response.text);
}

#[then(expr = "a consent-pending session is issued to human user {string}")]
fn consent_pending_session_is_issued(
    world: &mut SurfaceWorld,
    username: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("authentication response should exist");
    assert_eq!(response.body["username"], username);
    assert_eq!(response.body["consent_required"], true);
}

#[given(expr = "administrator {string} has a consent-pending session")]
async fn administrator_has_consent_pending_session(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = login_human_user(world, &username, "administrator").await;
    world
        .human_clients
        .entry(format!("administrator:{username}"))
        .or_default()
        .push(client);
}

#[given(expr = "administrator {string} loaded the applicable Terms")]
async fn administrator_loaded_applicable_terms(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = latest_client(world, &username);
    let status = client
        .get_admin_json("/v1/terms/status")
        .await;
    let accepted_terms = status.body["required_terms"]
        .as_array()
        .expect("required_terms should be an array")
        .iter()
        .map(|term| {
            json!({
                "terms_type": term["terms_type"],
                "version_id": term["version_id"],
                "accepted": true,
            })
        })
        .collect::<Vec<_>>();
    world.terms_submission = Some(json!({ "accepted_terms": accepted_terms }));
}

#[when(expr = "administrator {string} submits the previously loaded Terms")]
async fn administrator_submits_previously_loaded_terms(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = latest_client(world, &username);
    world.caller_response = Some(
        client
            .post_admin_json(
                "/v1/terms/acceptances",
                world
                    .terms_submission
                    .clone()
                    .expect("loaded Terms should be stored"),
            )
            .await,
    );
}

#[then("the acceptance is rejected as stale")]
fn acceptance_is_rejected_as_stale(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("Terms acceptance response should exist");
    assert_eq!(response.body["code"], "TERMS_VERSION_STALE");
}

#[when(expr = "administrator {string} requests a protected Admin API resource")]
async fn administrator_requests_protected_resource(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = world
        .human_clients
        .get(&format!("administrator:{username}"))
        .and_then(|clients| clients.last())
        .expect("administrator should have a client")
        .clone();
    world.caller_response = Some(
        client
            .get_admin_json("/v1/settings")
            .await,
    );
}

#[then("the request is rejected because Terms acceptance is required")]
fn request_is_rejected_for_terms(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("request response should exist");
    assert_eq!(response.body["code"], "TERMS_ACCEPTANCE_REQUIRED");
}

#[given(expr = "human user {string} has two consent-pending sessions")]
async fn human_user_has_two_pending_sessions(
    world: &mut SurfaceWorld,
    username: String,
) {
    login_human_user(world, &username, "administrator").await;
    login_human_user(world, &username, "administrator").await;
}

#[given("one session has accepted all applicable Terms")]
async fn one_session_accepts_terms(world: &mut SurfaceWorld) {
    let client = world
        .human_clients
        .values()
        .next()
        .and_then(|clients| clients.first())
        .expect("a pending human session should exist")
        .clone();
    accept_current_terms(&client).await;
}

#[when("the other session requests a protected product resource")]
async fn other_session_requests_product_resource(world: &mut SurfaceWorld) {
    let client = world
        .human_clients
        .values()
        .next()
        .and_then(|clients| clients.get(1))
        .expect("a second human session should exist")
        .clone();
    world.caller_response = Some(
        client
            .get_admin_json("/v1/settings")
            .await,
    );
}

#[when(expr = "administrator {string} requests the T&C Manager data")]
async fn administrator_requests_terms_manager_data(
    world: &mut SurfaceWorld,
    username: String,
) {
    world.caller_response = Some(
        latest_client(world, &username)
            .get_admin_json("/v1/terms")
            .await,
    );
}

#[then("the Affinidi Terms provider status is degraded")]
fn affinidi_provider_status_is_degraded(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("T&C Manager response should exist");
    assert_eq!(response.body["affinidi_provider"]["state"], "degraded");
}

#[then(expr = "Affinidi Terms version {string} remains active")]
fn affinidi_terms_version_remains_active(
    world: &mut SurfaceWorld,
    version: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("T&C Manager response should exist");
    assert_eq!(response.body["affinidi"]["version"], version);
}

#[then("the request succeeds")]
fn request_succeeds(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("request response should exist");
    assert_eq!(response.status, 200, "expected status 200, got {}: {}", response.status, response.text);
}

#[when(expr = "human user {string} signs in and requests Terms status")]
async fn human_user_signs_in_and_requests_terms_status(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = login_human_user(world, &username, "administrator").await;
    world.caller_response = Some(
        client
            .get_admin_json("/v1/terms/status")
            .await,
    );
}

#[then("only Affinidi Terms require acceptance")]
fn only_affinidi_terms_require_acceptance(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("Terms status response should exist");
    assert_eq!(response.status, 200, "Terms status should succeed: {}", response.text);
    let required = response.body["required_terms"]
        .as_array()
        .expect("required_terms should be an array");
    assert_eq!(required.len(), 1);
    assert_eq!(required[0]["terms_type"], "affinidi");
}

#[given(expr = "human user {string} accepted Customer Terms version {string}")]
async fn human_user_accepted_customer_terms(
    world: &mut SurfaceWorld,
    username: String,
    version: String,
) {
    accepted_customer_terms(world, &username, &version).await;
}

#[given(expr = "current Customer Terms version {string} requires re-consent")]
async fn current_customer_terms_requires_reconsent(
    world: &mut SurfaceWorld,
    version: String,
) {
    let username = world
        .human_clients
        .keys()
        .find(|name| !name.starts_with("administrator:"))
        .expect("an accepted human user should exist")
        .clone();
    publish_customer_terms_version(world, &username, &version).await;
}

#[given(expr = "human user {string} has an unrestricted session after accepting Customer Terms version {string}")]
async fn human_user_has_unrestricted_session(
    world: &mut SurfaceWorld,
    username: String,
    version: String,
) {
    accepted_customer_terms(world, &username, &version).await;
}

#[when(expr = "human user {string} requests a protected product resource with the active session")]
async fn human_user_requests_with_active_session(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = latest_client(world, &username);
    world.caller_response = Some(
        client
            .get_admin_json("/v1/settings")
            .await,
    );
}

#[then("authentication fails because Terms status is unavailable")]
fn authentication_fails_for_terms_status(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("authentication response should exist");
    assert_eq!(response.status, 503);
    assert_eq!(response.body["code"], "TERMS_OPERATIONAL_FAILURE");
}

#[then("no authenticated session is issued")]
fn no_authenticated_session_is_issued(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("authentication response should exist");
    assert!(
        response
            .body
            .get("session_token")
            .is_none()
    );
}

#[given(expr = "administrator {string} has saved Customer Terms draft version {string} at {string}")]
async fn administrator_saved_customer_terms_draft(
    world: &mut SurfaceWorld,
    username: String,
    version: String,
    url: String,
) {
    let client = login_human_user(world, &username, "administrator").await;
    accept_current_terms(&client).await;
    save_customer_draft(&client, &version, &url, true).await;
}

#[when(expr = "administrator {string} publishes the Customer Terms draft")]
async fn administrator_publishes_customer_terms(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = latest_client(world, &username);
    world.admin_response = Some(publish_customer_terms(&client).await);
}

#[then(expr = "Customer Terms version {string} is published")]
fn customer_terms_version_is_published(
    world: &mut SurfaceWorld,
    version: String,
) {
    let response = world
        .admin_response
        .as_ref()
        .expect("publication response should exist");
    assert_eq!(response.status, 201, "publication should succeed: {}", response.text);
    assert_eq!(response.body["version"], version);
}

#[then("the published Customer Terms have an immutable version ID")]
fn published_customer_terms_have_version_id(world: &mut SurfaceWorld) {
    let version_id = world
        .admin_response
        .as_ref()
        .and_then(|response| response.body["version_id"].as_str())
        .unwrap_or_default();
    assert!(!version_id.is_empty(), "published Customer Terms should have a version ID");
}

#[given(expr = "human user {string} lacks permission to edit Customer Terms")]
async fn human_user_lacks_terms_edit_permission(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = login_human_user(world, &username, "user").await;
    accept_current_terms(&client).await;
}

#[given("a Customer Terms draft is ready to publish")]
async fn customer_terms_draft_is_ready(world: &mut SurfaceWorld) {
    let client = login_human_user(world, "terms-admin", "administrator").await;
    accept_current_terms(&client).await;
    save_customer_draft(&client, "1", "https://example.com/terms/1", true).await;
}

#[when(expr = "human user {string} attempts to publish the Customer Terms draft")]
async fn human_user_attempts_to_publish(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = latest_client(world, &username);
    world.caller_response = Some(publish_customer_terms(&client).await);
}

#[then("publication is forbidden")]
fn publication_is_forbidden(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("publication response should exist");
    assert_eq!(response.status, 403, "expected forbidden publication, got {}", response.text);
}

#[given(expr = "approved human user {string} has not accepted all applicable Terms")]
async fn approved_human_user_has_not_accepted_terms(
    world: &mut SurfaceWorld,
    username: String,
) {
    login_human_user(world, &username, "administrator").await;
}

#[given(expr = "approved human user {string} has accepted all applicable Terms")]
async fn approved_human_user_has_accepted_terms(
    world: &mut SurfaceWorld,
    username: String,
) {
    let client = login_human_user(world, &username, "administrator").await;
    accept_current_terms(&client).await;
}

#[given(expr = "management access token {string} is owned by human user {string}")]
async fn management_token_owned_by_human(
    world: &mut SurfaceWorld,
    token_name: String,
    username: String,
) {
    create_management_token(world, &token_name, &username).await;
}

#[when(expr = "management access token {string} requests a protected Admin API resource")]
async fn management_token_requests_protected_resource(
    world: &mut SurfaceWorld,
    token_name: String,
) {
    let token = world
        .management_tokens
        .get(&token_name)
        .expect("management access token should exist")
        .clone();
    let client = world
        .human_clients
        .values()
        .next()
        .and_then(|clients| clients.last())
        .expect("an HTTP client should exist")
        .clone();
    world.caller_response = Some(
        client
            .get_admin_json_with_bearer("/v1/settings", &token)
            .await,
    );
}

#[when(expr = "management access token {string} requests an allowed Admin API resource")]
async fn management_token_requests_allowed_resource(
    world: &mut SurfaceWorld,
    token_name: String,
) {
    management_token_requests_protected_resource(world, token_name).await;
}

#[then(expr = "the response status is {int}")]
fn response_status_is(
    world: &mut SurfaceWorld,
    expected: u16,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("response should exist");
    assert_eq!(response.status, expected, "unexpected response: {}", response.text);
}
