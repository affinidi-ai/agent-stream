//! Mode C — realtime voice (governed WebSocket relay).
//!
//! A caller opens a WebSocket to `…/v1/realtime`; the gateway authenticates and
//! authorizes the connection (source auth + OPA, exactly like the chat path),
//! opens a second WebSocket to the surface's upstream provider (OpenAI Realtime),
//! and relays frames both ways. The continuous session is segmented into
//! attestable **turns** (`RealtimeAccumulator`): one committed user input →
//! one assistant response, each written as a signed governance VC on the
//! surface's existing hash chain, with the user audio persisted to the
//! content-addressed multimedia store (hash-only reference in the record).
//!
//! Off by default per surface (`RealtimeConfig`, strict opt-in) and gated on a
//! realtime-capable model. See `docs/MODALITIES.md`.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::FromRequestParts;
use axum::extract::ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade};
use axum::response::{IntoResponse, Response};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message as UpMessage;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tracing::{info, warn};

use crate::pipes::config::PipeConfig;
use crate::pipes::handlers::PipeHandlerState;
use crate::pipes::types::llm_provider_ext::LLMProviderExt;

/// Per-surface realtime-voice opt-in (Mode C). **Off by default.** When absent or
/// disabled the surface refuses a `…/v1/realtime` upgrade.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RealtimeConfig {
    /// Master switch. A surface accepts a realtime upgrade only when this is set.
    #[serde(default)]
    pub enabled: bool,
    /// Accepted input audio container formats (advisory; the provider validates).
    #[serde(default = "default_realtime_formats")]
    pub allowed_formats: Vec<String>,
    /// Hard ceiling on session wall-clock duration, so a stuck socket can't pin
    /// resources. Clamped to a sane band at connection open.
    #[serde(default = "default_max_session_secs")]
    pub max_session_secs: u64,
    /// Optional default voice hint forwarded to the provider session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voice: Option<String>,
    /// Per-turn voice safety (Judge on input + Jury on output). Off by default;
    /// reuses the surface's own `judge`/`jury`. See `realtime_safety`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safety: Option<crate::pipes::realtime_safety::RealtimeSafetyConfig>,
    /// Pre-recorded clip playback: escalating filler during a Gated hold, a
    /// refusal on a blocked turn, and an "on fail" clip on upstream error. Clip
    /// ids reference the shared audio-stream catalog. Off by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_streams: Option<crate::pipes::audio_streams::RealtimeAudioStreamsConfig>,
}

fn default_realtime_formats() -> Vec<String> {
    vec!["pcm16".to_string()]
}

fn default_max_session_secs() -> u64 {
    600
}

impl Default for RealtimeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_formats: default_realtime_formats(),
            max_session_secs: default_max_session_secs(),
            voice: None,
            safety: None,
            audio_streams: None,
        }
    }
}

/// Upper bound on buffered per-turn user audio (base64) kept for a governance
/// record. Beyond this the turn records the transcript only (audio dropped), so
/// a long turn never balloons memory.
const MAX_TURN_AUDIO_B64: usize = 24 * 1024 * 1024;

/// Front-door entry for a realtime WebSocket. Resolves the surface, enforces the
/// opt-in + capability gate, runs source auth + open-time policy, resolves the
/// upstream, and — only on success — upgrades the connection into the relay.
/// Any failure returns a plain HTTP error (the upgrade never completes).
pub async fn handle_realtime_get(
    state: PipeHandlerState,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, _body) = req.into_parts();

    // Extract the upgrade handshake first; a non-WS request here is a bug (the
    // dispatcher only routes WS upgrades to us), so reject cleanly.
    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(ws) => ws,
        Err(rej) => return rej.into_response(),
    };
    let mut headers = parts.headers.clone();
    let uri = parts.uri.clone();
    let peer_cert = parts
        .extensions
        .get::<crate::source_auth::models::PeerCertInfo>()
        .cloned();
    let path = uri.path().to_string();

    info!(path = %path, "realtime WebSocket upgrade requested");

    // A browser cannot set an `Authorization` header on a WebSocket handshake, so
    // (mirroring OpenAI's own Realtime API) accept the caller token carried in a
    // `Sec-WebSocket-Protocol` subprotocol and promote it to a Bearer header for
    // the normal source-auth path.
    if !headers.contains_key(axum::http::header::AUTHORIZATION)
        && let Some(token) = bearer_from_subprotocols(&headers)
        && let Ok(value) = format!("Bearer {token}").parse()
    {
        headers.insert(axum::http::header::AUTHORIZATION, value);
    }

    // ── Resolve the surface from the path (longest-prefix match, scoped to this
    // listener) — the same resolution the chat/health handlers use.
    let Some((pipe_id, _suffix)) = resolve_surface(&state, &path).await else {
        return reject_and_record(
            ws,
            &state,
            None,
            None,
            "unknown",
            &path,
            "no_surface",
            "No surface configured for this realtime path",
        )
        .await;
    };

    let pipe = match load_pipe(&state, &pipe_id).await {
        Some(p) => p,
        None => {
            return reject_and_record(
                ws,
                &state,
                Some(pipe_id.as_str()),
                None,
                "unknown",
                &path,
                "pipe_not_found",
                "Surface not found",
            )
            .await;
        }
    };
    if !pipe.status.is_enabled() {
        return reject_and_record(
            ws,
            &state,
            Some(pipe_id.as_str()),
            Some(pipe.name.as_str()),
            "unknown",
            &path,
            "pipe_not_available",
            "Surface not available",
        )
        .await;
    }

    // ── Resolve the realtime variant. The WebSocket transport is the routing
    // signal: a `modality: realtime` routing rule selects the surface's
    // realtime-capable variant; absent that, the base/default config is used.
    // Source auth, OPA, upstream, governance, and safety all read the resolved
    // config so a variant's overrides apply to the session. ──
    let realtime_alias = select_realtime_variant(&pipe);
    let resolved = match pipe.resolve_variant(realtime_alias.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            warn!(reason = %e, "[PIPE:{pipe_id}] realtime variant resolution failed");
            return reject_and_record(
                ws,
                &state,
                Some(pipe_id.as_str()),
                Some(pipe.name.as_str()),
                "unknown",
                &path,
                "realtime_variant_unavailable",
                "The realtime variant for this surface is unavailable",
            )
            .await;
        }
    };

    // ── Opt-in + capability gate (strict, like audio). ──
    let realtime_cfg = match resolved
        .realtime
        .as_ref()
        .filter(|r| r.enabled)
    {
        Some(cfg) => cfg.clone(),
        None => {
            return reject_and_record(
                ws,
                &state,
                Some(pipe_id.as_str()),
                Some(pipe.name.as_str()),
                "unknown",
                &path,
                "realtime_not_enabled",
                "This surface does not accept realtime voice sessions",
            )
            .await;
        }
    };
    let crate::pipes::PipeType::LLM { provider, .. } = &resolved.pipe_type else {
        return reject_and_record(
            ws,
            &state,
            Some(pipe_id.as_str()),
            Some(pipe.name.as_str()),
            "unknown",
            &path,
            "realtime_not_supported",
            "Realtime is only available on an LLM Surface",
        )
        .await;
    };
    let provider = provider.as_ref();
    let profile = crate::pipes::executor::resolve_request_profile(provider);
    let model = provider
        .model_name()
        .to_string();
    let dialect = match profile.api_schema.as_str() {
        "openai" => RealtimeDialect::OpenAI,
        "gemini" => RealtimeDialect::Gemini,
        _ => {
            return reject_and_record(
                ws,
                &state,
                Some(pipe_id.as_str()),
                Some(pipe.name.as_str()),
                &model,
                &path,
                "realtime_not_supported",
                "Realtime is supported only on an OpenAI- or Gemini-schema surface",
            )
            .await;
        }
    };
    // Capability is catalog-authoritative (`capabilities.supports_realtime`),
    // falling back to the narrow name-based default.
    if !profile.supports_realtime {
        return reject_and_record(
            ws,
            &state,
            Some(pipe_id.as_str()),
            Some(pipe.name.as_str()),
            &model,
            &path,
            "realtime_not_supported",
            "The target model does not support realtime voice; use a realtime-capable model",
        )
        .await;
    }

    // ── Source auth (same credential the chat path enforces). ──
    let mut caller_identity: Option<crate::source_auth::AuthenticatedIdentity> = None;
    let source_auth = crate::source_auth::source_auth_gate(
        resolved.source_auth.as_ref(),
        state
            .source_auth_middleware
            .as_deref(),
    );
    if let crate::source_auth::SourceAuthGate::Unavailable = source_auth {
        warn!("[PIPE:{pipe_id}] realtime source auth is configured but its middleware is not running - refusing");
        return reject_and_record(
            ws,
            &state,
            Some(pipe_id.as_str()),
            Some(pipe.name.as_str()),
            &model,
            &path,
            "source_authentication_unavailable",
            "Source authentication is unavailable",
        )
        .await;
    }
    if let crate::source_auth::SourceAuthGate::Required(sa, auth_config) = source_auth {
        match sa
            .authenticate(auth_config, &headers, &pipe.name, resolved.tenant_id.as_deref(), peer_cert.as_ref())
            .await
        {
            Ok(id) => caller_identity = Some(id),
            Err(e) => {
                warn!(reason = %e, "[PIPE:{pipe_id}] realtime source auth failed");
                return reject_and_record(
                    ws,
                    &state,
                    Some(pipe_id.as_str()),
                    Some(pipe.name.as_str()),
                    &model,
                    &path,
                    "unauthorized",
                    "Authentication failed",
                )
                .await;
            }
        }
    }

    // ── Open-time policy (appliance-wide global set, then the surface's own). ──
    if let Some(policy_mgr) = &state.pipe_policy_manager
        && !crate::observability::request_context::with_tenant(resolved.tenant_id.as_deref(), || {
            evaluate_open_policy(policy_mgr, &resolved, &pipe_id, &headers, &path, &model, caller_identity.as_ref())
        })
    {
        return reject_and_record(
            ws,
            &state,
            Some(pipe_id.as_str()),
            Some(pipe.name.as_str()),
            &model,
            &path,
            "policy_denied",
            "Realtime session denied by policy",
        )
        .await;
    }

    // ── Team gate: the member's access, per-minute rates and token caps, as on
    // the chat path. The context bills the voice-safety jurors' text usage. ──
    let (call_budget, team) = match crate::teams::team_pre_check(
        resolved
            .team_attribution
            .as_ref(),
        &headers,
        caller_identity.as_ref(),
        &Value::Null,
    )
    .await
    {
        crate::teams::TeamGateDecision::Block { code, .. } => {
            return reject_and_record(
                ws,
                &state,
                Some(pipe_id.as_str()),
                Some(pipe.name.as_str()),
                &model,
                &path,
                code,
                "Realtime session refused by the team gate",
            )
            .await;
        }
        crate::teams::TeamGateDecision::Allow(ctx) => (ctx.call_budget.clone(), Some(ctx)),
        crate::teams::TeamGateDecision::Skip => (None, None),
    };

    // ── Resolve the upstream (endpoint + key). ──
    let secrets = crate::secrets::SurfaceSecrets::new(Some(state.secrets_store.clone()), resolved.tenant_id.clone());
    let secret_id = provider
        .get_api_key()
        .map(str::to_string);
    let (api_key, key_source) = match resolve_secret(&secrets, secret_id.as_deref()).await {
        Some(key) => (key.value, key.source),
        None => {
            return reject_and_record(
                ws,
                &state,
                Some(pipe_id.as_str()),
                Some(pipe.name.as_str()),
                &model,
                &path,
                "no_credential",
                "Upstream credential could not be resolved",
            )
            .await;
        }
    };
    // ── Metering: realtime audio has no price, so while a budget is in
    // scope a session runs only when its key and its voice-safety jurors'
    // keys are the customer's own. ──
    if let Some(unmetered) =
        session_refusal(call_budget.is_some(), key_source, &resolved, &realtime_cfg, &secrets).await
    {
        return reject_and_record(
            ws,
            &state,
            Some(pipe_id.as_str()),
            Some(pipe.name.as_str()),
            &model,
            &path,
            unmetered.code(),
            unmetered.message(),
        )
        .await;
    }
    let upstream_url = match dialect {
        RealtimeDialect::OpenAI => openai_realtime_url(&provider.get_endpoint(), &model),
        RealtimeDialect::Gemini => gemini_live_url(&provider.get_endpoint()),
    };

    let governance_active = crate::governance::is_ready()
        && resolved
            .governance_recording
            .as_ref()
            .map(|g| g.enabled)
            .unwrap_or(false);
    let ctx = SessionCtx {
        surface_id: pipe_id.clone(),
        surface_name: pipe.name.clone(),
        model: model.clone(),
        provider: provider
            .provider_type_str()
            .to_string(),
        key_source,
        dialect,
        voice: realtime_cfg.voice.clone(),
        caller: caller_identity
            .as_ref()
            .map(crate::pipes::handlers::http_handlers::caller_identity_string),
        governance_active,
        policy: resolved
            .governance_recording
            .as_ref()
            .map(|g| g.capture_policy())
            .unwrap_or_default(),
        sink: resolved
            .governance_recording
            .as_ref()
            .and_then(|g| g.export.clone()),
        input_format: realtime_cfg
            .allowed_formats
            .first()
            .cloned()
            .unwrap_or_else(|| "pcm16".to_string()),
        max_session_secs: realtime_cfg
            .max_session_secs
            .clamp(10, 3600),
        metrics_store: state
            .global_metrics_store
            .clone(),
        judge: resolved.judge.clone(),
        jury: resolved.jury.clone(),
        safety: realtime_cfg.safety.clone(),
        audio_streams: realtime_cfg
            .audio_streams
            .clone()
            .unwrap_or_default(),
        secrets,
        request: {
            let mut request = crate::observability::request_context::RequestContext::for_request(&headers);
            request.set_identity(caller_identity.as_ref());
            request.usage.tenant_id = resolved.tenant_id.clone();
            request
        },
        team,
    };

    info!(
        model = %model,
        "[PIPE:{pipe_id}] realtime session authorized — upgrading and relaying to upstream"
    );
    // Echo the `realtime` subprotocol so a browser client (which offered it
    // alongside its token subprotocol) completes the handshake.
    ws.protocols(["realtime"])
        .on_upgrade(move |socket| {
            crate::teams::call_budget::scope(call_budget, run_relay(socket, upstream_url, api_key, ctx))
        })
}

/// Why a realtime session is refused at open, `None` when it may run. While a
/// budget is in scope (`budget_in_scope`), a session whose upstream key, or
/// the key of a juror its voice safety calls (see
/// [`crate::pipes::realtime_safety::RealtimeGuard`]), is a platform key is
/// refused, credit or not: realtime audio has no price, so nothing would bill
/// the session (see [`crate::pipes::metering::Unmetered::Realtime`]). A
/// keyless juror that bills nothing is not counted. Where no budget is in
/// scope a platform session runs, and its jurors' text usage is billed per
/// turn.
async fn session_refusal(
    budget_in_scope: bool,
    key_source: crate::pipes::key_source::KeySource,
    resolved: &crate::pipes::PipeConfig,
    realtime: &RealtimeConfig,
    secrets: &crate::secrets::SurfaceSecrets,
) -> Option<crate::pipes::metering::Unmetered> {
    if !budget_in_scope {
        return None;
    }
    let mut sources = vec![key_source];
    if realtime
        .safety
        .as_ref()
        .is_some_and(|safety| safety.enabled)
    {
        let jurors = resolved
            .jury
            .as_ref()
            .filter(|j| j.enabled)
            .into_iter()
            .flat_map(|j| j.jurors.iter())
            .filter(|j| j.enabled)
            .map(|j| &j.llm);
        for target in jurors {
            if let Some(source) = crate::pipes::judge_jury::target_budget_source(&resolved.id, target, secrets).await {
                sources.push(source);
            }
        }
    }
    sources
        .iter()
        .any(|source| !source.owned())
        .then_some(crate::pipes::metering::Unmetered::Realtime)
}

/// Everything the relay needs after the connection is authorized. Owned +
/// `Send + 'static` so it can move into the upgraded task.
#[derive(Clone)]
struct SessionCtx {
    surface_id: String,
    surface_name: String,
    model: String,
    provider: String,
    /// Source of the upstream key the session relays on.
    key_source: crate::pipes::key_source::KeySource,
    dialect: RealtimeDialect,
    voice: Option<String>,
    caller: Option<String>,
    governance_active: bool,
    policy: crate::governance::CapturePolicy,
    sink: Option<crate::governance::GovernanceExport>,
    input_format: String,
    max_session_secs: u64,
    metrics_store: Arc<crate::metrics::MetricsStore>,
    judge: Option<crate::pipes::judge_jury::JudgeConfig>,
    jury: Option<crate::pipes::judge_jury::JuryConfig>,
    safety: Option<crate::pipes::realtime_safety::RealtimeSafetyConfig>,
    audio_streams: crate::pipes::audio_streams::RealtimeAudioStreamsConfig,
    secrets: crate::secrets::SurfaceSecrets,
    /// Trace id and caller attribution every turn record of the session carries.
    request: crate::observability::request_context::RequestContext,
    /// The member and teams the team gate attributed the session to, which its
    /// voice-safety jurors' text usage is billed to; `None` when no
    /// attribution applies.
    team: Option<crate::teams::gate::TeamUsageContext>,
}

/// Frame size (bytes) for chunking a pre-recorded clip into realtime
/// `response.audio.delta` events. 16 KiB of PCM16 @ 24 kHz ≈ 340 ms per frame.
const REALTIME_CLIP_FRAME_BYTES: usize = 16 * 1024;

/// The split write half of the caller WebSocket, shared by the upstream→client
/// relay loop and the filler task.
type ClientSink = futures::stream::SplitSink<WebSocket, AxumMessage>;

/// Control messages for the filler task.
enum FillerCmd {
    /// A Gated hold began — start escalating filler clips from now.
    Start,
    /// The hold ended (reply released or blocked) — stop starting new clips.
    Stop,
}

/// Turn a clip into realtime `response.audio.delta` events (base64 PCM chunks).
fn clip_audio_events(clip: &crate::pipes::audio_streams::AudioStreamClip) -> Vec<Value> {
    clip.base64_frames(REALTIME_CLIP_FRAME_BYTES)
        .into_iter()
        .map(|b64| json!({ "type": "response.audio.delta", "delta": b64 }))
        .collect()
}

/// Resolve the next round-robin clip from `clips` and return its audio events.
/// Empty when nothing is configured or the id isn't in the store.
fn round_robin_clip_events(
    store: &Option<Arc<crate::pipes::audio_streams::AudioStreamStore>>,
    clips: &[String],
    counter: &mut usize,
) -> Vec<Value> {
    let Some(store) = store.as_ref() else {
        return Vec::new();
    };
    let Some(id) = crate::pipes::audio_streams::next_round_robin(clips, counter) else {
        return Vec::new();
    };
    store
        .clip(id)
        .map(|clip| clip_audio_events(&clip))
        .unwrap_or_default()
}

/// Resolve the next filler clip and return both its events and playback duration.
fn round_robin_clip_events_with_duration(
    store: &Option<Arc<crate::pipes::audio_streams::AudioStreamStore>>,
    clips: &[String],
    counter: &mut usize,
) -> (Vec<Value>, u64) {
    let Some(store) = store.as_ref() else {
        return (Vec::new(), 0);
    };
    let Some(id) = crate::pipes::audio_streams::next_round_robin(clips, counter) else {
        return (Vec::new(), 0);
    };
    store
        .clip(id)
        .map(|clip| (clip_audio_events(&clip), clip.duration_ms()))
        .unwrap_or_default()
}

/// Whether an OpenAI-canonical event is model reply content (audio or its
/// transcript) — the signal that a Gated turn has begun holding a reply.
/// Upstream events that mark the caller's turn as finished and the model as now
/// working (LLM latency + generation + any Gated vet). Starting the filler and
/// the "on it" signal here — the moment the caller stops speaking — fills the
/// wait instead of a long silence before the first reply token. Covers both the
/// OpenAI shapes (`speech_stopped` / `committed` / `response.created`) and the
/// translated Gemini one (`input_audio_transcription.completed`, emitted at the
/// first model turn).
fn is_turn_start(ev_type: &str) -> bool {
    matches!(
        ev_type,
        "input_audio_buffer.speech_stopped"
            | "input_audio_buffer.committed"
            | "response.created"
            | "conversation.item.input_audio_transcription.completed"
    )
}

/// Send OpenAI-canonical events to the caller through the shared sink. Returns
/// `false` if the socket errored (the caller should stop relaying).
async fn send_client_events(
    sink: &Arc<Mutex<ClientSink>>,
    events: &[Value],
) -> bool {
    let mut guard = sink.lock().await;
    for ev in events {
        if guard
            .send(AxumMessage::Text(ev.to_string().into()))
            .await
            .is_err()
        {
            return false;
        }
    }
    true
}

/// Spawn the filler streamer. On `Start` it streams escalating tiers of
/// pre-recorded clips (round-robin) to the caller by elapsed time until `Stop`,
/// so a Gated safety hold is filled with "one moment…" audio instead of dead
/// air. A no-op when no clips are configured or the store is absent (it just
/// drains commands so the sender never errors).
fn spawn_filler_task(
    sink: Arc<Mutex<ClientSink>>,
    tiers: Vec<crate::pipes::audio_streams::AudioStreamTier>,
    guard_band_ms: u64,
    release_not_before: Arc<Mutex<Option<tokio::time::Instant>>>,
    mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<FillerCmd>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let store = crate::pipes::audio_streams::global_audio_stream_store();
        let has_clips = store.is_some()
            && tiers
                .iter()
                .any(|t| !t.clips.is_empty());
        if !has_clips {
            while cmd_rx.recv().await.is_some() {}
            return;
        }
        let mut rr = vec![0usize; tiers.len()];
        while let Some(cmd) = cmd_rx.recv().await {
            if !matches!(cmd, FillerCmd::Start) {
                continue;
            }
            let hold_start = std::time::Instant::now();
            *release_not_before
                .lock()
                .await = None;
            let mut tier_idx = 0usize;
            let mut ticker = tokio::time::interval(Duration::from_millis(150));
            ticker.tick().await; // consume the immediate first tick
            'hold: loop {
                tokio::select! {
                    cmd = cmd_rx.recv() => match cmd {
                        Some(FillerCmd::Stop) | None => break 'hold,
                        Some(FillerCmd::Start) => tier_idx = 0,
                    },
                    _ = ticker.tick() => {
                        let elapsed = hold_start.elapsed().as_millis() as u64;
                        while tier_idx < tiers.len() && elapsed >= tiers[tier_idx].after_ms {
                            let (events, duration_ms) = round_robin_clip_events_with_duration(
                                &store,
                                &tiers[tier_idx].clips,
                                &mut rr[tier_idx],
                            );
                            tier_idx += 1;
                            if !events.is_empty() && !send_client_events(&sink, &events).await {
                                return;
                            }
                            if !events.is_empty() {
                                *release_not_before.lock().await = Some(
                                    tokio::time::Instant::now()
                                        + Duration::from_millis(duration_ms.saturating_add(guard_band_ms)),
                                );
                            }
                        }
                    }
                }
            }
        }
    })
}

/// Connect to the upstream provider and pump frames both ways until either side
/// closes or the session deadline elapses, segmenting turns for governance.
async fn run_relay(
    client: WebSocket,
    upstream_url: String,
    api_key: String,
    ctx: SessionCtx,
) {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let started = std::time::Instant::now();
    let mut request = match upstream_url
        .as_str()
        .into_client_request()
    {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "[PIPE:{}] realtime upstream request build failed", ctx.surface_id);
            record_session(&ctx, crate::metrics::ConnectionStatus::Failed, started).await;
            close_client_with_error(client, "realtime upstream endpoint is invalid").await;
            return;
        }
    };
    let (auth_name, auth_value) = match realtime_auth_header(ctx.dialect, &api_key) {
        Ok(header) => header,
        Err(e) => {
            warn!(error = %e, "[PIPE:{}] realtime provider key is not a valid header value", ctx.surface_id);
            record_session(&ctx, crate::metrics::ConnectionStatus::Failed, started).await;
            close_client_with_error(client, UPSTREAM_CONNECT_FAILED).await;
            return;
        }
    };
    let headers = request.headers_mut();
    headers.insert(auth_name, auth_value);
    if ctx.dialect == RealtimeDialect::OpenAI {
        headers.insert("OpenAI-Beta", HeaderValue::from_static("realtime=v1"));
    }

    let upstream = match connect_realtime_upstream(request, &upstream_url).await {
        Ok((stream, _resp)) => stream,
        Err(e) => {
            warn!(error = %e, "[PIPE:{}] realtime upstream connect failed", ctx.surface_id);
            record_session(&ctx, crate::metrics::ConnectionStatus::Failed, started).await;
            close_client_with_error(client, UPSTREAM_CONNECT_FAILED).await;
            return;
        }
    };
    info!(provider = %ctx.provider, "[PIPE:{}] realtime upstream connected — relaying", ctx.surface_id);

    let acc = Arc::new(Mutex::new(RealtimeAccumulator::new(
        ctx.policy.bodies.keeps_any() && ctx.governance_active,
        MAX_TURN_AUDIO_B64,
        ctx.input_format.clone(),
    )));

    let (client_tx, mut client_rx) = client.split();
    let (mut up_tx, mut up_rx) = upstream.split();

    // Shared client sink so the relay loop and the filler task can both write to
    // the caller (the filler streams "one moment…" clips during a Gated hold).
    let sink = Arc::new(Mutex::new(client_tx));
    let (filler_cmd_tx, filler_cmd_rx) = tokio::sync::mpsc::unbounded_channel::<FillerCmd>();
    let release_not_before = Arc::new(Mutex::new(None));
    let filler_task = spawn_filler_task(
        sink.clone(),
        ctx.audio_streams
            .filler_tiers
            .clone(),
        ctx.audio_streams
            .filler_guard_band_ms,
        release_not_before.clone(),
        filler_cmd_rx,
    );

    let dialect = ctx.dialect;
    let model_c = ctx.model.clone();
    let voice_c = ctx.voice.clone();
    let acc_c = acc.clone();
    let sid_client = ctx.surface_id.clone();
    let client_to_upstream = async move {
        // Gemini requires its `setup` frame first, so hold audio until it is sent.
        let mut setup_sent = false;
        let mut first_audio_logged = false;
        let mut pending: Vec<UpMessage> = Vec::new();
        'client: while let Some(Ok(msg)) = client_rx.next().await {
            match msg {
                AxumMessage::Text(t) => {
                    let ev: Option<Value> = serde_json::from_str(t.as_str()).ok();
                    if let Some(ev) = &ev {
                        acc_c.lock().await.feed(ev);
                    }
                    match dialect {
                        RealtimeDialect::OpenAI => {
                            if up_tx
                                .send(UpMessage::Text(t.as_str().into()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        RealtimeDialect::Gemini => {
                            let Some(ev) = ev else { continue };
                            for g in client_event_to_gemini(&ev, &model_c, voice_c.as_deref()) {
                                let is_setup = g.get("setup").is_some();
                                let frame = UpMessage::Text(g.to_string().into());
                                if is_setup {
                                    if up_tx
                                        .send(frame)
                                        .await
                                        .is_err()
                                    {
                                        break 'client;
                                    }
                                    setup_sent = true;
                                    info!("[PIPE:{}] realtime gemini setup sent to upstream", sid_client);
                                    for p in std::mem::take(&mut pending) {
                                        if up_tx.send(p).await.is_err() {
                                            break 'client;
                                        }
                                    }
                                } else if setup_sent {
                                    if !first_audio_logged {
                                        first_audio_logged = true;
                                        info!("[PIPE:{}] realtime forwarding audio to gemini", sid_client);
                                    }
                                    if up_tx
                                        .send(frame)
                                        .await
                                        .is_err()
                                    {
                                        break 'client;
                                    }
                                } else if pending.len() < 512 {
                                    pending.push(frame);
                                }
                            }
                        }
                    }
                }
                AxumMessage::Close(frame) => {
                    match frame {
                        Some(f) => {
                            info!(code = f.code, reason = %f.reason, "[PIPE:{}] realtime client closed the socket", sid_client)
                        }
                        None => info!("[PIPE:{}] realtime client closed the socket (no reason)", sid_client),
                    }
                    break;
                }
                other => {
                    if let Some(m) = axum_to_upstream(other)
                        && up_tx.send(m).await.is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = up_tx.close().await;
    };

    let acc_u = acc;
    let ctx_u = ctx.clone();
    let upstream_to_client = async move {
        let mut gemini_state = GeminiTurnState::default();
        let mut up_frames_logged = 0u32;
        // Per-turn voice safety (Judge on input, Jury on output). None when the
        // surface hasn't opted in, so the relay stays a plain passthrough.
        let mut guard = crate::pipes::realtime_safety::RealtimeGuard::new(
            &ctx_u.surface_id,
            ctx_u.safety.as_ref(),
            ctx_u.judge.as_ref(),
            ctx_u.jury.as_ref(),
            ctx_u.secrets.clone(),
        );
        // Pre-recorded clip playback: filler during a Gated hold, a refusal on a
        // block, an "on fail" clip on upstream error. The store is resolved once.
        let store = crate::pipes::audio_streams::global_audio_stream_store();
        let gated_filler = guard.is_some()
            && ctx_u
                .safety
                .as_ref()
                .map(|s| s.mode == crate::pipes::realtime_safety::RealtimeSafetyMode::Gated)
                .unwrap_or(false)
            && !ctx_u
                .audio_streams
                .filler_tiers
                .is_empty();
        let mut hold_open = false;
        let mut on_fail_rr = 0usize;
        let mut refusal_rr: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        'upstream: loop {
            let msg = match up_rx.next().await {
                Some(Ok(m)) => m,
                Some(Err(e)) => {
                    warn!(error = %e, "[PIPE:{}] realtime upstream stream error", ctx_u.surface_id);
                    let _ = filler_cmd_tx.send(FillerCmd::Stop);
                    let on_fail = round_robin_clip_events(&store, &ctx_u.audio_streams.on_fail, &mut on_fail_rr);
                    let _ = send_client_events(&sink, &on_fail).await;
                    let _ = send_client_events(
                        &sink,
                        &[json!({ "type": "error", "error": { "message": format!("realtime upstream error: {e}") } })],
                    )
                    .await;
                    break;
                }
                None => {
                    info!("[PIPE:{}] realtime upstream stream ended without a close frame", ctx_u.surface_id);
                    break;
                }
            };
            if up_frames_logged < 25 {
                up_frames_logged += 1;
                if let Some(j) = upstream_json(&msg) {
                    info!(
                        "[PIPE:{}] realtime upstream frame #{}: {}",
                        ctx_u.surface_id,
                        up_frames_logged,
                        redact_realtime_frame(&j)
                    );
                }
            }
            if let Some(reason) = upstream_close_reason(&msg) {
                warn!(reason = %reason, "[PIPE:{}] realtime upstream closed", ctx_u.surface_id);
                let _ = filler_cmd_tx.send(FillerCmd::Stop);
                let on_fail = round_robin_clip_events(&store, &ctx_u.audio_streams.on_fail, &mut on_fail_rr);
                let _ = send_client_events(&sink, &on_fail).await;
                let _ = send_client_events(&sink, &[json!({ "type": "error", "error": { "message": reason } })]).await;
                break;
            }
            // Normalize this upstream frame into zero or more OpenAI-canonical
            // events (OpenAI passes through, Gemini is translated). Non-event
            // frames (ping/pong/binary/non-JSON) are forwarded raw.
            let events: Vec<Value> = match dialect {
                RealtimeDialect::OpenAI => match &msg {
                    UpMessage::Text(t) => match serde_json::from_str::<Value>(t.as_str()) {
                        Ok(ev) => vec![ev],
                        Err(_) => {
                            if let Some(m) = upstream_to_axum(msg)
                                && sink
                                    .lock()
                                    .await
                                    .send(m)
                                    .await
                                    .is_err()
                            {
                                break;
                            }
                            continue;
                        }
                    },
                    _ => {
                        if let Some(m) = upstream_to_axum(msg)
                            && sink
                                .lock()
                                .await
                                .send(m)
                                .await
                                .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                },
                RealtimeDialect::Gemini => match upstream_json(&msg) {
                    Some(gmsg) => {
                        if let Some(err) = gmsg.get("error") {
                            let m = err
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("gemini live error");
                            warn!(error = %m, "[PIPE:{}] realtime upstream error", ctx_u.surface_id);
                            let _ = filler_cmd_tx.send(FillerCmd::Stop);
                            let on_fail =
                                round_robin_clip_events(&store, &ctx_u.audio_streams.on_fail, &mut on_fail_rr);
                            let _ = send_client_events(&sink, &on_fail).await;
                            let _ = send_client_events(&sink, &[json!({ "type": "error", "error": { "message": m } })])
                                .await;
                            break;
                        }
                        gemini_event_to_client(&gmsg, &mut gemini_state)
                    }
                    None => continue,
                },
            };

            for ev in events {
                let ev_type = ev
                    .get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                // Governance sees every event; the safety guard decides what the
                // caller sees. Both resolve the turn at `response.done`.
                let acc_turn = acc_u.lock().await.feed(&ev);

                // From the moment the caller stops speaking the model is
                // working (LLM latency + generation + the Gated vet). Start the
                // escalating filler and signal "on it" *now*, so the wait is
                // filled instead of a long silent freeze before the first reply
                // token. The demo mutes its mic on this signal, so the streamed
                // clips aren't captured and fed back as a new turn.
                if gated_filler && !hold_open && is_turn_start(&ev_type) {
                    let _ = send_client_events(&sink, &[json!({ "type": "output_audio.reviewing" })]).await;
                    let _ = filler_cmd_tx.send(FillerCmd::Start);
                    hold_open = true;
                }

                let (to_send, turn_block) = match guard.as_mut() {
                    Some(g) => {
                        // In Gated mode, tell the caller we're vetting the reply
                        // before the blocking Judge/Jury call, so the hold reads
                        // as "working…" rather than a freeze. Skip it when the
                        // filler path already signalled at turn-start (`hold_open`),
                        // so the caller isn't sent a second `reviewing` event.
                        if !hold_open && let Some(rev) = g.reviewing_event(&ev) {
                            let _ = send_client_events(&sink, std::slice::from_ref(&rev)).await;
                        }
                        let out = g.on_upstream_event(ev).await;
                        bill_jury_usage(ctx_u.team.as_ref(), &out.jury_usage).await;
                        (out.to_client, out.block)
                    }
                    None => (vec![ev], None),
                };

                // The turn resolved — stop filler before the released reply or the
                // refusal is sent, so a queued filler clip finishes but no new one
                // starts (the guard band before the real audio).
                if hold_open && ev_type == "response.done" {
                    let _ = filler_cmd_tx.send(FillerCmd::Stop);
                    hold_open = false;
                    let deadline = *release_not_before
                        .lock()
                        .await;
                    if let Some(deadline) = deadline {
                        let now = tokio::time::Instant::now();
                        if deadline > now {
                            tokio::time::sleep_until(deadline).await;
                        }
                    }
                }

                if let Some(turn) = acc_turn {
                    capture_turn(&ctx_u, turn, turn_block);
                }

                for send_ev in &to_send {
                    if !send_client_events(&sink, std::slice::from_ref(send_ev)).await {
                        break 'upstream;
                    }
                    // On a safety block the guard emits an `output_audio.flush`
                    // carrying the rejection category; stream a round-robin refusal
                    // clip right after it (the flush cleared any queued filler), so
                    // the caller hears a spoken refusal, not just a text one.
                    if send_ev
                        .get("type")
                        .and_then(|t| t.as_str())
                        == Some("output_audio.flush")
                        && send_ev
                            .get("reason")
                            .and_then(|r| r.as_str())
                            == Some("safety")
                    {
                        let category = send_ev
                            .get("category")
                            .and_then(|c| c.as_str());
                        let clips = ctx_u
                            .audio_streams
                            .refusal_clips(category);
                        let counter = refusal_rr
                            .entry(
                                category
                                    .unwrap_or("default")
                                    .to_string(),
                            )
                            .or_insert(0);
                        let refusal = round_robin_clip_events(&store, clips, counter);
                        if !refusal.is_empty() && !send_client_events(&sink, &refusal).await {
                            break 'upstream;
                        }
                    }
                }
            }
        }
        let _ = filler_cmd_tx.send(FillerCmd::Stop);
        let _ = sink
            .lock()
            .await
            .close()
            .await;
    };

    let deadline = tokio::time::sleep(Duration::from_secs(ctx.max_session_secs));
    tokio::select! {
        _ = client_to_upstream => info!("[PIPE:{}] realtime session ended: client leg closed first", ctx.surface_id),
        _ = upstream_to_client => info!("[PIPE:{}] realtime session ended: upstream leg closed first", ctx.surface_id),
        _ = deadline => info!("[PIPE:{}] realtime session reached max duration", ctx.surface_id),
    }
    filler_task.abort();
    let duration_ms = started.elapsed().as_millis() as u64;
    info!(provider = %ctx.provider, duration_ms, "[PIPE:{}] realtime session ended", ctx.surface_id);
    record_session(&ctx, crate::metrics::ConnectionStatus::Success, started).await;
}

const UPSTREAM_CONNECT_FAILED: &str = "realtime upstream connection failed — check the model and provider key";

/// The provider credential header for the upstream handshake, marked sensitive
/// so it is never rendered in debug output. OpenAI takes a bearer token, Gemini
/// Live an `x-goog-api-key` header.
fn realtime_auth_header(
    dialect: RealtimeDialect,
    api_key: &str,
) -> Result<(&'static str, HeaderValue), tokio_tungstenite::tungstenite::http::header::InvalidHeaderValue> {
    let (name, mut value) = match dialect {
        RealtimeDialect::OpenAI => ("Authorization", HeaderValue::from_str(&format!("Bearer {api_key}"))?),
        RealtimeDialect::Gemini => ("x-goog-api-key", HeaderValue::from_str(api_key)?),
    };
    value.set_sensitive(true);
    Ok((name, value))
}

/// Bound on the TCP connect to each resolved address.
const REALTIME_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on the whole upstream dial: DNS, TCP connects, TLS, and the WebSocket
/// handshake, so an upstream that accepts and then stalls cannot hold the
/// caller's socket open.
const REALTIME_DIAL_TIMEOUT: Duration = Duration::from_secs(30);

type RealtimeUpstream = (
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    tokio_tungstenite::tungstenite::handshake::client::Response,
);

async fn connect_realtime_upstream(
    request: tokio_tungstenite::tungstenite::handshake::client::Request,
    upstream_url: &str,
) -> Result<RealtimeUpstream, String> {
    connect_realtime_upstream_within(request, upstream_url, REALTIME_DIAL_TIMEOUT).await
}

async fn connect_realtime_upstream_within(
    request: tokio_tungstenite::tungstenite::handshake::client::Request,
    upstream_url: &str,
    deadline: Duration,
) -> Result<RealtimeUpstream, String> {
    let dial = async {
        let addresses = resolve_realtime_upstream(upstream_url).await?;
        let socket = connect_first_address(&addresses).await?;
        tokio_tungstenite::client_async_tls_with_config(request, socket, None, None)
            .await
            .map_err(|error| format!("realtime upstream WebSocket handshake failed: {error}"))
    };
    tokio::time::timeout(deadline, dial)
        .await
        .map_err(|_| format!("realtime upstream dial timed out after {}s", deadline.as_secs_f32()))?
}

/// Resolve the upstream host and validate every address it resolves to. An IP
/// literal (including a bracketed IPv6 one) is used as-is.
async fn resolve_realtime_upstream(upstream_url: &str) -> Result<Vec<std::net::SocketAddr>, String> {
    let parsed = url::Url::parse(upstream_url).map_err(|error| format!("invalid upstream URL: {error}"))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "realtime upstream URL has no usable port".to_string())?;
    let addresses: Vec<std::net::SocketAddr> = match parsed.host() {
        Some(url::Host::Domain(domain)) => tokio::net::lookup_host((domain, port))
            .await
            .map_err(|error| format!("realtime upstream DNS resolution failed: {error}"))?
            .collect(),
        Some(url::Host::Ipv4(ip)) => vec![(ip, port).into()],
        Some(url::Host::Ipv6(ip)) => vec![(ip, port).into()],
        None => return Err("realtime upstream URL has no host".to_string()),
    };
    let host = parsed
        .host_str()
        .unwrap_or_default();
    validate_realtime_addresses(host, &addresses)?;
    Ok(addresses)
}

async fn connect_first_address(addresses: &[std::net::SocketAddr]) -> Result<tokio::net::TcpStream, String> {
    let mut last_error = String::from("no addresses to connect to");
    for address in addresses {
        match tokio::time::timeout(REALTIME_CONNECT_TIMEOUT, tokio::net::TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last_error = format!("{address}: {error}"),
            Err(_) => last_error = format!("{address}: timed out after {}s", REALTIME_CONNECT_TIMEOUT.as_secs()),
        }
    }
    Err(format!("realtime upstream connection failed for all resolved addresses: {last_error}"))
}

/// The realtime endpoint is operator-configured and may be a same-VPC provider,
/// so private ranges are allowed; the addresses `is_blocked_resolved_ip`
/// lists are refused. This is the `ServiceEndpointDnsResolver` check itself,
/// test-mode loopback allowlist included.
fn validate_realtime_addresses(
    host: &str,
    addresses: &[std::net::SocketAddr],
) -> Result<(), String> {
    crate::url_validation::validate_service_endpoint_addresses(host, addresses)
        .map_err(|error| format!("realtime upstream refused: {error}"))
}

/// Register a realtime session on the surface's ops time-series so the monitoring
/// graphs show realtime connections (accepted or upstream-failed) alongside chat
/// traffic. Metered at `$0` for now (a duration cost model is a follow-up).
async fn record_session(
    ctx: &SessionCtx,
    status: crate::metrics::ConnectionStatus,
    started: std::time::Instant,
) {
    ctx.metrics_store
        .record_pipe_execution(
            ctx.surface_id.clone(),
            Some(ctx.surface_name.clone()),
            format!("realtime:{}", ctx.provider),
            ctx.model.clone(),
            status,
            started.elapsed().as_millis() as u64,
            None,
            None,
            0,
            0,
            0.0,
            None,
            None,
            ctx.caller.clone(),
            0,
            0,
            0,
            None,
        )
        .await;
}

/// Reassembles the provider event stream into governed turns. Pure and
/// direction-agnostic: fed by both relay legs (user audio + input transcript
/// from the client/echo, assistant transcript + usage from the upstream).
pub struct RealtimeAccumulator {
    capture_audio: bool,
    max_audio_b64: usize,
    input_format: String,
    user_audio: String,
    audio_truncated: bool,
    user_transcript: String,
    assistant_transcript: String,
}

/// One completed realtime turn, ready to attest.
pub struct RealtimeTurn {
    pub user_transcript: String,
    pub assistant_transcript: String,
    /// Concatenated base64 user audio, present only when body capture is on and
    /// the turn stayed under the buffer cap.
    pub user_audio_b64: Option<String>,
    pub input_format: String,
    pub usage: Option<Value>,
}

impl RealtimeAccumulator {
    pub fn new(
        capture_audio: bool,
        max_audio_b64: usize,
        input_format: String,
    ) -> Self {
        Self {
            capture_audio,
            max_audio_b64,
            input_format,
            user_audio: String::new(),
            audio_truncated: false,
            user_transcript: String::new(),
            assistant_transcript: String::new(),
        }
    }

    /// Feed one JSON event. Returns the completed turn on `response.done`.
    pub fn feed(
        &mut self,
        ev: &Value,
    ) -> Option<RealtimeTurn> {
        match ev
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("")
        {
            "input_audio_buffer.append" => {
                if self.capture_audio
                    && !self.audio_truncated
                    && let Some(a) = ev
                        .get("audio")
                        .and_then(|a| a.as_str())
                {
                    if self.user_audio.len() + a.len() > self.max_audio_b64 {
                        self.audio_truncated = true;
                    } else {
                        self.user_audio.push_str(a);
                    }
                }
                None
            }
            "conversation.item.input_audio_transcription.completed" => {
                if let Some(t) = ev
                    .get("transcript")
                    .and_then(|t| t.as_str())
                {
                    if !self
                        .user_transcript
                        .is_empty()
                    {
                        self.user_transcript.push(' ');
                    }
                    self.user_transcript
                        .push_str(t);
                }
                None
            }
            "response.audio_transcript.delta" | "response.output_audio_transcript.delta" => {
                if let Some(d) = ev
                    .get("delta")
                    .and_then(|d| d.as_str())
                {
                    self.assistant_transcript
                        .push_str(d);
                }
                None
            }
            "response.done" => {
                let usage = ev
                    .get("response")
                    .and_then(|r| r.get("usage"))
                    .cloned();
                let user_audio_b64 = (!self.audio_truncated && !self.user_audio.is_empty())
                    .then(|| std::mem::take(&mut self.user_audio));
                let turn = RealtimeTurn {
                    user_transcript: std::mem::take(&mut self.user_transcript),
                    assistant_transcript: std::mem::take(&mut self.assistant_transcript),
                    user_audio_b64,
                    input_format: self.input_format.clone(),
                    usage,
                };
                self.user_audio.clear();
                self.audio_truncated = false;
                Some(turn)
            }
            _ => None,
        }
    }
}

/// Bill a turn's voice-safety juror usage to the member and teams the session
/// is attributed to (`team`), as a chat request's Jury is billed: its billed
/// cost (zero on owned keys) and its tokens.
async fn bill_jury_usage(
    team: Option<&crate::teams::gate::TeamUsageContext>,
    usage: &crate::pipes::config::StageUsage,
) {
    if let Some(team) = team
        && *usage != crate::pipes::config::StageUsage::default()
    {
        crate::teams::record_team_usage(team, usage.billed_cost, usage.total_tokens()).await;
    }
}

/// What a realtime turn on a key from `source` is recorded as billing: nothing
/// on an owned key, and unknown (`None`) on a platform key, since realtime has
/// no price model yet.
fn turn_billed_cost(source: crate::pipes::key_source::KeySource) -> Option<f64> {
    source.owned().then_some(0.0)
}

/// Attest one realtime turn as a signed governance VC on the surface's chain.
/// No-op when the surface has not opted into recording. `block` carries the
/// safety rejection reason when the turn was blocked, so the record is a
/// governance **Block** (never-delivered reply) rather than a completed one.
fn capture_turn(
    ctx: &SessionCtx,
    turn: RealtimeTurn,
    block: Option<crate::pipes::realtime_safety::TurnBlock>,
) {
    if !ctx.governance_active || !crate::governance::is_ready() {
        return;
    }

    let mut user_content = Vec::new();
    if let Some(b64) = &turn.user_audio_b64 {
        user_content.push(json!({
            "type": "input_audio",
            "input_audio": { "data": b64, "format": turn.input_format }
        }));
    }
    if !turn
        .user_transcript
        .is_empty()
    {
        user_content.push(json!({ "type": "text", "text": turn.user_transcript }));
    }
    let request = json!({
        "model": ctx.model,
        "modality": "audio_realtime",
        "messages": [ { "role": "user", "content": user_content } ],
    });
    let response = json!({
        "choices": [ { "message": { "role": "assistant", "content": turn.assistant_transcript } } ],
        "usage": turn.usage,
    });

    let usage = turn.usage.as_ref();
    let input_tokens = usage
        .and_then(|u| u.get("input_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let output_tokens = usage
        .and_then(|u| u.get("output_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let total_tokens = usage
        .and_then(|u| u.get("total_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(input_tokens + output_tokens);

    let metrics = crate::governance::RecordMetrics {
        input_tokens,
        output_tokens,
        total_tokens,
        // Realtime bills by audio duration, not tokens — metered at $0 until a
        // duration cost model lands (parity with Mode B transcription). A
        // session on an owned key bills the account nothing; what one on a
        // platform key bills is not known, so it is not stated.
        cost: 0.0,
        latency_ms: 0,
        provider: Some(ctx.provider.clone()),
        model: Some(ctx.model.clone()),
        currency: crate::governance::RecordMetrics::usd(),
        billed_cost: turn_billed_cost(ctx.key_source),
        key_source: Some(ctx.key_source),
        ..Default::default()
    };

    let blocked = block.is_some();
    let categories = block
        .as_ref()
        .map(|b| b.categories.clone())
        .unwrap_or_default();
    let mut stage = crate::governance::StageEntry::decision(
        "realtime_turn",
        if blocked {
            crate::governance::StageOutcome::Block
        } else {
            crate::governance::StageOutcome::Observed
        },
        block
            .as_ref()
            .map(|b| b.reason.clone())
            .or_else(|| Some("realtime voice turn".to_string())),
    )
    .with_io(
        (!turn
            .user_transcript
            .is_empty())
        .then(|| turn.user_transcript.clone()),
        (!turn
            .assistant_transcript
            .is_empty())
        .then(|| {
            turn.assistant_transcript
                .clone()
        }),
    );

    stage.categories = categories.clone();

    let outcome = match block {
        Some(crate::pipes::realtime_safety::TurnBlock { reason, .. }) => {
            crate::governance::InteractionOutcome::Blocked {
                stage: "realtime_safety".to_string(),
                reason: Some(reason),
                input: (!turn
                    .user_transcript
                    .is_empty())
                .then(|| turn.user_transcript.clone()),
                output: (!turn
                    .assistant_transcript
                    .is_empty())
                .then(|| {
                    turn.assistant_transcript
                        .clone()
                }),
                categories,
            }
        }
        None => crate::governance::InteractionOutcome::Completed,
    };

    let input = crate::governance::CaptureInput {
        surface_id: ctx.surface_id.clone(),
        surface_name: Some(ctx.surface_name.clone()),
        trace_id: None,
        caller_identity: ctx.caller.clone(),
        request: Some(request),
        response: Some(response),
        completion_text: (!blocked).then(|| {
            turn.assistant_transcript
                .clone()
        }),
        policy: ctx.policy,
        metrics,
        outcome,
        extra_stages: vec![stage],
        export: ctx.sink.clone(),
    };
    crate::observability::request_context::sync_scope(ctx.request.clone(), || crate::governance::capture(input));
}

/// The variant alias a `modality: realtime` routing rule targets, when routing
/// is enabled. The WebSocket transport is the routing signal, so a realtime
/// session resolves to the surface's realtime-capable variant. `None` falls
/// back to the base/default config (backward compatible with a surface that
/// carries `realtime` on its base).
fn select_realtime_variant(pipe: &PipeConfig) -> Option<String> {
    if !pipe.routing_enabled {
        return None;
    }
    pipe.routing_rules
        .iter()
        .find_map(|rule| match &rule.match_on {
            crate::pipes::config::RoutingMatch::Modality { has } if has == "realtime" => rule
                .target
                .variant
                .as_ref()
                .filter(|a| !a.trim().is_empty())
                .cloned(),
            _ => None,
        })
}

/// Longest-prefix surface resolution for a realtime path (mirrors the health
/// handler's GET-proxy match), scoped to this listener.
async fn resolve_surface(
    state: &PipeHandlerState,
    path: &str,
) -> Option<(String, String)> {
    let route_map = state
        .route_to_pipe
        .read()
        .await;
    let mut best: Option<(String, String, String)> = None;
    for (key, id) in route_map.iter() {
        if !crate::pipes::route_manager::route_key_matches_listener(key, &state.listener_scopes) {
            continue;
        }
        let route = &key.route;
        if path.starts_with(route) {
            let suffix = path
                .strip_prefix(route)
                .unwrap_or("");
            if best
                .as_ref()
                .map(|(_, r, _)| route.len() > r.len())
                .unwrap_or(true)
            {
                best = Some((id.clone(), route.clone(), suffix.to_string()));
            }
        }
    }
    best.map(|(id, _route, suffix)| (id, suffix))
}

async fn load_pipe(
    state: &PipeHandlerState,
    pipe_id: &str,
) -> Option<Arc<PipeConfig>> {
    {
        let cache = state.pipe_cache.read().await;
        if let Some(p) = cache.get(pipe_id) {
            return Some(p.clone());
        }
    }
    let pipe = state
        .pipe_store
        .get(pipe_id)
        .await?;
    let arc = Arc::new(pipe.with_global_surface_defaults());
    state
        .pipe_cache
        .write()
        .await
        .insert(pipe_id.to_string(), arc.clone());
    Some(arc)
}

async fn resolve_secret(
    secrets: &crate::secrets::SurfaceSecrets,
    secret_id: Option<&str>,
) -> Option<crate::pipes::key_source::CallKey> {
    let id = secret_id?;
    // The resolution the save-time tenancy check uses, re-checked against the
    // surface's tenant, so only a secret the surface may use is ever sent. A
    // realtime relay never sends the caller's key, only the surface's own.
    let resolved = crate::pipes::key_source::resolve_call_key(crate::pipes::key_source::CallerKey::NotOffered, || {
        secrets.resolve_key(id)
    })
    .await;
    match resolved {
        Ok(key) => key,
        Err(e) => {
            warn!(error = ?e.to_string(), reference = ?id, "realtime secret resolution failed");
            None
        }
    }
}

/// Evaluate the appliance-wide (global) policy set for this surface type, then
/// the surface's own OPA, both fail-closed. Returns `true` iff the session is
/// allowed to open.
fn evaluate_open_policy(
    policy_mgr: &crate::pipes::PipePolicyManager,
    pipe: &PipeConfig,
    pipe_id: &str,
    headers: &axum::http::HeaderMap,
    path: &str,
    model: &str,
    caller: Option<&crate::source_auth::AuthenticatedIdentity>,
) -> bool {
    let surface_type = crate::pipes::pipe_policy_type(&pipe.pipe_type);
    let enforce_global = policy_mgr.has_global(surface_type);
    let enforce_surface = pipe.opa_enabled();
    if !enforce_global && !enforce_surface {
        return true;
    }

    let mut policy_input = crate::surface_context::PolicyInput::new(
        "GET",
        path,
        crate::surface_context::filter_sensitive_headers(headers),
        "inbound",
        None,
        None,
        Some(pipe_id.to_string()),
        &pipe.name,
    );
    policy_input.source_auth = caller.map(crate::surface_context::SourceAuthContext::from);
    policy_input.action = Some("connect".to_string());
    policy_input.resource = Some(crate::surface_context::ResourceContext {
        surface_type: Some(surface_type.to_string()),
        model: Some(model.to_string()),
        modality: Some("audio_realtime".to_string()),
        ..Default::default()
    });
    let input_value = serde_json::to_value(&policy_input).unwrap_or_default();

    if enforce_global {
        let (decision, _evidence) = policy_mgr.evaluate_global(surface_type, input_value.clone());
        if !matches!(decision, Ok(true)) {
            warn!(pipe_id = %pipe_id, "realtime denied by appliance-wide policy");
            return false;
        }
    }
    if enforce_surface {
        let (decision, _evidence) = policy_mgr.evaluate_with_evidence(pipe_id, None, input_value);
        if !matches!(decision, Ok(true)) {
            warn!(pipe_id = %pipe_id, "realtime denied by surface policy");
            return false;
        }
    }
    true
}

/// Extract a caller bearer token offered in a `Sec-WebSocket-Protocol`
/// subprotocol. Accepts `bearer.<token>` or OpenAI's `openai-insecure-api-key.
/// <token>` form, so a browser (which cannot set an `Authorization` header on a
/// WebSocket) can still authenticate.
fn bearer_from_subprotocols(headers: &axum::http::HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::SEC_WEBSOCKET_PROTOCOL)?
        .to_str()
        .ok()?;
    for proto in raw.split(',') {
        let proto = proto.trim();
        for prefix in ["bearer.", "openai-insecure-api-key."] {
            if let Some(token) = proto.strip_prefix(prefix)
                && !token.is_empty()
            {
                return Some(token.to_string());
            }
        }
    }
    None
}

/// Build the OpenAI realtime WebSocket URL from a provider base URL.
fn openai_realtime_url(
    base: &str,
    model: &str,
) -> String {
    let base = base.trim_end_matches('/');
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        format!("wss://{base}")
    };
    format!("{ws_base}/v1/realtime?model={}", model.replace(' ', "%20"))
}

/// Which realtime wire dialect the surface's upstream speaks. The client always
/// speaks OpenAI Realtime; a Gemini upstream is translated on both relay legs so
/// the caller and the governance accumulator stay OpenAI-canonical.
#[derive(Clone, Copy, PartialEq, Debug)]
enum RealtimeDialect {
    OpenAI,
    Gemini,
}

/// Build the Gemini Live (BidiGenerateContent) WebSocket URL. Only the scheme+host of `base` is
/// used — a Gemini provider endpoint carries a REST path (`/v1beta/models/…`)
/// that must be dropped; the Live socket lives at a fixed path on the same host.
fn gemini_live_url(base: &str) -> String {
    let host = base
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("wss://")
        .trim_start_matches("ws://")
        .split('/')
        .next()
        .unwrap_or(base);
    format!("wss://{host}/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent")
}

/// The Gemini `setup` message (the required first upstream frame), built from the
/// surface model plus the client's session instructions/voice.
fn gemini_setup(
    model: &str,
    instructions: Option<&str>,
    voice: Option<&str>,
) -> Value {
    let mut generation_config = json!({ "responseModalities": ["AUDIO"] });
    if let Some(v) = voice.filter(|s| !s.is_empty()) {
        generation_config["speechConfig"] = json!({ "voiceConfig": { "prebuiltVoiceConfig": { "voiceName": v } } });
    }
    let mut setup = json!({
        "model": format!("models/{}", model.trim_start_matches("models/")),
        "generationConfig": generation_config,
        "inputAudioTranscription": {},
        "outputAudioTranscription": {},
    });
    if let Some(instr) = instructions.filter(|s| !s.is_empty()) {
        setup["systemInstruction"] = json!({ "parts": [{ "text": instr }] });
    }
    json!({ "setup": setup })
}

/// Translate one OpenAI-realtime client event into Gemini Live message(s).
/// `session.update` becomes the `setup` (built from the surface model + the
/// client's instructions/voice); an audio append becomes a `realtimeInput`
/// `audio` blob (the client's pcm16 rate is declared verbatim in the mimeType;
/// the Live API resamples any rate). Everything else (commit / response.create
/// under server VAD) needs no frame.
fn client_event_to_gemini(
    ev: &Value,
    model: &str,
    cfg_voice: Option<&str>,
) -> Vec<Value> {
    match ev
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("")
    {
        "session.update" => {
            let session = ev.get("session");
            let instructions = session
                .and_then(|s| s.get("instructions"))
                .and_then(|i| i.as_str());
            let voice = session
                .and_then(|s| s.get("voice"))
                .and_then(|v| v.as_str())
                .or(cfg_voice);
            vec![gemini_setup(model, instructions, voice)]
        }
        "input_audio_buffer.append" => ev
            .get("audio")
            .and_then(|a| a.as_str())
            .map(|a| {
                vec![json!({
                    "realtimeInput": { "audio": { "mimeType": "audio/pcm;rate=24000", "data": a } }
                })]
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Per-turn state for the Gemini→OpenAI translation: Gemini streams the user
/// (input) transcript incrementally, so it is accumulated and emitted once as a
/// single completed event at turn end (one caller bubble + one governance turn).
#[derive(Default)]
struct GeminiTurnState {
    input_transcript: String,
    input_emitted: bool,
}

/// Translate one Gemini Live server message into OpenAI-realtime event(s), which
/// are both forwarded to the caller and fed to the governance accumulator.
/// `setupComplete` → `session.created` (a browser starts its mic on it);
/// model-turn audio → `response.audio.delta`; output transcription →
/// `response.audio_transcript.delta`; `turnComplete` → the accumulated user
/// transcript's completed event + `response.done`.
fn gemini_event_to_client(
    msg: &Value,
    state: &mut GeminiTurnState,
) -> Vec<Value> {
    let mut out = Vec::new();
    if msg
        .get("setupComplete")
        .is_some()
    {
        out.push(json!({ "type": "session.created", "session": { "id": "gemini-live" } }));
        return out;
    }
    let Some(sc) = msg.get("serverContent") else {
        return out;
    };
    if let Some(parts) = sc
        .get("modelTurn")
        .and_then(|m| m.get("parts"))
        .and_then(|p| p.as_array())
    {
        // Emit the user's input transcript as soon as the model starts replying,
        // so the caller sees what they said without waiting for the whole reply
        // and `turnComplete` (the previous behaviour, which read as a long delay).
        if !parts.is_empty()
            && !state.input_emitted
            && !state
                .input_transcript
                .is_empty()
        {
            out.push(json!({
                "type": "conversation.item.input_audio_transcription.completed",
                "transcript": state.input_transcript.clone()
            }));
            state.input_emitted = true;
        }
        for part in parts {
            if let Some(data) = part
                .get("inlineData")
                .and_then(|d| d.get("data"))
                .and_then(|d| d.as_str())
            {
                out.push(json!({ "type": "response.audio.delta", "delta": data }));
            }
        }
    }
    if let Some(t) = sc
        .get("inputTranscription")
        .and_then(|i| i.get("text"))
        .and_then(|t| t.as_str())
    {
        state
            .input_transcript
            .push_str(t);
    }
    if let Some(t) = sc
        .get("outputTranscription")
        .and_then(|o| o.get("text"))
        .and_then(|t| t.as_str())
    {
        out.push(json!({ "type": "response.audio_transcript.delta", "delta": t }));
    }
    if sc
        .get("turnComplete")
        .and_then(|t| t.as_bool())
        .unwrap_or(false)
    {
        if !state.input_emitted
            && !state
                .input_transcript
                .is_empty()
        {
            out.push(json!({
                "type": "conversation.item.input_audio_transcription.completed",
                "transcript": state.input_transcript.clone()
            }));
        }
        state.input_transcript.clear();
        state.input_emitted = false;
        let mut done = json!({ "type": "response.done" });
        if let Some(u) = msg
            .get("usageMetadata")
            .cloned()
        {
            done["response"] = json!({ "usage": u });
        }
        out.push(done);
    }
    out
}

/// JSON payload of an upstream frame, whether it arrives as Text or Binary
/// (Gemini Live sends its JSON messages as binary frames).
fn upstream_json(msg: &UpMessage) -> Option<Value> {
    match msg {
        UpMessage::Text(t) => serde_json::from_str(t.as_str()).ok(),
        UpMessage::Binary(b) => serde_json::from_slice(b).ok(),
        _ => None,
    }
}

/// A human-readable reason from an upstream Close frame, or `None` if the frame
/// isn't a close. Gemini Live rejects a bad `setup` (wrong model, malformed
/// payload, no model access) by closing the socket with a code + reason right
/// after connect, so this is the primary diagnostic for a session that ends
/// immediately — it's logged and relayed to the caller as an `error` event.
fn upstream_close_reason(msg: &UpMessage) -> Option<String> {
    let UpMessage::Close(frame) = msg else {
        return None;
    };
    let (code, reason) = frame
        .as_ref()
        .map(|c| (u16::from(c.code), c.reason.to_string()))
        .unwrap_or((0, String::new()));
    Some(if reason.is_empty() {
        format!("upstream closed (code {code})")
    } else {
        format!("upstream closed (code {code}): {reason}")
    })
}

/// A compact, audio-redacted copy of an upstream frame for logs: any long string
/// (a base64 audio blob) is replaced with a byte-length marker, so a frame's
/// shape (setupComplete / transcripts / modelTurn / turnComplete / error) is
/// visible without dumping audio to the log.
fn redact_realtime_frame(v: &Value) -> Value {
    match v {
        Value::String(s) if s.len() > 96 => Value::String(format!("<{} chars>", s.len())),
        Value::Array(a) => Value::Array(
            a.iter()
                .map(redact_realtime_frame)
                .collect(),
        ),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, val)| (k.clone(), redact_realtime_frame(val)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn axum_to_upstream(msg: AxumMessage) -> Option<UpMessage> {
    match msg {
        AxumMessage::Text(t) => Some(UpMessage::Text(t.as_str().into())),
        AxumMessage::Binary(b) => Some(UpMessage::Binary(b)),
        AxumMessage::Ping(b) => Some(UpMessage::Ping(b)),
        AxumMessage::Pong(b) => Some(UpMessage::Pong(b)),
        AxumMessage::Close(_) => Some(UpMessage::Close(None)),
    }
}

fn upstream_to_axum(msg: UpMessage) -> Option<AxumMessage> {
    match msg {
        UpMessage::Text(t) => Some(AxumMessage::Text(t.as_str().into())),
        UpMessage::Binary(b) => Some(AxumMessage::Binary(b)),
        UpMessage::Ping(b) => Some(AxumMessage::Ping(b)),
        UpMessage::Pong(b) => Some(AxumMessage::Pong(b)),
        UpMessage::Close(_) => Some(AxumMessage::Close(None)),
        UpMessage::Frame(_) => None,
    }
}

/// Close an already-upgraded client socket after telling it *why* — sends an
/// OpenAI-style `error` event (which the caller surfaces) then a Close frame, so
/// a post-handshake failure (e.g. the upstream connect) isn't a blank socket
/// error.
async fn close_client_with_error(
    client: WebSocket,
    message: &str,
) {
    let mut client = client;
    let event = json!({
        "type": "error",
        "error": { "type": "realtime_error", "code": "upstream_unavailable", "message": message }
    });
    let _ = client
        .send(AxumMessage::Text(event.to_string().into()))
        .await;
    let _ = client
        .send(AxumMessage::Close(None))
        .await;
}

/// Log a realtime rejection and register it as a **failed** connection on the
/// surface's ops time-series (so a refused session shows up in the logs *and*
/// the monitoring graphs), then reject the upgrade with a browser-visible reason.
#[allow(clippy::too_many_arguments)]
async fn reject_and_record(
    ws: WebSocketUpgrade,
    state: &PipeHandlerState,
    pipe_id: Option<&str>,
    pipe_name: Option<&str>,
    model: &str,
    path: &str,
    code: &'static str,
    message: &'static str,
) -> Response {
    warn!(path = %path, code = code, "[PIPE:{}] realtime session rejected ({}): {}", pipe_id.unwrap_or("-"), code, message);
    if let Some(id) = pipe_id {
        state
            .global_metrics_store
            .record_pipe_execution(
                id.to_string(),
                pipe_name.map(str::to_string),
                "realtime".to_string(),
                model.to_string(),
                crate::metrics::ConnectionStatus::Failed,
                0,
                None,
                None,
                0,
                0,
                0.0,
                None,
                None,
                None,
                0,
                0,
                0,
                None,
            )
            .await;
    }
    reject_realtime(ws, code, message)
}

/// Complete the WebSocket handshake and immediately close it with a structured
/// reason. A browser client cannot read an HTTP error body on a *refused*
/// upgrade (it only sees a generic connection failure), so instead we accept the
/// upgrade, send an OpenAI-style `error` event (the caller surfaces it), then
/// send a Close frame carrying the reason. The `realtime` subprotocol is echoed
/// so the browser handshake completes and `onmessage`/`onclose` fire.
fn reject_realtime(
    ws: WebSocketUpgrade,
    code: &str,
    message: &str,
) -> Response {
    let code = code.to_string();
    let message = message.to_string();
    ws.protocols(["realtime"])
        .on_upgrade(move |mut socket| async move {
            let event = json!({
                "type": "error",
                "error": { "type": "realtime_error", "code": code, "message": message },
            });
            let _ = socket
                .send(AxumMessage::Text(event.to_string().into()))
                .await;
            // The WS close reason is capped at 123 bytes; keep well under it.
            let reason: String = message
                .chars()
                .take(110)
                .collect();
            let _ = socket
                .send(AxumMessage::Close(Some(axum::extract::ws::CloseFrame {
                    code: axum::extract::ws::close_code::POLICY,
                    reason: reason.into(),
                })))
                .await;
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(v: Value) -> Value {
        v
    }

    #[test]
    fn a_platform_session_never_records_that_it_billed_nothing() {
        use crate::pipes::key_source::KeySource;
        assert_eq!(turn_billed_cost(KeySource::Platform), None);
        assert_eq!(turn_billed_cost(KeySource::Customer), Some(0.0));
        assert_eq!(turn_billed_cost(KeySource::Client), Some(0.0));
    }

    #[tokio::test]
    async fn under_a_budget_a_session_on_a_platform_key_or_with_a_platform_juror_is_refused_even_with_credit() {
        use crate::pipes::key_source::KeySource;
        use crate::pipes::metering::Unmetered;
        use crate::secrets::store::memory::{MemorySecretsStore, secret};

        let store: Arc<dyn crate::secrets::SecretsStore> = Arc::new(MemorySecretsStore::with(vec![
            secret("uuid-operator", "operator-key", "OPERATOR", None),
            secret("uuid-own", "own-key", "OWN", Some("tenant-a")),
        ]));
        let secrets = crate::secrets::SurfaceSecrets::new(Some(store), Some("tenant-a".to_string()));
        let juror = |key: &str| {
            json!({
                "enabled": true,
                "jurors": [{
                    "name": "juror",
                    "system_prompt": "Review.",
                    "llm": {
                        "provider_type": "openai",
                        "model": "gpt-4o",
                        "endpoint_url": "https://api.openai.com/v1/chat/completions",
                        "api_key_secret": key
                    }
                }]
            })
        };
        let mut surface = crate::pipes::PipeConfig::new(
            "p-voice".to_string(),
            "Voice".to_string(),
            serde_json::from_value(json!({
                "type": "llm",
                "provider": { "provider_type": "openai", "model": "gpt-4o-realtime-preview" }
            }))
            .expect("pipe type"),
        );
        surface.tenant_id = Some("tenant-a".to_string());
        let plain = RealtimeConfig {
            enabled: true,
            ..Default::default()
        };
        let guarded = RealtimeConfig {
            enabled: true,
            safety: Some(serde_json::from_value(json!({ "enabled": true })).expect("safety")),
            ..Default::default()
        };
        // The answer does not depend on credit: no budget bucket is read.
        let refused = Some(Unmetered::Realtime);

        assert_eq!(session_refusal(true, KeySource::Platform, &surface, &plain, &secrets).await, refused);
        assert_eq!(session_refusal(true, KeySource::Customer, &surface, &plain, &secrets).await, None);
        assert_eq!(
            session_refusal(false, KeySource::Platform, &surface, &plain, &secrets).await,
            None,
            "no budget in scope"
        );

        surface.jury = Some(serde_json::from_value(juror("operator-key")).expect("jury"));
        assert_eq!(
            session_refusal(true, KeySource::Customer, &surface, &guarded, &secrets).await,
            refused,
            "the voice safety's juror runs on the operator's key"
        );
        assert_eq!(
            session_refusal(true, KeySource::Customer, &surface, &plain, &secrets).await,
            None,
            "no voice safety, no juror call"
        );
        surface.jury = Some(serde_json::from_value(juror("own-key")).expect("jury"));
        assert_eq!(session_refusal(true, KeySource::Customer, &surface, &guarded, &secrets).await, None);
        assert_eq!(Unmetered::Realtime.code(), "realtime_not_metered");
    }

    #[tokio::test]
    async fn a_turns_juror_usage_is_billed_to_the_sessions_member() {
        use crate::pipes::config::StageUsage;
        use crate::pipes::key_source::KeySource;
        use crate::teams::call_budget::test_support;

        let tracker = test_support::tracker().await;
        let member = test_support::member(Some(1.0));
        let team = crate::teams::gate::TeamUsageContext {
            member_id: member.id.clone(),
            budget_period_anchor: None,
            teams: Vec::new(),
            provisioned: None,
            call_budget: None,
        };

        bill_jury_usage(Some(&team), &StageUsage::call(1000, 1000, 0.25, 0, KeySource::Platform)).await;
        bill_jury_usage(Some(&team), &StageUsage::call(1000, 1000, 0.5, 0, KeySource::Customer)).await;
        bill_jury_usage(None, &StageUsage::call(1000, 1000, 0.5, 0, KeySource::Platform)).await;

        let (_, usage) = tracker
            .member_usage(&member.id, None)
            .await;
        assert!((usage.total_cost - 0.25).abs() < 1e-12, "only the platform juror bills: {}", usage.total_cost);
        assert_eq!(usage.total_tokens, 4000, "every juror's tokens count, as on the chat path");
    }

    #[test]
    fn realtime_config_defaults_are_off_and_bounded() {
        let cfg = RealtimeConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.allowed_formats, vec!["pcm16".to_string()]);
        assert_eq!(cfg.max_session_secs, 600);
    }

    #[test]
    fn realtime_config_round_trips_and_fills_defaults() {
        let parsed: RealtimeConfig = serde_json::from_value(json!({ "enabled": true })).unwrap();
        assert!(parsed.enabled);
        assert_eq!(parsed.max_session_secs, 600);
        assert_eq!(parsed.allowed_formats, vec!["pcm16".to_string()]);
    }

    #[test]
    fn accumulator_segments_a_turn_with_transcripts_and_usage() {
        let mut acc = RealtimeAccumulator::new(true, MAX_TURN_AUDIO_B64, "pcm16".to_string());
        assert!(
            acc.feed(&ev(json!({ "type": "input_audio_buffer.append", "audio": "AAAA" })))
                .is_none()
        );
        assert!(
            acc.feed(&ev(json!({
                "type": "conversation.item.input_audio_transcription.completed",
                "transcript": "what's the weather"
            })))
            .is_none()
        );
        assert!(
            acc.feed(&ev(json!({ "type": "response.audio_transcript.delta", "delta": "It is " })))
                .is_none()
        );
        assert!(
            acc.feed(&ev(json!({ "type": "response.audio_transcript.delta", "delta": "sunny." })))
                .is_none()
        );
        let turn = acc
            .feed(&ev(json!({
                "type": "response.done",
                "response": { "usage": { "input_tokens": 3, "output_tokens": 5, "total_tokens": 8 } }
            })))
            .expect("response.done completes a turn");
        assert_eq!(turn.user_transcript, "what's the weather");
        assert_eq!(turn.assistant_transcript, "It is sunny.");
        assert_eq!(turn.user_audio_b64.as_deref(), Some("AAAA"));
        assert_eq!(turn.usage.unwrap()["total_tokens"], 8);
    }

    #[test]
    fn accumulator_omits_audio_when_capture_off() {
        let mut acc = RealtimeAccumulator::new(false, MAX_TURN_AUDIO_B64, "pcm16".to_string());
        acc.feed(&ev(json!({ "type": "input_audio_buffer.append", "audio": "AAAA" })));
        let turn = acc
            .feed(&ev(json!({ "type": "response.done", "response": {} })))
            .unwrap();
        assert!(turn.user_audio_b64.is_none());
    }

    #[test]
    fn accumulator_drops_audio_over_cap() {
        let mut acc = RealtimeAccumulator::new(true, 4, "pcm16".to_string());
        acc.feed(&ev(json!({ "type": "input_audio_buffer.append", "audio": "AAAAAAAA" })));
        let turn = acc
            .feed(&ev(json!({ "type": "response.done", "response": {} })))
            .unwrap();
        assert!(turn.user_audio_b64.is_none(), "oversized turn audio is dropped");
    }

    #[test]
    fn accumulator_resets_between_turns() {
        let mut acc = RealtimeAccumulator::new(true, MAX_TURN_AUDIO_B64, "pcm16".to_string());
        acc.feed(&ev(json!({ "type": "response.audio_transcript.delta", "delta": "one" })));
        acc.feed(&ev(json!({ "type": "response.done", "response": {} })));
        acc.feed(&ev(json!({ "type": "response.audio_transcript.delta", "delta": "two" })));
        let turn = acc
            .feed(&ev(json!({ "type": "response.done", "response": {} })))
            .unwrap();
        assert_eq!(turn.assistant_transcript, "two");
    }

    #[test]
    fn realtime_url_maps_https_to_wss() {
        assert_eq!(
            openai_realtime_url("https://api.openai.com", "gpt-realtime"),
            "wss://api.openai.com/v1/realtime?model=gpt-realtime"
        );
        assert_eq!(
            openai_realtime_url("https://api.openai.com/", "gpt-4o-realtime-preview"),
            "wss://api.openai.com/v1/realtime?model=gpt-4o-realtime-preview"
        );
    }

    #[test]
    fn realtime_dns_policy_allows_private_and_rejects_loopback_and_metadata() {
        let public = "93.184.216.34:443"
            .parse()
            .unwrap();
        let private = "10.0.0.1:443"
            .parse()
            .unwrap();
        let loopback = "127.0.0.1:443"
            .parse()
            .unwrap();
        let metadata = "169.254.169.254:443"
            .parse()
            .unwrap();

        assert!(validate_realtime_addresses("example.com", &[]).is_err());
        assert!(validate_realtime_addresses("example.com", &[public]).is_ok());
        assert!(validate_realtime_addresses("example.com", &[private]).is_ok());
        assert!(validate_realtime_addresses("example.com", &[loopback]).is_err());
        assert!(validate_realtime_addresses("example.com", &[metadata]).is_err());
    }

    #[test]
    fn realtime_dns_policy_honours_the_test_loopback_allowlist() {
        let loopback = "127.0.0.1:9000"
            .parse()
            .unwrap();
        let metadata = "169.254.169.254:80"
            .parse()
            .unwrap();
        let _allowed =
            crate::url_validation::test_service_endpoints::allow(&["ws://127.0.0.1:9000/v1/realtime".to_string()]);
        assert!(validate_realtime_addresses("127.0.0.1", &[loopback]).is_ok());
        assert!(validate_realtime_addresses("localhost", &[loopback]).is_err(), "only the allowlisted host");
        assert!(validate_realtime_addresses("127.0.0.1", &[metadata]).is_err(), "metadata stays blocked");
    }

    #[tokio::test]
    async fn realtime_upstream_accepts_an_ipv6_literal() {
        let addresses = resolve_realtime_upstream("wss://[fd00::1]:8443/v1/realtime")
            .await
            .unwrap();
        assert_eq!(
            addresses,
            vec![
                "[fd00::1]:8443"
                    .parse()
                    .unwrap()
            ]
        );
        assert!(
            resolve_realtime_upstream("wss://[::1]/v1/realtime")
                .await
                .is_err(),
            "an IPv6 loopback literal is still refused"
        );
    }

    #[tokio::test]
    async fn realtime_dial_times_out_when_the_handshake_stalls() {
        // Accepts the TCP connection and never answers the WebSocket upgrade.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let url = format!(
            "ws://127.0.0.1:{}/v1/realtime",
            listener
                .local_addr()
                .unwrap()
                .port()
        );
        let held = tokio::spawn(async move {
            let (socket, _) = listener
                .accept()
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(socket);
        });
        let _allowed = crate::url_validation::test_service_endpoints::allow(std::slice::from_ref(&url));
        let request =
            tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(url.as_str()).unwrap();

        let started = std::time::Instant::now();
        let result = connect_realtime_upstream_within(request, &url, Duration::from_millis(200)).await;
        let error = result.expect_err("a stalled handshake must fail");
        assert!(error.contains("timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(5));
        held.abort();
    }

    #[test]
    fn realtime_auth_header_is_sensitive_per_dialect() {
        let (name, value) = realtime_auth_header(RealtimeDialect::OpenAI, "sk-test").unwrap();
        assert_eq!(name, "Authorization");
        assert_eq!(value, "Bearer sk-test");
        assert!(value.is_sensitive());

        let (name, value) = realtime_auth_header(RealtimeDialect::Gemini, "g-test").unwrap();
        assert_eq!(name, "x-goog-api-key");
        assert_eq!(value, "g-test");
        assert!(value.is_sensitive());
    }

    #[test]
    fn realtime_auth_header_rejects_unusable_key() {
        assert!(realtime_auth_header(RealtimeDialect::OpenAI, "sk-\ntest").is_err());
        assert!(realtime_auth_header(RealtimeDialect::Gemini, "g-\rtest").is_err());
    }

    #[tokio::test]
    async fn realtime_connect_failure_reports_last_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let refused = listener.local_addr().unwrap();
        drop(listener);

        let error = connect_first_address(&[refused])
            .await
            .unwrap_err();
        assert!(error.contains(&refused.to_string()), "{error}");
        assert!(error.contains("refused"), "{error}");
    }

    #[test]
    fn bearer_subprotocol_is_extracted() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::SEC_WEBSOCKET_PROTOCOL,
            "realtime, bearer.abc123"
                .parse()
                .unwrap(),
        );
        assert_eq!(bearer_from_subprotocols(&h).as_deref(), Some("abc123"));

        let mut h2 = axum::http::HeaderMap::new();
        h2.insert(
            axum::http::header::SEC_WEBSOCKET_PROTOCOL,
            "openai-insecure-api-key.sk-xyz, realtime"
                .parse()
                .unwrap(),
        );
        assert_eq!(bearer_from_subprotocols(&h2).as_deref(), Some("sk-xyz"));

        let mut h3 = axum::http::HeaderMap::new();
        h3.insert(axum::http::header::SEC_WEBSOCKET_PROTOCOL, "realtime".parse().unwrap());
        assert!(bearer_from_subprotocols(&h3).is_none());
    }

    #[test]
    fn gemini_live_url_does_not_contain_credentials() {
        let url = gemini_live_url("https://generativelanguage.googleapis.com");
        assert!(url.starts_with("wss://generativelanguage.googleapis.com/ws/"));
        assert!(url.ends_with("BidiGenerateContent"));
        assert!(!url.contains("KEY123"));
        // A Gemini provider endpoint carries a REST path that must be dropped —
        // only the host is used for the Live socket.
        assert_eq!(
            gemini_live_url(
                "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-live-001:generateContent",
            ),
            "wss://generativelanguage.googleapis.com/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent"
        );
    }

    #[test]
    fn client_session_update_becomes_gemini_setup() {
        let ev = json!({ "type": "session.update", "session": { "instructions": "be brief", "voice": "aoede" } });
        let msgs = client_event_to_gemini(&ev, "gemini-2.0-flash-live", None);
        assert_eq!(msgs.len(), 1);
        let setup = &msgs[0]["setup"];
        assert_eq!(setup["model"], "models/gemini-2.0-flash-live");
        assert_eq!(setup["systemInstruction"]["parts"][0]["text"], "be brief");
        assert_eq!(
            setup["generationConfig"]["speechConfig"]["voiceConfig"]["prebuiltVoiceConfig"]["voiceName"],
            "aoede"
        );
        assert_eq!(setup["generationConfig"]["responseModalities"][0], "AUDIO");
    }

    #[test]
    fn client_audio_append_becomes_realtime_input() {
        let ev = json!({ "type": "input_audio_buffer.append", "audio": "QUJD" });
        let msgs = client_event_to_gemini(&ev, "gemini-2.5-flash-native-audio-latest", None);
        assert_eq!(msgs[0]["realtimeInput"]["audio"]["data"], "QUJD");
        assert_eq!(msgs[0]["realtimeInput"]["audio"]["mimeType"], "audio/pcm;rate=24000");
    }

    #[test]
    fn gemini_turn_translates_to_openai_events() {
        let mut st = GeminiTurnState::default();
        assert_eq!(gemini_event_to_client(&json!({ "setupComplete": {} }), &mut st)[0]["type"], "session.created");
        let audio = gemini_event_to_client(
            &json!({ "serverContent": { "modelTurn": { "parts": [{ "inlineData": { "data": "WAV" } }] } } }),
            &mut st,
        );
        assert_eq!(audio[0]["type"], "response.audio.delta");
        assert_eq!(audio[0]["delta"], "WAV");
        // Input transcript accumulates silently; output transcript is a delta.
        assert!(
            gemini_event_to_client(
                &json!({ "serverContent": { "inputTranscription": { "text": "hi there" } } }),
                &mut st
            )
            .is_empty()
        );
        assert_eq!(
            gemini_event_to_client(
                &json!({ "serverContent": { "outputTranscription": { "text": "hello" } } }),
                &mut st
            )[0]["type"],
            "response.audio_transcript.delta"
        );
        let done = gemini_event_to_client(
            &json!({ "serverContent": { "turnComplete": true }, "usageMetadata": { "totalTokenCount": 5 } }),
            &mut st,
        );
        assert_eq!(done[0]["type"], "conversation.item.input_audio_transcription.completed");
        assert_eq!(done[0]["transcript"], "hi there");
        assert_eq!(done[1]["type"], "response.done");
        assert_eq!(done[1]["response"]["usage"]["totalTokenCount"], 5);
    }

    #[test]
    fn gemini_emits_input_transcript_when_model_starts_replying() {
        let mut st = GeminiTurnState::default();
        // The user's transcript arrives first (as Gemini sends it), silently.
        assert!(
            gemini_event_to_client(
                &json!({ "serverContent": { "inputTranscription": { "text": "hi there" } } }),
                &mut st,
            )
            .is_empty()
        );
        // The first model audio flushes the input transcript immediately (before
        // the reply completes), ahead of the audio.
        let ev = gemini_event_to_client(
            &json!({ "serverContent": { "modelTurn": { "parts": [{ "inlineData": { "data": "WAV" } }] } } }),
            &mut st,
        );
        assert_eq!(ev[0]["type"], "conversation.item.input_audio_transcription.completed");
        assert_eq!(ev[0]["transcript"], "hi there");
        assert_eq!(ev[1]["type"], "response.audio.delta");
        // `turnComplete` does not re-emit the already-sent input transcript.
        let done = gemini_event_to_client(&json!({ "serverContent": { "turnComplete": true } }), &mut st);
        assert_eq!(done[0]["type"], "response.done");
    }

    #[test]
    fn translated_gemini_turn_feeds_the_accumulator() {
        // The events the Gemini translation emits must drive the OpenAI-canonical
        // accumulator to one governed turn.
        let mut acc = RealtimeAccumulator::new(false, MAX_TURN_AUDIO_B64, "pcm16".to_string());
        let mut st = GeminiTurnState::default();
        for src in [
            json!({ "serverContent": { "inputTranscription": { "text": "what is two plus two" } } }),
            json!({ "serverContent": { "outputTranscription": { "text": "four" } } }),
            json!({ "serverContent": { "turnComplete": true } }),
        ] {
            for oev in gemini_event_to_client(&src, &mut st) {
                if let Some(turn) = acc.feed(&oev) {
                    assert_eq!(turn.user_transcript, "what is two plus two");
                    assert_eq!(turn.assistant_transcript, "four");
                    return;
                }
            }
        }
        panic!("expected a completed turn");
    }
}
