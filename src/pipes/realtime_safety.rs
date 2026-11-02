//! Realtime voice safety — per-turn Jury enforcement for the Mode C WebSocket
//! relay.
//!
//! The relay speaks OpenAI-realtime canonical events on both legs, so this guard
//! is dialect-agnostic: it inspects the per-turn **output transcript** (what the
//! model said) with the surface's existing [`JuryConfig`]. The normal surface
//! [`JudgeConfig`] is intentionally not run for realtime voice because it would
//! only see a provider-produced transcript after caller audio has already reached
//! the upstream realtime model/provider.
//!
//! Two operator-selectable enforcement modes:
//! - [`RealtimeSafetyMode::Gated`] — the model's reply is **buffered** (audio and
//!   transcript held, never forwarded live) until the turn completes; the Jury
//!   runs, and the audio is released to the caller **only if it passes**.
//!   Guarantees no unsafe model reply audio reaches the caller, at the cost of a
//!   per-turn delay (generation + evaluation).
//! - [`RealtimeSafetyMode::BargeIn`] — audio is forwarded live; the Jury runs on
//!   the output transcript **incrementally** (debounced), and on a violation the
//!   guard cuts the reply off and tells the caller to flush queued audio. Low
//!   latency, best-effort (a fragment may play before the cutoff).
//!
//! On a block the guard emits, in OpenAI-canonical form, an `output_audio.flush`
//! (clear any queued playback), a refusal transcript delta, and a terminal
//! `response.done`; the caller records the turn as a governance **Block**.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::warn;

use crate::pipes::config::StageUsage;
use crate::pipes::judge_jury::{JudgeConfig, JuryConfig, JuryVerdict, execute_jury};
use crate::secrets::SurfaceSecrets;

/// How output safety is enforced on a voice reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RealtimeSafetyMode {
    /// Hold the reply, vet it, release only if it passes (guaranteed).
    #[default]
    Gated,
    /// Stream live, vet incrementally, cut off on a violation (best-effort).
    BargeIn,
}

/// Per-surface realtime safety configuration. The actual response-review rules
/// come from the surface's own `jury`; this block only says whether realtime
/// response safety is enabled and how to enforce it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealtimeSafetyConfig {
    /// Master switch for voice-turn enforcement.
    #[serde(default)]
    pub enabled: bool,
    /// Gated (guaranteed) or BargeIn (best-effort) output enforcement.
    #[serde(default)]
    pub mode: RealtimeSafetyMode,
    /// Deprecated compatibility field. Caller-side Judge is no longer applied in
    /// realtime voice because it cannot run before the upstream model receives
    /// audio.
    #[serde(default)]
    pub judge: bool,
    /// Deprecated compatibility field. Realtime response safety follows the
    /// surface Jury whenever `enabled` is true.
    #[serde(default = "default_true")]
    pub jury: bool,
    /// Spoken/shown to the caller when a turn is blocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_message: Option<String>,
    /// BargeIn only: minimum new output-transcript characters before the Jury is
    /// re-run mid-turn (a debounce so a long reply doesn't hammer the jurors).
    #[serde(default = "default_barge_in_min_chars")]
    pub barge_in_min_chars: usize,
}

fn default_true() -> bool {
    true
}

fn default_barge_in_min_chars() -> usize {
    160
}

impl Default for RealtimeSafetyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: RealtimeSafetyMode::default(),
            judge: false,
            jury: true,
            refusal_message: None,
            barge_in_min_chars: default_barge_in_min_chars(),
        }
    }
}

/// Default refusal spoken/shown when the caller configured none.
const DEFAULT_REFUSAL: &str = "I'm sorry, but I can't help with that.";

/// The outcome of a safety check on one transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyVerdict {
    Allow,
    Block {
        reason: String,
        /// Canonical rejection category (for picking a refusal clip bucket).
        category: Option<String>,
    },
}

/// Map a raw jury reason onto a canonical rejection category id via the
/// appliance taxonomy. `None` only when the classifier yields nothing usable.
fn category_of(
    raw: &str,
    source: &str,
) -> Option<String> {
    crate::rejection_taxonomy::classify_global(&[raw.to_string()], source)
        .into_iter()
        .find(|c| !c.is_empty())
}

/// Run the surface Jury on a model output transcript, with the jurors' text
/// usage (billed by each juror's key source; empty when no juror ran or the
/// Jury failed). Allows when the Jury is absent/disabled/unselected or the
/// transcript is empty. A rejection blocks; a jury execution failure also
/// blocks (fail-closed).
pub async fn jury_output(
    pipe_id: &str,
    jury: Option<&JuryConfig>,
    apply: bool,
    transcript: &str,
    secrets: &SurfaceSecrets,
) -> (SafetyVerdict, StageUsage) {
    let Some(jury) = jury.filter(|_| apply) else {
        return (SafetyVerdict::Allow, StageUsage::default());
    };
    if !jury.enabled || transcript.trim().is_empty() {
        return (SafetyVerdict::Allow, StageUsage::default());
    }
    let response = json!({
        "choices": [ { "message": { "role": "assistant", "content": transcript } } ]
    });
    match execute_jury(pipe_id, jury, &response, secrets).await {
        Ok((JuryVerdict::Approved, usage, _)) => (SafetyVerdict::Allow, usage),
        Ok((JuryVerdict::Rejected(reason), usage, _)) => (
            SafetyVerdict::Block {
                category: category_of(&reason, "jury"),
                reason: format!("output blocked by Jury: {reason}"),
            },
            usage,
        ),
        Err(e) => (
            SafetyVerdict::Block {
                category: category_of(&e.to_string(), "jury"),
                reason: format!("output blocked by Jury: {e}"),
            },
            StageUsage::default(),
        ),
    }
}

/// What the relay should do with the events it just fed the guard.
#[derive(Debug, Default)]
pub struct GuardOutcome {
    /// OpenAI-canonical events to forward to the caller, already safety-processed
    /// (held audio flushed, refusal injected, etc.).
    pub to_client: Vec<Value>,
    /// Set only on the turn-final event: `Some(reason)` when the turn was blocked
    /// (so the caller records a governance Block), `None` when it completed.
    pub block: Option<TurnBlock>,
    /// The jurors' text usage the guard incurred handling this event (a Jury
    /// run at the turn's end, or a BargeIn checkpoint), billed by each
    /// juror's key source; the relay records it to the member's budget.
    pub jury_usage: StageUsage,
}

/// The reason a turn was blocked, for the governance record.
#[derive(Debug, Clone)]
pub struct TurnBlock {
    pub reason: String,
    /// Canonical rejection-category ids of the Jury verdict that blocked the turn.
    pub categories: Vec<String>,
}

/// Per-session realtime safety engine. One guard per relay; fed every
/// OpenAI-canonical event bound for the caller.
pub struct RealtimeGuard {
    pipe_id: String,
    cfg: RealtimeSafetyConfig,
    jury: Option<JuryConfig>,
    secrets: SurfaceSecrets,
    // ── per-turn state ──
    held: Vec<Value>,
    input_transcript: String,
    output_transcript: String,
    last_jury_len: usize,
    turn_block_reason: Option<String>,
    turn_block_category: Option<String>,
    /// Juror usage incurred since the last event was handled.
    jury_usage: StageUsage,
}

impl RealtimeGuard {
    /// Build a guard, or `None` when enforcement is off or nothing to check (so
    /// the relay stays a plain passthrough with zero overhead).
    pub fn new(
        pipe_id: &str,
        cfg: Option<&RealtimeSafetyConfig>,
        _judge: Option<&JudgeConfig>,
        jury: Option<&JuryConfig>,
        secrets: SurfaceSecrets,
    ) -> Option<Self> {
        let cfg = cfg.filter(|c| c.enabled)?;
        let jury_active = jury
            .map(|j| j.enabled)
            .unwrap_or(false);
        if !jury_active {
            return None;
        }
        let mut effective_cfg = cfg.clone();
        effective_cfg.judge = false;
        effective_cfg.jury = true;
        Some(Self {
            pipe_id: pipe_id.to_string(),
            cfg: effective_cfg,
            jury: jury.cloned(),
            secrets,
            held: Vec::new(),
            input_transcript: String::new(),
            output_transcript: String::new(),
            last_jury_len: 0,
            turn_block_reason: None,
            turn_block_category: None,
            jury_usage: StageUsage::default(),
        })
    }

    fn gated(&self) -> bool {
        self.cfg.mode == RealtimeSafetyMode::Gated
    }

    fn refusal(&self) -> String {
        self.cfg
            .refusal_message
            .clone()
            .filter(|m| !m.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_REFUSAL.to_string())
    }

    /// The caller-facing events emitted when a turn is blocked: flush any queued
    /// playback, speak/show the refusal, and terminate the turn. The flush event
    /// carries the rejection category so the relay can stream a matching refusal
    /// clip (round-robin) before the spoken fallback.
    fn block_events(&self) -> Vec<Value> {
        let mut flush = json!({ "type": "output_audio.flush", "reason": "safety" });
        if let Some(cat) = &self.turn_block_category {
            flush["category"] = json!(cat);
        }
        vec![
            flush,
            json!({ "type": "response.audio_transcript.delta", "delta": self.refusal() }),
            json!({ "type": "response.done", "response": { "status": "blocked" } }),
        ]
    }

    /// In Gated mode, the event the caller shows while a just-finished reply is
    /// vetted — emitted *before* the blocking Judge/Jury call so the hold isn't
    /// perceived as a freeze (and the demo can play filler audio meanwhile).
    /// `None` outside a gated turn-end that actually has buffered content to vet.
    pub fn reviewing_event(
        &self,
        ev: &Value,
    ) -> Option<Value> {
        let is_done = ev
            .get("type")
            .and_then(|t| t.as_str())
            == Some("response.done");
        (is_done
            && self.gated()
            && self
                .turn_block_reason
                .is_none()
            && !self.held.is_empty())
        .then(|| json!({ "type": "output_audio.reviewing" }))
    }

    fn reset_turn(&mut self) {
        self.held.clear();
        self.input_transcript.clear();
        self.output_transcript.clear();
        self.last_jury_len = 0;
        self.turn_block_reason = None;
        self.turn_block_category = None;
    }

    /// Feed one OpenAI-canonical upstream event. Returns the events to actually
    /// forward to the caller (after gating), on the turn-final event whether
    /// the turn was blocked (for governance), and the juror usage handling it
    /// incurred (for the member's budget).
    pub async fn on_upstream_event(
        &mut self,
        ev: Value,
    ) -> GuardOutcome {
        let mut outcome = self
            .handle_upstream_event(ev)
            .await;
        outcome.jury_usage = std::mem::take(&mut self.jury_usage);
        outcome
    }

    async fn handle_upstream_event(
        &mut self,
        ev: Value,
    ) -> GuardOutcome {
        let kind = ev
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        match kind.as_str() {
            "conversation.item.input_audio_transcription.completed" => {
                if let Some(t) = ev
                    .get("transcript")
                    .and_then(|t| t.as_str())
                {
                    if !self
                        .input_transcript
                        .is_empty()
                    {
                        self.input_transcript
                            .push(' ');
                    }
                    self.input_transcript
                        .push_str(t);
                }
                self.forward_or_hold(ev)
            }
            "response.audio.delta" | "response.output_audio.delta" => {
                if self.gated() {
                    self.held.push(ev);
                    GuardOutcome::default()
                } else if self
                    .turn_block_reason
                    .is_some()
                {
                    GuardOutcome::default()
                } else {
                    GuardOutcome::forward(vec![ev])
                }
            }
            "response.audio_transcript.delta" | "response.output_audio_transcript.delta" => {
                if let Some(d) = ev
                    .get("delta")
                    .and_then(|d| d.as_str())
                {
                    self.output_transcript
                        .push_str(d);
                }
                if self.gated() {
                    self.held.push(ev);
                    return GuardOutcome::default();
                }
                if self
                    .turn_block_reason
                    .is_some()
                {
                    return GuardOutcome::default();
                }
                // BargeIn: debounced incremental Jury on the growing reply.
                if self
                    .output_transcript
                    .len()
                    .saturating_sub(self.last_jury_len)
                    >= self.cfg.barge_in_min_chars
                {
                    self.last_jury_len = self.output_transcript.len();
                    if let SafetyVerdict::Block { reason, category } = self.run_jury().await {
                        return self.block_now(reason, category);
                    }
                }
                GuardOutcome::forward(vec![ev])
            }
            "response.done" => self.on_turn_end(ev).await,
            _ => self.forward_or_hold(ev),
        }
    }

    /// Non-content control events (session.created, errors, …) pass straight
    /// through; in Gated mode a still-open turn holds nothing here because these
    /// carry no reply content.
    fn forward_or_hold(
        &mut self,
        ev: Value,
    ) -> GuardOutcome {
        if self.gated()
            && self
                .turn_block_reason
                .is_some()
        {
            return GuardOutcome::default();
        }
        GuardOutcome::forward(vec![ev])
    }

    async fn run_jury(&mut self) -> SafetyVerdict {
        let (verdict, usage) =
            jury_output(&self.pipe_id, self.jury.as_ref(), self.cfg.jury, &self.output_transcript, &self.secrets).await;
        self.jury_usage.add(usage);
        verdict
    }

    /// BargeIn block: cut the reply off now (flush + refusal + done) and mark the
    /// turn blocked so its remaining audio is dropped until the turn ends.
    fn block_now(
        &mut self,
        reason: String,
        category: Option<String>,
    ) -> GuardOutcome {
        warn!(reason = %reason, "[PIPE:{}] realtime turn blocked (barge-in)", self.pipe_id);
        self.turn_block_reason = Some(reason);
        self.turn_block_category = category;
        GuardOutcome {
            to_client: self.block_events(),
            block: None,
            jury_usage: StageUsage::default(),
        }
    }

    /// The turn boundary. In Gated mode the held reply is vetted here and either
    /// released whole or discarded for a refusal; in BargeIn mode a final Jury
    /// pass covers the untested tail. Always reports the block reason (if any)
    /// for the governance record.
    async fn on_turn_end(
        &mut self,
        done_ev: Value,
    ) -> GuardOutcome {
        // Already cut off mid-turn (BargeIn): swallow the real done (a synthetic
        // one was already sent) and report the block for governance.
        if let Some(reason) = self.turn_block_reason.clone() {
            let categories = self.block_categories();
            self.reset_turn();
            return GuardOutcome {
                to_client: Vec::new(),
                block: Some(TurnBlock { reason, categories }),
                jury_usage: StageUsage::default(),
            };
        }

        if self.gated() {
            if let SafetyVerdict::Block { reason, category } = self.run_jury().await {
                return self.finish_blocked(reason, category);
            }
            // Passed — release the whole buffered reply, then the terminal event.
            let mut out = std::mem::take(&mut self.held);
            out.push(done_ev);
            self.reset_turn();
            GuardOutcome::forward(out)
        } else {
            // BargeIn: vet the tail after the last incremental checkpoint.
            if self.output_transcript.len() > self.last_jury_len
                && let SafetyVerdict::Block { reason, category } = self.run_jury().await
            {
                self.turn_block_category = category;
                let events = self.block_events();
                let categories = self.block_categories();
                self.reset_turn();
                return GuardOutcome {
                    to_client: events,
                    block: Some(TurnBlock { reason, categories }),
                    jury_usage: StageUsage::default(),
                };
            }
            self.reset_turn();
            GuardOutcome {
                to_client: vec![done_ev],
                block: None,
                jury_usage: StageUsage::default(),
            }
        }
    }

    /// Gated block: discard the buffered reply, emit the refusal, report the block.
    fn finish_blocked(
        &mut self,
        reason: String,
        category: Option<String>,
    ) -> GuardOutcome {
        warn!(reason = %reason, "[PIPE:{}] realtime turn blocked (gated)", self.pipe_id);
        self.turn_block_category = category;
        let events = self.block_events();
        let categories = self.block_categories();
        self.reset_turn();
        GuardOutcome {
            to_client: events,
            block: Some(TurnBlock { reason, categories }),
            jury_usage: StageUsage::default(),
        }
    }

    fn block_categories(&self) -> Vec<String> {
        self.turn_block_category
            .iter()
            .cloned()
            .collect()
    }
}

impl GuardOutcome {
    fn forward(events: Vec<Value>) -> Self {
        Self {
            to_client: events,
            block: None,
            jury_usage: StageUsage::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipes::judge_jury::{JudgeConfig, JuryConfig};

    fn jury(enabled: bool) -> JuryConfig {
        serde_json::from_value(json!({ "enabled": enabled, "jurors": [] })).unwrap()
    }

    fn judge(enabled: bool) -> JudgeConfig {
        serde_json::from_value(json!({
            "enabled": enabled,
            "llm": { "provider_type": "openai", "model": "gpt-4o-mini", "endpoint_url": "/chat/completions" }
        }))
        .unwrap()
    }

    fn safety(mode: RealtimeSafetyMode) -> RealtimeSafetyConfig {
        RealtimeSafetyConfig {
            enabled: true,
            mode,
            judge: true,
            jury: true,
            refusal_message: Some("blocked".to_string()),
            barge_in_min_chars: 4,
        }
    }

    #[test]
    fn guard_absent_when_disabled_or_nothing_to_check() {
        // Disabled → no guard.
        let mut off = safety(RealtimeSafetyMode::Gated);
        off.enabled = false;
        assert!(RealtimeGuard::new("p", Some(&off), Some(&judge(true)), None, SurfaceSecrets::default()).is_none());
        // Enabled but no active Jury → no guard.
        let on = safety(RealtimeSafetyMode::Gated);
        assert!(
            RealtimeGuard::new("p", Some(&on), Some(&judge(false)), Some(&jury(false)), SurfaceSecrets::default())
                .is_none()
        );
        // Enabled with an active jury → guard exists.
        assert!(RealtimeGuard::new("p", Some(&on), None, Some(&jury(true)), SurfaceSecrets::default()).is_some());
    }

    #[test]
    fn default_safety_follows_surface_jury_not_caller_transcript() {
        let cfg = RealtimeSafetyConfig::default();
        assert!(!cfg.judge, "caller transcript Judge is not a realtime safety path");
        assert!(cfg.jury, "legacy field defaults to response-safety compatibility");
    }

    #[test]
    fn guard_ignores_legacy_stage_switches() {
        let mut cfg = safety(RealtimeSafetyMode::Gated);
        cfg.judge = true;
        cfg.jury = false;
        let guard =
            RealtimeGuard::new("p", Some(&cfg), Some(&judge(true)), Some(&jury(true)), SurfaceSecrets::default())
                .unwrap();
        assert!(!guard.cfg.judge, "realtime never runs caller-side Judge");
        assert!(guard.cfg.jury, "enabled realtime response safety follows the surface Jury");
    }

    #[tokio::test]
    async fn gated_holds_audio_until_done_then_releases_when_no_checks_reject() {
        // Jury enabled with no jurors → approves offline; an empty transcript also
        // short-circuits Allow. So the buffered reply is released untouched.
        let cfg = safety(RealtimeSafetyMode::Gated);
        let mut g = RealtimeGuard::new("p", Some(&cfg), None, Some(&jury(true)), SurfaceSecrets::default()).unwrap();

        // Audio is held (nothing forwarded yet).
        let a = g
            .on_upstream_event(json!({ "type": "response.audio.delta", "delta": "AAAA" }))
            .await;
        assert!(a.to_client.is_empty(), "gated must hold audio");
        // done → jury allow → buffered audio released with the terminal event.
        let done = g
            .on_upstream_event(json!({ "type": "response.done" }))
            .await;
        assert!(done.block.is_none(), "empty reply is not blocked");
        assert_eq!(done.to_client.len(), 2, "held audio + done released together");
        assert_eq!(done.to_client[0]["type"], "response.audio.delta");
        assert_eq!(done.to_client[1]["type"], "response.done");
    }

    #[tokio::test]
    async fn gated_passes_control_events_through_immediately() {
        let cfg = safety(RealtimeSafetyMode::Gated);
        let mut g = RealtimeGuard::new("p", Some(&cfg), None, Some(&jury(true)), SurfaceSecrets::default()).unwrap();
        let out = g
            .on_upstream_event(json!({ "type": "session.created", "session": { "id": "x" } }))
            .await;
        assert_eq!(out.to_client.len(), 1, "session.created must pass through so the mic starts");
        assert_eq!(out.to_client[0]["type"], "session.created");
    }

    #[test]
    fn block_events_flush_then_refuse_then_done() {
        let cfg = safety(RealtimeSafetyMode::Gated);
        let g = RealtimeGuard::new("p", Some(&cfg), None, Some(&jury(true)), SurfaceSecrets::default()).unwrap();
        let ev = g.block_events();
        assert_eq!(ev[0]["type"], "output_audio.flush");
        assert_eq!(ev[1]["type"], "response.audio_transcript.delta");
        assert_eq!(ev[1]["delta"], "blocked");
        assert_eq!(ev[2]["type"], "response.done");
        assert_eq!(ev[2]["response"]["status"], "blocked");
    }

    #[tokio::test]
    async fn jury_allows_when_unselected() {
        // apply=false must short-circuit Allow without touching the engine.
        assert_eq!(
            jury_output("p", Some(&jury(true)), false, "hi", &SurfaceSecrets::default()).await,
            (SafetyVerdict::Allow, StageUsage::default())
        );
    }

    #[tokio::test]
    async fn gated_block_discards_reply_and_refuses() {
        let cfg = safety(RealtimeSafetyMode::Gated);
        let mut g = RealtimeGuard::new("p", Some(&cfg), None, Some(&jury(true)), SurfaceSecrets::default()).unwrap();
        // Buffer some reply audio (held, not forwarded).
        let held = g
            .on_upstream_event(json!({ "type": "response.audio.delta", "delta": "AAAA" }))
            .await;
        assert!(held.to_client.is_empty());
        // A Jury rejection at turn end discards the buffered audio and refuses.
        let out = g.finish_blocked("weather is off-limits".to_string(), Some("weather".to_string()));
        assert_eq!(out.to_client.len(), 3, "flush + refusal + done, not the held audio");
        assert_eq!(out.to_client[0]["type"], "output_audio.flush");
        assert_eq!(out.to_client[0]["category"], "weather", "flush carries the category for the refusal bucket");
        assert_eq!(out.to_client[1]["type"], "response.audio_transcript.delta");
        assert_eq!(out.to_client[2]["type"], "response.done");
        assert_eq!(
            out.block
                .as_ref()
                .map(|b| b.reason.as_str()),
            Some("weather is off-limits"),
            "governance sees the block reason"
        );
        assert_eq!(out.block.unwrap().categories, vec!["weather".to_string()], "governance sees the categories");
    }

    #[tokio::test]
    async fn barge_in_cutoff_drops_rest_of_turn_then_reports_block_at_done() {
        let cfg = safety(RealtimeSafetyMode::BargeIn);
        let mut g = RealtimeGuard::new("p", Some(&cfg), None, Some(&jury(true)), SurfaceSecrets::default()).unwrap();
        // Mid-turn cutoff (as the incremental Jury would trigger): flush + refuse.
        let cut = g.block_now("policy".to_string(), Some("weather".to_string()));
        assert_eq!(cut.to_client[0]["type"], "output_audio.flush");
        assert_eq!(cut.to_client[0]["category"], "weather", "flush carries the category");
        assert!(cut.block.is_none(), "block is reported at the turn boundary, not mid-turn");
        // Remaining audio for this turn is dropped.
        let dropped = g
            .on_upstream_event(json!({ "type": "response.audio.delta", "delta": "BBBB" }))
            .await;
        assert!(dropped.to_client.is_empty(), "cut-off turn drops remaining audio");
        // The real done is swallowed (a synthetic one was already sent) and carries
        // the block reason for the governance record.
        let done = g
            .on_upstream_event(json!({ "type": "response.done" }))
            .await;
        assert!(done.to_client.is_empty(), "real done swallowed after cutoff");
        assert_eq!(
            done.block
                .as_ref()
                .map(|b| b.reason.as_str()),
            Some("policy")
        );
        assert_eq!(done.block.unwrap().categories, vec!["weather".to_string()]);
    }

    #[tokio::test]
    async fn gated_emits_reviewing_only_when_a_reply_is_held() {
        let cfg = safety(RealtimeSafetyMode::Gated);
        let mut g = RealtimeGuard::new("p", Some(&cfg), None, Some(&jury(true)), SurfaceSecrets::default()).unwrap();
        // Nothing held yet → a bare done has nothing to review.
        assert!(
            g.reviewing_event(&json!({ "type": "response.done" }))
                .is_none()
        );
        // Hold some reply audio, then the done triggers a "reviewing" signal.
        let _ = g
            .on_upstream_event(json!({ "type": "response.audio.delta", "delta": "AAAA" }))
            .await;
        let rev = g.reviewing_event(&json!({ "type": "response.done" }));
        assert_eq!(
            rev.as_ref()
                .and_then(|v| v["type"].as_str()),
            Some("output_audio.reviewing")
        );
    }

    #[tokio::test]
    async fn a_turns_juror_usage_is_handed_to_the_relay_to_bill() {
        let juror = crate::pipes::test_upstreams::CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
        let _allowed = crate::url_validation::test_service_endpoints::allow(std::slice::from_ref(&juror.url));
        let priced_jury: JuryConfig = serde_json::from_value(json!({
            "enabled": true,
            "jurors": [{
                "name": "juror",
                "system_prompt": "Review.",
                "llm": {
                    "provider_type": "openai",
                    "model": "gpt-4o",
                    "endpoint_url": juror.url,
                    "pricing": { "input_per_million": 1.0, "output_per_million": 2.0 }
                }
            }]
        }))
        .unwrap();
        // The capture upstream reports 1,000 input and 1,000 output tokens.
        let one_call = 1000.0 * 1.0 / 1_000_000.0 + 1000.0 * 2.0 / 1_000_000.0;

        for mode in [RealtimeSafetyMode::Gated, RealtimeSafetyMode::BargeIn] {
            let mut g =
                RealtimeGuard::new("p", Some(&safety(mode)), None, Some(&priced_jury), SurfaceSecrets::default())
                    .unwrap();
            let mut usage = StageUsage::default();
            for ev in [
                json!({ "type": "response.audio_transcript.delta", "delta": "hello there" }),
                json!({ "type": "response.done" }),
            ] {
                let out = g.on_upstream_event(ev).await;
                assert!(out.block.is_none(), "{mode:?}: the juror approved");
                usage.add(out.jury_usage);
            }
            assert_eq!(usage.key_sources.platform, 1, "{mode:?}: one juror call on a keyless (platform) target");
            assert!((usage.cost - one_call).abs() < 1e-12, "{mode:?}: {}", usage.cost);
            assert_eq!(usage.billed_cost, usage.cost, "{mode:?}: a platform juror bills its text usage");
        }
        assert_eq!(juror.requests(), 2);
    }

    #[test]
    fn barge_in_has_no_reviewing_event() {
        let cfg = safety(RealtimeSafetyMode::BargeIn);
        let g = RealtimeGuard::new("p", Some(&cfg), None, Some(&jury(true)), SurfaceSecrets::default()).unwrap();
        assert!(
            g.reviewing_event(&json!({ "type": "response.done" }))
                .is_none()
        );
    }
}
