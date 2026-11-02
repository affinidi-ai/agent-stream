//! In-process multi-resolution usage telemetry.
//!
//! Records spend, tokens, and request counts for surfaces, pipeline stages,
//! members, and teams into an RRD-style pyramid of fixed resolution tiers
//! (finest 30s, coarsest 1 year). The store is in-memory authoritative with a
//! periodic per-tier JSON snapshot, so the dashboard can plot usage over time at
//! the right resolution for any window from *now* back to roughly a year ago,
//! without an external time-series database. Series keys are namespaced so a
//! future surface type inherits time-series for free by emitting the same
//! `(key, cost, tokens)` samples.

mod store;
mod types;

pub use store::{TelemetryStore, global_telemetry_store, set_global_telemetry_store};
pub use types::SeriesResponse;

use dashmap::DashMap;
use std::sync::{Arc, OnceLock};

use crate::pipes::config::StageUsage;
use crate::pipes::key_source::{KeySource, KeySourceCounts};
use crate::timeseries::KeyMatch;
use types::Sample;

/// Per-pipeline stage labels, in the fixed order used by [`SurfaceKeys::stages`]
/// and the `(llm, judge, jury, decider)` sample tuple.
const STAGE_LABELS: [&str; 4] = ["llm", "judge", "jury", "decider"];

/// Pre-formatted series keys for one surface. The recording path runs on every
/// execution, so the surface grand-total key and the four per-stage keys are
/// computed once per surface and cached rather than re-`format!`-ed each time.
struct SurfaceKeys {
    surface: String,
    /// Per-stage keys in [`STAGE_LABELS`] order: llm, judge, jury, decider.
    stages: [String; 4],
}

/// Compute (without caching) the series keys for a surface. Used by the cache
/// and by series GC.
fn compute_surface_keys(pipe_id: &str) -> SurfaceKeys {
    SurfaceKeys {
        surface: surface_key(pipe_id),
        stages: [
            stage_key(pipe_id, STAGE_LABELS[0]),
            stage_key(pipe_id, STAGE_LABELS[1]),
            stage_key(pipe_id, STAGE_LABELS[2]),
            stage_key(pipe_id, STAGE_LABELS[3]),
        ],
    }
}

/// Process-wide cache of pre-formatted per-surface series keys, keyed by pipe id.
static SURFACE_KEY_CACHE: OnceLock<DashMap<String, Arc<SurfaceKeys>>> = OnceLock::new();

/// Resolve a surface's cached series keys, computing and inserting them on first
/// use. Evicted by [`remove_surface_series`] when the surface is soft-deleted.
fn surface_keys(pipe_id: &str) -> Arc<SurfaceKeys> {
    let cache = SURFACE_KEY_CACHE.get_or_init(DashMap::new);
    if let Some(existing) = cache.get(pipe_id) {
        return existing.clone();
    }
    let keys = Arc::new(compute_surface_keys(pipe_id));
    cache.insert(pipe_id.to_string(), keys.clone());
    keys
}

/// Series key for the appliance-wide aggregate across every surface. Always
/// emitted, so the dashboard can plot total spend/tokens over time from a single
/// series (no client-side fan-in over per-surface keys, which could land on
/// different resolution tiers).
pub fn all_surfaces_key() -> String {
    "surfaces:all".to_string()
}

/// Series key for a whole surface (pipe) — its grand-total spend/tokens.
pub fn surface_key(pipe_id: &str) -> String {
    format!("surface:{pipe_id}")
}

/// Series key for one member's spend/tokens on a single surface. Lets the member
/// view break a member's usage down by surface, mirroring how the team view
/// breaks a team down by member.
pub fn member_surface_key(
    member_id: &str,
    pipe_id: &str,
) -> String {
    format!("member:{member_id}:surface:{pipe_id}")
}

/// Series key for one pipeline stage (`llm` / `judge` / `jury` / `decider`).
pub fn stage_key(
    pipe_id: &str,
    stage: &str,
) -> String {
    format!("surface:{pipe_id}:stage:{stage}")
}

/// Series key for one member's spend/tokens aggregated across every surface.
pub fn member_key(member_id: &str) -> String {
    format!("member:{member_id}")
}

/// Series key for one team's spend/tokens aggregated across every surface.
pub fn team_key(team_id: &str) -> String {
    format!("team:{team_id}")
}

/// Reserved category id recorded once per rejection (in addition to each
/// triggered canonical category) so per-scope rejection *totals* stay accurate
/// even when several categories fire together. Distinct from any real category.
pub const REJECTION_TOTAL_CATEGORY: &str = "_total";

/// Synthetic category recorded when a Judge/Jury rejection is *recovered* by a
/// redrive (the request ultimately succeeded). Distinct from the real content
/// category, which is only attributed when the request is finally blocked. Must
/// match the `redrive` category id declared in the rejection taxonomy so the
/// read endpoint can enumerate it.
pub const REJECTION_REDRIVE_CATEGORY: &str = "redrive";

/// Rejection series key for the appliance-wide count of one category.
pub fn rejection_all_key(category: &str) -> String {
    format!("rejection:all:{category}")
}

/// Rejection series key for one surface and category.
pub fn rejection_surface_key(
    pipe_id: &str,
    category: &str,
) -> String {
    format!("rejection:surface:{pipe_id}:{category}")
}

/// Rejection series key for one surface, pipeline stage, and category.
pub fn rejection_stage_key(
    pipe_id: &str,
    stage: &str,
    category: &str,
) -> String {
    format!("rejection:surface:{pipe_id}:stage:{stage}:{category}")
}

/// Rejection series key for one team and category.
pub fn rejection_team_key(
    team_id: &str,
    category: &str,
) -> String {
    format!("rejection:team:{team_id}:{category}")
}

/// Rejection series key for one member and category (recorded only when a caller
/// resolved to a member).
pub fn rejection_member_key(
    member_id: &str,
    category: &str,
) -> String {
    format!("rejection:member:{member_id}:{category}")
}

/// Build the `(series_key, 0.0, 0)` samples for one content rejection. Each
/// sample carries zero cost/tokens, so [`store::TelemetryStore::record_many`]
/// increments only the `requests` counter — i.e. the rejection *count*. A
/// rejection is counted once under **each** distinct triggered canonical
/// category plus once under the reserved [`REJECTION_TOTAL_CATEGORY`], across the
/// appliance-wide, surface, surface-stage, member (when resolved), and team
/// scopes. Pure (no store access) so the fan-out can be unit-tested directly.
fn build_rejection_samples(
    pipe_id: &str,
    stage_label: &str,
    categories: &[String],
    member_id: Option<&str>,
    team_ids: &[String],
) -> Vec<(String, f64, u64)> {
    let mut cats: Vec<&str> = Vec::with_capacity(categories.len() + 1);
    for c in categories {
        let c = c.as_str();
        if !cats.contains(&c) {
            cats.push(c);
        }
    }
    cats.push(REJECTION_TOTAL_CATEGORY);

    let per_cat = 3 + member_id.is_some() as usize + team_ids.len();
    let mut samples: Vec<(String, f64, u64)> = Vec::with_capacity(cats.len() * per_cat);
    for cat in &cats {
        samples.push((rejection_all_key(cat), 0.0, 0));
        samples.push((rejection_surface_key(pipe_id, cat), 0.0, 0));
        samples.push((rejection_stage_key(pipe_id, stage_label, cat), 0.0, 0));
        if let Some(member) = member_id {
            samples.push((rejection_member_key(member, cat), 0.0, 0));
        }
        for team in team_ids {
            samples.push((rejection_team_key(team, cat), 0.0, 0));
        }
    }
    samples
}

/// Record one content rejection into the time-series store across the
/// appliance-wide, surface, surface-stage, member (when resolved), and team
/// scopes, counted once per distinct triggered category plus a reserved total.
/// No-op when no store is registered (telemetry disabled).
pub async fn record_rejection(
    pipe_id: &str,
    stage_label: &str,
    categories: &[String],
    member_id: Option<&str>,
    team_ids: &[String],
) {
    let Some(store) = global_telemetry_store() else {
        return;
    };
    let samples = build_rejection_samples(pipe_id, stage_label, categories, member_id, team_ids);
    store
        .record_many(&samples, chrono::Utc::now())
        .await;
}

/// Garbage-collect a soft-deleted member's usage series (memory + disk). The
/// member record is retained as `status: deleted`, but its graph can never
/// accrue again, so the series is dropped to bound store growth. Removes both
/// the member grand total and every per-surface (`member:{id}:surface:*`) series.
/// No-op when no telemetry store is registered.
pub async fn remove_member_series(member_id: &str) {
    if let Some(store) = global_telemetry_store() {
        let exact = member_key(member_id);
        let prefix = format!("{exact}:");
        let rejection_prefix = format!("rejection:member:{member_id}:");
        store
            .delete_series_matching(&KeyMatch::Any(vec![
                KeyMatch::Exact(exact),
                KeyMatch::Prefix(prefix),
                KeyMatch::Prefix(rejection_prefix),
            ]))
            .await;
    }
}

/// Garbage-collect a soft-deleted team's usage series (memory + disk).
pub async fn remove_team_series(team_id: &str) {
    if let Some(store) = global_telemetry_store() {
        let exact = team_key(team_id);
        let rejection_prefix = format!("rejection:team:{team_id}:");
        store
            .delete_series_matching(&KeyMatch::Any(vec![KeyMatch::Exact(exact), KeyMatch::Prefix(rejection_prefix)]))
            .await;
    }
}

/// Garbage-collect a soft-deleted surface's usage series — its grand total, every
/// per-stage series, and every member's per-surface series for this surface
/// (memory + disk). Also evicts the surface's cached series keys so a recreated
/// id recomputes them.
pub async fn remove_surface_series(pipe_id: &str) {
    if let Some(cache) = SURFACE_KEY_CACHE.get() {
        cache.remove(pipe_id);
    }
    if let Some(store) = global_telemetry_store() {
        let surface = surface_key(pipe_id);
        let stage_prefix = format!("{surface}:stage:");
        let member_suffix = format!(":surface:{pipe_id}");
        let rejection_prefix = format!("rejection:surface:{pipe_id}:");
        store
            .delete_series_matching(&KeyMatch::Any(vec![
                KeyMatch::Exact(surface),
                KeyMatch::Prefix(stage_prefix),
                KeyMatch::Suffix(member_suffix),
                KeyMatch::Prefix(rejection_prefix),
            ]))
            .await;
    }
}

/// One stage's (or a grand total's) sample: its cost, tokens and one request,
/// with the part of the cost spent on owned keys and the calls by key source.
fn usage_sample(
    cost: f64,
    billed_cost: f64,
    tokens: u64,
    key_sources: KeySourceCounts,
) -> Sample {
    Sample {
        cost,
        tokens,
        requests: 1,
        owned_cost: (cost - billed_cost).max(0.0),
        key_sources,
    }
}

/// Build the samples for one surface execution: the appliance-wide
/// aggregate, the surface grand total, each pipeline stage that actually ran,
/// and the attributed member/team(s) (plus the member's per-surface series)
/// when a caller resolved. Pure (no store access) so the attribution fan-out
/// can be unit-tested directly.
///
/// The grand-total series count the request under the source of the key its
/// main call sent (`key_source`); a stage series counts that stage's model
/// calls by the source of each one's key.
fn build_samples(
    keys: &SurfaceKeys,
    pipe_id: &str,
    stages: [&StageUsage; 4],
    key_source: Option<KeySource>,
    member_id: Option<&str>,
    team_ids: &[String],
) -> Vec<(String, Sample)> {
    let total_cost: f64 = stages
        .iter()
        .map(|s| s.cost)
        .sum();
    let total_billed: f64 = stages
        .iter()
        .map(|s| s.billed_cost)
        .sum();
    let total_tokens: u64 = stages
        .iter()
        .map(|s| s.total_tokens())
        .sum();
    let total = usage_sample(
        total_cost,
        total_billed,
        total_tokens,
        key_source
            .map(KeySourceCounts::one)
            .unwrap_or_default(),
    );
    // surfaces:all + surface grand total + up to 4 stages + (member grand total
    // & member-per-surface) + one per team.
    let mut samples: Vec<(String, Sample)> = Vec::with_capacity(2 + keys.stages.len() + 2 + team_ids.len());
    samples.push((all_surfaces_key(), total));
    samples.push((keys.surface.clone(), total));
    for (key, stage) in keys.stages.iter().zip(stages) {
        if stage.cost > 0.0 || stage.total_tokens() > 0 {
            samples.push((
                key.clone(),
                usage_sample(stage.cost, stage.billed_cost, stage.total_tokens(), stage.key_sources),
            ));
        }
    }
    if let Some(member) = member_id {
        samples.push((member_key(member), total));
        samples.push((member_surface_key(member, pipe_id), total));
    }
    for team in team_ids {
        samples.push((team_key(team), total));
    }
    samples
}

/// Record one surface execution into the time-series store: the appliance-wide
/// aggregate, the surface grand total, each pipeline stage that actually ran,
/// plus the attributed member and team(s) (and the member's per-surface series)
/// when team attribution resolved a caller. Every sample carries its cost, the
/// part of it billed (see [`StageUsage::billed_cost`]) and its key sources;
/// `key_source` is the source of the key the main call sent. No-op when no
/// store is registered (telemetry disabled).
#[allow(clippy::too_many_arguments)]
pub async fn record_pipe_execution(
    pipe_id: &str,
    llm: &StageUsage,
    judge: &StageUsage,
    jury: &StageUsage,
    decider: &StageUsage,
    key_source: Option<KeySource>,
    member_id: Option<&str>,
    team_ids: &[String],
) {
    let Some(store) = global_telemetry_store() else {
        return;
    };
    let keys = surface_keys(pipe_id);
    let samples = build_samples(&keys, pipe_id, [llm, judge, jury, decider], key_source, member_id, team_ids);
    store
        .record_samples(samples, chrono::Utc::now())
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(
        cost: f64,
        billed_cost: f64,
        tokens: u64,
        key_sources: KeySourceCounts,
    ) -> StageUsage {
        StageUsage {
            input_tokens: tokens,
            cost,
            billed_cost,
            key_sources,
            ..Default::default()
        }
    }

    fn sample_keys(samples: &[(String, Sample)]) -> Vec<&str> {
        samples
            .iter()
            .map(|(k, _)| k.as_str())
            .collect()
    }

    fn sample<'a>(
        samples: &'a [(String, Sample)],
        key: &str,
    ) -> &'a Sample {
        &samples
            .iter()
            .find(|(k, _)| k == key)
            .unwrap_or_else(|| panic!("no {key} sample"))
            .1
    }

    #[test]
    fn samples_always_include_surface_total() {
        let keys = compute_surface_keys("p1");
        let idle = StageUsage::default();
        let s = build_samples(&keys, "p1", [&idle, &idle, &idle, &idle], None, None, &[]);
        // Appliance-wide aggregate plus the surface grand total, nothing else.
        assert_eq!(sample_keys(&s), vec!["surfaces:all", "surface:p1"]);
        assert_eq!(sample(&s, "surface:p1").requests, 1);
    }

    #[test]
    fn samples_emit_only_nonzero_stages() {
        let keys = compute_surface_keys("p1");
        let idle = StageUsage::default();
        let llm = usage(1.0, 1.0, 10, KeySourceCounts::one(KeySource::Platform));
        let jury = usage(0.0, 0.0, 5, KeySourceCounts::one(KeySource::Platform));
        let s = build_samples(&keys, "p1", [&llm, &idle, &jury, &idle], Some(KeySource::Platform), None, &[]);
        let keys = sample_keys(&s);
        assert!(keys.contains(&"surfaces:all"));
        assert!(keys.contains(&"surface:p1"));
        assert!(keys.contains(&"surface:p1:stage:llm"));
        assert!(keys.contains(&"surface:p1:stage:jury")); // nonzero tokens
        assert!(!keys.contains(&"surface:p1:stage:judge")); // all-zero, omitted
        assert!(!keys.contains(&"surface:p1:stage:decider"));
    }

    #[test]
    fn samples_attribute_member_and_teams_when_present() {
        let keys = compute_surface_keys("p1");
        let teams = vec!["t1".to_string(), "t2".to_string()];
        let idle = StageUsage::default();
        let llm = usage(2.0, 2.0, 20, KeySourceCounts::one(KeySource::Platform));
        let s = build_samples(&keys, "p1", [&llm, &idle, &idle, &idle], Some(KeySource::Platform), Some("m1"), &teams);
        let sample_keys = sample_keys(&s);
        assert!(sample_keys.contains(&"member:m1"));
        assert!(sample_keys.contains(&"member:m1:surface:p1"));
        assert!(sample_keys.contains(&"team:t1"));
        assert!(sample_keys.contains(&"team:t2"));
        // Member/team carry the grand total, not a stage figure.
        let member = sample(&s, "member:m1");
        assert_eq!((member.cost, member.tokens), (2.0, 20));
    }

    #[test]
    fn samples_split_billed_from_owned_spend_and_count_requests_by_key_source() {
        let keys = compute_surface_keys("p1");
        let idle = StageUsage::default();
        // The main call ran on the customer's own key; the Judge on the platform's.
        let llm = usage(1.0, 0.0, 100, KeySourceCounts::one(KeySource::Customer));
        let judge = usage(0.25, 0.25, 10, KeySourceCounts::one(KeySource::Platform));
        let s = build_samples(&keys, "p1", [&llm, &judge, &idle, &idle], Some(KeySource::Customer), Some("m1"), &[]);

        for key in ["surfaces:all", "surface:p1", "member:m1", "member:m1:surface:p1"] {
            let total = sample(&s, key);
            assert!((total.cost - 1.25).abs() < 1e-9, "{key}: cost stays the catalog spend");
            assert!((total.billed_cost() - 0.25).abs() < 1e-9, "{key}: only the platform call bills");
            assert_eq!(total.key_sources, KeySourceCounts::one(KeySource::Customer), "{key}: by the main call's key");
        }
        let llm_stage = sample(&s, "surface:p1:stage:llm");
        assert_eq!(llm_stage.billed_cost(), 0.0);
        assert_eq!(llm_stage.key_sources, KeySourceCounts::one(KeySource::Customer));
        let judge_stage = sample(&s, "surface:p1:stage:judge");
        assert!((judge_stage.billed_cost() - 0.25).abs() < 1e-9);
        assert_eq!(judge_stage.key_sources, KeySourceCounts::one(KeySource::Platform));
    }

    #[test]
    fn surface_keys_are_cached_and_match_computed() {
        let first = surface_keys("cache-test");
        let second = surface_keys("cache-test");
        // Same cached Arc is returned on repeat lookups.
        assert!(Arc::ptr_eq(&first, &second));
        let computed = compute_surface_keys("cache-test");
        assert_eq!(first.surface, computed.surface);
        assert_eq!(first.stages, computed.stages);
        assert_eq!(first.surface, "surface:cache-test");
        assert_eq!(first.stages[0], "surface:cache-test:stage:llm");
    }

    #[test]
    fn rejection_samples_count_each_category_plus_total() {
        let cats = vec!["hate".to_string(), "toxicity".to_string()];
        let s = build_rejection_samples("p1", "jury", &cats, None, &[]);
        let keys: Vec<&str> = s
            .iter()
            .map(|(k, _, _)| k.as_str())
            .collect();
        // Each category fans out to all-surface, surface, and stage scopes.
        assert!(keys.contains(&"rejection:all:hate"));
        assert!(keys.contains(&"rejection:all:toxicity"));
        assert!(keys.contains(&"rejection:surface:p1:hate"));
        assert!(keys.contains(&"rejection:surface:p1:stage:jury:toxicity"));
        // The reserved total is recorded exactly once per scope.
        assert!(keys.contains(&"rejection:all:_total"));
        assert_eq!(
            keys.iter()
                .filter(|k| **k == "rejection:all:_total")
                .count(),
            1
        );
        // Every sample carries zero cost/tokens so only `requests` increments.
        assert!(
            s.iter()
                .all(|(_, c, t)| *c == 0.0 && *t == 0)
        );
    }

    #[test]
    fn rejection_samples_dedupe_categories() {
        // A duplicated category must not be counted twice in one rejection.
        let cats = vec!["hate".to_string(), "hate".to_string()];
        let s = build_rejection_samples("p1", "judge", &cats, None, &[]);
        let hate_all = s
            .iter()
            .filter(|(k, _, _)| k == "rejection:all:hate")
            .count();
        assert_eq!(hate_all, 1);
    }

    #[test]
    fn rejection_samples_attribute_member_and_teams() {
        let cats = vec!["pii".to_string()];
        let teams = vec!["t1".to_string()];
        let s = build_rejection_samples("p1", "regex_request", &cats, Some("m1"), &teams);
        let keys: Vec<&str> = s
            .iter()
            .map(|(k, _, _)| k.as_str())
            .collect();
        assert!(keys.contains(&"rejection:member:m1:pii"));
        assert!(keys.contains(&"rejection:member:m1:_total"));
        assert!(keys.contains(&"rejection:team:t1:pii"));
        assert!(keys.contains(&"rejection:team:t1:_total"));
    }

    #[test]
    fn redrive_rejection_samples_use_synthetic_category() {
        // A recovered redrive is recorded under the synthetic `redrive`
        // category (plus the reserved total), never a real content category.
        let cats = vec![REJECTION_REDRIVE_CATEGORY.to_string()];
        let s = build_rejection_samples("p1", "jury", &cats, Some("m1"), &["t1".to_string()]);
        let keys: Vec<&str> = s
            .iter()
            .map(|(k, _, _)| k.as_str())
            .collect();
        assert!(keys.contains(&"rejection:all:redrive"));
        assert!(keys.contains(&"rejection:surface:p1:stage:jury:redrive"));
        assert!(keys.contains(&"rejection:member:m1:redrive"));
        assert!(keys.contains(&"rejection:team:t1:redrive"));
        assert!(keys.contains(&"rejection:all:_total"));
        // No real content category leaks into a redrive record.
        assert!(
            !keys
                .iter()
                .any(|k| k.ends_with(":hate") || k.ends_with(":banned_keyword"))
        );
    }
}
