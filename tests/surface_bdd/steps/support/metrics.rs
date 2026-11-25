use crate::world::SurfaceWorld;

/// Scrape the appliance's Prometheus text endpoint. Each scenario runs its own
/// appliance process, so the returned counters start at zero and reflect only
/// this scenario's appliance.
pub(crate) async fn scrape_prometheus_metrics(world: &SurfaceWorld) -> String {
    let base_url = world
        .infra
        .as_ref()
        .expect("appliance should be running")
        ._appliance
        .base_url();
    reqwest::Client::new()
        .get(format!("{base_url}/v1/metrics/prometheus"))
        .send()
        .await
        .expect("metrics endpoint should respond")
        .text()
        .await
        .expect("metrics body should decode")
}

/// Read a single Prometheus counter value from scraped text, matching a metric
/// name and a subset of its labels. Returns 0.0 when the series is absent (an
/// untouched labeled counter emits no line).
pub(crate) fn metric_value(
    text: &str,
    metric: &str,
    labels: &[(&str, &str)],
) -> f64 {
    text.lines()
        .filter(|line| line.starts_with(metric))
        .find(|line| {
            labels
                .iter()
                .all(|(key, value)| line.contains(&format!("{key}=\"{value}\"")))
        })
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0.0)
}
