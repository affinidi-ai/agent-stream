//! The monthly window a member's caps are measured over.
//!
//! Without an anchor a member's period is the UTC calendar month. With one, it
//! is the monthly anniversary of the anchor: an anchor of 27 September 09:14
//! gives periods starting on the 27th of every month at 09:14. Each boundary is
//! derived from the anchor itself, so an anchor on the 31st clamps to the last
//! day of shorter months and returns to the 31st afterwards.

use chrono::{DateTime, Datelike, Months, TimeZone, Utc};
use serde::Serialize;

/// A half-open `[start, end)` budget window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BudgetPeriod {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl BudgetPeriod {
    /// The window containing `now`.
    pub fn containing(
        anchor: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Self {
        match anchor {
            Some(anchor) => anniversary(anchor, now),
            None => calendar_month(now),
        }
    }
}

fn calendar_month(now: DateTime<Utc>) -> BudgetPeriod {
    let start = Utc
        .with_ymd_and_hms(now.year(), now.month(), 1, 0, 0, 0)
        .single()
        .unwrap_or(now);
    BudgetPeriod {
        start,
        end: start
            .checked_add_months(Months::new(1))
            .unwrap_or(start),
    }
}

fn shift(
    anchor: DateTime<Utc>,
    months: i64,
) -> Option<DateTime<Utc>> {
    let magnitude = Months::new(u32::try_from(months.unsigned_abs()).ok()?);
    if months >= 0 {
        anchor.checked_add_months(magnitude)
    } else {
        anchor.checked_sub_months(magnitude)
    }
}

fn anniversary(
    anchor: DateTime<Utc>,
    now: DateTime<Utc>,
) -> BudgetPeriod {
    let mut months = i64::from(now.year() - anchor.year()) * 12 + i64::from(now.month()) - i64::from(anchor.month());
    let mut start = shift(anchor, months);
    if start.is_some_and(|s| s > now) {
        months -= 1;
        start = shift(anchor, months);
    }
    match (start, shift(anchor, months + 1)) {
        (Some(start), Some(end)) => BudgetPeriod { start, end },
        _ => calendar_month(now),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn no_anchor_is_the_calendar_month() {
        let p = BudgetPeriod::containing(None, at("2026-09-27T13:00:00Z"));
        assert_eq!(p.start, at("2026-09-01T00:00:00Z"));
        assert_eq!(p.end, at("2026-10-01T00:00:00Z"));
    }

    #[test]
    fn an_anchor_measures_from_its_monthly_anniversary() {
        let anchor = Some(at("2026-09-27T09:14:00Z"));
        let p = BudgetPeriod::containing(anchor, at("2026-10-03T00:00:00Z"));
        assert_eq!(p.start, at("2026-09-27T09:14:00Z"));
        assert_eq!(p.end, at("2026-10-27T09:14:00Z"));
    }

    #[test]
    fn the_boundary_instant_starts_the_next_period() {
        let anchor = Some(at("2026-09-27T09:14:00Z"));
        let before = BudgetPeriod::containing(anchor, at("2026-10-27T09:13:59Z"));
        let on = BudgetPeriod::containing(anchor, at("2026-10-27T09:14:00Z"));
        assert_eq!(before.end, on.start);
        assert_eq!(on.start, at("2026-10-27T09:14:00Z"));
    }

    #[test]
    fn earlier_in_the_month_than_the_anchor_day_is_last_months_period() {
        let anchor = Some(at("2026-01-20T00:00:00Z"));
        let p = BudgetPeriod::containing(anchor, at("2026-09-05T00:00:00Z"));
        assert_eq!(p.start, at("2026-08-20T00:00:00Z"));
        assert_eq!(p.end, at("2026-09-20T00:00:00Z"));
    }

    #[test]
    fn a_31st_anchor_clamps_in_short_months_and_recovers() {
        let anchor = Some(at("2026-01-31T00:00:00Z"));
        let feb = BudgetPeriod::containing(anchor, at("2026-03-10T00:00:00Z"));
        assert_eq!(feb.start, at("2026-02-28T00:00:00Z"));
        assert_eq!(feb.end, at("2026-03-31T00:00:00Z"));
        let apr = BudgetPeriod::containing(anchor, at("2026-04-15T00:00:00Z"));
        assert_eq!(apr.start, at("2026-03-31T00:00:00Z"));
        assert_eq!(apr.end, at("2026-04-30T00:00:00Z"));
    }

    #[test]
    fn a_future_anchor_counts_backwards() {
        let anchor = Some(at("2027-03-10T00:00:00Z"));
        let p = BudgetPeriod::containing(anchor, at("2026-09-15T00:00:00Z"));
        assert_eq!(p.start, at("2026-09-10T00:00:00Z"));
        assert_eq!(p.end, at("2026-10-10T00:00:00Z"));
    }

    #[test]
    fn every_instant_falls_inside_its_period() {
        let anchor = Some(at("2025-12-31T23:59:59Z"));
        let mut now = at("2026-01-01T00:00:00Z");
        while now < at("2027-01-01T00:00:00Z") {
            let p = BudgetPeriod::containing(anchor, now);
            assert!(p.start <= now && now < p.end, "{now} not in {p:?}");
            now += chrono::Duration::hours(7);
        }
    }
}
