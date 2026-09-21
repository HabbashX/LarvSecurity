//! Cron explainer: parse 5-field cron, describe in words, and compute
//! the next run times by minute-stepping (capped at 366 days out).
//!
//! Supported: `*`, `*/n`, `a-b`, `a-b/n`, lists, month/dow names.
//! No external cron crate — small and explicit.

use chrono::{DateTime, Datelike, Local, Timelike};

use crate::models::ToolkitError;

#[derive(Debug, Clone)]
pub struct Cron {
    pub minute: Vec<u32>,
    pub hour: Vec<u32>,
    pub dom: Vec<u32>,
    pub month: Vec<u32>,
    pub dow: Vec<u32>,
    pub raw: String,
}

fn parse_field(s: &str, lo: u32, hi: u32, names: Option<&[(&str, u32)]>) -> Result<Vec<u32>, ToolkitError> {
    let mut out = Vec::new();
    let s = s.trim().to_lowercase();
    if s.is_empty() {
        return Err(ToolkitError::InvalidInput("empty cron field".into()));
    }
    for part in s.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((r, st)) => (r, st.parse::<u32>().map_err(|_| ToolkitError::InvalidInput(format!("bad step in {part}")))?),
            None => (part, 1),
        };
        if step == 0 {
            return Err(ToolkitError::InvalidInput("step must be >= 1".into()));
        }
        let resolve = |v: &str| -> Result<u32, ToolkitError> {
            if let Some(names) = names {
                for (n, val) in names {
                    if *n == v {
                        return Ok(*val);
                    }
                }
            }
            // Allow 7 as Sunday.
            let mut num: u32 = v.parse().map_err(|_| ToolkitError::InvalidInput(format!("bad value {v}")))?;
            if lo == 0 && hi == 6 && num == 7 {
                num = 0;
            }
            Ok(num)
        };
        let (start, end) = if range == "*" {
            (lo, hi)
        } else if let Some((a, b)) = range.split_once('-') {
            (resolve(a)?, resolve(b)?)
        } else {
            let v = resolve(range)?;
            (v, v)
        };
        if start > end || end > hi || start < lo {
            return Err(ToolkitError::InvalidInput(format!("{part} out of range {lo}-{hi}")));
        }
        let mut v = start;
        while v <= end {
            if (v - start) % step == 0 && !out.contains(&v) {
                out.push(v);
            }
            v += 1;
        }
    }
    out.sort_unstable();
    Ok(out)
}

const MONTHS: &[(&str, u32)] = &[
    ("jan", 1), ("feb", 2), ("mar", 3), ("apr", 4), ("may", 5), ("jun", 6),
    ("jul", 7), ("aug", 8), ("sep", 9), ("oct", 10), ("nov", 11), ("dec", 12),
];
const DOWS: &[(&str, u32)] = &[
    ("sun", 0), ("mon", 1), ("tue", 2), ("wed", 3), ("thu", 4), ("fri", 5), ("sat", 6),
];

pub fn parse_cron(expr: &str) -> Result<Cron, ToolkitError> {
    let fields: Vec<&str> = expr.trim().split_whitespace().collect();
    if fields.len() != 5 {
        return Err(ToolkitError::InvalidInput("cron needs 5 fields: min hour dom month dow".into()));
    }
    Ok(Cron {
        minute: parse_field(fields[0], 0, 59, None)?,
        hour: parse_field(fields[1], 0, 23, None)?,
        dom: parse_field(fields[2], 1, 31, None)?,
        month: parse_field(fields[3], 1, 12, Some(MONTHS))?,
        dow: parse_field(fields[4], 0, 6, Some(DOWS))?,
        raw: expr.trim().to_string(),
    })
}

fn matches(c: &Cron, dt: &DateTime<Local>) -> bool {
    // Standard cron: dom OR dow (when both restricted).
    let dom_star = c.dom.len() == 31;
    let dow_star = c.dow.len() == 7;
    let day_ok = if dom_star && dow_star {
        true
    } else if dom_star {
        c.dow.contains(&dt.weekday().num_days_from_sunday())
    } else if dow_star {
        c.dom.contains(&dt.day())
    } else {
        c.dom.contains(&dt.day()) || c.dow.contains(&dt.weekday().num_days_from_sunday())
    };
    c.minute.contains(&dt.minute())
        && c.hour.contains(&dt.hour())
        && c.month.contains(&dt.month())
        && day_ok
}

/// Next `count` run times after now (minute resolution).
pub fn next_runs(c: &Cron, count: usize) -> Vec<DateTime<Local>> {
    let mut out = Vec::new();
    let mut dt = Local::now() + chrono::Duration::minutes(1);
    dt = dt.with_second(0).unwrap().with_nanosecond(0).unwrap();
    for _ in 0..527040 {
        if matches(c, &dt) {
            out.push(dt);
            if out.len() >= count {
                break;
            }
        }
        dt += chrono::Duration::minutes(1);
    }
    out
}

pub fn describe(c: &Cron) -> String {
    fn part(vals: &[u32], lo: u32, hi: u32, unit: &str) -> String {
        if vals.len() as u32 == hi - lo + 1 {
            format!("every {unit}")
        } else if vals.len() == 1 {
            format!("at {} {}", vals[0], unit.trim_end_matches('s'))
        } else {
            format!("at {} {}s {}", vals.len(), unit.trim_end_matches('s'), vals.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(","))
        }
    }
    format!(
        "Runs {} · {} · day-of-month {} · month {} · weekday {}.",
        part(&c.minute, 0, 59, "minutes"),
        part(&c.hour, 0, 23, "hours"),
        if c.dom.len() == 31 { "every day".into() } else { c.dom.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",") },
        if c.month.len() == 12 { "every month".into() } else { c.month.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",") },
        if c.dow.len() == 7 { "every weekday".into() } else { c.dow.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(",") },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daily_midnight() {
        let c = parse_cron("0 0 * * *").unwrap();
        let runs = next_runs(&c, 2);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].hour(), 0);
        assert_eq!(runs[0].minute(), 0);
        assert!(runs[1] > runs[0]);
    }

    #[test]
    fn invalid_rejected() {
        assert!(parse_cron("* * *").is_err());
        assert!(parse_cron("61 * * * *").is_err());
        assert!(parse_cron("*/0 * * * *").is_err());
    }

    #[test]
    fn names_and_lists() {
        let c = parse_cron("*/15 9-17 * * mon-fri").unwrap();
        assert!(c.minute.contains(&30));
        assert!(c.dow.contains(&1) && !c.dow.contains(&0));
    }
}
