//! Cross-correlation against a burstgen `events.json`.
//!
//! This module is what turns flowscope from "a standalone pcap analyzer"
//! into burstgen's actual verification partner. burstgen reports what it
//! *believes* it sent and, via kernel counters, what the target
//! *believes* happened. flowscope reconstructs what the wire *shows*
//! happened, from a source (packet bytes) that has no code path in common
//! with either of burstgen's self-reports. When the two agree, that
//! agreement is real evidence, not two views of the same measurement.
//!
//! Only a minimal, read-only subset of burstgen's event schema is
//! reproduced here (just enough to extract counts) — this module does
//! not depend on the burstgen crate itself, since the two tools are
//! meant to be usable independently and shipped as separate repos.

use crate::stats::{percentile, HandshakeStats};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Mirrors the shape of one line of burstgen's `events.json` closely
/// enough to extract the fields flowscope needs, without depending on
/// burstgen's crate. Fields flowscope doesn't use are captured by
/// `serde`'s default behavior of ignoring unknown fields — this struct
/// intentionally does not need to track burstgen's schema exactly, only
/// the `type` discriminant and the couple of fields under it that matter
/// here.
#[derive(Debug, Deserialize)]
struct BurstgenEvent {
    kind: BurstgenEventKind,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum BurstgenEventKind {
    ConnectAttempt {
        #[allow(dead_code)]
        conn_id: u64,
    },
    ConnectResult {
        success: bool,
        #[serde(default)]
        latency_us: u64,
    },
    // Every other burstgen event variant is irrelevant to correlation
    // and deliberately not modeled — serde skips whatever doesn't match
    // a known variant tag rather than failing the whole parse, so this
    // stays forward-compatible with burstgen event types added later.
    #[serde(other)]
    Other,
}

/// The numbers pulled out of a burstgen events.json that are meaningful
/// to compare against flowscope's own wire-level reconstruction.
#[derive(Debug, Default)]
pub struct BurstgenSummary {
    pub connect_attempts: u64,
    pub connect_successes: u64,
    pub connect_failures: u64,
    /// `latency_us` of every successful connect, ascending. Zero is
    /// excluded: the field defaults to 0 when a burstgen version did not
    /// record it, and a successful connect cannot genuinely take 0us, so
    /// keeping those would drag every percentile toward zero.
    pub connect_latencies_us: Vec<u64>,
}

pub fn load_burstgen_summary(path: &Path) -> Result<BurstgenSummary> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read burstgen events file: {}", path.display()))?;
    let events: Vec<BurstgenEvent> = serde_json::from_str(&contents)
        .context("failed to parse burstgen events.json — is this the right file?")?;

    let mut summary = BurstgenSummary::default();
    for event in events {
        match event.kind {
            BurstgenEventKind::ConnectAttempt { .. } => summary.connect_attempts += 1,
            BurstgenEventKind::ConnectResult {
                success,
                latency_us,
            } => {
                if success {
                    summary.connect_successes += 1;
                    if latency_us > 0 {
                        summary.connect_latencies_us.push(latency_us);
                    }
                } else {
                    summary.connect_failures += 1;
                }
            }
            BurstgenEventKind::Other => {}
        }
    }

    summary.connect_latencies_us.sort_unstable();
    Ok(summary)
}

/// One line of the correlation report: a burstgen-reported number next
/// to flowscope's independently-derived equivalent, with the difference
/// called out explicitly rather than left for the reader to compute.
pub struct Correlation {
    pub label: String,
    pub burstgen_value: u64,
    pub flowscope_value: u64,
}

impl Correlation {
    pub fn difference(&self) -> i64 {
        self.flowscope_value as i64 - self.burstgen_value as i64
    }

    pub fn agrees_within(&self, tolerance_pct: f64) -> bool {
        if self.burstgen_value == 0 {
            return self.flowscope_value == 0;
        }
        let pct_diff = (self.difference().abs() as f64 / self.burstgen_value as f64) * 100.0;
        pct_diff <= tolerance_pct
    }
}

/// Builds the correlation table: burstgen's self-reported connection
/// counts against flowscope's counts of actual SYNs and SYN-ACKs seen on
/// the wire for TCP flows. `syns_seen` and `syn_acks_seen` are computed
/// by the caller from the reconstructed flows (see `main.rs`), since
/// that computation depends on `flow::Flow`, which this module
/// deliberately doesn't import — keeping the burstgen-schema concerns and
/// the flow-analysis concerns in separate modules.
pub fn build_correlations(
    burstgen: &BurstgenSummary,
    syns_seen: u64,
    syn_acks_seen: u64,
) -> Vec<Correlation> {
    vec![
        Correlation {
            label: "Connection attempts (burstgen count vs. SYNs seen on wire)".to_string(),
            burstgen_value: burstgen.connect_attempts,
            flowscope_value: syns_seen,
        },
        Correlation {
            label: "Successful connections (burstgen count vs. SYN-ACKs seen on wire)".to_string(),
            burstgen_value: burstgen.connect_successes,
            flowscope_value: syn_acks_seen,
        },
    ]
}

/// One percentile of connect latency, burstgen's number beside the wire's.
///
/// Deliberately **not** given an agrees/mismatch verdict, unlike the count
/// correlations. The two numbers measure different spans: burstgen times
/// `connect()` as the client process sees it (including scheduling and
/// syscall overhead), while flowscope times first-SYN to SYN-ACK at the
/// capture point. The wire figure should not exceed the client's, but how
/// much smaller it is depends on the host, so no fixed tolerance would be
/// honest. The pair is reported so a reader can judge the gap.
pub struct LatencyComparison {
    pub label: String,
    pub burstgen_us: u64,
    pub wire_us: u64,
}

impl LatencyComparison {
    /// `wire - burstgen`, negative when the wire is faster (the expected
    /// direction).
    pub fn difference_us(&self) -> i64 {
        self.wire_us as i64 - self.burstgen_us as i64
    }
}

/// p50 and p99 connect latency from both sources. Empty when either side
/// has no latency samples (e.g. an events file from a burstgen build that
/// did not record `latency_us`, or a capture with no completed handshakes).
pub fn build_latency_comparisons(
    burstgen: &BurstgenSummary,
    handshakes: &HandshakeStats,
) -> Vec<LatencyComparison> {
    let mut out = Vec::new();
    for (label, pct) in [("p50", 50.0), ("p99", 99.0)] {
        if let (Some(b), Some(w)) = (
            percentile(&burstgen.connect_latencies_us, pct),
            percentile(&handshakes.latencies_us, pct),
        ) {
            out.push(LatencyComparison {
                label: format!("Connect latency {label} (burstgen connect() vs. wire SYN→SYN-ACK)"),
                burstgen_us: b,
                wire_us: w,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_counts_and_latencies() {
        let json = r#"[
          {"kind":{"type":"connect_attempt","conn_id":1}},
          {"kind":{"type":"connect_result","success":true,"latency_us":120}},
          {"kind":{"type":"connect_attempt","conn_id":2}},
          {"kind":{"type":"connect_result","success":false,"latency_us":999999}},
          {"kind":{"type":"connect_result","success":true}},
          {"kind":{"type":"something_new","x":1}}
        ]"#;
        let dir = std::env::temp_dir().join(format!("flowscope-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.json");
        std::fs::write(&path, json).unwrap();
        let s = load_burstgen_summary(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(s.connect_attempts, 2);
        assert_eq!(s.connect_successes, 2);
        assert_eq!(s.connect_failures, 1);
        // failure latency excluded; success with missing latency excluded
        assert_eq!(s.connect_latencies_us, vec![120]);
    }

    #[test]
    fn agrees_within_handles_zero_baseline() {
        let c = Correlation {
            label: String::new(),
            burstgen_value: 0,
            flowscope_value: 0,
        };
        assert!(c.agrees_within(5.0));
        let c = Correlation {
            label: String::new(),
            burstgen_value: 0,
            flowscope_value: 1,
        };
        assert!(!c.agrees_within(5.0));
        let c = Correlation {
            label: String::new(),
            burstgen_value: 100,
            flowscope_value: 104,
        };
        assert!(c.agrees_within(5.0));
        let c = Correlation {
            label: String::new(),
            burstgen_value: 100,
            flowscope_value: 106,
        };
        assert!(!c.agrees_within(5.0));
    }
}
