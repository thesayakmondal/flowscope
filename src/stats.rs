//! Descriptive statistics over a reconstructed capture.
//!
//! Where `analysis.rs` answers "what went wrong", this module answers
//! "what is in here": how big the capture is, how long TCP handshakes
//! took, and which flows moved the most data. The handshake latency
//! numbers also feed `correlate.rs`, which compares them against what
//! burstgen measured from the client side.

use crate::flow::{Direction, Flow};
use chrono::{DateTime, Utc};
use serde::Serialize;

/// Whole-capture facts for the report header. Filled in by `main.rs`
/// because it combines reader bookkeeping (skipped frames, link types)
/// with flow-level counts.
#[derive(Debug, Serialize)]
pub struct CaptureInfo {
    pub packets: u64,
    /// Frames in the file that were not parsed into packets.
    pub skipped_frames: u64,
    pub link_types: Vec<String>,
    /// The file ended mid-record; analysis covers only what came before.
    pub truncated: bool,
    /// Packets dropped by `--host` / `--port` before analysis.
    pub filtered_out: u64,
    pub first_packet: Option<DateTime<Utc>>,
    pub last_packet: Option<DateTime<Utc>>,
    pub tcp_flows: u64,
    pub udp_flows: u64,
    pub tcp_payload_bytes: u64,
}

/// Wire-level view of TCP connection establishment.
#[derive(Debug, Default, Serialize)]
pub struct HandshakeStats {
    /// Flows containing at least one initial SYN (one per connection
    /// attempt, not per SYN packet — see `detect_unanswered_syns`).
    pub syns_seen: u64,
    /// Flows containing a SYN-ACK from the other side.
    pub syn_acks_seen: u64,
    /// Flows where the initial SYN was sent more than once, i.e. the
    /// client's kernel had to retry.
    pub syn_retried_flows: u64,
    /// Microseconds from a flow's *first* SYN to its first SYN-ACK, one
    /// entry per answered attempt, sorted ascending. Measured from the
    /// first SYN (not the last retry) because that is what a client
    /// calling `connect()` actually waits for — retry backoff included.
    pub latencies_us: Vec<u64>,
}

/// Counts attempts, answers, and times the handshakes. The attempt and
/// SYN-ACK counts are the exact ones `main.rs` used before this module
/// existed: one SYN per flow, one SYN-ACK per flow.
pub fn handshake_stats(flows: &[Flow]) -> HandshakeStats {
    let mut stats = HandshakeStats::default();

    for flow in flows.iter().filter(|f| f.key.protocol_is_tcp) {
        let mut syn_count = 0u32;
        let mut first_syn: Option<DateTime<Utc>> = None;
        let mut first_syn_ack: Option<DateTime<Utc>> = None;

        for (p, d) in &flow.packets {
            if *d == Direction::Forward && p.flags.syn && !p.flags.ack {
                syn_count += 1;
                first_syn.get_or_insert(p.timestamp);
            } else if *d == Direction::Reverse && p.flags.syn && p.flags.ack {
                first_syn_ack.get_or_insert(p.timestamp);
            }
        }

        if syn_count > 0 {
            stats.syns_seen += 1;
        }
        if syn_count > 1 {
            stats.syn_retried_flows += 1;
        }
        if first_syn_ack.is_some() {
            stats.syn_acks_seen += 1;
        }
        if let (Some(syn), Some(ack)) = (first_syn, first_syn_ack) {
            if let Some(us) = (ack - syn).num_microseconds() {
                // A SYN-ACK captured *before* its SYN (clock step, or a
                // capture that started mid-handshake) has no meaningful
                // latency and is left out rather than clamped to 0.
                if us >= 0 {
                    stats.latencies_us.push(us as u64);
                }
            }
        }
    }

    stats.latencies_us.sort_unstable();
    stats
}

/// Nearest-rank percentile of an ascending-sorted slice: the smallest
/// value such that at least `pct` percent of the data is at or below it.
/// Nearest-rank (rather than interpolation) is used so every reported
/// percentile is a value that was actually observed.
pub fn percentile(sorted: &[u64], pct: f64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((pct / 100.0) * sorted.len() as f64).ceil() as usize;
    Some(sorted[rank.clamp(1, sorted.len()) - 1])
}

/// One row of the "top flows" table.
#[derive(Debug, Serialize)]
pub struct FlowSummary {
    pub flow: String,
    /// `ip:port` of the endpoint that sent the flow's first captured
    /// packet — normally the client.
    pub initiator: String,
    pub packets: u64,
    pub payload_bytes: u64,
    pub duration_ms: i64,
}

/// The `n` flows carrying the most payload bytes (ties broken by flow
/// identity so the table is reproducible). Flows with no payload are
/// omitted — a list of empty handshakes is not a "top" anything.
pub fn top_flows(flows: &[Flow], n: usize) -> Vec<FlowSummary> {
    let mut rows: Vec<FlowSummary> = flows
        .iter()
        .map(|f| {
            let payload_bytes: u64 = f.packets.iter().map(|(p, _)| p.payload_len as u64).sum();
            let duration_ms = match (f.packets.first(), f.packets.last()) {
                (Some((a, _)), Some((b, _))) => (b.timestamp - a.timestamp).num_milliseconds(),
                _ => 0,
            };
            FlowSummary {
                flow: f.key.describe(),
                initiator: format!("{}:{}", f.initiator.0, f.initiator.1),
                packets: f.packets.len() as u64,
                payload_bytes,
                duration_ms,
            }
        })
        .filter(|r| r.payload_bytes > 0)
        .collect();

    rows.sort_by(|a, b| {
        b.payload_bytes
            .cmp(&a.payload_bytes)
            .then_with(|| a.flow.cmp(&b.flow))
    });
    rows.truncate(n);
    rows
}

/// Total TCP payload bytes across every flow.
pub fn tcp_payload_bytes(flows: &[Flow]) -> u64 {
    flows
        .iter()
        .filter(|f| f.key.protocol_is_tcp)
        .flat_map(|f| f.packets.iter())
        .map(|(p, _)| p.payload_len as u64)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_nearest_rank() {
        let v: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&v, 50.0), Some(50));
        assert_eq!(percentile(&v, 99.0), Some(99));
        assert_eq!(percentile(&v, 100.0), Some(100));
        assert_eq!(percentile(&v, 0.0), Some(1));
        assert_eq!(percentile(&[7], 99.0), Some(7));
        assert_eq!(percentile(&[], 50.0), None);
    }
}
