//! Anomaly detection.
//!
//! Takes reconstructed flows and flags six specific, narrowly-defined
//! patterns rather than trying to be a general "is something wrong"
//! classifier:
//!
//! - **Retransmit storms**: several retransmissions on one flow clustered
//!   in time, the wire-level signature of sustained loss or a backlog
//!   that's dropping segments under load (this is the TCP-layer view of
//!   the same event burstgen's `--collect-target-stats` sees at the
//!   kernel-counter layer — the two are meant to corroborate each other).
//! - **Unanswered SYNs**: a SYN with no matching SYN-ACK within a
//!   timeout, the wire-level signature of a connection attempt that the
//!   target's accept path silently dropped — the direct pcap-level
//!   evidence for the same failure burstgen's `ListenOverflows` counter
//!   reports from inside the kernel.
//! - **Out-of-order bursts**: several segments arriving with a lower
//!   sequence number than one already seen, clustered in time — evidence
//!   of packet reordering, relevant to micro-burst testing in particular
//!   since reordering under a burst can trigger unnecessary fast
//!   retransmits even when nothing was actually lost.
//! - **Connection resets**: a flow torn down by RST rather than by FIN —
//!   either refused outright (RST in reply to the SYN: closed port, or a
//!   full accept queue with `tcp_abort_on_overflow`) or aborted
//!   mid-connection.
//! - **Duplicate-ACK bursts**: a run of identical pure ACKs, the receiver
//!   telling the sender "I'm still missing the same byte" — the signal
//!   that triggers fast retransmit (RFC 5681 uses three).
//! - **Zero-window stalls**: a receiver advertising a zero receive
//!   window, i.e. the *application* on that end is not reading and the
//!   sender is blocked. Distinguishes "the network is lossy" from "the
//!   target is slow to drain its socket".
//!
//! Each detector is intentionally narrow and named for the specific
//! mechanism it finds, rather than a single fuzzy "severity score" —
//! a narrow, correctly-labeled finding is something a reader can verify
//! against the raw packets; a vague severity number is not.

use crate::flow::{Direction, Flow};
use crate::packet::Packet;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub flow_description: String,
    pub kind: FindingKind,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub count: u32,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    RetransmitStorm,
    UnansweredSyn,
    OutOfOrderBurst,
    ConnectionReset,
    DuplicateAckBurst,
    ZeroWindowStall,
}

impl FindingKind {
    /// Every kind, in report order.
    pub const ALL: [FindingKind; 6] = [
        FindingKind::RetransmitStorm,
        FindingKind::UnansweredSyn,
        FindingKind::OutOfOrderBurst,
        FindingKind::ConnectionReset,
        FindingKind::DuplicateAckBurst,
        FindingKind::ZeroWindowStall,
    ];

    /// Human-readable heading used in the Markdown report.
    pub fn label(self) -> &'static str {
        match self {
            FindingKind::RetransmitStorm => "Retransmit storm",
            FindingKind::UnansweredSyn => "Unanswered SYN",
            FindingKind::OutOfOrderBurst => "Out-of-order burst",
            FindingKind::ConnectionReset => "Connection reset",
            FindingKind::DuplicateAckBurst => "Duplicate-ACK burst",
            FindingKind::ZeroWindowStall => "Zero-window stall",
        }
    }

    /// Stable machine name used in the CSV `kind` column and JSON output.
    pub fn slug(self) -> &'static str {
        match self {
            FindingKind::RetransmitStorm => "retransmit_storm",
            FindingKind::UnansweredSyn => "unanswered_syn",
            FindingKind::OutOfOrderBurst => "out_of_order_burst",
            FindingKind::ConnectionReset => "connection_reset",
            FindingKind::DuplicateAckBurst => "duplicate_ack_burst",
            FindingKind::ZeroWindowStall => "zero_window_stall",
        }
    }
}

pub struct AnalysisConfig {
    pub retransmit_threshold: u32,
    pub retransmit_window_ms: i64,
    pub ooo_threshold: u32,
    pub ooo_window_ms: i64,
    pub syn_ack_timeout_ms: i64,
    pub dupack_threshold: u32,
    pub dupack_window_ms: i64,
    pub zero_window_min_ms: i64,
}

/// Runs all detectors over every flow and returns the combined finding
/// list, sorted by first occurrence so the report reads in roughly
/// chronological order rather than grouped arbitrarily by flow. Ties on
/// timestamp are broken by flow identity and kind so identical input
/// always yields byte-identical output.
pub fn analyze(flows: &[Flow], config: &AnalysisConfig) -> Vec<Finding> {
    let mut findings = Vec::new();

    for flow in flows {
        if !flow.key.protocol_is_tcp {
            continue;
        }
        let description = flow.key.describe();

        // Retransmits and out-of-order segments come from one pass so a
        // segment is only ever classified as one or the other.
        let segments = classify_segments(flow);
        findings.extend(cluster_and_flag(
            segments.retransmits,
            config.retransmit_threshold,
            config.retransmit_window_ms,
            &description,
            FindingKind::RetransmitStorm,
            |n| {
                format!(
                    "{n} retransmitted segments within {}ms of each other",
                    config.retransmit_window_ms
                )
            },
        ));
        findings.extend(cluster_and_flag(
            segments.out_of_order,
            config.ooo_threshold,
            config.ooo_window_ms,
            &description,
            FindingKind::OutOfOrderBurst,
            |n| {
                format!(
                    "{n} out-of-order segments within {}ms of each other",
                    config.ooo_window_ms
                )
            },
        ));

        findings.extend(detect_unanswered_syns(flow, config));
        findings.extend(detect_connection_resets(flow));
        findings.extend(detect_duplicate_ack_bursts(flow, config));
        findings.extend(detect_zero_window_stalls(flow, config));
    }

    findings.sort_by(|a, b| {
        a.first_seen
            .cmp(&b.first_seen)
            .then_with(|| a.flow_description.cmp(&b.flow_description))
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.last_seen.cmp(&b.last_seen))
    });
    findings
}

/// `a` comes before `b` in TCP sequence space. Sequence numbers are
/// 32-bit and wrap, so a plain `a < b` calls every segment after the
/// wrap "out of order" — the signed difference is the standard
/// (RFC 1982 serial-number) comparison and is correct as long as the two
/// numbers are within 2^31 of each other, which holds for any window
/// TCP can actually use.
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Groups a sorted list of anomaly timestamps into clusters where
/// consecutive timestamps are no more than `window_ms` apart, emitting
/// one finding per cluster that meets `threshold`. This clustering logic
/// is shared between the retransmit and out-of-order detectors since
/// both reduce to "several of event X close together in time" — only
/// what counts as "event X" differs between them.
fn cluster_and_flag(
    mut timestamps: Vec<DateTime<Utc>>,
    threshold: u32,
    window_ms: i64,
    flow_description: &str,
    kind: FindingKind,
    detail_fmt: impl Fn(u32) -> String,
) -> Vec<Finding> {
    timestamps.sort_unstable();
    let mut findings = Vec::new();
    let mut cluster_start_idx = 0;

    for i in 1..=timestamps.len() {
        let cluster_broke = i == timestamps.len()
            || (timestamps[i] - timestamps[i - 1]).num_milliseconds() > window_ms;

        if cluster_broke {
            let cluster = &timestamps[cluster_start_idx..i];
            if cluster.len() as u32 >= threshold {
                findings.push(Finding {
                    flow_description: flow_description.to_string(),
                    kind,
                    first_seen: cluster[0],
                    last_seen: *cluster.last().unwrap(),
                    count: cluster.len() as u32,
                    detail: detail_fmt(cluster.len() as u32),
                });
            }
            cluster_start_idx = i;
        }
    }

    findings
}

/// Per-flow result of walking the data segments once.
#[derive(Default)]
struct SegmentEvents {
    retransmits: Vec<DateTime<Utc>>,
    out_of_order: Vec<DateTime<Utc>>,
}

/// Classifies every payload-carrying segment, per direction, as new
/// in-order data, a retransmission, or out-of-order.
///
/// A **retransmission** is a segment whose sequence number, in a given
/// direction, was already seen earlier in the flow. This catches exact
/// retransmits (the common case for bulk-send loss recovery); it does not
/// attempt to detect partial / overlapping retransmits with different
/// segment boundaries, which would require full byte-range tracking
/// rather than a seen-seq set — a reasonable scope given the traffic
/// burstgen actually generates (fixed-size chunks at a steady rate, not
/// variable-size application framing).
///
/// A segment is **out-of-order** if it is *new* (not a retransmission) yet
/// its sequence number is lower than the highest already observed in that
/// direction — it arrived after a segment that logically follows it.
/// Retransmissions are deliberately excluded: a resent earlier segment
/// also has a sequence number below the maximum, and counting it here as
/// well reported the same packets twice, once as a storm and again as a
/// reordering burst. Caveat inherent to observing from one point: if the
/// original transmission was lost *before* the capture point, its
/// retransmission is the first copy seen and will look out-of-order.
///
/// Both directions are tracked separately since forward and reverse
/// traffic are logically independent streams sharing one flow record.
fn classify_segments(flow: &Flow) -> SegmentEvents {
    let mut seen = [HashSet::<u32>::new(), HashSet::<u32>::new()];
    let mut max_seq: [Option<u32>; 2] = [None, None];
    let mut events = SegmentEvents::default();

    for (packet, direction) in &flow.packets {
        if packet.payload_len == 0 {
            continue;
        }
        let d = dir_index(*direction);

        if !seen[d].insert(packet.seq) {
            events.retransmits.push(packet.timestamp);
            continue;
        }
        match max_seq[d] {
            Some(m) if seq_lt(packet.seq, m) => events.out_of_order.push(packet.timestamp),
            Some(m) if seq_lt(m, packet.seq) => max_seq[d] = Some(packet.seq),
            Some(_) => {}
            None => max_seq[d] = Some(packet.seq),
        }
    }

    events
}

fn dir_index(d: Direction) -> usize {
    match d {
        Direction::Forward => 0,
        Direction::Reverse => 1,
    }
}

fn endpoint(p: &Packet) -> String {
    format!("{}:{}", p.src_ip, p.src_port)
}

/// A SYN is "unanswered" if the flow contains at least one pure SYN (SYN
/// set, ACK not set — the initial connection attempt) sent by the
/// initiator, and no SYN+ACK ever arrives from the other side. This is
/// the direct packet-level evidence for exactly the failure burstgen's
/// `ListenOverflows` counter reports from inside the target's kernel — a
/// capture showing several of these alongside a burstgen report showing
/// a non-zero `ListenOverflows` delta is two independent tools agreeing
/// on the same failure.
///
/// One finding per *flow*, not per SYN packet: when a target silently
/// drops a SYN, the client's own TCP stack retransmits it several times
/// (Linux's default is a handful of retries with exponential backoff)
/// before giving up — all of those retransmissions belong to the same
/// logical connection attempt on the same flow (same 4-tuple, since the
/// client doesn't pick a new ephemeral port to retry). Flagging each
/// retransmitted SYN as its own finding would inflate the count by
/// roughly the retry factor (observed ~6x in testing) and make
/// `syns_seen` in the correlation table disagree with burstgen's
/// per-attempt count for a reason that has nothing to do with an actual
/// discrepancy between the two tools — it would just be double-counting
/// retries. Grouping by flow avoids that: the correlation in
/// `correlate.rs` counts one SYN per flow for the same reason.
fn detect_unanswered_syns(flow: &Flow, config: &AnalysisConfig) -> Vec<Finding> {
    let initial_syns: Vec<&Packet> = flow
        .packets
        .iter()
        .filter(|(p, d)| *d == Direction::Forward && p.flags.syn && !p.flags.ack)
        .map(|(p, _)| p)
        .collect();

    let Some(first_syn) = initial_syns.first() else {
        return Vec::new();
    };

    let got_syn_ack = flow.packets.iter().any(|(p, d)| {
        *d == Direction::Reverse
            && p.flags.syn
            && p.flags.ack
            && p.timestamp >= first_syn.timestamp
            && (p.timestamp - first_syn.timestamp).num_milliseconds() <= config.syn_ack_timeout_ms
    });

    if got_syn_ack {
        return Vec::new();
    }

    // A SYN answered by an RST was refused, not silently dropped. That is
    // reported once, as a `ConnectionReset`, instead of also appearing
    // here — otherwise one failed attempt would be two findings, and
    // "silently dropped" would be claimed for a target that actively
    // said no.
    let refused = flow.packets.iter().any(|(p, d)| {
        *d == Direction::Reverse && p.flags.rst && p.timestamp >= first_syn.timestamp
    });
    if refused {
        return Vec::new();
    }

    let last_syn = initial_syns.last().unwrap();
    vec![Finding {
        flow_description: flow.key.describe(),
        kind: FindingKind::UnansweredSyn,
        first_seen: first_syn.timestamp,
        last_seen: last_syn.timestamp,
        count: initial_syns.len() as u32,
        detail: format!(
            "{} SYN attempt(s) (including kernel retransmits) between {} and {}, none received a SYN-ACK within {}ms",
            initial_syns.len(),
            first_syn.timestamp.to_rfc3339(),
            last_syn.timestamp.to_rfc3339(),
            config.syn_ack_timeout_ms
        ),
    }]
}

/// One finding per flow that was ended or refused by RST, split by what
/// the packets show:
///
/// - **refused**: the initiator's SYN was answered by an RST instead of a
///   SYN-ACK. This is what a closed port does, and also what a full
///   accept queue does when `tcp_abort_on_overflow` is set — the loud
///   counterpart of the silent drop `UnansweredSyn` reports.
/// - **aborted**: an RST after the handshake, before either side sent a
///   FIN — a peer or middlebox killing an established connection.
///
/// An RST that arrives *after* a FIN is deliberately **not** flagged. It
/// is the ordinary way a socket closes when it still has unread data or
/// uses `SO_LINGER` 0, and flagging it would drown real aborts in noise
/// on perfectly healthy captures.
fn detect_connection_resets(flow: &Flow) -> Vec<Finding> {
    let rsts: Vec<(usize, &Packet, Direction)> = flow
        .packets
        .iter()
        .enumerate()
        .filter(|(_, (p, _))| p.flags.rst)
        .map(|(i, (p, d))| (i, p, *d))
        .collect();

    let Some(&(first_idx, first_rst, first_dir)) = rsts.first() else {
        return Vec::new();
    };
    let before = &flow.packets[..first_idx];

    if before.iter().any(|(p, _)| p.flags.fin) {
        return Vec::new();
    }

    let saw_syn = before
        .iter()
        .any(|(p, d)| *d == Direction::Forward && p.flags.syn && !p.flags.ack);
    let saw_syn_ack = before
        .iter()
        .any(|(p, d)| *d == Direction::Reverse && p.flags.syn && p.flags.ack);

    let who = endpoint(first_rst);
    let detail = if saw_syn && !saw_syn_ack && first_dir == Direction::Reverse {
        format!("connection refused: SYN answered with RST from {who}")
    } else if !saw_syn_ack && first_dir == Direction::Forward && saw_syn {
        format!("initiator {who} reset the connection before the handshake completed")
    } else {
        let role = if first_dir == Direction::Forward {
            "initiator"
        } else {
            "responder"
        };
        format!("established connection aborted: RST from {role} {who} with no preceding FIN")
    };

    vec![Finding {
        flow_description: flow.key.describe(),
        kind: FindingKind::ConnectionReset,
        first_seen: first_rst.timestamp,
        last_seen: rsts.last().unwrap().1.timestamp,
        count: rsts.len() as u32,
        detail,
    }]
}

/// Finds runs of duplicate ACKs. Per RFC 5681 a duplicate ACK is a
/// segment that carries no data, no SYN/FIN/RST, and repeats both the
/// acknowledgment number and the window of the previous such segment
/// from the same sender. A run is flagged when it holds at least
/// `dupack_threshold` duplicates (default 3, the fast-retransmit
/// trigger). Duplicates further apart than `dupack_window_ms` do not form
/// a run — that spacing is a keep-alive or idle connection repeating
/// itself, not a receiver reporting a hole.
///
/// This works on the ACK stream alone: it does not check that the other
/// direction actually has unacknowledged data outstanding.
fn detect_duplicate_ack_bursts(flow: &Flow, config: &AnalysisConfig) -> Vec<Finding> {
    struct Run {
        ack: u32,
        window: u16,
        dupes: u32,
        first_dup: Option<DateTime<Utc>>,
        last: DateTime<Utc>,
        sender: String,
    }

    fn flush(run: &Run, threshold: u32, flow: &Flow, out: &mut Vec<Finding>) {
        if run.dupes >= threshold {
            let first = run.first_dup.unwrap_or(run.last);
            out.push(Finding {
                flow_description: flow.key.describe(),
                kind: FindingKind::DuplicateAckBurst,
                first_seen: first,
                last_seen: run.last,
                count: run.dupes,
                detail: format!(
                    "{} duplicate ACKs for ack={} from {} — receiver repeatedly reporting the same missing byte",
                    run.dupes, run.ack, run.sender
                ),
            });
        }
    }

    let mut runs: [Option<Run>; 2] = [None, None];
    let mut findings = Vec::new();

    for (p, d) in &flow.packets {
        let pure_ack =
            p.flags.ack && p.payload_len == 0 && !p.flags.syn && !p.flags.fin && !p.flags.rst;
        if !pure_ack {
            continue;
        }
        let slot = &mut runs[dir_index(*d)];

        let continues = matches!(slot, Some(r)
            if r.ack == p.ack
                && r.window == p.window
                && (p.timestamp - r.last).num_milliseconds() <= config.dupack_window_ms);

        if continues {
            let r = slot.as_mut().unwrap();
            r.dupes += 1;
            r.first_dup.get_or_insert(p.timestamp);
            r.last = p.timestamp;
        } else {
            if let Some(r) = slot.as_ref() {
                flush(r, config.dupack_threshold, flow, &mut findings);
            }
            *slot = Some(Run {
                ack: p.ack,
                window: p.window,
                dupes: 0,
                first_dup: None,
                last: p.timestamp,
                sender: endpoint(p),
            });
        }
    }
    for r in runs.iter().flatten() {
        flush(r, config.dupack_threshold, flow, &mut findings);
    }

    findings
}

/// Finds episodes where one side advertised a zero receive window, which
/// tells the peer to stop sending until the window reopens. An episode
/// runs from the first zero-window segment from a sender to that sender's
/// next segment advertising a non-zero window (or, if that never comes,
/// to the last packet in the flow). Only episodes lasting at least
/// `zero_window_min_ms` are reported, since brief zero windows are
/// ordinary flow control.
///
/// This is the one detector that points at the *receiving application*
/// rather than the network: a zero window means the process on that end
/// is not draining its socket buffer. SYN and RST segments are ignored,
/// as their window field is not a receive-buffer advertisement.
fn detect_zero_window_stalls(flow: &Flow, config: &AnalysisConfig) -> Vec<Finding> {
    struct Episode {
        start: DateTime<Utc>,
        packets: u32,
        sender: String,
    }

    let flow_end = match flow.packets.last() {
        Some((p, _)) => p.timestamp,
        None => return Vec::new(),
    };

    let mut open: [Option<Episode>; 2] = [None, None];
    let mut findings = Vec::new();

    let mut emit = |ep: Episode, end: DateTime<Utc>, reopened: bool| {
        let ms = (end - ep.start).num_milliseconds();
        if ms >= config.zero_window_min_ms {
            findings.push(Finding {
                flow_description: flow.key.describe(),
                kind: FindingKind::ZeroWindowStall,
                first_seen: ep.start,
                last_seen: end,
                count: ep.packets,
                detail: format!(
                    "{} advertised a zero receive window for {}ms ({} segments); {}",
                    ep.sender,
                    ms,
                    ep.packets,
                    if reopened {
                        "sender was blocked until the window reopened"
                    } else {
                        "window was still zero when the capture ended"
                    }
                ),
            });
        }
    };

    for (p, d) in &flow.packets {
        if p.flags.syn || p.flags.rst {
            continue;
        }
        let slot = &mut open[dir_index(*d)];
        if p.window == 0 {
            match slot {
                Some(ep) => ep.packets += 1,
                None => {
                    *slot = Some(Episode {
                        start: p.timestamp,
                        packets: 1,
                        sender: endpoint(p),
                    })
                }
            }
        } else if let Some(ep) = slot.take() {
            emit(ep, p.timestamp, true);
        }
    }
    for ep in open.into_iter().flatten() {
        emit(ep, flow_end, false);
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::reconstruct_flows;
    use crate::packet::{Protocol, TcpFlags};
    use std::net::{IpAddr, Ipv4Addr};

    const C: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const S: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    fn cfg() -> AnalysisConfig {
        AnalysisConfig {
            retransmit_threshold: 5,
            retransmit_window_ms: 1000,
            ooo_threshold: 5,
            ooo_window_ms: 500,
            syn_ack_timeout_ms: 3000,
            dupack_threshold: 3,
            dupack_window_ms: 1000,
            zero_window_min_ms: 100,
        }
    }

    /// Packet from client (`fwd`) or server at `ms` milliseconds.
    #[allow(clippy::too_many_arguments)]
    fn pkt(fwd: bool, ms: i64, seq: u32, ack: u32, win: u16, flags: &str, len: u32) -> Packet {
        let (si, di, sp, dp) = if fwd {
            (C, S, 40000, 80)
        } else {
            (S, C, 80, 40000)
        };
        Packet {
            timestamp: DateTime::<Utc>::from_timestamp_millis(1_000_000 + ms).unwrap(),
            protocol: Protocol::Tcp,
            src_ip: si,
            dst_ip: di,
            src_port: sp,
            dst_port: dp,
            seq,
            ack,
            window: win,
            flags: TcpFlags {
                syn: flags.contains('S'),
                ack: flags.contains('A'),
                fin: flags.contains('F'),
                rst: flags.contains('R'),
            },
            payload_len: len,
        }
    }

    fn run(pkts: Vec<Packet>) -> Vec<Finding> {
        analyze(&reconstruct_flows(pkts), &cfg())
    }

    fn handshake() -> Vec<Packet> {
        vec![
            pkt(true, 0, 999, 0, 65535, "S", 0),
            pkt(false, 1, 5000, 1000, 65535, "SA", 0),
            pkt(true, 2, 1000, 5001, 65535, "A", 0),
        ]
    }

    fn kinds(f: &[Finding]) -> Vec<FindingKind> {
        f.iter().map(|f| f.kind).collect()
    }

    #[test]
    fn seq_comparison_handles_wraparound() {
        assert!(seq_lt(0xFFFF_FF00, 5));
        assert!(!seq_lt(5, 0xFFFF_FF00));
        assert!(seq_lt(1, 2));
        assert!(!seq_lt(2, 2));
    }

    #[test]
    fn in_order_stream_across_wrap_is_not_out_of_order() {
        let mut p = handshake();
        for i in 0..20u32 {
            p.push(pkt(
                true,
                10 + i as i64,
                0xFFFF_FF00u32.wrapping_add(i * 100),
                5001,
                65535,
                "PA",
                100,
            ));
        }
        assert!(run(p).is_empty());
    }

    #[test]
    fn retransmit_is_not_also_reported_as_reordering() {
        let mut p = handshake();
        for i in 0..8u32 {
            p.push(pkt(
                true,
                10 + i as i64,
                1000 + i * 100,
                5001,
                65535,
                "PA",
                100,
            ));
        }
        for i in 0..6i64 {
            p.push(pkt(true, 100 + i * 10, 1200, 5001, 65535, "PA", 100));
        }
        assert_eq!(kinds(&run(p)), vec![FindingKind::RetransmitStorm]);
    }

    #[test]
    fn genuine_reordering_is_flagged_once() {
        let mut p = handshake();
        // send 20 segments, then 6 *new* segments with lower seq than the max
        for i in 0..20u32 {
            p.push(pkt(
                true,
                10 + i as i64,
                10_000 + i * 100,
                5001,
                65535,
                "PA",
                100,
            ));
        }
        for i in 0..6u32 {
            p.push(pkt(
                true,
                40 + i as i64,
                1000 + i * 100,
                5001,
                65535,
                "PA",
                100,
            ));
        }
        assert_eq!(kinds(&run(p)), vec![FindingKind::OutOfOrderBurst]);
    }

    #[test]
    fn unanswered_syn_one_finding_per_flow() {
        let p = vec![
            pkt(true, 0, 999, 0, 65535, "S", 0),
            pkt(true, 1000, 999, 0, 65535, "S", 0),
            pkt(true, 3000, 999, 0, 65535, "S", 0),
        ];
        let f = run(p);
        assert_eq!(kinds(&f), vec![FindingKind::UnansweredSyn]);
        assert_eq!(f[0].count, 3);
    }

    #[test]
    fn syn_answered_by_rst_is_refused() {
        let p = vec![
            pkt(true, 0, 999, 0, 65535, "S", 0),
            pkt(false, 1, 0, 1000, 0, "RA", 0),
        ];
        let f = run(p);
        // refusal is reported once, as a reset — not also as an "unanswered" SYN
        assert_eq!(kinds(&f), vec![FindingKind::ConnectionReset]);
        assert!(f[0].detail.contains("refused"), "{}", f[0].detail);
    }

    #[test]
    fn mid_connection_rst_is_abort() {
        let mut p = handshake();
        p.push(pkt(true, 10, 1000, 5001, 65535, "PA", 100));
        p.push(pkt(false, 11, 5001, 1100, 65535, "R", 0));
        let f = run(p);
        assert_eq!(kinds(&f), vec![FindingKind::ConnectionReset]);
        assert!(f[0].detail.contains("aborted"), "{}", f[0].detail);
        assert!(f[0].detail.contains("responder"), "{}", f[0].detail);
    }

    #[test]
    fn rst_after_fin_is_not_flagged() {
        let mut p = handshake();
        p.push(pkt(true, 10, 1000, 5001, 65535, "FA", 0));
        p.push(pkt(false, 11, 5001, 1001, 65535, "R", 0));
        assert!(run(p).is_empty());
    }

    #[test]
    fn three_dupacks_flagged_two_are_not() {
        let mk = |n: i64| {
            let mut p = handshake();
            p.push(pkt(true, 10, 1000, 5001, 65535, "PA", 100));
            for i in 0..=n {
                p.push(pkt(false, 20 + i, 5001, 1000, 65535, "A", 0));
            }
            run(p)
        };
        assert!(mk(2).is_empty()); // 1 original + 2 dupes
        let f = mk(3); // 1 original + 3 dupes
        assert_eq!(kinds(&f), vec![FindingKind::DuplicateAckBurst]);
        assert_eq!(f[0].count, 3);
    }

    #[test]
    fn widely_spaced_identical_acks_are_not_dupacks() {
        let mut p = handshake();
        for i in 0..10i64 {
            p.push(pkt(false, 10 + i * 5000, 5001, 1001, 65535, "A", 0));
        }
        assert!(run(p).is_empty());
    }

    #[test]
    fn zero_window_stall_reported_with_duration() {
        let mut p = handshake();
        p.push(pkt(false, 10, 5001, 2000, 0, "A", 0));
        p.push(pkt(false, 300, 5001, 2000, 0, "A", 0));
        p.push(pkt(false, 900, 5001, 2000, 4096, "A", 0));
        let f = run(p);
        assert_eq!(kinds(&f), vec![FindingKind::ZeroWindowStall]);
        assert_eq!(f[0].count, 2);
        assert!(f[0].detail.contains("890ms"), "{}", f[0].detail);
        assert!(f[0].detail.contains("reopened"), "{}", f[0].detail);
    }

    #[test]
    fn brief_zero_window_below_minimum_ignored() {
        let mut p = handshake();
        p.push(pkt(false, 10, 5001, 2000, 0, "A", 0));
        p.push(pkt(false, 50, 5001, 2000, 4096, "A", 0));
        assert!(run(p).is_empty());
    }

    #[test]
    fn zero_window_open_at_end_of_capture() {
        let mut p = handshake();
        p.push(pkt(false, 10, 5001, 2000, 0, "A", 0));
        p.push(pkt(true, 500, 2000, 5001, 65535, "A", 0));
        let f = run(p);
        assert_eq!(kinds(&f), vec![FindingKind::ZeroWindowStall]);
        assert!(f[0].detail.contains("still zero"), "{}", f[0].detail);
    }
}
