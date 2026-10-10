//! flowscope — pcap-driven flow reconstruction and anomaly detector.
//!
//! See `cli.rs` for the full description. This file's job is orchestration
//! only: read the capture, filter it, reconstruct flows, run the detectors,
//! optionally correlate against a burstgen events log, write the report.
//! All of the actual logic lives in the other modules, each scoped to one
//! concern: `packet.rs` (bytes -> structured packets), `filter.rs` (which
//! packets to keep), `flow.rs` (packets -> flows), `analysis.rs` (flows ->
//! findings), `stats.rs` (flows -> descriptive numbers), `correlate.rs`
//! (findings/flows vs. burstgen's self-report), `report.rs` (all of the
//! above -> output files).

mod analysis;
mod cli;
mod correlate;
mod filter;
mod flow;
mod packet;
mod report;
mod stats;

use analysis::AnalysisConfig;
use clap::Parser;
use cli::{AnalyzeArgs, Cli, Command};
use filter::PacketFilter;
use report::ReportInput;
use stats::CaptureInfo;

/// Exit status when `--fail-on-findings` is set and anomalies were found.
/// Not 2: clap exits 2 for a usage error, and a script gating on flowscope's
/// status must be able to tell "bad command line" from "anomalies found".
const EXIT_FINDINGS: i32 = 3;
/// Exit status when `--fail-on-mismatch` is set and a correlation disagreed.
const EXIT_MISMATCH: i32 = 4;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let code = match &cli.command {
        Command::Analyze(args) => run_analyze(args)?,
    };
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

/// Returns the process exit code (0 unless a `--fail-on-*` gate tripped);
/// real errors propagate as `Err` and exit 1 via `anyhow`.
fn run_analyze(args: &AnalyzeArgs) -> anyhow::Result<i32> {
    std::fs::create_dir_all(&args.output_dir)?;

    println!("Reading capture: {}", args.pcap.display());
    let capture = packet::read_pcap(&args.pcap)?;
    println!("Parsed {} packets", capture.packets.len());

    if capture.skipped > 0 {
        println!(
            "Skipped {} frames that were not IP TCP/UDP",
            capture.skipped
        );
    }
    if capture.packets.is_empty() && capture.skipped > 0 {
        eprintln!(
            "warning: no packets could be parsed from {} frames (link type: {}). \
             If the link type is not one of Ethernet, Linux cooked (SLL/SLL2), raw IP, or \
             BSD loopback, flowscope cannot read this capture.",
            capture.skipped,
            capture.link_types.join(", ")
        );
    }
    if capture.truncated {
        eprintln!(
            "warning: capture file ended mid-record (truncated); analyzing the {} packets before it",
            capture.packets.len()
        );
    }

    let packet_filter = PacketFilter {
        hosts: args.hosts.clone(),
        ports: args.ports.clone(),
    };
    let total_before_filter = capture.packets.len() as u64;
    let packets: Vec<packet::Packet> = if packet_filter.is_empty() {
        capture.packets
    } else {
        capture
            .packets
            .into_iter()
            .filter(|p| packet_filter.matches(p))
            .collect()
    };
    let filtered_out = total_before_filter - packets.len() as u64;
    if filtered_out > 0 {
        println!(
            "Filter excluded {filtered_out} packets; analyzing {}",
            packets.len()
        );
    }

    // Min/max rather than first/last: a pcapng with several interfaces is
    // not guaranteed to be in timestamp order.
    let first_packet = packets.iter().map(|p| p.timestamp).min();
    let last_packet = packets.iter().map(|p| p.timestamp).max();
    let packet_count = packets.len() as u64;

    let flows = flow::reconstruct_flows(packets);
    println!("Reconstructed {} flows", flows.len());

    let config = AnalysisConfig {
        retransmit_threshold: args.retransmit_threshold,
        retransmit_window_ms: args.retransmit_window_ms,
        ooo_threshold: args.ooo_threshold,
        ooo_window_ms: args.ooo_window_ms,
        syn_ack_timeout_ms: args.syn_ack_timeout_ms,
        dupack_threshold: args.dupack_threshold,
        dupack_window_ms: args.dupack_window_ms,
        zero_window_min_ms: args.zero_window_min_ms,
    };
    let findings = analysis::analyze(&flows, &config);
    println!("Found {} anomalies", findings.len());

    let handshakes = stats::handshake_stats(&flows);
    let tcp_flows = flows.iter().filter(|f| f.key.protocol_is_tcp).count() as u64;
    let info = CaptureInfo {
        packets: packet_count,
        skipped_frames: capture.skipped,
        link_types: capture.link_types,
        truncated: capture.truncated,
        filtered_out,
        first_packet,
        last_packet,
        tcp_flows,
        udp_flows: flows.len() as u64 - tcp_flows,
        tcp_payload_bytes: stats::tcp_payload_bytes(&flows),
    };
    let top_flows = stats::top_flows(&flows, args.top_flows);

    // Correlation against burstgen is entirely optional — flowscope is a
    // standalone tool that works on any capture, not only ones burstgen
    // produced. When a burstgen events file is supplied, we compare the
    // two wire-level counts (SYNs seen, SYN-ACKs seen) that are directly
    // comparable to burstgen's own self-reported attempt/success counts,
    // and the connect-latency percentiles. `handshake_stats` counts one
    // SYN per flow (the initial attempt), not one per packet — a target
    // that silently drops a SYN causes the client's kernel to retransmit
    // it several times on the same flow, and those retries are the same
    // logical connection attempt. See the comment on
    // `detect_unanswered_syns` in analysis.rs for the full reasoning and
    // the ~6x inflation this caused before the fix.
    let (correlations, latency) = if let Some(events_path) = &args.burstgen_events {
        println!(
            "Cross-checking against burstgen events: {}",
            events_path.display()
        );
        let summary = correlate::load_burstgen_summary(events_path)?;
        (
            correlate::build_correlations(&summary, handshakes.syns_seen, handshakes.syn_acks_seen),
            correlate::build_latency_comparisons(&summary, &handshakes),
        )
    } else {
        (Vec::new(), Vec::new())
    };

    let input = ReportInput {
        capture: &info,
        findings: &findings,
        correlations: &correlations,
        latency: &latency,
        handshakes: &handshakes,
        top_flows: &top_flows,
        tolerance_pct: args.mismatch_tolerance_pct,
    };
    report::write_markdown(&input, &args.output_dir.join("report.md"))?;
    report::write_csv(&findings, &args.output_dir.join("findings.csv"))?;
    report::write_json(&input, &args.output_dir.join("summary.json"))?;

    println!(
        "Report written: {}",
        args.output_dir.join("report.md").display()
    );

    let mismatch = correlations
        .iter()
        .any(|c| !c.agrees_within(args.mismatch_tolerance_pct));
    if args.fail_on_mismatch && mismatch {
        eprintln!("burstgen correlation MISMATCH (see report.md)");
        return Ok(EXIT_MISMATCH);
    }
    if args.fail_on_findings && !findings.is_empty() {
        eprintln!("{} anomalies found", findings.len());
        return Ok(EXIT_FINDINGS);
    }

    Ok(0)
}
