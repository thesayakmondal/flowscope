//! Command-line interface.
//!
//! flowscope has a single real subcommand (`analyze`) rather than several,
//! because unlike burstgen's four genuinely different traffic shapes,
//! there's only one thing flowscope does: read a capture, reconstruct
//! flows, find anomalies. The surface area that varies is the anomaly
//! *thresholds* and *filters*, which are flags, not separate commands.
//!
//! Exit codes (so flowscope can gate a CI job or a test script):
//! `0` success, `1` runtime error, `2` command-line usage error (clap's
//! own convention), `3` findings present with `--fail-on-findings`, `4` a
//! correlation disagreed with `--fail-on-mismatch` (4 wins when both
//! apply, since a tool disagreement is the stronger signal).

use clap::Parser;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "flowscope",
    version,
    about = "Reconstructs TCP flows from a .pcap capture and flags reliability anomalies.",
    long_about = "flowscope reads a packet capture (as written by tcpdump or Wireshark) \
and reconstructs it into per-connection TCP flows, then flags three specific \
anomaly patterns: retransmit storms, SYNs that never got a SYN-ACK, bursts \
of out-of-order segments, connection resets, duplicate-ACK bursts, and \
zero-window stalls. It reads .pcap and .pcapng captures. It is designed as burstgen's counterpart: \
burstgen generates a traffic shape and logs what it sent; flowscope reads \
what actually crossed the wire and independently reconstructs what happened, \
so the two can be compared rather than trusting either one alone."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Read a .pcap file, reconstruct flows, detect anomalies, write a report.
    Analyze(AnalyzeArgs),
}

#[derive(Parser, Debug)]
pub struct AnalyzeArgs {
    /// Path to the capture file, .pcap or .pcapng (e.g. produced by
    /// `tcpdump -i lo -w capture.pcap`). The format is detected from the
    /// file contents, not the extension.
    #[arg(long)]
    pub pcap: PathBuf,

    /// Directory where the report (Markdown + CSV + JSON) is written.
    #[arg(long, default_value = "./flowscope-out")]
    pub output_dir: PathBuf,

    /// Optional burstgen `events.json` from the run that generated this
    /// capture's traffic. When supplied, flowscope cross-checks its own
    /// independently-reconstructed counts (e.g. connection attempts seen
    /// on the wire) against burstgen's self-reported counts, and reports
    /// any mismatch — this is the strongest form of verification either
    /// tool can offer, since the two have no shared code path.
    #[arg(long)]
    pub burstgen_events: Option<PathBuf>,

    /// Minimum number of retransmitted segments within
    /// `retransmit_window_ms` of each other, on a single flow, to be
    /// flagged as a "retransmit storm" rather than incidental loss.
    #[arg(long, default_value_t = 5)]
    pub retransmit_threshold: u32,

    /// Time window, in milliseconds, used to group retransmissions into a
    /// storm. Retransmits further apart than this are treated as
    /// unrelated, isolated loss events rather than one incident.
    #[arg(long, default_value_t = 1000)]
    pub retransmit_window_ms: i64,

    /// Minimum number of out-of-order segments within
    /// `ooo_window_ms` of each other, on a single flow, to be flagged as
    /// an out-of-order burst.
    #[arg(long, default_value_t = 5)]
    pub ooo_threshold: u32,

    /// Time window, in milliseconds, used to group out-of-order segments
    /// into a burst.
    #[arg(long, default_value_t = 500)]
    pub ooo_window_ms: i64,

    /// How long, in milliseconds, flowscope waits after a SYN for a
    /// matching SYN-ACK before concluding it was dropped rather than
    /// merely slow. Should be set well above normal RTT for the network
    /// being analyzed to avoid false positives.
    #[arg(long, default_value_t = 3000)]
    pub syn_ack_timeout_ms: i64,

    /// Minimum number of duplicate ACKs in one run to be flagged. Three is
    /// the RFC 5681 fast-retransmit trigger.
    #[arg(long, default_value_t = 3)]
    pub dupack_threshold: u32,

    /// Duplicate ACKs further apart than this many milliseconds are not
    /// treated as one run (keep-alives and idle connections repeat
    /// identical ACKs too, but slowly).
    #[arg(long, default_value_t = 1000)]
    pub dupack_window_ms: i64,

    /// Minimum duration, in milliseconds, of a zero-receive-window episode
    /// to be flagged. Shorter ones are ordinary flow control.
    #[arg(long, default_value_t = 100)]
    pub zero_window_min_ms: i64,

    /// Only analyze packets to or from this IP address. May be repeated;
    /// any listed address matches. Combined with `--port` by AND.
    #[arg(long = "host")]
    pub hosts: Vec<IpAddr>,

    /// Only analyze packets to or from this TCP/UDP port. May be repeated;
    /// any listed port matches. Combined with `--host` by AND.
    #[arg(long = "port")]
    pub ports: Vec<u16>,

    /// Percentage difference below which a burstgen-vs-wire count is
    /// reported as agreeing.
    #[arg(long, default_value_t = 5.0)]
    pub mismatch_tolerance_pct: f64,

    /// How many of the highest-volume flows to list in the report.
    #[arg(long, default_value_t = 5)]
    pub top_flows: usize,

    /// Exit with status 3 if any anomaly was found.
    #[arg(long)]
    pub fail_on_findings: bool,

    /// Exit with status 4 if any burstgen correlation disagrees beyond
    /// `--mismatch-tolerance-pct`. Requires `--burstgen-events`.
    #[arg(long, requires = "burstgen_events")]
    pub fail_on_mismatch: bool,
}
