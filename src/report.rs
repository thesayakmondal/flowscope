//! Report generation.
//!
//! Mirrors burstgen's `report.rs` in shape deliberately (a Markdown summary
//! and a CSV of details) so the two tools' output is consistent to read
//! side by side, since they're meant to be used together on the same test
//! run. A JSON summary is written alongside for anything scripting against
//! the results instead of reading them.

use crate::analysis::{Finding, FindingKind};
use crate::correlate::{Correlation, LatencyComparison};
use crate::stats::{percentile, CaptureInfo, FlowSummary, HandshakeStats};
use anyhow::Result;
use serde_json::json;
use std::path::Path;

/// Everything a report is built from, bundled so the three writers take
/// one argument instead of a growing parameter list.
pub struct ReportInput<'a> {
    pub capture: &'a CaptureInfo,
    pub findings: &'a [Finding],
    pub correlations: &'a [Correlation],
    pub latency: &'a [LatencyComparison],
    pub handshakes: &'a HandshakeStats,
    pub top_flows: &'a [FlowSummary],
    pub tolerance_pct: f64,
}

/// Formats microseconds compactly: `850µs`, `12.34ms`, `1.50s`.
fn fmt_us(us: u64) -> String {
    if us >= 1_000_000 {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    } else if us >= 1_000 {
        format!("{:.2}ms", us as f64 / 1_000.0)
    } else {
        format!("{us}µs")
    }
}

pub fn write_markdown(input: &ReportInput, path: &Path) -> Result<()> {
    let ReportInput {
        capture,
        findings,
        correlations,
        latency,
        handshakes,
        top_flows,
        tolerance_pct,
    } = input;

    let mut out = String::new();

    out.push_str("# flowscope report\n\n");
    out.push_str(&format!(
        "Generated: {}\n\n",
        chrono::Utc::now().to_rfc3339()
    ));

    out.push_str("## Capture summary\n\n");
    out.push_str(&format!(
        "- Total flows reconstructed: {} ({} TCP, {} UDP)\n",
        capture.tcp_flows + capture.udp_flows,
        capture.tcp_flows,
        capture.udp_flows
    ));
    out.push_str(&format!(
        "- Packets analyzed: {} (link type: {})\n",
        capture.packets,
        if capture.link_types.is_empty() {
            "unknown".to_string()
        } else {
            capture.link_types.join(", ")
        }
    ));
    if let (Some(first), Some(last)) = (capture.first_packet, capture.last_packet) {
        out.push_str(&format!(
            "- Time span: {} → {} ({}ms)\n",
            first.to_rfc3339(),
            last.to_rfc3339(),
            (last - first).num_milliseconds()
        ));
    }
    out.push_str(&format!(
        "- TCP payload carried: {} bytes\n",
        capture.tcp_payload_bytes
    ));
    if capture.skipped_frames > 0 {
        out.push_str(&format!(
            "- Frames not parsed (non-IP, non-TCP/UDP, or unsupported link type): {}\n",
            capture.skipped_frames
        ));
    }
    if capture.filtered_out > 0 {
        out.push_str(&format!(
            "- Packets excluded by --host/--port filter: {}\n",
            capture.filtered_out
        ));
    }
    if capture.truncated {
        out.push_str(
            "- ⚠ Capture file ended mid-record (truncated); only packets before the damage were analyzed\n",
        );
    }
    out.push('\n');

    if !handshakes.latencies_us.is_empty() {
        let l = &handshakes.latencies_us;
        out.push_str("## TCP handshake latency\n\n");
        out.push_str(&format!(
            "First SYN → SYN-ACK across {} answered connection attempts (retry backoff included, \
             as a client calling `connect()` would experience it): p50 {}, p90 {}, p99 {}, max {}. \
             {} flow(s) needed more than one SYN.\n\n",
            l.len(),
            fmt_us(percentile(l, 50.0).unwrap()),
            fmt_us(percentile(l, 90.0).unwrap()),
            fmt_us(percentile(l, 99.0).unwrap()),
            fmt_us(*l.last().unwrap()),
            handshakes.syn_retried_flows,
        ));
    }

    if !top_flows.is_empty() {
        out.push_str("## Top flows by payload\n\n");
        out.push_str(
            "| Flow | Initiator | Packets | Payload bytes | Duration |\n|---|---|---|---|---|\n",
        );
        for f in top_flows.iter() {
            out.push_str(&format!(
                "| `{}` | `{}` | {} | {} | {}ms |\n",
                f.flow, f.initiator, f.packets, f.payload_bytes, f.duration_ms
            ));
        }
        out.push('\n');
    }

    if !correlations.is_empty() {
        out.push_str("## Correlation against burstgen events\n\n");
        out.push_str(
            "Comparing burstgen's self-reported counts against flowscope's independent \
             wire-level reconstruction. Agreement here means two tools with no shared code \
             path arrived at the same conclusion by different means — the strongest evidence \
             either tool can offer on its own.\n\n",
        );
        for c in correlations.iter() {
            let status = if c.agrees_within(*tolerance_pct) {
                "✓ agrees"
            } else {
                "⚠ MISMATCH"
            };
            out.push_str(&format!(
                "- {}: burstgen={}, flowscope={}, diff={} — {}\n",
                c.label,
                c.burstgen_value,
                c.flowscope_value,
                c.difference(),
                status
            ));
        }
        out.push('\n');

        if !latency.is_empty() {
            out.push_str(
                "Latency is shown side by side without a verdict: burstgen times `connect()` \
                 from the client process, flowscope times first-SYN to SYN-ACK at the capture \
                 point, so the wire figure is expected to be the smaller of the two.\n\n",
            );
            for c in latency.iter() {
                out.push_str(&format!(
                    "- {}: burstgen={}, wire={}, diff={}{}\n",
                    c.label,
                    fmt_us(c.burstgen_us),
                    fmt_us(c.wire_us),
                    if c.difference_us() < 0 { "-" } else { "+" },
                    fmt_us(c.difference_us().unsigned_abs()),
                ));
            }
            out.push('\n');
        }
    }

    out.push_str("## Findings\n\n");
    if findings.is_empty() {
        out.push_str("No anomalies detected at the configured thresholds.\n\n");
    } else {
        out.push_str(&format!("{} total findings:\n\n", findings.len()));
        for kind in FindingKind::ALL {
            let n = findings.iter().filter(|f| f.kind == kind).count();
            out.push_str(&format!("- {}: {}\n", kind.label(), n));
        }
        out.push('\n');

        for finding in findings.iter() {
            out.push_str(&format!(
                "### {} — {}\n\n- Flow: `{}`\n- First seen: {}\n- Last seen: {}\n- Count: {}\n- {}\n\n",
                finding.kind.label(),
                finding.first_seen.to_rfc3339(),
                finding.flow_description,
                finding.first_seen.to_rfc3339(),
                finding.last_seen.to_rfc3339(),
                finding.count,
                finding.detail,
            ));
        }
    }

    std::fs::write(path, out)?;
    Ok(())
}

pub fn write_csv(findings: &[Finding], path: &Path) -> Result<()> {
    let mut writer = csv::Writer::from_path(path)?;
    writer.write_record(["kind", "flow", "first_seen", "last_seen", "count", "detail"])?;

    for finding in findings {
        writer.write_record([
            finding.kind.slug(),
            &finding.flow_description,
            &finding.first_seen.to_rfc3339(),
            &finding.last_seen.to_rfc3339(),
            &finding.count.to_string(),
            &finding.detail,
        ])?;
    }

    writer.flush()?;
    Ok(())
}

/// Machine-readable counterpart of `report.md`: the same facts, as JSON,
/// for scripts and CI to consume without scraping Markdown.
pub fn write_json(input: &ReportInput, path: &Path) -> Result<()> {
    let l = &input.handshakes.latencies_us;
    let by_kind: serde_json::Map<String, serde_json::Value> = FindingKind::ALL
        .iter()
        .map(|k| {
            let n = input.findings.iter().filter(|f| f.kind == *k).count();
            (k.slug().to_string(), json!(n))
        })
        .collect();

    let value = json!({
        "generated": chrono::Utc::now().to_rfc3339(),
        "capture": input.capture,
        "handshake": {
            "syns_seen": input.handshakes.syns_seen,
            "syn_acks_seen": input.handshakes.syn_acks_seen,
            "syn_retried_flows": input.handshakes.syn_retried_flows,
            "latency_us": {
                "samples": l.len(),
                "p50": percentile(l, 50.0),
                "p90": percentile(l, 90.0),
                "p99": percentile(l, 99.0),
                "max": l.last(),
            },
        },
        "correlations": input.correlations.iter().map(|c| json!({
            "label": c.label,
            "burstgen": c.burstgen_value,
            "flowscope": c.flowscope_value,
            "difference": c.difference(),
            "agrees": c.agrees_within(input.tolerance_pct),
        })).collect::<Vec<_>>(),
        "latency_comparisons": input.latency.iter().map(|c| json!({
            "label": c.label,
            "burstgen_us": c.burstgen_us,
            "wire_us": c.wire_us,
            "difference_us": c.difference_us(),
        })).collect::<Vec<_>>(),
        "findings_by_kind": by_kind,
        "findings": input.findings,
        "top_flows": input.top_flows,
    });

    std::fs::write(path, serde_json::to_string_pretty(&value)?)?;
    Ok(())
}
