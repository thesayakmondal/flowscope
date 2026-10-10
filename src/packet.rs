//! Packet capture reading.
//!
//! Reads a capture file from disk (classic `.pcap` or `.pcapng`, detected
//! from the file's magic number rather than its extension) and parses each
//! frame's link/IP/TCP (or UDP) headers into a flat `Packet` record. This
//! module deliberately knows nothing about flows or anomalies — it only
//! turns bytes into structured fields. Flow reconstruction (`flow.rs`) is a
//! separate pass over the resulting `Vec<Packet>`, kept separate so each
//! stage can be tested and reasoned about independently: a bug in header
//! parsing and a bug in flow-state tracking should never be confused for
//! each other.
//!
//! Supported link layers: Ethernet, Linux "cooked" capture v1 and v2
//! (`tcpdump -i any`), raw IP, and BSD loopback/null. Anything else is
//! counted in `Capture::skipped` rather than silently vanishing, so a
//! capture in an unsupported link type is visible as "0 parsed, N skipped"
//! instead of looking like an empty, healthy capture.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
use pcap_file::pcapng::{Block, PcapNgReader};
use pcap_file::DataLink;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::Path;

/// TCP flags relevant to reliability analysis. Only the flags that matter
/// to the anomaly detectors in `analysis.rs` are kept — ECE/CWR/NS/PSH are
/// parsed by etherparse but dropped here since nothing downstream uses
/// them, and carrying fields nothing reads is a common source of the
/// "which field actually matters" confusion in packet-analysis code.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// One parsed packet, with just the fields flow reconstruction and
/// anomaly detection actually need. Not a general-purpose packet
/// representation — e.g. no support for IP options or fragmentation
/// details, since burstgen's traffic (the intended input source) never
/// produces those.
#[derive(Debug, Clone)]
pub struct Packet {
    pub timestamp: DateTime<Utc>,
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// TCP sequence number of the first byte of payload in this segment.
    /// Zero and unused for UDP.
    pub seq: u32,
    /// TCP acknowledgment number. Zero and unused for UDP. Used by the
    /// duplicate-ACK detector.
    pub ack: u32,
    /// Raw (unscaled) TCP receive-window field. Only its being zero is
    /// ever interpreted — window scaling is negotiated in SYN options
    /// and a zero window is zero under any scale factor — so the scale
    /// option is deliberately not parsed. Zero and unused for UDP.
    pub window: u16,
    pub flags: TcpFlags,
    /// Payload length in bytes, excluding all headers. This is what flow
    /// reconstruction uses to predict the next expected sequence number.
    pub payload_len: u32,
}

/// Everything read from one capture file: the parsed packets plus enough
/// bookkeeping to tell the user what was *not* parsed.
#[derive(Debug, Default)]
pub struct Capture {
    pub packets: Vec<Packet>,
    /// Frames present in the file that did not become a `Packet`: non-IP
    /// traffic (ARP, ...), non-TCP/UDP protocols, or an unsupported link
    /// type. Reported so that silence never means "unsupported".
    pub skipped: u64,
    /// Distinct link-layer types seen, as human-readable names.
    pub link_types: Vec<String>,
    /// True when the file ended mid-record (typical when tcpdump is
    /// killed while writing). Everything before the damage is still
    /// analyzed.
    pub truncated: bool,
}

impl Capture {
    fn note_link(&mut self, link: DataLink) {
        let name = format!("{link:?}");
        if !self.link_types.contains(&name) {
            self.link_types.push(name);
        }
    }
}

/// Reads every packet in the given capture file and parses the ones we
/// understand (TCP and UDP over IPv4/IPv6). Frames that fail to parse
/// (non-IP frames, protocols we don't handle) are counted in
/// `Capture::skipped` rather than aborting the whole analysis — a capture
/// taken with a broad `tcpdump` filter routinely includes ARP, mDNS, and
/// other background noise that has nothing to do with the flow being
/// analyzed.
pub fn read_pcap(path: &Path) -> Result<Capture> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open pcap file: {}", path.display()))?;

    // The pcapng section-header block always starts with 0x0A0D0D0A; classic
    // pcap uses one of four magics (either endianness, us or ns). Sniffing
    // the magic means a pcapng file renamed to `.pcap` (tcpdump and
    // Wireshark both do this readily) still works.
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .with_context(|| format!("capture file too short to be a pcap: {}", path.display()))?;
    file.seek(SeekFrom::Start(0))?;

    if magic == [0x0A, 0x0D, 0x0D, 0x0A] {
        read_pcapng(file)
    } else {
        read_classic(file)
    }
}

fn read_classic(file: File) -> Result<Capture> {
    let mut reader = PcapReader::new(file).context("failed to parse pcap file header")?;
    let link = reader.header().datalink;

    let mut capture = Capture::default();
    capture.note_link(link);

    while let Some(pkt) = reader.next_packet() {
        let raw = match pkt {
            Ok(p) => p,
            // The reader does not advance past a record it failed to
            // decode, so `continue` here would spin forever on the same
            // bytes — which is exactly what a capture truncated mid-record
            // (tcpdump killed while writing) triggers. Stop reading and
            // keep what was parsed before the damage; the caller is told
            // via `truncated` so it can say so in the report.
            Err(_) => {
                capture.truncated = true;
                break;
            }
        };

        let timestamp = DateTime::<Utc>::from_timestamp(
            raw.timestamp.as_secs() as i64,
            raw.timestamp.subsec_nanos(),
        )
        .unwrap_or_else(Utc::now);

        match parse_frame(link, &raw.data, timestamp) {
            Some(parsed) => capture.packets.push(parsed),
            None => capture.skipped += 1,
        }
    }

    Ok(capture)
}

fn read_pcapng(file: File) -> Result<Capture> {
    let mut reader = PcapNgReader::new(file).context("failed to parse pcapng section header")?;
    let mut capture = Capture::default();

    // Interface Description Blocks are scoped to the section they appear
    // in; a new Section Header Block starts a fresh numbering.
    let mut interfaces: Vec<(DataLink, u8)> = Vec::new();

    while let Some(block) = reader.next_block() {
        let block = match block {
            Ok(b) => b,
            // As in the classic reader: a block that fails to decode
            // leaves the stream in an unknown state, so stop rather than
            // guess at where the next block starts.
            Err(_) => {
                capture.truncated = true;
                break;
            }
        };

        match block {
            Block::SectionHeader(_) => interfaces.clear(),
            Block::InterfaceDescription(idb) => {
                // pcapng's default timestamp resolution is 10^-6 s when
                // the `if_tsresol` option is absent.
                let tsresol = idb
                    .options
                    .iter()
                    .find_map(|o| match o {
                        InterfaceDescriptionOption::IfTsResol(v) => Some(*v),
                        _ => None,
                    })
                    .unwrap_or(6);
                capture.note_link(idb.linktype);
                interfaces.push((idb.linktype, tsresol));
            }
            Block::EnhancedPacket(epb) => {
                let Some(&(link, tsresol)) = interfaces.get(epb.interface_id as usize) else {
                    capture.skipped += 1;
                    continue;
                };
                // `pcap-file` hands back the raw 64-bit tick count wrapped
                // in a `Duration` built with `from_nanos`, i.e. it treats
                // every pcapng timestamp as nanoseconds regardless of the
                // interface's `if_tsresol`. With the default microsecond
                // resolution that would make every timestamp 1000x too
                // small, so the tick count is re-scaled here.
                let ticks = epb.timestamp.as_nanos();
                let nanos = ticks_to_nanos(ticks, tsresol);
                let timestamp = DateTime::<Utc>::from_timestamp(
                    (nanos / 1_000_000_000) as i64,
                    (nanos % 1_000_000_000) as u32,
                )
                .unwrap_or_else(Utc::now);

                match parse_frame(link, &epb.data, timestamp) {
                    Some(parsed) => capture.packets.push(parsed),
                    None => capture.skipped += 1,
                }
            }
            // Simple Packet Blocks carry no timestamp, so they cannot
            // take part in time-based analysis; count them as skipped.
            Block::SimplePacket(_) => capture.skipped += 1,
            _ => {}
        }
    }

    Ok(capture)
}

/// Converts a pcapng tick count to nanoseconds given the interface's
/// `if_tsresol` byte: if the top bit is clear the resolution is
/// 10^-value seconds, if set it is 2^-(value & 0x7f) seconds.
fn ticks_to_nanos(ticks: u128, tsresol: u8) -> u128 {
    let units_per_sec: u128 = if tsresol & 0x80 == 0 {
        10u128.checked_pow(tsresol as u32).unwrap_or(u128::MAX)
    } else {
        1u128
            .checked_shl((tsresol & 0x7f) as u32)
            .unwrap_or(u128::MAX)
    };
    ticks.saturating_mul(1_000_000_000) / units_per_sec.max(1)
}

/// Dispatches one captured frame to the right link-layer parser and
/// returns `None` for anything that isn't IPv4/IPv6-over-TCP-or-UDP.
/// Uses etherparse's layered parser rather than hand-computed byte
/// offsets, since header lengths vary (IP options, VLAN tags) in ways that
/// are easy to get subtly wrong by hand and hard to notice getting wrong.
fn parse_frame(link: DataLink, data: &[u8], timestamp: DateTime<Utc>) -> Option<Packet> {
    let sliced = match link {
        DataLink::ETHERNET => etherparse::SlicedPacket::from_ethernet(data).ok()?,
        DataLink::LINUX_SLL => etherparse::SlicedPacket::from_linux_sll(data).ok()?,
        // Linux cooked v2 (what libpcap >= 1.10 writes for `-i any`) is a
        // fixed 20-byte header: protocol(2, big-endian EtherType),
        // reserved(2), ifindex(4), arphrd(2), pkttype(1), halen(1),
        // addr(8). etherparse 0.15 has no SLL2 parser, so the one field
        // that matters — the EtherType — is read directly.
        DataLink::LINUX_SLL2 => {
            if data.len() < 20 {
                return None;
            }
            let ether_type = etherparse::EtherType(u16::from_be_bytes([data[0], data[1]]));
            etherparse::SlicedPacket::from_ether_type(ether_type, &data[20..]).ok()?
        }
        DataLink::RAW | DataLink::IPV4 | DataLink::IPV6 => {
            etherparse::SlicedPacket::from_ip(data).ok()?
        }
        // BSD loopback/null (host byte order) and OpenBSD loop (network
        // byte order) both prefix the IP packet with a 4-byte address
        // family. The IP version nibble that follows identifies v4 vs v6
        // unambiguously, so the family value itself — whose byte order
        // and numbering differ across BSDs — is not interpreted.
        DataLink::NULL | DataLink::LOOP => {
            if data.len() < 4 {
                return None;
            }
            etherparse::SlicedPacket::from_ip(&data[4..]).ok()?
        }
        _ => return None,
    };

    let (src_ip, dst_ip) = match sliced.net.as_ref()? {
        etherparse::NetSlice::Ipv4(ipv4) => (
            IpAddr::V4(ipv4.header().source_addr()),
            IpAddr::V4(ipv4.header().destination_addr()),
        ),
        etherparse::NetSlice::Ipv6(ipv6) => (
            IpAddr::V6(ipv6.header().source_addr()),
            IpAddr::V6(ipv6.header().destination_addr()),
        ),
    };

    match sliced.transport? {
        etherparse::TransportSlice::Tcp(tcp) => Some(Packet {
            timestamp,
            protocol: Protocol::Tcp,
            src_ip,
            dst_ip,
            src_port: tcp.source_port(),
            dst_port: tcp.destination_port(),
            seq: tcp.sequence_number(),
            ack: tcp.acknowledgment_number(),
            window: tcp.window_size(),
            flags: TcpFlags {
                syn: tcp.syn(),
                ack: tcp.ack(),
                fin: tcp.fin(),
                rst: tcp.rst(),
            },
            payload_len: tcp.payload().len() as u32,
        }),
        etherparse::TransportSlice::Udp(udp) => Some(Packet {
            timestamp,
            protocol: Protocol::Udp,
            src_ip,
            dst_ip,
            src_port: udp.source_port(),
            dst_port: udp.destination_port(),
            seq: 0,
            ack: 0,
            window: 0,
            flags: TcpFlags::default(),
            payload_len: udp.payload().len() as u32,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tsresol_microseconds_default() {
        // 1.5 s expressed in microsecond ticks.
        assert_eq!(ticks_to_nanos(1_500_000, 6), 1_500_000_000);
    }

    #[test]
    fn tsresol_nanoseconds() {
        assert_eq!(ticks_to_nanos(1_500_000_000, 9), 1_500_000_000);
    }

    #[test]
    fn tsresol_binary_fraction() {
        // top bit set: 2^-10 s per tick; 1024 ticks == 1 s.
        assert_eq!(ticks_to_nanos(1024, 0x80 | 10), 1_000_000_000);
    }
}
