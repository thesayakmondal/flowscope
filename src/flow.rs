//! Flow reconstruction.
//!
//! Takes the flat, arrival-order packet list from `packet.rs` and groups
//! it into per-connection flows, keyed by the unordered 4-tuple (or
//! 2-tuple of endpoints for UDP) so that both directions of one
//! conversation land in the same flow rather than being treated as two
//! unrelated ones. This is the step that turns "a pile of packets" into
//! "a list of conversations", which is the unit anomaly detection
//! actually reasons about.

use crate::packet::{Packet, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;

/// Identifies one conversation. Deliberately order-independent (`Ord` on
/// the endpoint pair) so a lookup doesn't care which side happened to
/// send first — two `FlowKey`s built from the same pair of endpoints in
/// either order always compare equal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub protocol_is_tcp: bool,
    endpoint_a: (IpAddr, u16),
    endpoint_b: (IpAddr, u16),
}

impl FlowKey {
    fn new(protocol: Protocol, ip1: IpAddr, port1: u16, ip2: IpAddr, port2: u16) -> Self {
        let a = (ip1, port1);
        let b = (ip2, port2);
        // Canonical ordering: smaller endpoint always goes in `endpoint_a`.
        // This is what makes the same conversation hash identically
        // regardless of which packet (and which direction) we saw first.
        let (endpoint_a, endpoint_b) = if a <= b { (a, b) } else { (b, a) };
        Self {
            protocol_is_tcp: protocol == Protocol::Tcp,
            endpoint_a,
            endpoint_b,
        }
    }

    pub fn describe(&self) -> String {
        format!(
            "{} {}:{} <-> {}:{}",
            if self.protocol_is_tcp { "tcp" } else { "udp" },
            self.endpoint_a.0,
            self.endpoint_a.1,
            self.endpoint_b.0,
            self.endpoint_b.1
        )
    }
}

/// Which side of the flow a packet traveled: from whichever endpoint
/// initiated the conversation (sent the first packet observed) toward
/// the other, or the reverse. For TCP this initiator is normally the
/// side that sent the SYN; for UDP it's simply whichever endpoint's
/// address matched the source of the first packet seen for this key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Reverse,
}

/// One reconstructed conversation: its key, and every packet belonging
/// to it in the order they were captured, tagged with direction.
#[derive(Debug)]
pub struct Flow {
    pub key: FlowKey,
    pub initiator: (IpAddr, u16),
    pub packets: Vec<(Packet, Direction)>,
}

/// Groups a flat packet list into flows. Packets are assumed to already
/// be in capture order (pcap files are written in arrival order, and
/// `read_pcap` preserves that), which flow-level analysis (retransmit
/// and out-of-order detection in particular) depends on.
pub fn reconstruct_flows(packets: Vec<Packet>) -> Vec<Flow> {
    let mut initiators: HashMap<FlowKey, (IpAddr, u16)> = HashMap::new();
    let mut grouped: HashMap<FlowKey, Vec<(Packet, Direction)>> = HashMap::new();

    for packet in packets {
        let key = FlowKey::new(
            packet.protocol,
            packet.src_ip,
            packet.src_port,
            packet.dst_ip,
            packet.dst_port,
        );

        // The first packet observed for a given key establishes which
        // endpoint is the "initiator" for direction-tagging purposes.
        // This is a pragmatic choice rather than a strict SYN check: a
        // capture that starts mid-conversation (missed the SYN) still
        // gets consistent, if arbitrary, direction labeling rather than
        // panicking or dropping the flow.
        let initiator = *initiators
            .entry(key.clone())
            .or_insert((packet.src_ip, packet.src_port));

        let direction = if (packet.src_ip, packet.src_port) == initiator {
            Direction::Forward
        } else {
            Direction::Reverse
        };

        grouped.entry(key).or_default().push((packet, direction));
    }

    let mut flows: Vec<Flow> = grouped
        .into_iter()
        .map(|(key, packets)| {
            let initiator = initiators[&key];
            Flow {
                key,
                initiator,
                packets,
            }
        })
        .collect();

    // `HashMap` iteration order differs from run to run, which made every
    // downstream list (findings with equal timestamps, top-flow tables)
    // come out in a different order for identical input. Output of a
    // verification tool has to be reproducible, so flows are put in a
    // total order: first-packet time, then the flow's textual identity.
    flows.sort_by(|a, b| {
        let ta = a.packets.first().map(|(p, _)| p.timestamp);
        let tb = b.packets.first().map(|(p, _)| p.timestamp);
        ta.cmp(&tb)
            .then_with(|| a.key.describe().cmp(&b.key.describe()))
    });
    flows
}
