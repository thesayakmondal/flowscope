//! Packet filtering applied before flow reconstruction.
//!
//! A capture taken on a busy interface holds far more than the one
//! conversation under test. Narrowing by host and port up front (rather
//! than hiding findings afterwards) keeps every number in the report —
//! flow counts, correlations, handshake latency — consistent with the
//! traffic the user actually asked about.

use crate::packet::Packet;
use std::net::IpAddr;

/// Keeps a packet when it matches *every* non-empty criterion; within one
/// criterion any value may match. A packet matches a host/port if that
/// value is its source **or** destination, so both directions of a
/// conversation are kept together and flows are never split in half.
#[derive(Debug, Default)]
pub struct PacketFilter {
    pub hosts: Vec<IpAddr>,
    pub ports: Vec<u16>,
}

impl PacketFilter {
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.ports.is_empty()
    }

    pub fn matches(&self, p: &Packet) -> bool {
        let host_ok =
            self.hosts.is_empty() || self.hosts.iter().any(|h| *h == p.src_ip || *h == p.dst_ip);
        let port_ok = self.ports.is_empty()
            || self
                .ports
                .iter()
                .any(|port| *port == p.src_port || *port == p.dst_port);
        host_ok && port_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Protocol, TcpFlags};
    use chrono::Utc;

    fn pkt(src: &str, sp: u16, dst: &str, dp: u16) -> Packet {
        Packet {
            timestamp: Utc::now(),
            protocol: Protocol::Tcp,
            src_ip: src.parse().unwrap(),
            dst_ip: dst.parse().unwrap(),
            src_port: sp,
            dst_port: dp,
            seq: 0,
            ack: 0,
            window: 0,
            flags: TcpFlags::default(),
            payload_len: 0,
        }
    }

    #[test]
    fn empty_filter_matches_everything() {
        assert!(PacketFilter::default().matches(&pkt("1.1.1.1", 1, "2.2.2.2", 2)));
    }

    #[test]
    fn port_matches_either_direction() {
        let f = PacketFilter {
            hosts: vec![],
            ports: vec![8080],
        };
        assert!(f.matches(&pkt("1.1.1.1", 40000, "2.2.2.2", 8080)));
        assert!(f.matches(&pkt("2.2.2.2", 8080, "1.1.1.1", 40000)));
        assert!(!f.matches(&pkt("1.1.1.1", 40000, "2.2.2.2", 80)));
    }

    #[test]
    fn criteria_are_anded() {
        let f = PacketFilter {
            hosts: vec!["2.2.2.2".parse().unwrap()],
            ports: vec![8080],
        };
        assert!(f.matches(&pkt("1.1.1.1", 40000, "2.2.2.2", 8080)));
        assert!(!f.matches(&pkt("3.3.3.3", 40000, "4.4.4.4", 8080)));
        assert!(!f.matches(&pkt("1.1.1.1", 40000, "2.2.2.2", 80)));
    }
}
