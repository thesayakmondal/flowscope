# flowscope

A pcap-driven TCP flow reconstructor and reliability-anomaly detector —
built as [`burstgen`](../burstgen)'s independent verification partner.

## What this is for

`burstgen` generates traffic and reports what it believes it sent, plus
(optionally) what the target's kernel counters show happened. Both of
those are self-reports. `flowscope` closes the loop: it reads the actual
packets that crossed the wire — captured independently with `tcpdump`,
parsed with no code shared with `burstgen` — and reconstructs its own
answer to "what happened here." When the two agree, that agreement means
something, because they have no way to be fooling each other.

## What it does

Given a `.pcap` or `.pcapng` file, flowscope:
1. Parses every frame into a structured packet record. Link types:
   Ethernet, Linux cooked (SLL and SLL2 — what `tcpdump -i any` writes),
   raw IP, and BSD loopback. The format is detected from the file's
   contents, so a pcapng renamed to `.pcap` still works.
2. Optionally narrows to the traffic under test (`--host`, `--port`)
3. Groups packets into per-connection flows (both directions of one
   conversation, correctly reassembled even if the capture starts
   mid-flow)
4. Runs six anomaly detectors over every flow:
   - **Retransmit storms** — several retransmitted segments clustered in
     time on one flow
   - **Unanswered SYNs** — a connection attempt (including the kernel's
     own retries) that never got a SYN-ACK — the packet-level signature
     of a target silently dropping connections
   - **Out-of-order bursts** — new segments arriving out of sequence
     order, clustered in time (retransmits are not counted here)
   - **Connection resets** — a SYN answered by RST (*refused*: closed
     port, or a full accept queue with `tcp_abort_on_overflow`) or an
     established connection killed by RST with no FIN first (*aborted*).
     An RST that follows a FIN is ordinary socket teardown and is not
     flagged.
   - **Duplicate-ACK bursts** — a run of identical pure ACKs (RFC 5681:
     same ack number and window, no data), the signal that triggers fast
     retransmit
   - **Zero-window stalls** — a receiver advertising a zero receive
     window, i.e. the *application* on that end is not reading and the
     sender is blocked. Separates "the network is lossy" from "the
     target is slow to drain its socket".
5. Reports descriptive statistics: TCP handshake latency (p50/p90/p99/max,
   first SYN → SYN-ACK), and the highest-volume flows
6. Optionally cross-checks its own independently-derived numbers against
   a `burstgen events.json` from the same run: connection-attempt and
   success counts (with a pass/fail verdict) and connect-latency p50/p99
   (shown side by side, no verdict — see below)

## Usage

```bash
cargo build --release

# Capture traffic while burstgen runs against a target
sudo tcpdump -i lo -n port 8080 -w capture.pcap &
burstgen conn-rate --target 127.0.0.1:8080 --rate 2000 --duration-secs 5

# Analyze it
./target/release/flowscope analyze --pcap capture.pcap \
    --burstgen-events burstgen-out/events.json
cat flowscope-out/report.md
```

Outputs, in `--output-dir` (default `./flowscope-out`): `report.md`
(human-readable), `findings.csv` (one row per finding), `summary.json`
(everything in the report, machine-readable).

Useful flags (`flowscope analyze --help` lists all of them):

| Flag | Meaning |
|---|---|
| `--host IP`, `--port N` | Keep only packets to/from this address / port. Repeatable; host and port are ANDed. |
| `--dupack-threshold N` (3), `--dupack-window-ms` (1000) | Duplicate-ACK burst sensitivity |
| `--zero-window-min-ms N` (100) | Shortest zero-window episode worth reporting |
| `--mismatch-tolerance-pct P` (5.0) | How far a burstgen count may differ before it's called a mismatch |
| `--top-flows N` (5) | Rows in the top-flows table |
| `--fail-on-findings` | Exit 3 if any anomaly was found |
| `--fail-on-mismatch` | Exit 4 if a burstgen correlation disagrees (needs `--burstgen-events`) |

Exit codes: `0` ok, `1` runtime error, `2` command-line usage error,
`3` findings (with `--fail-on-findings`), `4` mismatch (with
`--fail-on-mismatch`; wins over 3).

## Real test results (this build)

Everything below was run against real traffic on a loopback interface
captured with an independent sniffer, and checked against a source of
truth that shares no code with flowscope: counts recorded by the client
that generated the traffic, and the Linux kernel's own counters
(`/proc/net/netstat`, `/proc/net/snmp`).

| Scenario | flowscope | Independent truth |
|---|---|---|
| Healthy listener, 200 connections | 200 attempts, 200 SYN-ACKs, **0 findings** | client: 200 / 200 |
| Listener with `backlog=1`, never accepting, 60 attempts | **58** unanswered-SYN findings (2 succeeded) | client: 60 attempts − 2 successes = 58 |
| (same) SYN packets across those 58 flows | **174** | kernel `ListenOverflows` delta: **174** |
| 12 connects to a closed port | **12** "refused" resets, 0 unanswered SYNs | client saw 12 `ECONNREFUSED` |
| 5 connections closed with `SO_LINGER` 0 | **5** "aborted" resets | 5 RST closes issued |
| Receiver sleeps 1.5 s before reading | 1 zero-window stall, **1459 ms** | sender was blocked 1.52 s |
| 5 MB sent through 3 % random packet loss (`iptables`) | **147** retransmitted segments, 0 out-of-order | kernel `RetransSegs` delta: **147** |
| (same) duplicate-ACK runs | 61 runs; **61 / 61** have an ack number equal to a segment that was later retransmitted | independent parse of the pcap |

The healthy run also confirms the reset detector stays quiet on normal
close: no findings on 200 clean connections.

Handshake latency on the healthy run was p50 6 µs on the wire against
17 µs measured by the client around `connect()` — wire smaller than
client, the expected direction. These client-side numbers came from a
small Python client writing burstgen's `events.json` schema, not from
burstgen itself.

Link types and timestamps were verified by writing one identical capture
as Ethernet, raw IP, SLL, SLL2, BSD null, pcapng (default microsecond
resolution), pcapng (nanosecond resolution), pcapng-over-SLL2, and a
pcapng named `.pcap`: all nine parse to the same 16 packets, the same
finding, and the same timestamp.

## Bugs found and fixed

**Unanswered-SYN double counting (v0.1).** The first version of the
unanswered-SYN detector counted every SYN *packet*, not every connection
*attempt*. Under sustained backlog overflow, Linux's kernel retransmits
an unanswered SYN several times (observed ~6x on average, with
exponential backoff) before giving up — all on the same flow, since the
client doesn't open a new port to retry. The first version flagged each
retransmission as a separate finding and counted each one separately in
the correlation table, which inflated the finding count by roughly the
retry factor and made the correlation against burstgen's per-attempt
count disagree for a reason that had nothing to do with an actual
measurement discrepancy — it was double-counting retries, not measuring
anything wrong with the target.

Fixed by grouping to one finding per *flow* (the first SYN through the
last retry, with a `count` field showing how many retries occurred)
rather than one finding per SYN packet. Re-verified against the same
capture after the fix: the correlation now agrees exactly, and the
finding count (1814) is now internally consistent with the
attempts-minus-successes arithmetic, which it wasn't before.

**Four more, found in v0.2 by running the v0.1 binary on crafted and
real captures** (each reproduced before it was fixed):

1. *A truncated capture hung the tool forever.* The reader did
   `Err(_) => continue` on an undecodable record, but the reader does
   not advance past it, so a file cut off mid-record (tcpdump killed
   while writing) looped endlessly. Now it stops, analyzes what came
   before, and says so in the report.
2. *Retransmits were also reported as out-of-order.* A resent earlier
   segment has a sequence number below the maximum seen, so the same 6
   packets produced both a "retransmit storm" and an "out-of-order
   burst". Retransmits are now excluded from the out-of-order count.
3. *Sequence-number wraparound produced false out-of-order bursts.* A
   perfectly in-order stream crossing 2^32 gave 17 bogus out-of-order
   findings because sequence numbers were compared with plain `<`. They
   are now compared in serial-number arithmetic.
4. *Output order was nondeterministic.* Flows came out of a `HashMap`, so
   findings with equal timestamps were ordered differently on every run
   (three runs, three different CSV checksums). Flows and findings now
   have a total order; repeated runs are byte-identical apart from the
   `Generated:` timestamp.

## Known limitations

- Retransmission detection uses exact-sequence-number matching, which
  catches full retransmits (the common case for bulk transfers like
  burstgen's `large-flow` profile) but not partial/overlapping
  retransmits with different segment boundaries. If the original of a
  segment was lost *before* the capture point, its retransmission is the
  first copy seen and can appear out-of-order.
- **Capture on loopback with TSO/GSO enabled records ~64 KB
  super-segments, not wire-sized ones.** Retransmit and duplicate-ACK
  counts from such a capture will not match the kernel's per-segment
  counters. The loss test above was run with TSO/GSO/GRO turned off on
  `lo` (e.g. `ethtool -K lo tso off gso off gro off`).
- Out-of-order detection is covered by unit tests and by checking that
  it stays silent on real loss traffic, but was not validated against
  *real* reordered traffic (no `tc netem` in the test environment).
- Duplicate-ACK detection works on the ACK stream alone and does not
  check that the other side actually has unacknowledged data in flight.
  A window change correctly ends a run (RFC 5681), so one recovery
  episode can yield several runs.
- Zero-window detection only looks at whether the advertised window is
  zero, so it needs no window-scale parsing; it does not report
  *near*-zero windows.
- Connect-latency comparison against burstgen has no pass/fail verdict:
  burstgen times `connect()` in the client process, flowscope times
  first-SYN to SYN-ACK at the capture point, so the two are different
  spans by design.
- Flows are keyed by 4-tuple; a port reused within one capture is merged
  into one flow.
- IPv6 is parsed but untested end-to-end (no IPv6 test capture was
  available in this environment).
- No live capture mode — flowscope only reads `.pcap`/`.pcapng` files
  already written by `tcpdump`/Wireshark, it does not capture traffic
  itself, deliberately, to avoid needing libpcap or elevated capture
  permissions as a build/runtime dependency.
