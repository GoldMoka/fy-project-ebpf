# XDP Adaptive Firewall

A kernel-bypass TCP firewall running entirely in XDP (eXpress Data Path), with
adaptive per-IP thresholding, distributed gossip propagation, and a native-XDP
veth test environment for deterministic benchmarking.

---

## Table of Contents

1. [What This Is](#what-this-is)
2. [How It Works](#how-it-works)
   - [Scoring](#scoring)
   - [Decay](#decay)
   - [Adaptive Threshold (Jacobson EWMA)](#adaptive-threshold)
   - [Block paths](#block-paths)
3. [Threshold Bug Fixes](#threshold-bug-fixes)
4. [Distributed Gossip](#distributed-gossip)
   - [Multi-coordinator star](#multi-coordinator-star)
   - [Secure channel](#secure-channel)
5. [Files](#files)
6. [veth Test Environment](#veth-test-environment)
   - [Why veth instead of physical](#why-veth)
   - [Topology](#topology)
   - [Quick start](#quick-start)
7. [Benchmarking on veth](#benchmarking-on-veth)
8. [Physical Lab Usage](#physical-lab-usage)
9. [Tuning Reference](#tuning-reference)
10. [Comparison with iptables / nftables](#comparison)
11. [Known Limitations](#known-limitations)

---

## What This Is

This is not trying to replace iptables for policy-based filtering (allow port 443,
drop RFC-1918, etc.). The goal is anomaly detection — catching TCP flood attacks
in real time, at the NIC, before the kernel allocates any per-connection state.

The key claims:

- **Sub-microsecond drop** on blocked IPs (XDP_DROP before sk_buff allocation)
- **Adaptive per-IP threshold** — a server legitimately doing 50 connection
  attempts per second won't be blocked; the same IP doing 5000/s will
- **Gossip propagation** — a block detected on one node is pushed to peers
  within milliseconds
- **Secured gossip** — the gossip channel is HMAC-signed; forged or replayed
  block messages are rejected

---

## How It Works

### Scoring

Each TCP packet from a source IP increments or decrements a raw score:

| Packet type | Effect |
|---|---|
| SYN (no ACK) | +10 (or +20 if SRTT is elevated) |
| ACK (no SYN) | −2 (or −1 if SRTT is elevated) |
| RST | +5 |

SYNs are suspicious; ACKs indicate completed handshakes and reduce the score.
An IP doing normal traffic will hover near zero.

### Decay

Between packets the score decays exponentially:

```
score(t) = score(t0) × (1 − λ × Δt_ms / 1000)
```

With `λ = 5` and a 200 ms silence the score halves (~138 ms half-life). This
means a short connection burst that stops is forgotten in under a second.

### Adaptive Threshold (Jacobson EWMA)

The system runs a Jacobson RTT estimator — repurposed for score peaks rather
than network latency.

Every 500 ms window, the peak score seen in that window is taken as a sample.
It feeds into:

```
SRTT   = SRTT   × (1 − 1/8) + sample × (1/8)
RTTVAR = RTTVAR × (1 − 1/4) + |SRTT − sample| × (1/4)
threshold = SRTT + 4 × RTTVAR
```

An IP that always peaks at 30 will converge to SRTT ≈ 30. If it suddenly
peaks at 200, the previous baseline was SRTT ≈ 30, RTTVAR ≈ small, so
threshold ≈ 30 + small — and 200 >> 30, block fires.

A floor threshold of 50 (6 SYNs in quick succession) protects against fresh
IPs with no baseline history.

### Block paths

```
Stage 1: blacklist check → XDP_DROP  (fastest, no computation)
Stage 3: decay
Stage 4–5: score update
Stage 6: score > FLOOR_THRESHOLD (50) → XDP_DROP + gossip
Stage 7: EWMA window expired AND prev_peak > prev_threshold → XDP_DROP + gossip
```

---

## Threshold Bug Fixes

Three bugs were found and fixed in `xdp_fw.c`:

### Bug 1 — Check-then-update ordering (CRITICAL)

**Original behaviour:** The EWMA was updated with the current window's peak,
*then* the threshold was checked against that same peak. Since the threshold
rises whenever the peak rises, a sustained constant-rate attack could ride the
EWMA upward indefinitely and the adaptive path would never fire.

Concrete example: an IP sending 4 SYNs every 500 ms (score peak = 40, below
the floor of 50) would never be blocked. The threshold converges to 40 + small,
which is always ≥ 40.

**Fix:** Snapshot `prev_srtt`, `prev_rttvar`, `prev_peak` *before* updating the
EWMA. Evaluate the threshold against those previous-window values. An attack
window is now compared against the calm-traffic baseline, not against a
threshold that just absorbed the attack.

```c
/* snapshot */
u64 prev_srtt   = j->srtt;
u64 prev_rttvar = j->rttvar;
u64 prev_peak   = j->peak;

/* update EWMA */
...

/* check against PREVIOUS baseline */
if (prev_srtt > 0) {
    u64 threshold = (prev_srtt + K * prev_rttvar) / FP;
    if (prev_peak > threshold) → BLOCK
}
```

### Bug 2 — rttvar minimum floor too small (MEDIUM)

**Original behaviour:** `rttvar` was floored at 1 FP unit (= 0.01 raw score).
The check `4 * 1 / 100` evaluates to 0 in integer division. Once rttvar
converged toward zero, the `K × RTTVAR` safety margin disappeared entirely
and the threshold became just SRTT with no deviation buffer.

**Fix:** Floor rttvar at `FP/4` (25 FP units = 0.25 raw score). This ensures
`4 × 25 / 100 = 1` minimum contribution, maintaining a small deviation
buffer even after convergence.

```c
#define RTTVAR_MIN_FP  (FP / 4ULL)   /* 25 FP units — guarantees K*rttvar >= 1 raw */
```

### Bug 3 — window_start not reset on floor-path block (MINOR)

**Original behaviour:** The floor path (Stage 6) reset `score` and `peak` after
a block, but did not reset `window_start`. If the IP was manually unblocked
and reconnected quickly, the stale `window_start` might already be past the
500 ms mark, triggering an immediate EWMA evaluation on a near-empty window.

**Fix:** Reset `window_start = 0` in the floor path, matching the behaviour of
the adaptive path.

---

## Distributed Gossip

When any node detects and blocks an IP, it immediately gossips the block to
peers so they apply it without waiting for their own EWMA to fire.

### Multi-coordinator star

The original design had a single coordinator — a single point of failure. The
new design supports multiple coordinators:

```
              ┌─ coord0 ──── coord1 ─┐
              │    ↕ coord sync      │
leaf-fw0 ─────┤                      ├───── leaf-fw2
              │                      │
leaf-fw1 ─────┘                      
```

- **Leaves** hold a `coordinators` list and send to *all* of them on every
  detected block. If one coordinator is down, the other still propagates.
- **Coordinators** hold a `coordinator_peers` list. When one receives a block
  from a leaf, it fans out to its leaf list and syncs the block to sibling
  coordinators. An `origin` field prevents echo-back loops.

Peers files are generated by `veth_setup.sh` and look like:

```json
// coordinator node
{
  "role": "coordinator",
  "coordinator_peers": ["10.99.0.2"],
  "peers": ["10.0.1.1", "10.0.2.1"]
}

// leaf node
{
  "role": "leaf",
  "coordinators": ["10.0.0.1", "10.99.0.1"]
}
```

### Secure channel

Every gossip message is HMAC-SHA256 signed:

```json
{
  "ip":    "1.2.3.4",
  "ts":    1744123456.789,
  "nonce": "a3f7c1b2d4e69801",
  "sig":   "e3b0c44298fc1c14..."
}
```

`sig = HMAC-SHA256(shared_key, ip + ":" + ts + ":" + nonce)`

Security properties:
- **Forgery resistance** — without the shared key an attacker cannot produce
  a valid signature for any IP
- **Tamper resistance** — mutating any field invalidates the signature
- **Replay protection** — messages older than 30 seconds are rejected; each
  nonce is cached for the window duration and duplicates are rejected
- **Trust model** — shared-key cluster trust (same model as WireGuard PSK and
  TSIG). Nodes sharing the key implicitly trust each other. Per-node identity
  is out of scope by design.

Pass the key with `--hmac-key <hex>`. All nodes in the cluster must use the
same key. Omitting the key leaves gossip unauthenticated (development only).

---

## Files

| File | Description |
|---|---|
| `xdp_fw.c` | XDP BPF program — scoring, decay, adaptive threshold (with bug fixes) |
| `main.py` | Python controller — BPF attach, gossip, perf event handler, stats |
| `veth_setup.sh` | Create/teardown the veth test topology and generate peers files |
| `veth_test.sh` | Full test suite running inside the attacker netns |
| `test_firewall.sh` | Original two-device physical lab test script (still works) |
| `benchmark.sh` | Paper-quality benchmark suite (B1–B10) |
| `install_and_run.sh` | One-shot dependency installer + launcher |
| `diagnose.py` | Diagnostic tool for reading live BPF map state |

---

## veth Test Environment

### Why veth

Physical lab testing has inherent variables:

- ARP resolution races (test fails because MAC table hasn't populated)
- NIC offloads (GRO/GSO can coalesce packets before XDP sees them)
- Switch MAC table flaps between runs
- Kernel path changes depending on whether the NIC has a native XDP driver

The veth environment eliminates all of these. A veth pair is a direct
kernel-to-kernel wire: packet injected on one end appears instantly on the
other, with zero L2 indirection. Native XDP works on veth since kernel 5.9
(`drivers/net/veth.c` got `ndo_bpf`). Every benchmark run sees identical
conditions — reproducible numbers, no run-to-run variance from physical layer.

This is also why the benchmark result is more trustworthy than a physical-NIC
number for papers: the veth number is the XDP program's performance, not the
NIC driver's performance.

### Topology

```
root netns:

  fw0  10.0.0.1/24  ←──veth──→  atk0@xdp_attacker  10.0.0.99
  fw1  10.0.1.1/24  ←──veth──→  atk1@xdp_attacker  10.0.1.99
  fw2  10.0.2.1/24  ←──veth──→  atk2@xdp_attacker  10.0.2.99

  coord0  10.99.0.1/30  ←──veth──→  coord1  10.99.0.2/30
  (gossip backbone between coordinators)
```

- **fw0/fw1/fw2** — firewall-side veth ends. Attach `main.py` here.
- **atk0/atk1/atk2** — injector-side ends inside `xdp_attacker` netns.
  Packets sent here arrive directly on the fw* end without traversing any
  physical layer or switch.
- **coord0/coord1** — gossip backbone. fw0 plays coord0 role, fw1 plays coord1.

### Quick start

```bash
# 1. Create topology
sudo bash veth_setup.sh setup

# 2. Start all firewall nodes automatically (asks for HMAC key once)
#    Uses tmux if available (sudo apt install tmux), otherwise background processes
sudo bash veth_setup.sh start simple

# 3. Run test suite (use the key printed by the start command)
sudo bash veth_test.sh $KEY

# 4. Stop all nodes cleanly
sudo bash veth_setup.sh stop simple

# 5. Tear down when done
sudo bash veth_setup.sh teardown
```

**Manual start (original, for debugging):**

```bash
KEY=$(python3 -c "import secrets; print(secrets.token_hex(16))")

# Terminal 1 — coordinator 0 on fw0
sudo python3 main.py --iface fw0 --port 5000 --peer-port 5001 \
     --topology star --peers-file peers_coord0.json \
     --xdp-mode native --hmac-key $KEY

# Terminal 2 — coordinator 1 on fw1
sudo python3 main.py --iface fw1 --port 5001 --peer-port 5000 \
     --topology star --peers-file peers_coord1.json \
     --xdp-mode native --hmac-key $KEY

# Terminal 3 — leaf on fw2
sudo python3 main.py --iface fw2 --port 5002 --peer-port 5000 \
     --topology star --peers-file peers_fw2.json \
     --xdp-mode native --hmac-key $KEY
```

The test suite covers:

| Test | What it checks |
|---|---|
| 1 | Balanced SYN+ACK traffic — should NOT block |
| 2 | SYN flood on fw0 — alert + block + gossip to fw1/fw2 |
| 3 | Adaptive decay — score rises then decays to 0, no permanent block |
| 4 | SYN flood on fw2 (leaf) — both coordinators receive the gossip |
| 5 | Direct gossip injection — signed UDP block message applied |
| 6 | Forge attempt + replay — both rejected with REJECT log lines |

---

## Benchmarking on veth

Run `benchmark.sh` against one of the fw* interfaces. The firewall must be
running on that interface first.

```bash
# With fw0 running main.py (simple topology):
sudo bash benchmark.sh --iface fw0 --target 10.0.0.1 --runs 5 --veth --hmac-key $KEY

# With fw-mesh-0 running main.py (mesh-6 topology):
sudo bash benchmark.sh --iface fw-mesh-0 --target 10.40.0.1 --runs 5 --veth --hmac-key $KEY

# --veth now accepts ANY fw* interface. The attacker peer is derived
# automatically: fw<X> → atk<X> in the xdp_attacker netns.
```

Results go to `./results/`. The `summary_table.txt` is paper-ready:

| Benchmark | Measures |
|---|---|
| B1 | Per-packet latency (µs) |
| B2 | Throughput (Mpps) |
| B3 | Block detection latency (ms from first SYN to blacklist entry) |
| B4 | Score decay half-life (should be ~138ms) |
| B5 | Gossip propagation latency (ms) |
| B6 | False positive rate on legitimate bursty traffic |
| B7 | Memory footprint (BPF maps + userspace RSS) |
| B8 | CPU overhead (idle / moderate load / flood) |
| B9 | Blacklist scalability (throughput vs map size, should be O(1)) |
| B10 | EWMA convergence (windows until threshold stabilises) |

**Interpreting B2 (throughput):** on a veth pair you are measuring the XDP
program's computational cost, not the NIC. Expected range is 3–10 Mpps on a
modern core depending on kernel version. A physical 10G NIC with a native XDP
driver (i40e, mlx5) will be limited by line rate (~14 Mpps for 64-byte frames)
rather than the program.

**Interpreting B6 (false positives):** with the Bug 1 fix, legitimate traffic
that establishes a stable SRTT baseline will have a threshold comfortably above
its normal peak. FPR should be 0% for balanced SYN+ACK traffic. Highly
asymmetric TCP (lots of SYN, few ACK — e.g. HTTP/1.0 without keep-alive) will
accumulate score faster; tune `W_ACK_BASE` up if your workload has this shape.

---

## Physical Lab Usage

The original `test_firewall.sh` and `install_and_run.sh` still work for
two-machine physical testing. The main change is `--xdp-mode native` is now
the default; if your NIC driver does not support native XDP it falls back to
generic automatically.

```bash
# Device 1 (firewall)
sudo bash install_and_run.sh --topology star --iface eno1

# Device 2 (attacker/tester)
sudo bash test_firewall.sh --iface eno1 --target <device1_IP>
```

For a star topology with multiple coordinators on physical hardware, create
`peers.json` manually following the format in the veth section above and pass
`--peers-file peers_coord0.json` etc.

---

## Tuning Reference

| Constant | Default | Effect |
|---|---|---|
| `FLOOR_THRESHOLD` | 50 | Block immediately above this score (6 bare SYNs). Lower = faster block, more false positives. |
| `W_SYN_BASE` | 10 | Score per SYN in normal mode. |
| `W_ACK_BASE` | 2 | Score reduction per ACK in normal mode. |
| `DECAY_LAMBDA` | 5 | Higher = faster decay (shorter memory). |
| `EWMA_WINDOW_NS` | 500ms | Longer = smoother baseline, slower to detect gradual ramp-up. |
| `JACOBSON_K` | 4 | Multiplier on RTTVAR. Higher = more tolerance for burst variance. |
| `WARMUP_PACKETS` | 5 | Packets before adaptive mode kicks in. |
| `ELEVATED_SRTT` | 200 | If smoothed peak score exceeds this, tighten weights. |

**For high-bandwidth servers (CDN, game server):** increase `FLOOR_THRESHOLD`
to 200 and `W_ACK_BASE` to 5 to reduce false positives on bursty but legitimate
connections.

**For hardened edge nodes:** decrease `FLOOR_THRESHOLD` to 30 and
`EWMA_WINDOW_NS` to 200ms for faster detection at the cost of higher FPR.

---

## Comparison

| Feature | iptables/nftables | This firewall |
|---|---|---|
| Drop position in kernel | After sk_buff alloc, after route lookup | XDP — before sk_buff alloc |
| Policy rules (port, addr, conntrack) | Yes | No (out of scope) |
| Anomaly detection | No | Yes (Jacobson EWMA) |
| Per-IP adaptive threshold | No | Yes |
| Gossip propagation | No | Yes (multi-coordinator star, HMAC) |
| Throughput at block stage | ~1–2 Mpps | ~3–10 Mpps on veth |
| State memory per IP | Conntrack: ~300 bytes | jac_map: 56 bytes |

The firewall does not replace iptables. It is intended to run alongside it: XDP
handles volume-based anomalies at line rate before the kernel stack; iptables
handles policy rules on the packets that survive.

---

## Known Limitations

- **TCP only.** UDP and ICMP floods are not scored (packets pass through).
- **Dummy-interface coordinators always run in GENERIC mode.** `fw-h-global`
  (hierarchical) and `fw-star-coord` (star-large) are created as
  `ip link type dummy` — they have no XDP driver (`ndo_bpf`), so native XDP
  is impossible. The kernel silently falls back to GENERIC (SKB) mode. This
  is correct and expected: these nodes are pure gossip relays, not packet
  inspection points. All veth-pair interfaces (rack coordinators, leaves) do
  run in native mode.
- **Shared-key gossip trust.** A node with the HMAC key can inject any block.
  There is no per-node certificate or revocation mechanism.
- **No unblock automation.** Blocked IPs stay blocked until manually removed.
  A legitimately-blocked IP that resolves its behaviour will not auto-recover.
- **jac_map is per-interface.** Each `main.py` instance has its own BPF maps.
  Gossip is the only synchronisation mechanism between nodes.
- **BPF map max_entries = 65536 by default.** If more than 65536 unique source
  IPs appear, new entries are silently dropped and those IPs are untracked.
  Increase `max_entries` in `xdp_fw.c` for high-diversity environments.
