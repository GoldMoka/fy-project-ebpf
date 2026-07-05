RUNBOOK — XDP Adaptive Firewall v8
Step-by-step: from zero to paper-ready benchmark numbers
=========================================================

Everything runs on a single machine. All topologies are veth-based.
Run every command as root (sudo -i or prefix with sudo).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 0 — ONE-TIME MACHINE SETUP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Step 0.1  Install all dependencies
────────────────────────────────────
  sudo apt update
  sudo bash install_and_run.sh --install-only

  Also install benchmark extras:
  sudo apt install -y bc gcc arping hping3 tmux

Ubuntu packages `bpftool` as part of the kernel tools package. Install the version that matches your running kernel:

  sudo apt install -y linux-tools-$(uname -r)

Verify the bpf version

  bpftool --version

  Verify kernel headers (required for BPF compilation):
  ls /lib/modules/$(uname -r)/build
    → Must exist. If not: sudo apt install linux-headers-$(uname -r)

Step 0.2  Build the C packet injector
──────────────────────────────────────
  gcc -O2 -o _bench_inject _bench_inject.c
  # benchmark.sh does this automatically on first run, but build it now
  # to catch any missing headers early.

  Why: the Python injector caps at ~0.2 Mpps (one syscall/packet).
       The C sendmmsg injector batches 64 frames/syscall → 1–3 Mpps.
       Without this, all throughput numbers are the sender ceiling, not XDP.

Step 0.3  Choose a topology and create the veth grid
─────────────────────────────────────────────────────
  Pick ONE of:

    sudo bash veth_setup.sh setup simple          # 3 nodes  — quickstart
    sudo bash veth_setup.sh setup ring-8          # 8 nodes  — ring gossip
    sudo bash veth_setup.sh setup hierarchical    # 13 nodes — 3-tier DC
    sudo bash veth_setup.sh setup mesh-6          # 6 nodes  — full mesh
    sudo bash veth_setup.sh setup multi-ring      # 9 nodes  — dual ring
    sudo bash veth_setup.sh setup star-large      # 9 nodes  — big star
    sudo bash veth_setup.sh setup all             # all above at once

  Verify everything is up:
    sudo bash veth_setup.sh status
    → All fw* interfaces should show UP with an IPv4 address.

Step 0.4  (Optional) Install tmux
───────────────────────────────────
  sudo apt install tmux

  The `start` command (see Part 1) uses tmux to open one pane per node so
  you can watch all nodes at once without managing N separate terminals.
  If tmux is absent it falls back to background processes with log files.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 1 — START THE FIREWALL CLUSTER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Option A — Automatic (recommended)
────────────────────────────────────
  sudo bash veth_setup.sh start <topology>
  # Example: sudo bash veth_setup.sh start simple/ring-8/hierarchical

  This command:
    1. Prompts for an HMAC key (or auto-generates one if you press Enter).
    2. Saves the key to logs/<topology>.key for reference.
    3. With tmux: opens a tmux session "xdp_<topology>" with one pane per
       node, starts each node, then offers to attach.
    4. Without tmux: launches all nodes in the background with setsid,
       logs to logs/<iface>.log.
    5. Prints the benchmark command to run after nodes are ready.

  No need to open additional terminals or type any commands.

  To stop all nodes cleanly:
    sudo bash veth_setup.sh stop <topology>

Option B — Manual (original behaviour, for debugging)
──────────────────────────────────────────────────────
  Generate a key:
    KEY=$(python3 -c "import secrets; print(secrets.token_hex(16))")

  Get the exact commands for your topology:
    sudo bash veth_setup.sh launch <topology>

  Copy-paste each block into its own terminal/pane.

Expected output on each node:
  [+] Attached in NATIVE mode on fw-ring-0
  [+] Maps pinned under /sys/fs/bpf/fw-ring-0/  (blacklist, jac_map)
  [Gossip] Listening on 0.0.0.0:7000  [HMAC-SHA256 key=a3f7c1b2...]
  XDP Adaptive Firewall — RUNNING

  ┌─ NOTE: Dummy-interface coordinators always show GENERIC mode ──────────┐
  │ fw-h-global and fw-star-coord are `ip link type dummy` interfaces.     │
  │ Dummy interfaces have no XDP driver (ndo_bpf) so native XDP is        │
  │ impossible — the kernel falls back to GENERIC (SKB) mode automatically.│
  │ This is CORRECT and EXPECTED. It does not affect benchmark accuracy:   │
  │ these nodes are pure gossip relays; no packet injection targets them.  │
  │ Only veth-pair nodes (rack coords, leaves) run in NATIVE mode.        │
  └───────────────────────────────────────────────────────────────────────┘

  ┌─ CRITICAL: start ALL nodes before running benchmarks ─────────────────┐
  │ Gossip propagation tests (B5) need all peers to be listening.          │
  │ Benchmark itself targets ONE node — stop the others ONLY when you      │
  │ need isolated throughput numbers (Bug 3 / map identity issue).         │
  └───────────────────────────────────────────────────────────────────────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 2 — LIVE MONITOR (optional, run while benchmarks are in progress)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  sudo python3 monitor.py --interval 1.0 --top 10

  Shows live: pps / drop-rate / sparklines / top-10 IPs / recent blocks.
  Run this in a separate pane during benchmarks to confirm traffic is
  actually reaching the XDP hook (non-zero pps = injector is working).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 3 — FUNCTIONAL TESTS (run before benchmarks to confirm everything works)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Only applies to the simple topology (veth_test.sh is wired to fw0/fw1/fw2):

  sudo bash veth_test.sh $KEYTest 1  Balanced SYN+ACK on fw0          → should NOT block
  Test 2  SYN flood on fw0 (200 SYNs)      → ALERT + block + gossip to fw1/fw2
  Test 3  Adaptive decay on fw1            → score rises then decays
  Test 4  SYN flood on fw2 (leaf)          → coord0 and coord1 both get gossip
  Test 5  Direct gossip inject (signed)    → block applied on fw0
  Test 6  Forge attempt + replay           → both REJECTED

  All 6 pass → proceed to benchmarks.

For ring/hierarchical/mesh topologies, functional tests are done by running
the benchmark B3 (block detect) and B5 (gossip) and checking non-zero results.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 4 — BENCHMARKS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Get the exact benchmark command for your topology:

  sudo bash veth_setup.sh benchmark <topology>
  # Example: sudo bash veth_setup.sh benchmark hierarchical

The general form is always:

  sudo bash benchmark.sh \
    --iface <fw-interface>  \   ← the interface XDP is attached to
    --target <fw-IP>        \   ← IPv4 address of that interface
    --runs 5                \   ← repetitions per benchmark (5 = paper quality)
    --veth                  \   ← REQUIRED on veth; omit only for physical NIC
    --hmac-key $KEY         \   ← must match the key used to start main.py
    --outdir results/<n>         ← where to save the output files

  --veth flag: works for ALL topology interface names.
    fw0/fw1/fw2      → atk0/atk1/atk2       (simple)
    fw-mesh-0        → atk-mesh-0            (mesh-6)
    fw-ring-0        → atk-ring-0            (ring-8)
    fw-h-rack0       → atk-h-rack0           (hierarchical)
    fw-h-r0-l0       → atk-h-r0-l0          (hierarchical)
    Any fw<X>        → atk<X>               (universal rule)

  ┌─ MAP IDENTITY WARNING ─────────────────────────────────────────────────┐
  │ When multiple main.py instances run simultaneously, BCC stubs may      │
  │ attach to the wrong instance's BPF maps.                               │
  │ For B2/B3/B4/B9 (throughput, block-detect, decay, scalability):        │
  │   stop all other main.py instances, benchmark fw0 alone, restart them. │
  │ For B5 (gossip): all peers must be running so they can receive.        │
  │ Sequence: start all → B5 → stop non-target nodes → B2/B3/B4/B9 alone  │
  └───────────────────────────────────────────────────────────────────────┘

  Runtime: ~20–30 min per node for --runs 5.

Step 4.1  What each benchmark measures
────────────────────────────────────────
  B1  Per-packet latency (µs)
      Uses hping3 SYN RTT. With hping3: true per-packet XDP time (~few µs).
      Without hping3: falls back to ICMP ping RTT (higher, includes TCP stack).
      Install: sudo apt install hping3

  B2  Throughput (Mpps)
      C injector blasts SYNs at max rate for 5s. Measures what XDP can actually
      process — should be 1–3 Mpps on veth with native mode.
      If still ~0.2: gcc failed to build _bench_inject (check step 0.2).

  B3  Block detection latency (ms + packets)
      One SYN at a time, polls blacklist after each. Expects 6 packets / <5ms.
      If shows 0.000: BCC stub attached to wrong instance (stop other nodes).

  B4  Score decay half-life (ms)
      4 SYNs (score=40), polls jac_map every 50ms until score halves.
      Expected: ~138ms (theoretical ln(2)/λ × 1000ms, λ=5).
      If N/A: either wrong instance or userspace decay wiped it early.

  B5  Gossip propagation latency (ms)
      Sends signed UDP gossip to fw, polls blacklist until entry appears.
      Expected: <10ms on veth for simple topology.
      For ring-8: roughly 8 × per-hop-latency.
      For hierarchical: 3-tier hop chain visible in higher latency.
      If 0.000: HMAC key mismatch, or main.py not running --hmac-key.

  B6  False positive rate (%)
      20 IPs each send balanced SYN+ACK. Expected: 0%.

  B7  Memory footprint
      BPF map sizes. Expected: blacklist ~40KB, jac_map ~560KB.

  B8  CPU overhead (%)
      idle / moderate-load (balanced C injector) / flood.
      Expected: idle~0.4%, moderate~2–5%, flood~10–20% sys on one core.

  B9  Blacklist scalability (Mpps vs map size)
      0 / 100 / 1000 / 5000 entries pre-populated. Should be flat (O(1)).

  B10 EWMA convergence (windows × 500ms)
      Steady mixed traffic, samples srtt/rttvar. Expected: stable in 4–6 windows.

Step 4.2  Results location
───────────────────────────
  results/<n>/summary_table.txt  ← paper-ready table
  results/<n>/B1_latency.txt
  results/<n>/B2_throughput.txt
  ... (one file per benchmark)

  cat results/<n>/summary_table.txt   ← paste into paper

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 5 — MULTI-TOPOLOGY COMPARISON (for paper's gossip section)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

To compare gossip propagation latency (B5) across topologies:

  1. sudo bash veth_setup.sh setup all
  2. sudo bash veth_setup.sh start <topology>
  3. Run benchmark (only B5 needed for comparison): benchmark.sh with --runs 3
  4. sudo bash veth_setup.sh stop <topology>
  5. Repeat for next topology.

  Expected B5 numbers:
    simple (star-3):    <5ms
    star-large (9):     <10ms   (1 extra hop: leaf→coord→target)
    ring-8:             ~N×2ms  (8 hops)
    hierarchical:       ~3×hop  (leaf→rack→global→rack→leaf)
    mesh-6:             ~2ms    (direct peer, no routing)
    multi-ring:         relay+ring hops

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 6 — TEARDOWN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  # Stop all main.py (XDP detaches cleanly, maps unpinned):
  sudo bash veth_setup.sh stop <topology>

  # Then tear down the veth interfaces:
  sudo bash veth_setup.sh teardown <topology>

  # Or tear down everything:
  sudo bash veth_setup.sh teardown all

  # Verify:
  sudo bash veth_setup.sh status   → should show no fw* interfaces

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 7 — NUMBERS TO RECORD FOR THE PAPER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

After running the suite, open results/<n>/summary_table.txt.

  B2  Throughput
      "The firewall processes X.XX ± 0.XX Mpps on veth in native XDP mode."
      Target: 1–3 Mpps. If still 0.2, the C injector did not compile.

  B3  Block detection
      "An IP is blocked within X.X ± Y.Y ms, after N packets
       (theoretical minimum 6 at W_SYN=10, floor threshold=50)."

  B4  Decay half-life
      "Score decays with half-life X ± Y ms (theoretical 138.6ms at λ=5)."

  B5  Gossip propagation
      "A block propagates to peers within X ± Y ms."
      Per-topology: quote the topology-specific number.

  B6  False positive rate
      "0% of balanced-traffic IPs were blocked (20 tested)."

  B7  Memory
      "BPF maps consume ~600KB total. Userspace RSS ~170MB per instance."

  B9  Scalability
      "Throughput is flat at X Mpps across blacklist sizes 0–5000 (O(1))."

  B10 Convergence
      "Adaptive threshold converges in N ± M windows (~X–Y seconds)."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 8 — TROUBLESHOOTING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

"[✗] --veth: --iface must start with fw (got: fw-mesh-0)":
  This error is GONE in v8. Any fw* interface name is now accepted.
  If you see this you are running the old benchmark.sh.

"[+] Attached in GENERIC (SKB) mode on fw-h-global":
  EXPECTED and CORRECT. fw-h-global and fw-star-coord are 'type dummy'
  interfaces — they have no XDP driver so native mode is impossible.
  The kernel silently falls back to generic. These nodes are gossip relays
  only; no benchmark traffic targets them. All veth-pair nodes (rack
  coordinators, leaves) will show NATIVE mode as expected.

"[!] Map pinning failed ('HashTable' object has no attribute 'pin')":
  Fixed in v8. main.py now falls back to 'bpftool map pin' automatically
  when the BCC .pin() method is absent (BCC < 0.23, Ubuntu 22.04 default).
  If you still see this:
    1. Check bpftool is installed: sudo apt install bpftool
    2. Check bpffs is mounted: mount | grep bpf
       If not: sudo mount -t bpf bpf /sys/fs/bpf
    3. If both fail, the benchmark proceeds without pinning — stop all but
       one main.py instance before running B2/B3/B4/B9.

"coordinators=['?']" in banner for fw-h-global:
  Fixed in v8. The banner now correctly displays
  "(global coordinator — no upstream)" for the hierarchical global node.

B2 throughput still ~0.2 Mpps:
  1. Check _INJECTOR_TYPE in summary_table.txt — must say "C", not "Python".
  2. If Python: gcc failed. Run manually: gcc -O2 -o _bench_inject _bench_inject.c
  3. If C but still 0.2: check that --veth flag is present.
  4. Verify native mode: main.py output should say "Attached in NATIVE mode".

B3/B4 show 0.000:
  1. Check that only ONE main.py is running (stop others with veth_setup.sh stop).
  2. Verify /sys/fs/bpf/<iface>/blacklist exists after main.py starts.
  3. Check _bench_inject compiled: ls -la _bench_inject  (should be binary).

B5 gossip shows 0.000 / NOT_APPLIED:
  1. Verify main.py uses --hmac-key and benchmark uses --hmac-key with SAME value.
     Even one hex character difference = HMAC mismatch = silent reject.
  2. Confirm gossip port: grep "Listening on" main.py output.
  3. Test: ss -ulnp | grep 5000

BPF compilation fails ("cannot find kernel headers"):
  sudo apt install linux-headers-$(uname -r)

monitor.py shows "Failed to open BPF maps":
  main.py must be running before monitor.py. Start main.py first.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 9 — FILE REFERENCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  xdp_fw.c            BPF kernel program. Stages: parse→whitelist→blacklist→
                      score→decay→threshold→verdict. 7 stages per packet.
                      Compiled and loaded by main.py via BCC.

  main.py             Python controller. Loads BPF, attaches XDP, pins maps,
                      runs gossip listener/sender, perf-event handler, stats.
                      v8 fix: map pinning now falls back to bpftool when
                      BCC < 0.23 (.pin() method absent).

  _bench_inject.c     C sendmmsg injector. Batches 64 frames per syscall.
                      Achieves 1–3 Mpps. Built automatically by benchmark.sh.

  benchmark.sh        B1–B10 paper benchmark suite. Auto-builds C injector.
                      v8 fix: --veth now accepts ANY fw* interface name, not
                      just fw0/fw1/fw2. Rule: fw<X> → atk<X>.

  veth_setup.sh       Multi-topology veth grid. Supports: simple, star-large,
                      ring-8, hierarchical, mesh-6, multi-ring, all.
                      v8 additions:
                        start <topo>  — ask for HMAC key, auto-launch all
                                        nodes (tmux or background)
                        stop  <topo>  — kill all nodes cleanly, detach XDP
                      Original commands (setup/teardown/status/launch/benchmark)
                      unchanged.

  monitor.py          Live terminal dashboard. Reads BPF maps at 1Hz.

  veth_test.sh        6 functional tests for the simple topology.

  install_and_run.sh  One-shot installer + launcher.
