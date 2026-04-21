#!/usr/bin/env python3
"""
monitor.py — Live XDP Firewall Dashboard
=========================================

Reads BPF maps from a running main.py instance and renders a real-time
terminal display, refreshing every second.

Metrics shown:
  - Total pps and drop pps (from BPF per-CPU counters, delta between polls)
  - Drop rate %
  - Blocked IP count
  - Alert count (from perf events, if --events is passed)
  - Top scored IPs with score, peak, adaptive threshold, state
  - Recent blocks (last 10)
  - Sparkline: pps history (last 60 seconds)

Usage:
  sudo python3 monitor.py [--iface fw0] [--interval 1.0] [--top 10]

No main.py source required — reads the BPF maps by compiling a minimal
stub with the same map declarations (BCC reuses maps by name).
"""

import sys
import os
import time
import socket
import struct
import argparse
import collections
import signal
import math

# ── BCC import ─────────────────────────────────────────────────────────────────
def _find_bcc():
    try:
        from bcc import BPF
        return BPF
    except ImportError:
        pass
    for p in [
        "/usr/lib/python3/dist-packages",
        "/usr/lib/python3.10/dist-packages",
        "/usr/lib/python3.11/dist-packages",
        "/usr/lib/python3.12/dist-packages",
    ]:
        if os.path.isfile(os.path.join(p, "bcc", "__init__.py")):
            if p not in sys.path:
                sys.path.insert(0, p)
            try:
                from bcc import BPF
                return BPF
            except ImportError:
                continue
    return None

BPF = _find_bcc()
if BPF is None:
    sys.exit("[✗] Cannot import BCC. Run install_and_run.sh first.")

# ── Args ───────────────────────────────────────────────────────────────────────
ap = argparse.ArgumentParser(description="XDP Firewall Live Dashboard")
ap.add_argument("--interval", type=float, default=1.0,
                help="Refresh interval in seconds (default: 1.0)")
ap.add_argument("--top",      type=int,   default=10,
                help="Number of top IPs to display (default: 10)")
ap.add_argument("--history",  type=int,   default=60,
                help="Seconds of pps history in sparkline (default: 60)")
args = ap.parse_args()

# ── Minimal BPF stub — just declares the maps so BCC gives us handles ─────────
# BCC reuses existing maps that share the same name and key/value types.
# The stub program itself is never attached.
STUB = r"""
#include <uapi/linux/bpf.h>

struct jacobson_t {
    u64 srtt;
    u64 rttvar;
    u64 score;
    u64 peak;
    u64 last_ts_ns;
    u64 window_start;
    u64 n_packets;
};

struct event_data_t {
    u32 saddr;
    u64 score;
    u64 threshold;
    u64 srtt;
    u64 rttvar;
};

enum { CTR_TOTAL = 0, CTR_DROP = 1, CTR_COUNT = 2 };

BPF_HASH(blacklist,    u32, u8);
BPF_HASH(jac_map,      u32, struct jacobson_t);
BPF_PERCPU_ARRAY(pkt_counters, u64, CTR_COUNT);
BPF_PERF_OUTPUT(events);

int stub(void *ctx) { return 0; }
"""

try:
    b            = BPF(text=STUB, cflags=["-w"])
    blacklist    = b.get_table("blacklist")
    jac_map      = b.get_table("jac_map")
    pkt_counters = b.get_table("pkt_counters")
except Exception as e:
    sys.exit(f"[✗] Failed to open BPF maps: {e}\n"
             f"    Is main.py running? The maps must exist before monitor.py starts.")

# ── Helpers ────────────────────────────────────────────────────────────────────
FP = 100
FLOOR = 50
RTTVAR_MIN_FP = FP // 4   # must match xdp_fw.c

def fmt_ip(packed_int: int) -> str:
    return socket.inet_ntoa(struct.pack("I", packed_int))

def read_counter(idx: int) -> int:
    """Sum per-CPU values for counter at index idx."""
    try:
        key = pkt_counters.Key(idx)
        vals = pkt_counters.getvalue(key)   # list of per-cpu u64
        return sum(int(v) for v in vals)
    except Exception:
        return 0

def threshold_for(srtt_fp: int, rttvar_fp: int) -> int:
    """Reproduce the C threshold formula in Python."""
    rv = max(rttvar_fp, RTTVAR_MIN_FP)
    return (srtt_fp + 4 * rv) // FP

def sparkline(vals, width=40, lo=None, hi=None) -> str:
    """Render a list of numbers as a unicode block sparkline."""
    bars = " ▁▂▃▄▅▆▇█"
    if not vals:
        return " " * width
    lo  = lo  if lo  is not None else min(vals)
    hi  = hi  if hi  is not None else max(vals)
    rng = hi - lo if hi != lo else 1
    out = []
    for v in vals[-width:]:
        idx = int((v - lo) / rng * (len(bars) - 1))
        out.append(bars[max(0, min(len(bars)-1, idx))])
    # Pad left if shorter than width
    return " " * (width - len(out)) + "".join(out)

def human(n: float) -> str:
    """Format a large number with K/M/G suffix."""
    if n >= 1_000_000:
        return f"{n/1_000_000:.2f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}K"
    return str(int(n))

# ── Terminal colours (no external deps) ───────────────────────────────────────
R  = "\033[31m"
G  = "\033[32m"
Y  = "\033[33m"
B  = "\033[34m"
M  = "\033[35m"
C  = "\033[36m"
W  = "\033[37m"
BR = "\033[1;31m"
BG = "\033[1;32m"
BY = "\033[1;33m"
BC = "\033[1;36m"
BW = "\033[1m"
NC = "\033[0m"
CLEAR_SCREEN = "\033[2J\033[H"
CLEAR_LINE   = "\033[K"

def color_rate(pps: float, drop_pct: float) -> str:
    if drop_pct > 50:   return BR
    if drop_pct > 10:   return Y
    if pps > 500_000:   return BY
    return BG

# ── State ──────────────────────────────────────────────────────────────────────
prev_total  = read_counter(0)
prev_drop   = read_counter(1)
prev_time   = time.monotonic()

pps_history      = collections.deque(maxlen=args.history)
drop_pps_history = collections.deque(maxlen=args.history)
recent_blocks    = collections.deque(maxlen=10)   # (time_str, ip, score, thr)
alert_total      = 0

# Track newly blocked IPs between polls
prev_blocked_set: set = set()

def handle_event(cpu, data, size):
    """Callback for perf buffer events (new blocks from main.py)."""
    global alert_total
    try:
        ev        = b["events"].event(data)
        ip        = fmt_ip(ev.saddr)
        ts        = time.strftime("%H:%M:%S")
        alert_total += 1
        recent_blocks.appendleft((ts, ip, int(ev.score), int(ev.threshold)))
    except Exception:
        pass

try:
    b["events"].open_perf_buffer(handle_event, page_cnt=64)
    has_events = True
except Exception:
    has_events = False

# ── Signal handler ─────────────────────────────────────────────────────────────
def _quit(sig, frame):
    print(f"\n{NC}Monitor stopped.")
    sys.exit(0)

signal.signal(signal.SIGINT,  _quit)
signal.signal(signal.SIGTERM, _quit)

# ── Main loop ──────────────────────────────────────────────────────────────────
def poll_and_render():
    global prev_total, prev_drop, prev_time, prev_blocked_set, alert_total

    # ── Drain perf buffer for new block events ─────────────────────────────
    if has_events:
        try:
            b.perf_buffer_poll(timeout=0)
        except Exception:
            pass

    # ── Read counters ──────────────────────────────────────────────────────
    now_total = read_counter(0)
    now_drop  = read_counter(1)
    now_time  = time.monotonic()

    dt = now_time - prev_time
    dt = max(dt, 0.001)

    pps      = (now_total - prev_total) / dt
    drop_pps = (now_drop  - prev_drop)  / dt
    pass_pps = max(0.0, pps - drop_pps)

    prev_total = now_total
    prev_drop  = now_drop
    prev_time  = now_time

    pps_history.append(pps)
    drop_pps_history.append(drop_pps)

    drop_pct = (drop_pps / pps * 100) if pps > 0 else 0.0

    # ── Read maps ──────────────────────────────────────────────────────────
    blocked_ips: set = set()
    try:
        blocked_ips = {fmt_ip(k.value) for k, _ in blacklist.items()}
    except Exception:
        pass

    # Detect IPs newly blocked since last poll (not via perf event)
    new_blocks = blocked_ips - prev_blocked_set
    for ip in new_blocks:
        ts = time.strftime("%H:%M:%S")
        recent_blocks.appendleft((ts, ip, 0, 0))
    prev_blocked_set = blocked_ips

    # Top IPs from jac_map
    scored = []
    try:
        for k, v in jac_map.items():
            ip      = fmt_ip(k.value)
            score   = int(v.score)
            peak    = int(v.peak)
            srtt_fp = int(v.srtt)
            rv_fp   = int(v.rttvar)
            n_pkts  = int(v.n_packets)
            thr     = threshold_for(srtt_fp, rv_fp) if srtt_fp > 0 else FLOOR
            thr     = max(thr, FLOOR)
            is_bl   = ip in blocked_ips
            scored.append((ip, score, peak, srtt_fp // FP, rv_fp // FP,
                           n_pkts, thr, is_bl))
    except Exception:
        pass

    # Sort: blocked first, then by score descending
    scored.sort(key=lambda x: (x[7], x[1]), reverse=True)

    # ── Render ─────────────────────────────────────────────────────────────
    lines = []
    W_COL = 78

    def ln(s=""):
        lines.append(s)

    ts_now = time.strftime("%H:%M:%S")
    rc = color_rate(pps, drop_pct)

    ln(f"{BC}{'═'*W_COL}{NC}")
    ln(f"{BC}  XDP Adaptive Firewall — Live Monitor{NC}   "
       f"{W}{ts_now}{NC}   interval={args.interval:.1f}s")
    ln(f"{BC}{'─'*W_COL}{NC}")

    # ── Throughput line ────────────────────────────────────────────────────
    bar_w = 20
    bar_fill = int(min(drop_pct / 100, 1.0) * bar_w)
    bar = f"{R}{'█'*bar_fill}{NC}{'░'*(bar_w-bar_fill)}"

    ln(f"  {BW}Total pps  {NC}{rc}{human(pps):>8}{NC}/s    "
       f"{BW}Pass {NC}{BG}{human(pass_pps):>8}{NC}/s    "
       f"{BW}Drop {NC}{BR}{human(drop_pps):>8}{NC}/s")
    ln(f"  {BW}Drop rate  {NC}{rc}{drop_pct:6.1f}%{NC}  [{bar}]    "
       f"{BW}Blocked IPs:{NC} {BR}{len(blocked_ips)}{NC}    "
       f"{BW}Alerts:{NC} {Y}{alert_total}{NC}")

    # ── Sparkline ──────────────────────────────────────────────────────────
    ln(f"{BC}{'─'*W_COL}{NC}")
    spark_w = W_COL - 18
    ln(f"  {BW}pps  (last {len(pps_history)}s){NC} {sparkline(list(pps_history), spark_w)}")
    ln(f"  {BW}drop (last {len(drop_pps_history)}s){NC} "
       f"{R}{sparkline(list(drop_pps_history), spark_w, lo=0)}{NC}")

    # ── Top IPs ────────────────────────────────────────────────────────────
    ln(f"{BC}{'─'*W_COL}{NC}")
    ln(f"  {BW}{'IP':<18} {'Score':>6} {'Peak':>6} {'SRTT':>5} {'RVar':>5} "
       f"{'Threshold':>9} {'Pkts':>6}  State{NC}")
    ln(f"  {'─'*72}")

    display = scored[:args.top]
    if not display:
        ln(f"  {W}  (no IP activity yet){NC}")
    for ip, score, peak, srtt, rvar, n_pkts, thr, is_bl in display:
        if is_bl:
            state_str = f"{BR}BLOCKED{NC}"
            ip_col    = BR
        elif n_pkts <= 5:
            state_str = f"{Y}warmup{NC}"
            ip_col    = W
        elif score > thr * 0.8:
            state_str = f"{Y}near-thr({thr}){NC}"
            ip_col    = Y
        else:
            state_str = f"{G}ok (thr={thr}){NC}"
            ip_col    = W

        score_col = BR if score > thr * 0.8 else (Y if score > 20 else W)
        ln(f"  {ip_col}{ip:<18}{NC} "
           f"{score_col}{score:>6}{NC} "
           f"{peak:>6} {srtt:>5} {rvar:>5} "
           f"{thr:>9} {n_pkts:>6}  {state_str}")

    # ── Recent blocks ──────────────────────────────────────────────────────
    if recent_blocks:
        ln(f"{BC}{'─'*W_COL}{NC}")
        ln(f"  {BW}Recent blocks (newest first){NC}")
        for ts_b, ip_b, sc_b, thr_b in list(recent_blocks)[:6]:
            sc_str  = f"score={sc_b}" if sc_b else "via-gossip"
            thr_str = f" thr={thr_b}" if thr_b else ""
            ln(f"  {Y}{ts_b}{NC}  {BR}{ip_b:<18}{NC}  {W}{sc_str}{thr_str}{NC}")

    # ── Cumulative counters ────────────────────────────────────────────────
    ln(f"{BC}{'─'*W_COL}{NC}")
    ln(f"  {W}Cumulative — total pkts:{NC} {human(now_total)}   "
       f"{W}total drops:{NC} {human(now_drop)}   "
       f"{W}drop ratio:{NC} "
       f"{(now_drop/now_total*100):.1f}%" if now_total else "  n/a")
    ln(f"{BC}{'═'*W_COL}{NC}")
    ln(f"  {W}q{NC} quit   {W}r{NC} reset recent-blocks   "
       f"Press Ctrl-C to exit")

    # ── Output all at once (minimises flicker) ─────────────────────────────
    out = CLEAR_SCREEN + "\n".join(lines)
    sys.stdout.write(out)
    sys.stdout.flush()


print(f"{BC}XDP Firewall Monitor — connecting to BPF maps...{NC}")
time.sleep(0.3)

# Hide cursor
sys.stdout.write("\033[?25l")
sys.stdout.flush()

try:
    while True:
        t_start = time.monotonic()
        poll_and_render()
        elapsed = time.monotonic() - t_start
        sleep_for = max(0.0, args.interval - elapsed)
        time.sleep(sleep_for)
finally:
    # Restore cursor on exit
    sys.stdout.write("\033[?25h\n")
    sys.stdout.flush()
