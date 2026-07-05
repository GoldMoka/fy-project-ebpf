#!/usr/bin/env python3
"""
XDP Adaptive Firewall — Python Controller
Handles: BPF attach, gossip (star/mesh/ring/hierarchical), alerts, cleanup

Changes from v1:
  - Multi-coordinator star topology
    * Leaves send to ALL coordinators (redundant delivery, no single SPOF)
    * Coordinators sync new blocks with each other via coordinator_peers
    * coordinator_peers prevents re-gossip loops (origin-tracking)

  - Native XDP preferred (--xdp-mode native, veth supports it kernel 5.9+)
    * Generic/SKB mode is still the fallback for older drivers

  - Secure gossip channel (--hmac-key <hex>)
    * Every gossip message is HMAC-SHA256 signed
    * Receiver verifies before applying any block
    * Replay protection: 30-second timestamp window
    * Without a matching key, injected gossip is silently rejected
    * "No trust mechanism for bad actors" = we authenticate the channel,
      not the identity; a node that shares the key is implicitly trusted —
      this is the same model as WireGuard PSK / TSIG
"""

import sys
import os
import socket
import struct
import hashlib
import hmac as _hmac
import threading
import argparse
import json
import time
import signal
import traceback
import secrets
from pathlib import Path

# ── Dependency check ───────────────────────────────────────────────────────────
def _find_bcc():
    try:
        from bcc import BPF
        return BPF
    except ImportError:
        pass

    search_paths = [
        "/usr/lib/python3/dist-packages",
        "/usr/lib/python3.6/dist-packages",
        "/usr/lib/python3.7/dist-packages",
        "/usr/lib/python3.8/dist-packages",
        "/usr/lib/python3.9/dist-packages",
        "/usr/lib/python3.10/dist-packages",
        "/usr/lib/python3.11/dist-packages",
        "/usr/lib/python3.12/dist-packages",
        "/usr/local/lib/python3/dist-packages",
    ]
    for p in search_paths:
        if os.path.isfile(os.path.join(p, "bcc", "__init__.py")):
            if p not in sys.path:
                sys.path.insert(0, p)
            try:
                from bcc import BPF
                print(f"[+] Found BCC at {p}")
                return BPF
            except ImportError:
                continue
    return None

BPF = _find_bcc()
if BPF is None:
    print("[✗] Cannot import BCC. Did you run install_and_run.sh first?")
    print("    Ubuntu 20.04/22.04/24.04 : sudo apt install python3-bpfcc bpfcc-tools")
    print("    Ubuntu 18.04             : sudo apt install python-bpfcc bpfcc-tools")
    print("    Fedora/RHEL              : sudo dnf install python3-bcc bcc-tools")
    print("    Arch                     : sudo pacman -S python-bcc")
    sys.exit(1)

# ── Argument parsing ───────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="XDP Adaptive Firewall")
parser.add_argument("--iface",      default="lo",      help="Interface to attach XDP")
parser.add_argument("--port",       type=int, default=5000, help="Local gossip UDP port")
parser.add_argument("--peer-port",  type=int, default=5001, help="Peer gossip UDP port")
parser.add_argument("--topology",   default="star",
                    choices=["star","mesh","ring","hierarchical"],
                    help="Gossip topology")
parser.add_argument("--peers-file", default="peers.json",
                    help="Path to peers.json")
parser.add_argument("--xdp-mode",   default="native",
                    choices=["native","generic"],
                    help="XDP attach mode (native=fastest, generic=fallback)")
parser.add_argument("--dry-run",    action="store_true",
                    help="Print alerts but don't update blacklist or gossip")
parser.add_argument("--hmac-key",   default="",
                    help="Hex HMAC-SHA256 key for gossip authentication. "
                         "All nodes in the cluster must share the same key. "
                         "If empty, gossip is unauthenticated (dev/test only).")
args = parser.parse_args()

# ── HMAC-secured gossip channel ────────────────────────────────────────────────
#
# Wire format (JSON):
#   { "ip": "1.2.3.4", "ts": <unix_float>, "nonce": "<hex16>", "sig": "<hex64>" }
#
# sig = HMAC-SHA256( key, ip + ":" + str(ts) + ":" + nonce )
#
# Replay window: +/-30 s.  After 30 s the message is rejected even if valid.
# Nonce dedup: a seen nonce is cached for the window duration; re-use rejected.
#
# Security claim: without the HMAC key an attacker cannot produce a valid sig
# for any IP.  They cannot mutate any field without breaking the sig.  They
# cannot replay a captured message after 30 s.
#
# Trust model: shared-key = cluster-level trust (same as WireGuard PSK, TSIG).
# We do NOT authenticate per-node identities — that is by design.

HMAC_KEY: bytes = bytes.fromhex(args.hmac_key) if args.hmac_key else b""
REPLAY_WINDOW_S: float = 30.0
_SEEN_NONCES: dict = {}   # nonce -> expiry_time
_NONCE_LOCK = threading.Lock()

def _sign_gossip(ip_str: str) -> bytes:
    ts    = time.time()
    nonce = secrets.token_hex(8)
    if HMAC_KEY:
        body = f"{ip_str}:{ts:.6f}:{nonce}"
        sig  = _hmac.new(HMAC_KEY, body.encode(), hashlib.sha256).hexdigest()
    else:
        sig  = ""
    msg = json.dumps({"ip": ip_str, "ts": ts, "nonce": nonce, "sig": sig})
    return msg.encode()

def _verify_gossip(raw: str):
    """Returns (ip_str, ok:bool)"""
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        ip = raw.strip()
        if not HMAC_KEY:
            return ip, True
        print("[Gossip] REJECT: unauthenticated plain-IP message (HMAC key is set)")
        return ip, False

    ip    = msg.get("ip", "")
    ts    = float(msg.get("ts", 0))
    nonce = msg.get("nonce", "")
    sig   = msg.get("sig", "")

    age = abs(time.time() - ts)
    if age > REPLAY_WINDOW_S:
        print(f"[Gossip] REJECT: stale message for {ip} (age={age:.1f}s)")
        return ip, False

    with _NONCE_LOCK:
        now = time.time()
        expired = [k for k, exp in _SEEN_NONCES.items() if exp < now]
        for k in expired:
            del _SEEN_NONCES[k]
        if nonce in _SEEN_NONCES:
            print(f"[Gossip] REJECT: replayed nonce for {ip}")
            return ip, False
        _SEEN_NONCES[nonce] = now + REPLAY_WINDOW_S

    if HMAC_KEY:
        body     = f"{ip}:{ts:.6f}:{nonce}"
        expected = _hmac.new(HMAC_KEY, body.encode(), hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(expected, sig):
            print(f"[Gossip] REJECT: HMAC mismatch for {ip} — possible forgery!")
            return ip, False

    return ip, True

# ── Locate xdp_fw.c ───────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent.resolve()
BPF_SRC    = SCRIPT_DIR / "xdp_fw.c"

if not BPF_SRC.exists():
    print(f"[✗] Cannot find {BPF_SRC}. Keep main.py and xdp_fw.c in the same directory.")
    sys.exit(1)

# ── Load peer config ───────────────────────────────────────────────────────────
PEERS_FILE = Path(args.peers_file)
if not PEERS_FILE.exists():
    print(f"[✗] Peers file not found: {PEERS_FILE}")
    print(f"    Run veth_setup.sh setup first, or create {PEERS_FILE} manually.")
    sys.exit(1)

with open(PEERS_FILE) as f:
    peer_config = json.load(f)

TOPOLOGY = args.topology
MY_ROLE  = peer_config.get("role", "leaf")

# ── Helpers ────────────────────────────────────────────────────────────────────
def fmt_ip(packed_int):
    return socket.inet_ntoa(struct.pack("I", packed_int))

def pack_ip(ip_str):
    return struct.unpack("I", socket.inet_aton(ip_str))[0]

def _own_ips():
    try:
        import subprocess as _sp
        out = _sp.check_output(["ip", "-4", "addr"], text=True)
        return {
            ln.strip().split()[1].split("/")[0]
            for ln in out.splitlines()
            if ln.strip().startswith("inet ")
        }
    except Exception:
        return set()

# ── eBPF setup ─────────────────────────────────────────────────────────────────
print(f"[*] Compiling eBPF program: {BPF_SRC}")
try:
    b = BPF(src_file=str(BPF_SRC), cflags=["-w"])
except Exception as e:
    print(f"[✗] BPF compilation failed:\n{e}")
    print("    Check kernel headers: ls /lib/modules/$(uname -r)/build")
    sys.exit(1)

fn = b.load_func("xdp_firewall_prog", BPF.XDP)

# ── XDP attach ─────────────────────────────────────────────────────────────────
def _attach_xdp(iface, mode_pref):
    # Compatibility with older BCC versions
    XDP_FLAGS_UPDATE_IF_NOEXIST = getattr(BPF, "XDP_FLAGS_UPDATE_IF_NOEXIST", 1)
    XDP_FLAGS_SKB_MODE          = getattr(BPF, "XDP_FLAGS_SKB_MODE", 2)
    XDP_FLAGS_DRV_MODE          = getattr(BPF, "XDP_FLAGS_DRV_MODE", 4)

    native_flag = XDP_FLAGS_DRV_MODE
    generic_flag = XDP_FLAGS_SKB_MODE
    

    if mode_pref == "native":
        try:
            b.attach_xdp(iface, fn, native_flag)
            print(f"[+] Attached in NATIVE mode on {iface}")
            return "native"
        except Exception as e:
            print(f"[!] Native mode failed on {iface} ({e}), falling back to generic...")

    try:
        b.attach_xdp(iface, fn, generic_flag)
        print(f"[+] Attached in GENERIC (SKB) mode on {iface}")
        return "generic"
    except Exception as e2:
        print(f"[✗] XDP attach failed entirely on {iface}: {e2}")
        print(f"    Try: sudo ip link set {iface} xdp off")
        sys.exit(1)

print(f"[*] Attaching XDP to {args.iface} (preferred mode: {args.xdp_mode})...")
ATTACHED_MODE = _attach_xdp(args.iface, args.xdp_mode)

blacklist_map = b.get_table("blacklist")
jac_map       = b.get_table("jac_map")

# ── Pin maps to bpffs so benchmark stubs can open fw0/fw1/fw2 maps by path ──
# Without pinning, BCC stubs that compile a fresh dummy prog get the most
# recently loaded map (whichever main.py started last), not this instance's.
# Pinning gives benchmark.sh a stable, identity-safe handle per firewall node.
_PIN_DIR = f"/sys/fs/bpf/{args.iface}"
def _pin_maps():
    import os as _os
    import ctypes

    _os.makedirs(_PIN_DIR, exist_ok=True)
    # Remove stale pins from a previous run
    for _name in ("blacklist", "jac_map"):
        _path = f"{_PIN_DIR}/{_name}"
        if _os.path.exists(_path):
            try:
                _os.remove(_path)
            except Exception:
                pass

    # Strategy 1: BCC native .pin() (BCC >= 0.23)
    try:
        b["blacklist"].pin(f"{_PIN_DIR}/blacklist")
        b["jac_map"].pin(f"{_PIN_DIR}/jac_map")
        print(f"[+] Maps pinned under {_PIN_DIR}/  [BCC native]")
        return
    except AttributeError:
        pass  # BCC too old — fall through
    except Exception:
        pass

    # Strategy 2: Call BPF syscall directly via BCC's internal libbcc!
    # This COMPLETELY bypasses the need for the `bpftool` command.
    try:
        from bcc.libbcc import lib
        for _name, _map_obj in (("blacklist", b["blacklist"]),
                                 ("jac_map",   b["jac_map"])):
            _fd   = _map_obj.map_fd
            _dest = f"{_PIN_DIR}/{_name}".encode('utf-8')
            res = lib.bpf_obj_pin(ctypes.c_int(_fd), ctypes.c_char_p(_dest))
            if res != 0:
                raise Exception(f"bpf_obj_pin returned {res}")
        print(f"[+] Maps pinned under {_PIN_DIR}/[libbcc native fallback]")
        return
    except Exception as _e2:
        print(f"[!] libbcc map pinning failed: {_e2}")

    print(f"[!] Map pinning failed completely.")
    print(f"    Fix: sudo mount -t bpf bpf /sys/fs/bpf")

_pin_maps()

# ── Gossip send ────────────────────────────────────────────────────────────────
_gossip_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
_seen_ips    = set()
_seen_lock   = threading.Lock()

def _send_to(ip, port, payload, label):
    try:
        _gossip_sock.sendto(payload, (ip, port))
        print(f"[Gossip] {label} → {ip}:{port}")
    except Exception as e:
        print(f"[!] Gossip send error to {ip}:{port}: {e}")

def send_gossip(ip_str, origin=""):
    if args.dry_run:
        print(f"[DRY-RUN] Would gossip: block {ip_str}")
        return

    own     = _own_ips()
    payload = _sign_gossip(ip_str)

    if TOPOLOGY == "mesh":
        for peer_ip in peer_config.get("peers", []):
            if peer_ip not in own:
                _send_to(peer_ip, args.peer_port, payload, "mesh")

    elif TOPOLOGY == "star":
        if MY_ROLE == "coordinator":
            # Fan-out to all leaves
            for peer_ip in peer_config.get("peers", []):
                if peer_ip not in own:
                    _send_to(peer_ip, args.peer_port, payload, "star[coord→leaf]")
            # Sync with sibling coordinators (skip origin to avoid loops)
            for coord_ip in peer_config.get("coordinator_peers", []):
                if coord_ip not in own and coord_ip != origin:
                    _send_to(coord_ip, args.peer_port, payload, "star[coord→coord]")
        else:
            # Leaf: send to ALL coordinators for redundancy
            coordinators = peer_config.get(
                "coordinators", [peer_config.get("coordinator", "127.0.0.1")]
            )
            for coord_ip in coordinators:
                if coord_ip not in own:
                    _send_to(coord_ip, args.peer_port, payload, "star[leaf→coord]")

    elif TOPOLOGY == "ring":
        next_ip   = peer_config.get("next", "127.0.0.1")
        ring_size = peer_config.get("ring_size", 8)
        _send_to(next_ip, args.peer_port, _sign_gossip(ip_str), "ring→next")

    elif TOPOLOGY == "hierarchical":
        rack = peer_config.get("rack_coordinator", "127.0.0.1")
        _send_to(rack, args.peer_port, payload, "hierarchical→rack")


# ── Gossip receive ─────────────────────────────────────────────────────────────
def apply_block(ip_str):
    if args.dry_run:
        print(f"[DRY-RUN] Would block: {ip_str}")
        return
    try:
        ip_int = pack_ip(ip_str)
        key = blacklist_map.Key(ip_int)
        val = blacklist_map.Leaf(1)
        blacklist_map[key] = val
        print(f"[eBPF] Kernel block applied: {ip_str}")
    except Exception as e:
        print(f"[!] Failed to apply block for {ip_str}: {e}")


def gossip_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", args.port))
    except OSError as e:
        print(f"[✗] Cannot bind gossip port {args.port}: {e}")
        print(f"    Is another instance running?  lsof -i :{args.port}")
        return

    auth_label = (f"HMAC-SHA256 key={args.hmac_key[:8]}..." if HMAC_KEY
                  else "UNAUTHENTICATED (dev mode)")
    print(f"[Gossip] Listening on 0.0.0.0:{args.port}  [{auth_label}]")

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            raw = data.decode("utf-8", errors="ignore").strip()

            malicious_ip, ok = _verify_gossip(raw)
            if not ok:
                continue
            if not malicious_ip:
                continue

            print(f"[Gossip] Verified from {addr[0]}: block {malicious_ip}")
            apply_block(malicious_ip)

            # Ring forwarding
            if TOPOLOGY == "ring":
                try:
                    msg    = json.loads(raw)
                    ttl    = msg.get("ttl", 1)
                    origin = msg.get("origin", "")
                    dedup_key = f"{malicious_ip}:{origin}"
                    with _seen_lock:
                        if dedup_key in _seen_ips:
                            continue
                        _seen_ips.add(dedup_key)
                        if len(_seen_ips) > 1000:
                            _seen_ips.clear()
                    if ttl > 1:
                        next_ip = peer_config.get("next", "127.0.0.1")
                        fwd = json.dumps({"ip": malicious_ip, "ttl": ttl-1, "origin": origin})
                        _gossip_sock.sendto(fwd.encode(), (next_ip, args.peer_port))
                except (json.JSONDecodeError, KeyError):
                    pass

            # Hierarchical rack fanout
            if TOPOLOGY == "hierarchical" and MY_ROLE == "rack_coordinator":
                for leaf in peer_config.get("leaves", []):
                    _send_to(leaf, args.peer_port, _sign_gossip(malicious_ip), "hier→leaf")

            # Star coordinator: propagate (origin=addr[0] prevents echo-back)
            if TOPOLOGY == "star" and MY_ROLE == "coordinator":
                send_gossip(malicious_ip, origin=addr[0])

        except Exception as e:
            print(f"[Gossip] Listener error: {e}")
            time.sleep(0.1)


# ── Perf event handler ─────────────────────────────────────────────────────────
ALERT_COUNT = 0

def handle_event(cpu, data, size):
    global ALERT_COUNT
    try:
        event     = b["events"].event(data)
        ip_str    = fmt_ip(event.saddr)
        score     = int(event.score)
        threshold = int(event.threshold)
        srtt      = int(event.srtt)
        rttvar    = int(event.rttvar)
        ALERT_COUNT += 1

        print(f"\n{'='*60}")
        print(f"  ALERT #{ALERT_COUNT} — IP BLOCKED")
        print(f"  IP         : {ip_str}")
        print(f"  Score      : {score}")
        print(f"  Threshold  : {threshold}  (SRTT={srtt} + 4*RTTVAR={rttvar})")
        print(f"  Action     : XDP_DROP + gossip propagation")
        print(f"{'='*60}\n")

        send_gossip(ip_str)

    except Exception as e:
        print(f"[!] Event handler error: {e}")
        traceback.print_exc()


# ── Userspace decay thread ─────────────────────────────────────────────────────
DECAY_LAMBDA_PY  = 0.693   # ln(2) — one tick (1 s) = exactly one half-life
DECAY_INTERVAL_S = 0.05    # 50 ms ticks match B4 poll resolution and prevent score wipe

def userspace_decay():
    prev_ts = time.monotonic()
    while True:
        time.sleep(DECAY_INTERVAL_S)
        try:
            now_ts  = time.monotonic()
            dt_ms   = int((now_ts - prev_ts) * 1000)
            prev_ts = now_ts
            dt_ms   = min(dt_ms, 1000)
            df      = dt_ms * DECAY_LAMBDA_PY
            if df > 1000:
                df = 1000
            factor_num = 1000 - df
            factor_den = 1000

            for k, v in jac_map.items():
                if v.score == 0:
                    continue
                new_score = (int(v.score) * factor_num) // factor_den
                if new_score != int(v.score):
                    v.score = new_score
                    jac_map[k] = v
        except Exception:
            pass


def print_stats():
    while True:
        time.sleep(5)
        try:
            blocked = sum(1 for _ in blacklist_map.items())
            print(f"\n[Stats] Blocked: {blocked}  Alerts: {ALERT_COUNT}  "
                  f"Role: {MY_ROLE}  Auth: {'HMAC' if HMAC_KEY else 'none'}")

            blocked_ips = set()
            try:
                blocked_ips = {fmt_ip(k.value) for k, _ in blacklist_map.items()}
            except Exception:
                pass

            scored = []
            for k, v in jac_map.items():
                ip = fmt_ip(k.value)
                scored.append((ip, int(v.score), int(v.peak),
                               int(v.srtt)//100, int(v.rttvar)//100,
                               int(v.n_packets), ip in blocked_ips))
            scored.sort(key=lambda x: (x[6], x[1]), reverse=True)
            if scored:
                print("  Top IPs:")
                for ip, sc, pk, sr, rv, np, is_blocked in scored[:5]:
                    if is_blocked:
                        state = "BLOCKED"
                    elif np <= 5:
                        state = "warmup"
                    else:
                        state = f"thr={max(sr + 4*rv, 50)}"
                    print(f"    {ip:18s}  sc={sc:5d}  pk={pk:5d}  "
                          f"srtt={sr:4d}  rttvar={rv:4d}  pkts={np:4d}  [{state}]")
        except Exception:
            pass


# ── Graceful shutdown ──────────────────────────────────────────────────────────
def shutdown(sig, frame):
    print(f"\n[+] Caught signal {sig}. Detaching XDP from {args.iface}...")
    try:
        b.remove_xdp(args.iface, 0)
        print(f"[+] XDP detached cleanly.")
    except Exception as e:
        print(f"[!] XDP detach error (may already be gone): {e}")
    # Unpin maps
    try:
        import os as _os
        _PIN_DIR = f"/sys/fs/bpf/{args.iface}"
        for _name in ("blacklist", "jac_map"):
            _path = f"{_PIN_DIR}/{_name}"
            if _os.path.exists(_path):
                _os.remove(_path)
    except Exception:
        pass
    sys.exit(0)

signal.signal(signal.SIGINT,  shutdown)
signal.signal(signal.SIGTERM, shutdown)

# ── Start threads ──────────────────────────────────────────────────────────────
threading.Thread(target=gossip_listener, daemon=True).start()
threading.Thread(target=userspace_decay,  daemon=True).start()
threading.Thread(target=print_stats,      daemon=True).start()

b["events"].open_perf_buffer(handle_event)

# ── Banner ─────────────────────────────────────────────────────────────────────
import subprocess as _sp

def _own_ip(iface):
    try:
        out = _sp.check_output(["ip", "-4", "addr", "show", iface], text=True)
        for ln in out.splitlines():
            ln = ln.strip()
            if ln.startswith("inet "):
                return ln.split()[1]
    except Exception:
        pass
    return "unknown"

_ip      = _own_ip(args.iface)
_ip_bare = _ip.split("/")[0]

if MY_ROLE == "coordinator":
    _peers_info = (f"leaves={peer_config.get('peers',[])}  "
                   f"coord_peers={peer_config.get('coordinator_peers',[])}")
elif MY_ROLE == "rack_coordinator":
    # Hierarchical: rack_coordinator fans down to leaves and up to a global,
    # OR is the global itself (no upstream coordinator).
    _leaves    = peer_config.get("leaves", [])
    _upstream  = peer_config.get("rack_coordinator", None)   # own upstream
    if _upstream:
        _peers_info = f"leaves={_leaves}  upstream={_upstream}"
    else:
        _peers_info = f"leaves={_leaves}  (global coordinator — no upstream)"
else:
    # Leaf nodes: show which coordinator(s) they report to.
    _coords = peer_config.get("coordinators",
                  [peer_config.get("coordinator",
                      peer_config.get("rack_coordinator", "?"))])
    _peers_info = f"coordinators={_coords}"
print(f"\n{'='*60}")
print(f"  XDP Adaptive Firewall — RUNNING")
print(f"{'='*60}")
print(f"  Interface : {args.iface}  ({_ip})")
print(f"  Role      : {MY_ROLE}")
print(f"  Topology  : {TOPOLOGY}")
print(f"  Gossip    : 0.0.0.0:{args.port}  (peers on :{args.peer_port})")
print(f"  XDP mode  : {ATTACHED_MODE.upper()}")
print(f"  Auth      : {'HMAC-SHA256' if HMAC_KEY else 'NONE (dev mode)'}")
print(f"  {_peers_info}")
print(f"{'='*60}\n")

while True:
    try:
        b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        shutdown(signal.SIGINT, None)
    except Exception as e:
        print(f"[!] Poll error: {e}")
        time.sleep(0.1)
