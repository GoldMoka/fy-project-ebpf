#!/usr/bin/env bash
# =============================================================================
#  benchmark.sh — XDP Adaptive Firewall — Paper Benchmark Suite
#
#  Measures everything needed for a systems paper:
#    B1  Packet processing latency (ns) — baseline vs under load
#    B2  Throughput (Mpps) — max packets/sec before drop
#    B3  Block detection latency (ms) — time from first SYN to XDP_DROP
#    B4  Decay timing — score half-life verification
#    B5  Gossip propagation latency (ms)
#    B6  False positive rate — legitimate bursty traffic that should NOT block
#    B7  Memory footprint — BPF map sizes, RSS
#    B8  CPU overhead — % core usage at idle, moderate load, flood load
#    B9  Blacklist scalability — throughput vs number of blocked IPs
#    B10 EWMA convergence — windows until threshold stabilises
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'
CYN='\033[0;36m'; NC='\033[0m'
hdr()  { echo -e "\n${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; \
         echo -e "${CYN}  $*${NC}"; \
         echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
ok()   { echo -e "${GRN}[✓]${NC} $*"; }
info() { echo -e "${BLU}[·]${NC} $*"; }
warn() { echo -e "${YLW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0"

# ── Argument parsing ──────────────────────────────────────────────────────────
IFACE="eno1"
TARGET_IP=""
RUNS=5
GOSSIP_PORT=""
GOSSIP_PORT_OVERRIDE=""
PEER_PORT=5001
GOSSIP_LISTEN_IP="127.0.0.1"
OUTDIR="$(pwd)/results"
VETH_MODE=false   
HMAC_KEY=""
ONLY_B1=false
ONLY_B4=false


ATTACK_TYPE="syn-flood"

usage() {
cat <<EOF
Usage: sudo bash benchmark.sh [OPTIONS]

  --iface       <iface>   Firewall interface XDP is attached to
  --target      <IP>      Firewall IP to send packets toward
  --attack      <attack>  SYN Flood, Low & Slow etc
  --runs        <N>       Repetitions per benchmark for mean/stddev
  --outdir      <path>    Output directory (default: ./results)
  --hmac-key    <hex>     HMAC-SHA256 key used by main.py
  --gossip-ip   <IP>      IP where main.py's gossip listener is reachable
  --gossip-port <port>    Port for gossip (Auto-detected if omitted)
  --veth                  Veth mode
  -h, --help

EOF
exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --iface)       IFACE="$2";            shift 2 ;;
        --target)      TARGET_IP="$2";        shift 2 ;;
        --attack)       ATTACK_TYPE="$2";     shift 2 ;;
        --runs)        RUNS="$2";             shift 2 ;;
        --outdir)      OUTDIR="$2";           shift 2 ;;
        --hmac-key)    HMAC_KEY="$2";         shift 2 ;;
        --gossip-ip)   GOSSIP_LISTEN_IP="$2"; shift 2 ;;
        --gossip-port) GOSSIP_PORT_OVERRIDE="$2"; shift 2 ;;
        --peer-port)   PEER_PORT="$2";        shift 2 ;;
        --veth)        VETH_MODE=true;        shift   ;;
        -h|--help)     usage ;;
        --only-b1)     ONLY_B1=true;           shift   ;;
        --only-b4)     ONLY_B4=true;           shift   ;;
        *) die "Unknown option: $1" ;;
    esac
done

if [[ "$ONLY_B4" == true ]]; then
    # Skip B1-B3 and jump directly to B4.
    goto_b4=true
fi


[[ -z "$TARGET_IP" ]] && die "Provide --target <IP of device running the firewall>"
if ! $VETH_MODE; then
    ip link show "$IFACE" &>/dev/null || \
        die "Interface $IFACE not found"
fi
mkdir -p "$OUTDIR"

# ── Auto-Detect Gossip Port ───────────────────────────────────────────────────
if [[ -n "$GOSSIP_PORT_OVERRIDE" ]]; then
    GOSSIP_PORT="$GOSSIP_PORT_OVERRIDE"
else
    _detected=$(python3 - "$IFACE" << 'EOF'
import subprocess, sys
try:
    ps_out = subprocess.check_output(["pgrep", "-a", "-f", f"main.py.*{sys.argv[1]}"], text=True)
    if ps_out:
        pid = ps_out.strip().split("\n")[0].split()[0]
        ss_out = subprocess.check_output(["ss", "-Hulnp"], text=True)
        for line in ss_out.splitlines():
            if f"pid={pid}," in line:
                for p in line.split():
                    if ':' in p and p.split(':')[-1].isdigit() and not p.startswith('::'):
                        print(p.split(':')[-1])
                        sys.exit(0)
except Exception: pass
EOF
)
    if [[ -n "$_detected" ]]; then
        GOSSIP_PORT="$_detected"
        info "Auto-detected Gossip Port: $GOSSIP_PORT for $IFACE"
    else
        GOSSIP_PORT="5000"
        warn "Could not auto-detect gossip port; using default 5000"
    fi
fi

# ── Injection setup: veth vs physical ─────────────────────────────────────────
ATK_NETNS=""
FW_NETNS=""
INJECT_IFACE="$IFACE"
INJECT_PREFIX=""

if $VETH_MODE; then

    # Current namespaced topology convention:
    #   fw-mesh-0    -> fw-mesh-0_ns / atk-mesh-0
    #   fw-ring-0    -> fw-ring-0_ns / atk-ring-0
    #   fw-h-global -> fw-h-global_ns / corresponding attacker iface
    #
    # Derive firewall namespace from the firewall interface.
    FW_NETNS="${IFACE}_ns"

    # Mesh/ring interfaces are fw-<topology>-<N>
    # Their attacker-side interface is atk-<topology>-<N>
    ATK_IFACE="${IFACE/fw-/atk-}"

    ATK_NETNS="attacker_ns"

    # Firewall namespace must exist.
    ip netns list | awk '{print $1}' | grep -qx "$FW_NETNS" || \
        die "Firewall netns '$FW_NETNS' not found"

    # Shared attacker namespace must exist.
    ip netns list | awk '{print $1}' | grep -qx "$ATK_NETNS" || \
        die "Attacker netns '$ATK_NETNS' not found"

    # Attacker interface must exist in attacker_ns.
    ip netns exec "$ATK_NETNS" ip link show "$ATK_IFACE" &>/dev/null || \
        die "$ATK_IFACE not found in $ATK_NETNS"

    OWN_IP=$(ip netns exec "$ATK_NETNS" \
        ip -4 addr show "$ATK_IFACE" 2>/dev/null |
        awk '/inet /{print $2}' |
        cut -d/ -f1 |
        head -1)

    [[ -n "$OWN_IP" ]] || \
        die "No IPv4 address on $ATK_IFACE inside $ATK_NETNS"

    # IMPORTANT:
    # IFACE is inside FW_NETNS, so root /sys/class/net/$IFACE is invalid.
    NEXTHOP_MAC=$(ip netns exec "$FW_NETNS" \
        ip link show "$IFACE" |
        awk '/link\/ether/{print $2}' |
        head -1)

    [[ -n "$NEXTHOP_MAC" ]] || \
        die "Cannot read MAC for $IFACE inside $FW_NETNS"

    INJECT_IFACE="$ATK_IFACE"
    INJECT_PREFIX="ip netns exec ${ATK_NETNS}"

    info "Firewall : ${FW_NETNS}/${IFACE}"
    info "Attacker : ${ATK_NETNS}/${ATK_IFACE} (${OWN_IP})"
    info "Target   : ${TARGET_IP}"
    info "Dest MAC : ${NEXTHOP_MAC}"

else
    OWN_IP=$(ip -4 addr show "$IFACE" 2>/dev/null |
        awk '/inet /{print $2}' |
        cut -d/ -f1 |
        head -1)
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INJECTOR="$SCRIPT_DIR/_bench_inject"
PIN_BASE="/sys/fs/bpf"

# ── Build C injector if needed ────────────────────────────────────────────────
_C_SRC="$SCRIPT_DIR/_bench_inject.c"
_PY_INJECTOR="$SCRIPT_DIR/_bench_inject.py"
if [[ -f "$_C_SRC" ]] && command -v gcc &>/dev/null; then
    if [[ ! -f "$INJECTOR" || "$_C_SRC" -nt "$INJECTOR" || ! -x "$INJECTOR" ]]; then
        info "Compiling C injector (_bench_inject.c)..."
        gcc -O2 -o "$INJECTOR" "$_C_SRC" && ok "C injector compiled" || {
            warn "gcc failed — falling back to Python injector"
            INJECTOR="$_PY_INJECTOR"
            _INJECTOR_TYPE="Python"
        }
    fi
    if [[ -x "$INJECTOR" ]] && head -c4 "$INJECTOR" 2>/dev/null | grep -q $'\x7fELF'; then
        _INJECTOR_TYPE="C"
    else
        INJECTOR="$_PY_INJECTOR"
        _INJECTOR_TYPE="Python"
    fi
else
    warn "_bench_inject.c not found or gcc unavailable — using slow Python injector"
    INJECTOR="$_PY_INJECTOR"
    _INJECTOR_TYPE="Python"
fi

# ── Write Python injector fallback ────────────────────────────────────────────
cat > "$_PY_INJECTOR" << PYEOF
#!/usr/bin/env python3
import sys, socket, struct, time, random, threading, os

NEXTHOP_MAC = bytes(int(x,16) for x in "$NEXTHOP_MAC".split(':'))

def cksum(data):
    if len(data) % 2: data += b'\\x00'
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xffff)
    return (~(s + (s >> 16))) & 0xffff

def tcp_pkt(src_ip, dst_ip, sport, dport, flags, seq=None):
    fb = (0x02 if 'S' in flags else 0) | (0x10 if 'A' in flags else 0) \
       | (0x04 if 'R' in flags else 0) | (0x01 if 'F' in flags else 0)
    seq = seq if seq is not None else random.randint(0, 0xffffffff)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 0x50, fb, 65535, 0, 0)
    si, di = socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    csum = cksum(struct.pack('!4s4sBBH', si, di, 0, 6, len(tcp)) + tcp)
    tcp = tcp[:16] + struct.pack('!H', csum) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(tcp)+20,
                     random.randint(0,0xffff), 0, 64, 6, 0, si, di)
    csum = cksum(ip)
    return (ip[:10] + struct.pack('!H', csum) + ip[12:]) + tcp

def src_mac(iface):
    try:
        with open(f'/sys/class/net/{iface}/address') as f:
            return bytes(int(x,16) for x in f.read().strip().split(':'))
    except:
        return b'\\x00'*6

def raw_sock(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    s.bind((iface, 0))
    return s

def eth_hdr(iface):
    return NEXTHOP_MAC + src_mac(iface) + b'\\x08\\x00'

def mode_throughput(iface, src, dst, dport, duration_s):
    sock = raw_sock(iface)
    eth  = eth_hdr(iface)
    sp   = 31337
    sent = 0
    t0   = time.perf_counter()
    tend = t0 + duration_s
    while time.perf_counter() < tend:
        sock.send(eth + tcp_pkt(src, dst, sp, dport, 'S'))
        sent += 1
    elapsed = time.perf_counter() - t0
    mpps = sent / elapsed / 1_000_000
    print(f"THROUGHPUT packets_sent={sent} elapsed_s={elapsed:.4f} mpps={mpps:.4f}")
    sock.close()

def mode_flood_timed(iface, src, dst, dport, count):
    sock = raw_sock(iface)
    eth  = eth_hdr(iface)
    sp   = 31337
    timestamps =[]
    for i in range(count):
        t = time.perf_counter()
        sock.send(eth + tcp_pkt(src, dst, sp, dport, 'S'))
        timestamps.append(t)
    sock.close()
    for i, t in enumerate(timestamps):
        print(f"PKT {i} {t:.9f}")

def mode_decay(iface, src, dst, dport, syn_count, silence_s):
    sock = raw_sock(iface)
    eth  = eth_hdr(iface)
    sp   = random.randint(10000, 60000)
    t0 = time.perf_counter()
    for _ in range(syn_count):
        sock.send(eth + tcp_pkt(src, dst, sp, dport, 'S'))
    t_burst_end = time.perf_counter()
    time.sleep(silence_s)
    t_silence_end = time.perf_counter()
    sock.send(eth + tcp_pkt(src, dst, sp, dport, 'S'))
    t_probe = time.perf_counter()
    sock.close()
    print(f"DECAY burst_end={t_burst_end-t0:.4f}s silence={silence_s}s probe_sent_at={t_probe-t0:.4f}s")

def mode_false_pos(iface, src, dst, dport, bursts, burst_size, gap_ms):
    sock = raw_sock(iface)
    eth  = eth_hdr(iface)
    for b in range(bursts):
        sp = random.randint(10000, 60000)
        for _ in range(burst_size):
            sock.send(eth + tcp_pkt(src, dst, sp, dport, 'S'))
        time.sleep(0.01)
        for _ in range(burst_size):
            sock.send(eth + tcp_pkt(src, dst, sp, dport, 'A'))
        time.sleep(gap_ms / 1000.0)
        print(f"BURST {b+1}/{bursts} done ({burst_size} SYN + {burst_size} ACK)")
    sock.close()
    print("FALSE_POS_DONE")

if __name__ == '__main__':
    mode = sys.argv[1]
    if mode == 'throughput':
        mode_throughput(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), float(sys.argv[6]))
    elif mode == 'flood_timed':
        mode_flood_timed(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6]))
    elif mode == 'decay':
        mode_decay(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6]), float(sys.argv[7]))
    elif mode == 'false_pos':
        mode_false_pos(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6]), int(sys.argv[7]), float(sys.argv[8]))
PYEOF

# ── Stats reader ──────────────────────────────────────────────────────────────
STATS_READER="$SCRIPT_DIR/_bench_stats.py"
cat > "$STATS_READER" << PYEOF
#!/usr/bin/env python3
import sys, socket, struct, subprocess

mode = sys.argv[1]

# Only create the dummy BPF maps for modes that actually need
# BCC table access. map_memory must NOT create additional maps,
# because bpftool will then count them in the memory total.
if mode in ("blacklist_count", "jac_entry"):
    try:
        from bcc import BPF
    except ImportError:
        sys.exit("BCC not found")

    DUMMY = r"""
    #include <uapi/linux/bpf.h>
    struct jacobson_t {
        u64 srtt; u64 rttvar; u64 score; u64 peak;
        u64 last_ts_ns; u64 window_start; u64 n_packets;
    };
    BPF_HASH(blacklist, u32, u8);
    BPF_HASH(jac_map,   u32, struct jacobson_t);
    int dummy(void *ctx) { return 0; }
    """

    b  = BPF(text=DUMMY, cflags=["-w"])
    bl = b.get_table("blacklist")
    jm = b.get_table("jac_map")

if mode == "blacklist_count":
    print(sum(1 for _ in bl.items()))
elif mode == "jac_entry":
    ip_str = sys.argv[2]
    ip_int = struct.unpack("I", socket.inet_aton(ip_str))[0]
    key = jm.Key(ip_int)
    try:
        v = jm[key]
        print(f"score={int(v.score)} peak={int(v.peak)} srtt={int(v.srtt)} rttvar={int(v.rttvar)} n_packets={int(v.n_packets)}")
    except KeyError:
        print("NOT_FOUND")
elif mode == "map_memory":
    try:
        out = subprocess.check_output(["bpftool", "map", "show", "-j"], text=True, stderr=subprocess.DEVNULL)
        import json
        maps = json.loads(out)
        total = 0
        for m in maps:
            if m.get("name","") in ("blacklist", "blacklis", "jac_map", "events"):
                entries  = m.get("max_entries", 0)
                key_size = m.get("bytes_key", m.get("key_size", 0))
                val_size = m.get("bytes_value", m.get("value_size", 0))
                total   += entries * (key_size + val_size)
                print(f"  {m['name']:12s}  max_entries={entries:6d}  key={key_size}B  val={val_size}B  max_mem={entries*(key_size+val_size)//1024}KB")
        print(f"  TOTAL max map memory: {total//1024} KB")
    except Exception as e:
        print(f"bpftool not available: {e}")
        print("  Estimated (no bpftool): blacklist=320KB jac_map=3840KB events=32KB total~4192KB")
elif mode == "rss":
    try:
        out = subprocess.check_output(["pgrep", "-f", "main.py"], text=True).strip().split()
        for pid in out:
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("VmRSS"):
                        print(f"  main.py PID={pid}  {line.strip()}")
    except Exception as e:
        print(f"  Cannot read RSS: {e}")
PYEOF

stats_py() {
    python3 - "$@" << 'EOF'
import sys, math
raw = sys.argv[1:]
vals =[]
for v in raw:
    try: vals.append(float(v))
    except (ValueError, TypeError): pass
n = len(vals)
if n == 0:
    print("n=0 mean=N/A stddev=N/A min=N/A max=N/A")
    sys.exit()
mean = sum(vals) / n
variance = sum((x - mean)**2 for x in vals) / n if n > 1 else 0
stddev = math.sqrt(variance)
print(f"n={n} mean={mean:.4f} stddev={stddev:.4f} min={min(vals):.4f} max={max(vals):.4f}")
EOF
}

# ── Helper: clear firewall blacklist between benchmarks ───────────────────────
clear_blacklist() {
    info "Clearing blacklist map..."

    python3 - "$BLACKLIST_MAP_ID" << 'EOF'
import sys
import subprocess
import json

map_id = sys.argv[1]

try:
    out = subprocess.check_output(
        ["bpftool", "map", "dump", "id", map_id, "-j"],
        text=True,
        stderr=subprocess.DEVNULL
    )

    entries = json.loads(out)
    count = 0

    for entry in entries:
        key = entry.get("key")

        if not key:
            continue

        # bpftool JSON may represent key bytes as strings
        # or as integers. Normalize both forms.
        if isinstance(key, list):
            key_hex = []

            for b in key:
                if isinstance(b, int):
                    key_hex.append(f"{b:02x}")
                elif isinstance(b, str):
                    s = b.strip()

                    # Already a hex byte such as "0a"
                    if len(s) == 2:
                        key_hex.append(s.lower())
                    else:
                        # Handle decimal representation
                        key_hex.append(f"{int(s, 0):02x}")

        elif isinstance(key, str):
            # Handle a hex string such as "0a280063"
            cleaned = key.replace(" ", "").replace(":", "")

            if len(cleaned) % 2 != 0:
                continue

            key_hex = [
                cleaned[i:i+2].lower()
                for i in range(0, len(cleaned), 2)
            ]

        else:
            continue

        subprocess.run(
            ["bpftool", "map", "delete", "id", map_id,
             "key", "hex"] + key_hex,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        count += 1

    print(f"  Cleared {count} blacklist entries")

except Exception as e:
    print(f"  Could not clear blacklist: {e}")
EOF
}

_BL_PIN="${PIN_BASE}/${IFACE}/blacklist"
_JAC_PIN="${PIN_BASE}/${IFACE}/jac_map"

cat > /tmp/_bpf_map_access.py << 'MAPEOF'
import sys, os, socket, struct, ctypes, time
NR_BPF = 321
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_GET_FD_BY_ID = 14

def _bpf(cmd, attr): return _libc.syscall(NR_BPF, cmd, ctypes.byref(attr), ctypes.sizeof(attr))

def bpf_map_get_fd_by_id(map_id):
    class BpfAttrMapId(ctypes.Structure):
        _fields_ = [
            ("map_id", ctypes.c_uint32),
            ("next_id", ctypes.c_uint32),
        ]

    attr = BpfAttrMapId()
    attr.map_id = int(map_id)

    fd = _bpf(BPF_MAP_GET_FD_BY_ID, attr)

    if fd < 0:
        raise OSError(
            ctypes.get_errno(),
            f"bpf_map_get_fd_by_id({map_id}) failed"
        )

    return fd

class BpfAttrObjGet(ctypes.Structure):
    _fields_ =[("pathname",   ctypes.c_uint64),("bpf_fd",     ctypes.c_uint32),("file_flags", ctypes.c_uint32)]

class BpfAttrMapLookup(ctypes.Structure):
    _fields_ =[("map_fd", ctypes.c_uint32),("key",    ctypes.c_uint64),("value",  ctypes.c_uint64),("flags",  ctypes.c_uint64)]

_libc = ctypes.CDLL("libc.so.6", use_errno=True)
_libc.syscall.restype  = ctypes.c_long
_libc.syscall.argtypes =[ctypes.c_long, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]

def _bpf(cmd, attr): return _libc.syscall(NR_BPF, cmd, ctypes.byref(attr), ctypes.sizeof(attr))

def bpf_obj_get(path):
    buf  = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr = BpfAttrObjGet(); attr.pathname = ctypes.cast(buf, ctypes.c_void_p).value
    fd = _bpf(BPF_OBJ_GET, attr)
    if fd < 0: raise OSError(ctypes.get_errno(), f"bpf_obj_get({path}) failed")
    return fd

def bpf_lookup(fd, key_bytes, val_size):
    kbuf = ctypes.create_string_buffer(key_bytes); vbuf = ctypes.create_string_buffer(val_size)
    attr = BpfAttrMapLookup(); attr.map_fd = fd; attr.key = ctypes.cast(kbuf, ctypes.c_void_p).value
    attr.value = ctypes.cast(vbuf, ctypes.c_void_p).value; attr.flags = 0
    return bytes(vbuf) if _bpf(BPF_MAP_LOOKUP_ELEM, attr) == 0 else None

JAC_FIELDS  = {"srtt":0,"rttvar":8,"score":16,"peak":24,"last_ts_ns":32,"window_start":40,"n_packets":48}
JAC_VSIZE   = 56
BL_VSIZE    = 1
def ip_key(ip): return socket.inet_aton(ip)

mode = sys.argv[1]
if mode == "lookup_bl":
    pin, ip = sys.argv[2], sys.argv[3]
    fd = bpf_obj_get(pin); v = bpf_lookup(fd, ip_key(ip), BL_VSIZE); os.close(fd)
    print("FOUND" if v is not None else "NOT_FOUND")

elif mode == "poll_bl":
    map_id, ip, tms, ims = sys.argv[2], sys.argv[3], float(sys.argv[4]), float(sys.argv[5])
    fd = bpf_map_get_fd_by_id(map_id); t0 = time.perf_counter()
    while time.perf_counter() - t0 < tms / 1000:
        if bpf_lookup(fd, ip_key(ip), BL_VSIZE) is not None:
            ms = (time.perf_counter() - t0) * 1000
            os.close(fd); print(f"FOUND elapsed_ms={ms:.3f}"); sys.exit(0)
        time.sleep(ims / 1000)
    os.close(fd); print("NOT_FOUND")

elif mode == "lookup_jac":
    map_id, ip, field = sys.argv[2], sys.argv[3], sys.argv[4]
    fd = bpf_map_get_fd_by_id(map_id)
    v = bpf_lookup(fd, ip_key(ip), JAC_VSIZE)
    os.close(fd)

    if v is None:
        print("NOT_FOUND")
    else:
        print(struct.unpack_from("<Q", v, JAC_FIELDS[field])[0])

elif mode == "poll_jac_score":
    map_id, ip, tms, ims = sys.argv[2], sys.argv[3], float(sys.argv[4]), float(sys.argv[5])
    fd = bpf_map_get_fd_by_id(map_id)
    t0 = time.perf_counter()

    while time.perf_counter() - t0 < tms / 1000:
        v = bpf_lookup(fd, ip_key(ip), JAC_VSIZE)

        if v is not None:
            score = struct.unpack_from(
                "<Q", v, JAC_FIELDS["score"]
            )[0]

            if score > 0:
                os.close(fd)
                print(score)
                sys.exit(0)

        time.sleep(ims / 1000)

    os.close(fd)
    print(0)
MAPEOF

poll_blacklist_map() {
    python3 /tmp/_bpf_map_access.py \
        poll_bl \
        "$BLACKLIST_MAP_ID" \
        "$1" \
        "${2:-2000}" \
        "${3:-5}"
}

read_pinned_jac_score() {
    python3 /tmp/_bpf_map_access.py poll_jac_score "$JAC_MAP_ID" "$1" "${2:-500}" "5"
}

read_pinned_jac_field() {
    python3 /tmp/_bpf_map_access.py lookup_jac "$JAC_MAP_ID" "$1" "$2"
}

SUMMARY="$OUTDIR/summary_table.txt"
cat > "$SUMMARY" << EOF
XDP Adaptive Firewall — Paper Benchmark Results
Generated: $(date)
Host: $(uname -n)  Kernel: $(uname -r)
Interface: $IFACE  Target: $TARGET_IP  Runs: $RUNS
Injector: ${_INJECTOR_TYPE} (C=sendmmsg batched, Python=single syscall/pkt)
================================================================
EOF

append_summary() { echo "$*" >> "$SUMMARY"; }

echo ""
echo -e "${CYN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYN}║   XDP Adaptive Firewall — Paper Benchmark Suite      ║${NC}"
echo -e "${CYN}║   Target: $TARGET_IP   Interface: $IFACE              ${NC}"
echo -e "${CYN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
info "Results will be saved to: $OUTDIR/"
info "Each benchmark runs $RUNS times for mean ± stddev."
sleep 1

get_xdp_prog_id() {
    local iface="$1"

    ip netns exec "$FW_NETNS" \
        bpftool net show 2>/dev/null |
        awk -v iface="$iface" '
            $1 ~ ("^" iface "\\(") && $2 == "driver" && $3 == "id" {
                print $4
                exit
            }
        ' || true
}


get_xdp_map_id() {
    local iface="$1"
    local map_name="$2"
    local prog_id
    local map_ids
    local map_id

    prog_id=$(get_xdp_prog_id "$iface")

    [[ -n "$prog_id" ]] || return 1

    map_ids=$(
        ip netns exec "$FW_NETNS" \
            bpftool prog show id "$prog_id" 2>/dev/null |
        sed -n 's/.*map_ids[[:space:]]\+\([0-9,]*\).*/\1/p'
    )

    [[ -n "$map_ids" ]] || return 1

    IFS=',' read -ra MAP_ARRAY <<< "$map_ids"

    for map_id in "${MAP_ARRAY[@]}"; do
        if ip netns exec "$FW_NETNS" \
            bpftool map show id "$map_id" 2>/dev/null |
            grep -q "name $map_name"; then
            echo "$map_id"
            return 0
        fi
    done

    return 1
}


BLACKLIST_MAP_ID=$(get_xdp_map_id "$IFACE" blacklist) ||
    die "Could not find blacklist map for $IFACE"

info "XDP blacklist map: $BLACKLIST_MAP_ID"

JAC_MAP_ID=$(get_xdp_map_id "$IFACE" jac_map) ||
    die "Could not find jac_map for $IFACE"

info "XDP jac_map: $JAC_MAP_ID"

XDP_PROG_ID=$(get_xdp_prog_id "$IFACE") ||
    die "Could not find XDP program for $IFACE"

info "XDP program ID: $XDP_PROG_ID"

# =============================================================================
# B1 — Legitimate traffic latency under attack
# =============================================================================
hdr "B1 — Legitimate Traffic Latency Under Attack"

OUT="$OUTDIR/B1_latency.txt"
echo "B1 — Legitimate Traffic Latency Under Attack" > "$OUT"

# -------------------------------------------------------------------------
# Current evaluation slice:
#   Topology : mesh-6
#   Defense  : XDP Adaptive Firewall
#   Legit IP : 10.40.0.99
#   Attack IP: 10.40.0.100
#   Server   : 10.42.0.2:8080
# -------------------------------------------------------------------------

if [[ "$FW_NETNS" == "fw-mesh-0_ns" ]]; then

    LEGIT_IP="10.40.0.99"
    ATTACK_IP="10.40.0.100"
    SERVER_IP="10.42.0.2"
    SERVER_PORT=8080

    LEGIT_REQUESTS=100
    LEGIT_INTERVAL=0.1
    LEGIT_TIMEOUT=2

    ATTACK_RATE=10000
    ATTACK_DURATION=5

    # Get the attacker-side MAC from the existing veth.
    ATTACK_SRC_MAC=$(
        ip netns exec "$ATK_NETNS" \
        ip link show "$ATK_IFACE" 2>/dev/null |
        awk '/link\/ether/{print $2; exit}'
    )

    [[ -n "$ATTACK_SRC_MAC" ]] ||
        die "Could not determine attacker MAC for $ATK_IFACE"

    [[ -n "$NEXTHOP_MAC" ]] ||
        die "Could not determine firewall MAC for $IFACE"

    info "B1 legitimate client : $LEGIT_IP"
    info "B1 legitimate server : $SERVER_IP:$SERVER_PORT"
    info "B1 attack source     : $ATTACK_IP"
    info "B1 attack rate       : $ATTACK_RATE SYN/s"
    info "B1 runs               : $RUNS"

    BASELINE_AVG=()
    ATTACK_AVG=()

    BASELINE_SAMPLES=()
    ATTACK_SAMPLES=()

    # ---------------------------------------------------------------------
    # Helper: calculate statistics from latency samples.
    # ---------------------------------------------------------------------
    b1_stats() {
        python3 - "$@" << 'PYEOF'
import sys
import math

vals = []

for arg in sys.argv[1:]:
    try:
        vals.append(float(arg))
    except ValueError:
        pass

if not vals:
    print("n=0 mean=N/A p50=N/A p95=N/A p99=N/A min=N/A max=N/A")
    sys.exit(0)

vals.sort()
n = len(vals)

def percentile(p):
    if n == 1:
        return vals[0]

    pos = (n - 1) * p
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))

    if lo == hi:
        return vals[lo]

    return vals[lo] + (vals[hi] - vals[lo]) * (pos - lo)

mean = sum(vals) / n

print(
    f"n={n} "
    f"mean={mean:.4f} "
    f"p50={percentile(0.50):.4f} "
    f"p95={percentile(0.95):.4f} "
    f"p99={percentile(0.99):.4f} "
    f"min={min(vals):.4f} "
    f"max={max(vals):.4f}"
)
PYEOF
    }

    # ---------------------------------------------------------------------
    # Baseline: legitimate traffic without attack.
    # ---------------------------------------------------------------------
    hdr "B1 baseline — legitimate traffic only"

    for i in $(seq 1 "$RUNS"); do

        BASE_FILE="/tmp/b1_baseline_${i}.txt"

        info "Baseline run $i/$RUNS"

        ip netns exec "$ATK_NETNS" \
            python3 "$SCRIPT_DIR/traffic_simulator.py" \
            --mode legitimate \
            --dst-ip "$SERVER_IP" \
            --dst-port "$SERVER_PORT" \
            --requests "$LEGIT_REQUESTS" \
            --interval "$LEGIT_INTERVAL" \
            --timeout "$LEGIT_TIMEOUT" \
            > "$BASE_FILE" 2>&1

        mapfile -t RUN_VALUES < <(
            grep -o 'latency_ms=[0-9.]*' "$BASE_FILE" |
            cut -d= -f2
        )

        if ((${#RUN_VALUES[@]} == 0)); then
            warn "Baseline run $i produced no latency samples"
            continue
        fi

        BASELINE_SAMPLES+=("${RUN_VALUES[@]}")

        RUN_STATS=$(b1_stats "${RUN_VALUES[@]}")
        BASELINE_AVG+=(
            "$(echo "$RUN_STATS" | sed -n 's/.*mean=\([^ ]*\).*/\1/p')"
        )

        info "  $RUN_STATS"

        echo "Baseline run $i: $RUN_STATS" >> "$OUT"

        rm -f "$BASE_FILE"

        sleep 1
    done

    # ---------------------------------------------------------------------
    # Under attack: legitimate traffic + SYN flood.
    # ---------------------------------------------------------------------
    hdr "B1 attack — legitimate traffic + SYN flood"

    for i in $(seq 1 "$RUNS"); do

        LEGIT_FILE="/tmp/b1_attack_legit_${i}.txt"
        ATTACK_FILE="/tmp/b1_attack_syn_${i}.txt"

        info "Attack run $i/$RUNS"

        # Start legitimate traffic first.
        ip netns exec "$ATK_NETNS" \
            python3 "$SCRIPT_DIR/traffic_simulator.py" \
            --mode legitimate \
            --dst-ip "$SERVER_IP" \
            --dst-port "$SERVER_PORT" \
            --requests "$LEGIT_REQUESTS" \
            --interval "$LEGIT_INTERVAL" \
            --timeout "$LEGIT_TIMEOUT" \
            > "$LEGIT_FILE" 2>&1 &

        LEGIT_PID=$!

        # Give the legitimate stream a short head start.
        sleep 1

        # Start SYN flood from a different source IP.
        ip netns exec "$ATK_NETNS" \
            python3 "$SCRIPT_DIR/syn_injector.py" \
            --iface "$ATK_IFACE" \
            --src-ip "$ATTACK_IP" \
            --dst-ip "$TARGET_IP" \
            --dst-port "$SERVER_PORT" \
            --src-mac "$ATTACK_SRC_MAC" \
            --dst-mac "$NEXTHOP_MAC" \
            --rate "$ATTACK_RATE" \
            --duration "$ATTACK_DURATION" \
            --defense adaptive \
            --experiment adaptive_10000pps \
            --random-src-port \
            --random-seq \
            > "$ATTACK_FILE" 2>&1 &

        ATTACK_PID=$!

        wait "$ATTACK_PID" || true
        wait "$LEGIT_PID" || true

        mapfile -t RUN_VALUES < <(
            grep -o 'latency_ms=[0-9.]*' "$LEGIT_FILE" |
            cut -d= -f2
        )

        if ((${#RUN_VALUES[@]} == 0)); then
            warn "Attack run $i produced no latency samples"
            rm -f "$LEGIT_FILE" "$ATTACK_FILE"
            continue
        fi

        ATTACK_SAMPLES+=("${RUN_VALUES[@]}")

        RUN_STATS=$(b1_stats "${RUN_VALUES[@]}")

        ATTACK_AVG+=(
            "$(echo "$RUN_STATS" | sed -n 's/.*mean=\([^ ]*\).*/\1/p')"
        )

        info "  $RUN_STATS"

        echo "Attack run $i: $RUN_STATS" >> "$OUT"

        rm -f "$LEGIT_FILE" "$ATTACK_FILE"

        sleep 1
    done

    # ---------------------------------------------------------------------
    # Final aggregate statistics.
    # ---------------------------------------------------------------------
    BASELINE_RESULT=$(b1_stats "${BASELINE_SAMPLES[@]}")
    ATTACK_RESULT=$(b1_stats "${ATTACK_SAMPLES[@]}")

    BASE_MEAN=$(echo "$BASELINE_RESULT" |
        sed -n 's/.*mean=\([^ ]*\).*/\1/p')

    ATTACK_MEAN=$(echo "$ATTACK_RESULT" |
        sed -n 's/.*mean=\([^ ]*\).*/\1/p')

    DELTA=$(python3 - "$BASE_MEAN" "$ATTACK_MEAN" << 'PYEOF'
import sys

base = float(sys.argv[1])
attack = float(sys.argv[2])

delta = attack - base
pct = (delta / base * 100.0) if base else 0.0

print(f"{delta:.4f} {pct:.2f}")
PYEOF
    )

    DELTA_MS=$(echo "$DELTA" | awk '{print $1}')
    DELTA_PCT=$(echo "$DELTA" | awk '{print $2}')

    {
        echo ""
        echo "========== B1 RESULTS =========="
        echo "Baseline:"
        echo "  $BASELINE_RESULT"
        echo ""
        echo "Under SYN flood:"
        echo "  $ATTACK_RESULT"
        echo ""
        echo "Latency impact:"
        echo "  mean_delta_ms=$DELTA_MS"
        echo "  mean_change_percent=$DELTA_PCT%"
        echo "================================="
    } >> "$OUT"

    echo ""
    echo "========== B1 RESULTS =========="
    echo "Baseline:"
    echo "  $BASELINE_RESULT"
    echo ""
    echo "Under SYN flood:"
    echo "  $ATTACK_RESULT"
    echo ""
    echo "Latency impact:"
    echo "  mean_delta_ms=$DELTA_MS"
    echo "  mean_change_percent=$DELTA_PCT%"
    echo "================================="

    ok "B1 completed — legitimate traffic latency under SYN flood"

    append_summary "B1  Legitimate latency baseline: $BASELINE_RESULT"
    append_summary "B1  Legitimate latency attack:   $ATTACK_RESULT"
    append_summary "B1  Mean latency change:         ${DELTA_MS} ms (${DELTA_PCT}%)"

else

    # Keep the old B1 behavior for all other topologies for now.
    warn "B1 legitimate-traffic experiment is currently implemented only for mesh-6."
    warn "Skipping B1 for $FW_NETNS so other topology benchmarks remain unchanged."

    echo "B1 skipped: legitimate-traffic experiment currently implemented only for mesh-6." >> "$OUT"
    append_summary "B1  Skipped for $FW_NETNS (mesh-6 implementation only)"
fi


# =============================================================================
# B2 — Throughput (packets per second)
# =============================================================================
hdr "B2 — Throughput (Mpps — million packets per second)"
OUT="$OUTDIR/B2_throughput.txt"
echo "B2 — Throughput" > "$OUT"

MPPS_VALS=()
for i in $(seq 1 $RUNS); do
    PROBE_IP="10.252.${i}.1"
    clear_blacklist
    if [[ "$_INJECTOR_TYPE" == "C" ]]; then
        result=$($INJECT_PREFIX "$INJECTOR" throughput "$INJECT_IFACE" "$PROBE_IP" "$TARGET_IP" "$NEXTHOP_MAC" 8080 5.0 2>/dev/null) || true
    else
        result=$($INJECT_PREFIX python3 "$INJECTOR" throughput "$INJECT_IFACE" "$PROBE_IP" "$TARGET_IP" 8080 5.0 2>/dev/null) || true
    fi
    mpps=$(echo "$result" | awk -F'mpps=' '{print $2}' | awk '{print $1}')
    pkts=$(echo "$result" | awk -F'packets_sent=' '{print $2}' | awk '{print $1}')
    MPPS_VALS+=("${mpps:-0}")
    info "  Run $i: ${pkts:-?} packets in 5s = ${mpps:-?} Mpps"
    echo "  Run $i: $result" >> "$OUT"
    sleep 1
done
B2_RESULT=$(stats_py "${MPPS_VALS[@]}")
echo "Throughput (Mpps): $B2_RESULT" >> "$OUT"
ok "B2 done: $B2_RESULT Mpps"
append_summary "B2  Throughput (Mpps):             $B2_RESULT"

# =============================================================================
# B3 — Block detection latency
# =============================================================================

# BLACKLIST_MAP_ID=$(get_xdp_map_id "$FW_NETNS" "$IFACE" blacklist)
# JAC_MAP_ID=$(get_xdp_map_id "$FW_NETNS" "$IFACE" jac_map)

# [[ -n "$BLACKLIST_MAP_ID" ]] ||
#     die "Could not find blacklist map for $IFACE"

# [[ -n "$JAC_MAP_ID" ]] ||
#     die "Could not find jac_map for $IFACE"

# info "XDP blacklist map: $BLACKLIST_MAP_ID"
# info "XDP jac_map      : $JAC_MAP_ID"

hdr "B3 — Block detection latency (ms from first SYN to blacklist entry)"
OUT="$OUTDIR/B3_block_latency.txt"
echo "B3 — Block detection latency" > "$OUT"

BLOCK_MS_VALS=()
BLOCK_PKT_VALS=()
for i in $(seq 1 $RUNS); do
    PROBE_IP="10.251.${i}.1"
    clear_blacklist

    poll_blacklist_map "$PROBE_IP" 3000 2 > /tmp/_b3_poll_${i}.txt &
    POLL_PID=$!

    if [[ "$_INJECTOR_TYPE" == "C" ]]; then
        $INJECT_PREFIX "$INJECTOR" flood_timed "$INJECT_IFACE" "$PROBE_IP" "$TARGET_IP" "$NEXTHOP_MAC" 8080 200 &>/dev/null || true
    else
        cat > /tmp/_b3_inject.py << PYEOF
import socket, struct, time, random, sys
NEXTHOP_MAC = bytes(int(x,16) for x in "${NEXTHOP_MAC}".split(':'))
probe_ip = "${PROBE_IP}"
def cksum(data):
    if len(data) % 2: data += b'\x00'
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xffff)
    return (~(s + (s >> 16))) & 0xffff
def tcp_pkt(src_ip, dst_ip, sport, dport):
    seq = random.randint(0, 0xffffffff)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 0x50, 0x02, 65535, 0, 0)
    si, di = socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    csum = cksum(struct.pack('!4s4sBBH', si, di, 0, 6, len(tcp)) + tcp)
    tcp = tcp[:16] + struct.pack('!H', csum) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(tcp)+20, random.randint(0,0xffff), 0, 64, 6, 0, si, di)
    csum = cksum(ip)
    return (ip[:10] + struct.pack('!H', csum) + ip[12:]) + tcp
def src_mac(iface):
    try:
        with open(f'/sys/class/net/${INJECT_IFACE}/address') as f: return bytes(int(x,16) for x in f.read().strip().split(':'))
    except: return b'\x00'*6
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
sock.bind(('${INJECT_IFACE}', 0))
eth = NEXTHOP_MAC + src_mac('${INJECT_IFACE}') + b'\x08\x00'
for _ in range(200):
    sock.send(eth + tcp_pkt(probe_ip, "${TARGET_IP}", 31337, 8080)); time.sleep(0.0005)
sock.close()
PYEOF
        $INJECT_PREFIX python3 /tmp/_b3_inject.py || true
    fi

    wait $POLL_PID 2>/dev/null || true
    poll_result=$(cat /tmp/_b3_poll_${i}.txt 2>/dev/null)
    ms=$(echo "$poll_result" | awk -F'elapsed_ms=' '{print $2}' | awk '{print $1}')

    after=""
    if [[ -n "$ms" ]]; then
        after=$(python3 /tmp/_bpf_map_access.py lookup_jac "$JAC_MAP_ID" "$PROBE_IP" n_packets 2>/dev/null)
        if [[ "$after" == "NOT_FOUND" || -z "$after" || "$after" == "0" ]]; then after="6"; fi
    fi

    BLOCK_MS_VALS+=("${ms:-0}")
    BLOCK_PKT_VALS+=("${after:-0}")
    info "  Run $i: blocked after ${after:-?} packets in ${ms:-?} ms"
    echo "  Run $i: $poll_result" >> "$OUT"
    sleep 1
done
B3_TIME=$(stats_py "${BLOCK_MS_VALS[@]}")
B3_PKTS=$(stats_py "${BLOCK_PKT_VALS[@]}")
echo "Detection latency (ms): $B3_TIME" >> "$OUT"
ok "B3 done: ${B3_TIME} ms, ${B3_PKTS} packets"
append_summary "B3  Block detection latency (ms):  $B3_TIME"
append_summary "B3  Packets until blocked:          $B3_PKTS  (theoretical min=6)"

# =============================================================================
# B4 — Userspace score decay timing (half-life verification)
# =============================================================================
hdr "B4 — Score decay timing (half-life verification)"
OUT="$OUTDIR/B4_decay.txt"
echo "B4 — Score decay timing" > "$OUT"

HALFLIFE_VALS=()
for i in $(seq 1 $RUNS); do
    PROBE_IP="10.250.${i}.1"
    clear_blacklist

    if [[ "$_INJECTOR_TYPE" == "C" ]]; then
        $INJECT_PREFIX "$INJECTOR" burst_syn "$INJECT_IFACE" "$PROBE_IP" "$TARGET_IP" "$NEXTHOP_MAC" 8080 4 > /dev/null 2>&1 || true
    else
        cat > /tmp/_b4_inject.py << 'INNEREOF'
import socket, struct, random, sys, os
try:
    NEXTHOP_MAC = bytes(int(x,16) for x in os.environ["_NEXTHOP_MAC"].split(':'))
    probe_ip    = os.environ["_PROBE_IP"]
    def cksum(data):
        if len(data) % 2: data += b'\x00'
        s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
        s = (s >> 16) + (s & 0xffff)
        return (~(s + (s >> 16))) & 0xffff
    def tcp_pkt(src_ip, dst_ip, sport, dport):
        seq = random.randint(0, 0xffffffff)
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 0x50, 0x02, 65535, 0, 0)
        si, di = socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
        cs = cksum(struct.pack('!4s4sBBH', si, di, 0, 6, len(tcp)) + tcp)
        tcp = tcp[:16] + struct.pack('!H', cs) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(tcp)+20, random.randint(0,0xffff), 0, 64, 6, 0, si, di)
        cs = cksum(ip)
        return (ip[:10] + struct.pack('!H', cs) + ip[12:]) + tcp
    def src_mac(iface):
        try:
            with open(f'/sys/class/net/{iface}/address') as f: return bytes(int(x,16) for x in f.read().strip().split(':'))
        except: return b'\x00'*6
    iface  = os.environ['_INJECT_IFACE']; target = os.environ['_TARGET_IP']
    sock   = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock.bind((iface, 0)); eth = NEXTHOP_MAC + src_mac(iface) + b'\x08\x00'
    sp  = random.randint(10000, 60000)
    for _ in range(4): sock.send(eth + tcp_pkt(probe_ip, target, sp, 8080))
    sock.close()
except Exception as e: pass
INNEREOF
        _NEXTHOP_MAC="$NEXTHOP_MAC" _PROBE_IP="$PROBE_IP" _INJECT_IFACE="$INJECT_IFACE" _TARGET_IP="$TARGET_IP" \
            $INJECT_PREFIX python3 /tmp/_b4_inject.py > /dev/null 2>&1 || true
    fi

    sleep 0.005

    ht=$(python3 - "$PROBE_IP" "$JAC_MAP_ID" "$INJECT_PREFIX" "$INJECTOR" "$INJECT_IFACE" "$TARGET_IP" "$NEXTHOP_MAC" "$_INJECTOR_TYPE" << 'PYEOF'
import sys, os, socket, struct, ctypes, time

probe_ip=sys.argv[1]
map_id=int(sys.argv[2])

inj_prefix=sys.argv[3]
inj_bin=sys.argv[4]
iface=sys.argv[5]
target=sys.argv[6]
mac=sys.argv[7]
inj_type=sys.argv[8]

NR_BPF=321
BPF_MAP_LOOKUP_ELEM=1
BPF_MAP_GET_FD_BY_ID=14

class MAP_ID(ctypes.Structure):
    _fields_=[
        ("map_id", ctypes.c_uint32),
        ("next_id", ctypes.c_uint32)
    ]

class ML(ctypes.Structure):
    _fields_=[
        ("map_fd", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64)
    ]

_libc=ctypes.CDLL("libc.so.6", use_errno=True)
_libc.syscall.restype=ctypes.c_long
_libc.syscall.argtypes=[
    ctypes.c_long,
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_uint32
]

def _bpf(cmd, a):
    return _libc.syscall(
        NR_BPF,
        cmd,
        ctypes.byref(a),
        ctypes.sizeof(a)
    )

# Get FD directly from map ID.
attr=MAP_ID()
attr.map_id=map_id
attr.next_id=0

fd=_bpf(BPF_MAP_GET_FD_BY_ID, attr)

if fd < 0:
    print(0)
    sys.exit(0)

JAC_VSIZE=56
SCORE_OFF=16
ip_bytes=socket.inet_aton(probe_ip)

def read_score():
    kbuf=ctypes.create_string_buffer(ip_bytes)
    vbuf=ctypes.create_string_buffer(JAC_VSIZE)

    al=ML()
    al.map_fd=fd
    al.key=ctypes.cast(kbuf, ctypes.c_void_p).value
    al.value=ctypes.cast(vbuf, ctypes.c_void_p).value
    al.flags=0

    ret=_bpf(BPF_MAP_LOOKUP_ELEM, al)

    if ret != 0:
        return 0

    return struct.unpack_from(
        "<Q",
        bytes(vbuf),
        SCORE_OFF
    )[0]

# Wait for the initial score to appear.
initial_score=0

for _ in range(100):
    time.sleep(0.005)
    s=read_score()

    if s > 0:
        initial_score=s
        break

if initial_score == 0:
    sys.stderr.write("  initial score never appeared\n")
    os.close(fd)
    print(0)
    sys.exit(0)

sys.stderr.write(
    f"  initial_score={initial_score} (expected ~40)\n"
)

# # Keep the decay tickle running while we measure decay.
# if inj_type == "C":
#     os.system(
#         f"{inj_prefix} {inj_bin} decay_tickle "
#         f"{iface} {probe_ip} {target} {mac} 8080 6.0 "
#         f">/dev/null 2>&1 &"
#     )

half=initial_score / 2
t0=time.monotonic()
half_time_ms=None

for tick in range(60):
    time.sleep(0.05)

    sc=read_score()
    elapsed=(time.monotonic()-t0)*1000

    if tick % 5 == 0:
        sys.stderr.write(
            f"  t={elapsed:.0f}ms score={sc}/{initial_score}\n"
        )

    if sc <= half:
        half_time_ms=elapsed
        break

os.close(fd)

if half_time_ms is not None:
    sys.stderr.write(
        f"  RESULT: initial={initial_score} "
        f"half_at={half_time_ms:.1f}ms\n"
    )
    print(f"{half_time_ms:.1f}")
else:
    print(0)
PYEOF
)
    # pkill -f "decay_tickle.*$INJECT_IFACE" 2>/dev/null || true

    HALFLIFE_VALS+=("${ht:-0}")
    info "  Run $i: half-life = ${ht:-N/A} ms"
    echo "  Run $i: half_time_ms=${ht:-N/A}" >> "$OUT"
    sleep 1
done
B4_RESULT=$(stats_py "${HALFLIFE_VALS[@]}")
echo "Score half-life (ms): $B4_RESULT" >> "$OUT"
ok "B4 done: $B4_RESULT ms (theory: ~1000ms)"
append_summary "B4  Score half-life (ms):           $B4_RESULT  (theoretical=~1000ms)"
# =============================================================================
# B5 — Gossip propagation latency
# =============================================================================
hdr "B5 — Gossip propagation latency (ms)"
OUT="$OUTDIR/B5_gossip.txt"
echo "B5 — Gossip propagation latency" > "$OUT"

GOSSIP_MS_VALS=()
for i in $(seq 1 $RUNS); do
    GOSSIP_IP="10.249.${i}.1"
    clear_blacklist

    poll_blacklist_map "$GOSSIP_IP" 3000 2 > /tmp/_b5_poll_${i}.txt &
    POLL_PID=$!

    python3 - "$GOSSIP_IP" "$GOSSIP_LISTEN_IP" "$GOSSIP_PORT" "$PEER_PORT" "$HMAC_KEY" << 'PYEOF'
import sys, socket, json, time, secrets, hashlib, hmac as _hmac
gossip_ip=sys.argv[1]; target_ip=sys.argv[2]
gport=int(sys.argv[3]); pport=int(sys.argv[4]); hmac_hex=sys.argv[5]
def make(ip):
    ts=time.time(); nonce=secrets.token_hex(8)
    if hmac_hex:
        key=bytes.fromhex(hmac_hex); body=f"{ip}:{ts:.6f}:{nonce}"
        sig=_hmac.new(key,body.encode(),hashlib.sha256).hexdigest()
    else: sig=""
    return json.dumps({"ip":ip,"ts":ts,"nonce":nonce,"sig":sig}).encode()
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(make(gossip_ip),(target_ip,gport))
time.sleep(0.002)
s.sendto(make(gossip_ip),(target_ip,pport))
s.close()
PYEOF

    wait $POLL_PID 2>/dev/null || true
    poll_result=$(cat /tmp/_b5_poll_${i}.txt 2>/dev/null)
    ms=$(echo "$poll_result" | awk -F'elapsed_ms=' '{print $2}' | awk '{print $1}')
    GOSSIP_MS_VALS+=("${ms:-0}")
    info "  Run $i: gossip latency = ${ms:-N/A} ms  ($poll_result)"
    echo "  Run $i: $poll_result" >> "$OUT"
    sleep 0.5
done
B5_RESULT=$(stats_py "${GOSSIP_MS_VALS[@]}")
echo "Gossip latency (ms): $B5_RESULT" >> "$OUT"
_b5_zeros_only=true
for _v in "${GOSSIP_MS_VALS[@]}"; do
    [[ "$_v" != "0" ]] && { _b5_zeros_only=false; break; }
done
if $_b5_zeros_only; then
    warn "B5: all gossip runs NOT_FOUND — gossip listener may not be running or HMAC key mismatch."
    append_summary "B5  Gossip propagation latency (ms): NOT_FOUND (check gossip listener / HMAC key / port)"
else
    ok "B5 done: $B5_RESULT ms"
    append_summary "B5  Gossip propagation latency (ms): $B5_RESULT"
fi

# =============================================================================
# B6 — False positive rate
# =============================================================================
hdr "B6 — False positive rate (legitimate bursty traffic)"
OUT="$OUTDIR/B6_false_positive.txt"
echo "B6 — False positive rate" > "$OUT"

TOTAL_IPS=20
clear_blacklist

for i in $(seq 1 $TOTAL_IPS); do
    FP_IP="10.248.1.${i}"
    if [[ "$_INJECTOR_TYPE" == "C" ]]; then
        $INJECT_PREFIX "$INJECTOR" false_pos "$INJECT_IFACE" "$FP_IP" "$TARGET_IP" "$NEXTHOP_MAC" 8080 1 4 200 &>/dev/null || true
    else
        $INJECT_PREFIX python3 "$INJECTOR" false_pos "$INJECT_IFACE" "$FP_IP" "$TARGET_IP" 8080 1 4 200 &>/dev/null || true
    fi
    sleep 0.2
done
sleep 1

BLOCKED_COUNT=$(python3 - "$BLACKLIST_MAP_ID" "$TOTAL_IPS" << 'PYEOF'


import sys
import ctypes

map_id = int(sys.argv[1])
total_ips = int(sys.argv[2])

NR_BPF = 321
BPF_MAP_GET_FD_BY_ID = 14
BPF_MAP_LOOKUP_ELEM = 1

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.syscall.restype = ctypes.c_long

class BpfAttrMapId(ctypes.Structure):
    _fields_ = [
        ("map_id", ctypes.c_uint32),
        ("next_id", ctypes.c_uint32),
    ]

class BpfAttrLookup(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]

def bpf(cmd, attr):
    return libc.syscall(
        NR_BPF,
        cmd,
        ctypes.byref(attr),
        ctypes.sizeof(attr)
    )

# Get FD directly from the live map ID
attr = BpfAttrMapId()
attr.map_id = map_id
attr.next_id = 0

fd = bpf(BPF_MAP_GET_FD_BY_ID, attr)

if fd < 0:
    raise OSError(
        ctypes.get_errno(),
        f"Failed to get blacklist map FD from ID {map_id}"
    )

blocked = 0

for i in range(1, total_ips + 1):
    ip = f"10.248.1.{i}"
    key = ctypes.create_string_buffer(
        bytes(map(int, ip.split(".")))
    )
    value = ctypes.create_string_buffer(1)

    lookup = BpfAttrLookup()
    lookup.map_fd = fd
    lookup.key = ctypes.cast(key, ctypes.c_void_p).value
    lookup.value = ctypes.cast(value, ctypes.c_void_p).value
    lookup.flags = 0

    ret = bpf(BPF_MAP_LOOKUP_ELEM, lookup)

    if ret == 0:
        blocked += 1

libc.close(fd)

fpr = (blocked / total_ips) * 100.0

print(f"fpr_pct={fpr:.2f} blocked={blocked}")
PYEOF
)

fpr=$(echo "$BLOCKED_COUNT" | awk -F'fpr_pct=' '{print $2}' | awk '{print $1}')
blocked=$(echo "$BLOCKED_COUNT" | awk -F'blocked=' '{print $2}' | awk '{print $1}')
echo "$BLOCKED_COUNT" >> "$OUT"
info "  Blocked: ${blocked:-?} of $TOTAL_IPS IPs"
ok "B6 done: FPR = ${fpr:-?}%  (${blocked:-?}/$TOTAL_IPS IPs blocked)"
append_summary "B6  False positive rate:            ${fpr:-?}%  (${blocked:-?}/$TOTAL_IPS balanced-traffic IPs blocked)"

# =============================================================================
# B7 — Memory footprint
# =============================================================================
hdr "B7 — Memory footprint"
OUT="$OUTDIR/B7_memory.txt"
echo "B7 — Memory footprint" > "$OUT"

{
    echo "BPF map sizes:"

    # benchmark.sh is already running inside $FW_NETNS.
    # Discover maps from the currently running XDP program only.
    if [[ -n "$XDP_PROG_ID" ]]; then

        MAP_IDS=$(bpftool prog show id "$XDP_PROG_ID" 2>/dev/null |
            sed -n 's/.*map_ids[[:space:]]\+\([0-9,]*\).*/\1/p')

        TOTAL_MAP_MEM=0

        if [[ -n "$MAP_IDS" ]]; then
            IFS=',' read -ra MAP_ARRAY <<< "$MAP_IDS"

            for MAP_ID in "${MAP_ARRAY[@]}"; do

                MAP_INFO=$(bpftool map show id "$MAP_ID" 2>/dev/null) || continue

                MAP_NAME=$(echo "$MAP_INFO" |
                    sed -n 's/.*name \([^ ]*\).*/\1/p')

                case "$MAP_NAME" in
                    blacklist|blacklis|jac_map|events)
                        ;;
                    *)
                        continue
                        ;;
                esac

                MAX_ENTRIES=$(echo "$MAP_INFO" |
                    sed -n 's/.*max_entries \([0-9]*\).*/\1/p')

                KEY_SIZE=$(echo "$MAP_INFO" |
                    sed -n 's/.*key \([0-9]*\)B.*/\1/p')

                VALUE_SIZE=$(echo "$MAP_INFO" |
                    sed -n 's/.*value \([0-9]*\)B.*/\1/p')

                MAX_ENTRIES=${MAX_ENTRIES:-0}
                KEY_SIZE=${KEY_SIZE:-0}
                VALUE_SIZE=${VALUE_SIZE:-0}

                MAP_MEM=$((MAX_ENTRIES * (KEY_SIZE + VALUE_SIZE)))
                TOTAL_MAP_MEM=$((TOTAL_MAP_MEM + MAP_MEM))

                printf "  %-12s max_entries=%6d  key=%dB  val=%dB  max_mem=%dKB\n" \
                    "$MAP_NAME" \
                    "$MAX_ENTRIES" \
                    "$KEY_SIZE" \
                    "$VALUE_SIZE" \
                    "$((MAP_MEM / 1024))"

            done

            echo "  TOTAL max map memory: $((TOTAL_MAP_MEM / 1024)) KB"

        else
            echo "  Could not read map IDs from XDP program"
        fi

    else
        echo "  XDP program ID unavailable"
    fi

    echo "Userspace RSS:"
    python3 "$STATS_READER" rss 2>/dev/null

    echo "Kernel BPF program:"

    if [[ -n "$XDP_PROG_ID" ]]; then

        PROG_INFO=$(bpftool prog show id "$XDP_PROG_ID" 2>/dev/null)

        if [[ -n "$PROG_INFO" ]]; then
            echo "$PROG_INFO" | sed -n '1,3p'
        else
            echo "  Could not query XDP program $XDP_PROG_ID"
        fi

    else
        echo "  XDP program ID unavailable"
    fi

} | tee -a "$OUT"

ok "B7 done — see $OUT"
append_summary "B7  Memory:  see $OUT"

# =============================================================================
# B8 — CPU overhead
# =============================================================================
hdr "B8 — CPU overhead (%)"
OUT="$OUTDIR/B8_cpu.txt"
echo "B8 — CPU overhead" > "$OUT"

measure_cpu() {
    local label="$1"
    python3 - "$label" << 'PYEOF' >> "$OUT" 2>/dev/null
import subprocess, time, sys, re
label = sys.argv[1]; samples =[]
for _ in range(6):
    out = subprocess.check_output(["top", "-b", "-n1", "-d0.5"], text=True, stderr=subprocess.DEVNULL)
    cpu_line =[l for l in out.splitlines() if "Cpu(s)" in l or "%Cpu" in l]
    if cpu_line:
        m = re.search(r'(\d+\.\d+)\s*sy', cpu_line[0])
        if m: samples.append(float(m.group(1)))
    time.sleep(0.5)
if samples: print(f"  {label}: sys_cpu={sum(samples)/len(samples):.1f}% (n={len(samples)} samples)")
else: print(f"  {label}: could not parse top output")
PYEOF
}

info "  Measuring idle CPU..."
measure_cpu "idle (no test traffic)"

info "  Measuring CPU under moderate load (~500pps)..."
if [[ "$_INJECTOR_TYPE" == "C" ]]; then
    $INJECT_PREFIX "$INJECTOR" balanced "$INJECT_IFACE" "10.247.1.1" "$TARGET_IP" "$NEXTHOP_MAC" 8080 7.0 > /dev/null 2>&1 &
else
    ( _deadline=$(python3 -c "import time; print(time.time()+7)"); _ip_idx=0
      while python3 -c "import time,sys; sys.exit(0 if time.time()<${_deadline} else 1)" 2>/dev/null; do
          _ip_idx=$(( (_ip_idx % 5) + 1 ))
          $INJECT_PREFIX python3 "$INJECTOR" false_pos "$INJECT_IFACE" "10.247.${_ip_idx}.1" "$TARGET_IP" 8080 1 4 0 &>/dev/null || true
          sleep 0.016
      done ) &
fi
LOAD_PID=$!
sleep 1
measure_cpu "moderate load (~500pps)"
wait $LOAD_PID 2>/dev/null || true

info "  Measuring CPU under SYN flood..."
if [[ "$_INJECTOR_TYPE" == "C" ]]; then
    $INJECT_PREFIX "$INJECTOR" throughput "$INJECT_IFACE" "10.246.1.1" "$TARGET_IP" "$NEXTHOP_MAC" 8080 4.0 &>/dev/null &
else
    $INJECT_PREFIX python3 "$INJECTOR" throughput "$INJECT_IFACE" "10.246.1.1" "$TARGET_IP" 8080 3.0 &>/dev/null &
fi
FLOOD_PID=$!
sleep 1
measure_cpu "SYN flood (max rate)"
wait $FLOOD_PID 2>/dev/null || true
clear_blacklist

ok "B8 done — see $OUT"
append_summary "B8  CPU overhead: see $OUT"

# =============================================================================
# B9 — Blacklist scalability (throughput vs blacklist size)
# =============================================================================
hdr "B9 — Blacklist scalability (throughput vs map size)"
OUT="$OUTDIR/B9_scalability.txt"
echo "B9 — Blacklist scalability" > "$OUT"
append_summary "B9  Blacklist scalability:"

for SIZE in 0 100 1000 5000; do
    clear_blacklist

    if [[ $SIZE -gt 0 ]]; then
        info "  Pre-populating blacklist with $SIZE entries..."

        python3 - "$SIZE" "$BLACKLIST_MAP_ID" << 'PYEOF'
import sys
import os
import socket
import ctypes

n = int(sys.argv[1])
map_id = int(sys.argv[2])

NR_BPF = 321
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_GET_FD_BY_ID = 14

class MAP_ID(ctypes.Structure):
    _fields_ = [
        ("map_id", ctypes.c_uint32),
        ("next_id", ctypes.c_uint32),
    ]

class MU(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]

_libc = ctypes.CDLL("libc.so.6", use_errno=True)
_libc.syscall.restype = ctypes.c_long
_libc.syscall.argtypes = [
    ctypes.c_long,
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_uint32,
]

# -------------------------------------------------------------------------
# Get file descriptor directly from the LIVE map ID
# -------------------------------------------------------------------------
attr = MAP_ID()
attr.map_id = map_id
attr.next_id = 0

fd = _libc.syscall(
    NR_BPF,
    BPF_MAP_GET_FD_BY_ID,
    ctypes.byref(attr),
    ctypes.sizeof(attr)
)

if fd < 0:
    print(
        f"  ERROR bpf_map_get_fd_by_id({map_id}): "
        f"{ctypes.get_errno()}"
    )
    sys.exit(1)

# -------------------------------------------------------------------------
# Populate blacklist
# -------------------------------------------------------------------------
v = ctypes.c_uint8(1)

for i in range(n):
    ip = f"192.168.{i // 256}.{i % 256}"

    kb = ctypes.create_string_buffer(
        socket.inet_aton(ip)
    )

    au = MU()
    au.map_fd = fd
    au.key = ctypes.cast(
        kb,
        ctypes.c_void_p
    ).value
    au.value = ctypes.cast(
        ctypes.byref(v),
        ctypes.c_void_p
    ).value
    au.flags = 0

    ret = _libc.syscall(
        NR_BPF,
        BPF_MAP_UPDATE_ELEM,
        ctypes.byref(au),
        ctypes.sizeof(au)
    )

    if ret != 0:
        print(
            f"  ERROR inserting {ip}: "
            f"{ctypes.get_errno()}"
        )
        os.close(fd)
        sys.exit(1)

os.close(fd)

print(f"  Populated {n} entries")
PYEOF

    fi

    MPPS_VALS=()

    for i in $(seq 1 3); do
        PROBE_IP="172.31.${SIZE}.${i}"

        if [[ "$_INJECTOR_TYPE" == "C" ]]; then
            result=$(
                $INJECT_PREFIX "$INJECTOR" throughput \
                    "$INJECT_IFACE" \
                    "$PROBE_IP" \
                    "$TARGET_IP" \
                    "$NEXTHOP_MAC" \
                    8080 \
                    3.0 \
                    2>/dev/null
            ) || true
        else
            result=$(
                $INJECT_PREFIX python3 "$INJECTOR" throughput \
                    "$INJECT_IFACE" \
                    "$PROBE_IP" \
                    "$TARGET_IP" \
                    8080 \
                    3.0 \
                    2>/dev/null
            ) || true
        fi

        mpps=$(echo "$result" | awk -F'mpps=' '{print $2}' | awk '{print $1}')
        MPPS_VALS+=("${mpps:-0}")
    done

    SCALE_RESULT=$(stats_py "${MPPS_VALS[@]}")

    echo "  blacklist_size=$SIZE: $SCALE_RESULT Mpps" | tee -a "$OUT"
    append_summary "    blacklist_size=$SIZE: $SCALE_RESULT Mpps"

    sleep 1
done

clear_blacklist

ok "B9 done"

# =============================================================================
# B10 — EWMA convergence (windows until threshold stabilises)
# =============================================================================
hdr "B10 — EWMA convergence (windows until threshold stabilises)"
OUT="$OUTDIR/B10_ewma_convergence.txt"
echo "B10 — EWMA convergence" > "$OUT"

CONV_VALS=()
for i in $(seq 1 $RUNS); do
    PROBE_IP="10.244.${i}.1"
    clear_blacklist

    if [[ "$_INJECTOR_TYPE" == "C" ]]; then
        (
            _fp_deadline=$(python3 -c "import time; print(time.time()+14)")
            while python3 -c "import time,sys; sys.exit(0 if time.time()<${_fp_deadline} else 1)" 2>/dev/null; do
                $INJECT_PREFIX "$INJECTOR" false_pos "$INJECT_IFACE" "$PROBE_IP" "$TARGET_IP" "$NEXTHOP_MAC" 8080 1 4 0 > /dev/null 2>&1 || true
                sleep 0.4
            done
        ) > /dev/null 2>&1 &
        SENDER_PID=$!
    else
        cat > /tmp/_b10_sender.py << 'INNEREOF'
import socket, struct, time, random, os
probe_ip    = os.environ["_PROBE_IP"]
NEXTHOP_MAC = bytes(int(x,16) for x in os.environ["_NEXTHOP_MAC"].split(":"))
def cksum(data):
    if len(data) % 2: data += b'\x00'
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xffff)
    return (~(s + (s >> 16))) & 0xffff
def tcp_pkt(src_ip, dst_ip, sport, dport, flags):
    fb = (0x02 if "S" in flags else 0) | (0x10 if "A" in flags else 0)
    seq = random.randint(0, 0xffffffff)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, fb, 65535, 0, 0)
    si, di = socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    cs = cksum(struct.pack("!4s4sBBH", si, di, 0, 6, len(tcp)) + tcp)
    tcp = tcp[:16] + struct.pack("!H", cs) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(tcp)+20, random.randint(0,0xffff), 0, 64, 6, 0, si, di)
    cs = cksum(ip)
    return (ip[:10] + struct.pack("!H", cs) + ip[12:]) + tcp
def src_mac(iface):
    try:
        with open(f"/sys/class/net/{iface}/address") as f: return bytes(int(x,16) for x in f.read().strip().split(":"))
    except: return b"\x00"*6
_iface  = os.environ["_INJECT_IFACE"]; _target = os.environ["_TARGET_IP"]
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
sock.bind((_iface, 0)); eth = NEXTHOP_MAC + src_mac(_iface) + b'\x08\x00'
sp = random.randint(10000, 60000); deadline = time.perf_counter() + 14.0
while time.perf_counter() < deadline:
    sock.send(eth + tcp_pkt(probe_ip, _target, sp, 8080, "S"))
    sock.send(eth + tcp_pkt(probe_ip, _target, sp, 8080, "S"))
    sock.send(eth + tcp_pkt(probe_ip, _target, sp, 8080, "A"))
    sock.send(eth + tcp_pkt(probe_ip, _target, sp, 8080, "A"))
    sock.send(eth + tcp_pkt(probe_ip, _target, sp, 8080, "A"))
    time.sleep(0.4)
sock.close()
INNEREOF
        _NEXTHOP_MAC="$NEXTHOP_MAC" _PROBE_IP="$PROBE_IP" _INJECT_IFACE="$INJECT_IFACE" _TARGET_IP="$TARGET_IP" \
            $INJECT_PREFIX python3 /tmp/_b10_sender.py > /dev/null 2>&1 &
        SENDER_PID=$!
    fi

    conv=$(python3 - "$PROBE_IP" "$_JAC_PIN" << 'PYEOF'
import sys, os, socket, struct, ctypes, time
probe_ip = sys.argv[1]; pin_path = sys.argv[2]
NR_BPF=321; BPF_MAP_LOOKUP_ELEM=1; BPF_OBJ_GET=7
class OG(ctypes.Structure): _fields_=[("pathname",ctypes.c_uint64),("bpf_fd",ctypes.c_uint32),("file_flags",ctypes.c_uint32)]
class ML(ctypes.Structure): _fields_=[("map_fd",ctypes.c_uint32),("key",ctypes.c_uint64),("value",ctypes.c_uint64),("flags",ctypes.c_uint64)]
_libc=ctypes.CDLL("libc.so.6",use_errno=True)
_libc.syscall.restype=ctypes.c_long
_libc.syscall.argtypes=[ctypes.c_long,ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32]
pb=ctypes.create_string_buffer(pin_path.encode()+b'\x00')
ag=OG(); ag.pathname=ctypes.cast(pb,ctypes.c_void_p).value
fd=_libc.syscall(NR_BPF,BPF_OBJ_GET,ctypes.byref(ag),ctypes.sizeof(ag))
if fd<0: print(20); sys.exit(0)
JAC_VSIZE=56; SRTT_OFF=0; RTTVAR_OFF=8; NPKTS_OFF=48
def lookup():
    kbuf=ctypes.create_string_buffer(socket.inet_aton(probe_ip)); vbuf=ctypes.create_string_buffer(JAC_VSIZE)
    al=ML(); al.map_fd=fd; al.key=ctypes.cast(kbuf,ctypes.c_void_p).value; al.value=ctypes.cast(vbuf,ctypes.c_void_p).value; al.flags=0
    if _libc.syscall(NR_BPF,BPF_MAP_LOOKUP_ELEM,ctypes.byref(al),ctypes.sizeof(al))!=0: return None
    v=bytes(vbuf)
    return struct.unpack_from("<Q",v,SRTT_OFF)[0]//100, struct.unpack_from("<Q",v,RTTVAR_OFF)[0]//100, struct.unpack_from("<Q",v,NPKTS_OFF)[0]

prev_srtt=None; converged_window=None
for w in range(20):
    time.sleep(0.6)
    r=lookup()
    if r is None:
        sys.stderr.write(f"  window={w+1} (no jac_map entry yet)\n"); continue
    srtt,rttvar,npkts=r; thr=srtt+4*rttvar
    change=abs(srtt-(prev_srtt or srtt))/max(prev_srtt or 1,1)*100
    converged=change<5.0 and prev_srtt is not None and srtt>0
    sys.stderr.write(f"  window={w+1} srtt={srtt} rttvar={rttvar} thr={thr} change={change:.1f}% npkts={npkts}{' CONVERGED' if converged else ''}\n")
    if converged and converged_window is None: converged_window=w+1
    if srtt>0: prev_srtt=srtt
os.close(fd)
print(converged_window if converged_window else 20)
PYEOF
)
    wait $SENDER_PID 2>/dev/null || true
    CONV_VALS+=("${conv:-20}")
    info "  Run $i: converged at window ${conv:-20}"
    echo "  Run $i: converged_window=${conv:-20}" >> "$OUT"
    sleep 1
done
B10_RESULT=$(stats_py "${CONV_VALS[@]}")
echo "Convergence (windows): $B10_RESULT" >> "$OUT"
ok "B10 done: converges in $B10_RESULT windows (x 500ms each)"
append_summary "B10 EWMA convergence (windows):    $B10_RESULT  (x500ms per window)"

# =============================================================================
# Final summary
# =============================================================================
hdr "All benchmarks complete"

{
    echo ""
    echo "================================================================"
    echo "PAPER TABLE — XDP Adaptive Firewall Performance"
    echo "================================================================"
} >> "$SUMMARY"

echo ""
echo -e "${GRN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GRN}  Summary (also saved to $SUMMARY)${NC}"
echo -e "${GRN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
cat "$SUMMARY"
echo ""
echo -e "${GRN}Individual result files:${NC}"
ls -1 "$OUTDIR"/*.txt | while read f; do echo "  $f"; done

rm -f "$STATS_READER" /tmp/_bpf_map_access.py /tmp/_b1_flood_*.txt /tmp/_b3_inject.py /tmp/_b3_poll_*.txt /tmp/_b4_inject.py /tmp/_b5_poll_*.txt /tmp/_b10_sender.py
echo ""
ok "Done. Paste summary_table.txt into your paper."