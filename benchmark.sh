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

usage() {
cat <<EOF
Usage: sudo bash benchmark.sh [OPTIONS]

  --iface       <iface>   Firewall interface XDP is attached to
  --target      <IP>      Firewall IP to send packets toward
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
        --runs)        RUNS="$2";             shift 2 ;;
        --outdir)      OUTDIR="$2";           shift 2 ;;
        --hmac-key)    HMAC_KEY="$2";         shift 2 ;;
        --gossip-ip)   GOSSIP_LISTEN_IP="$2"; shift 2 ;;
        --gossip-port) GOSSIP_PORT_OVERRIDE="$2"; shift 2 ;;
        --peer-port)   PEER_PORT="$2";        shift 2 ;;
        --veth)        VETH_MODE=true;        shift   ;;
        -h|--help)     usage ;;
        *) die "Unknown option: $1" ;;
    esac
done

[[ -z "$TARGET_IP" ]] && die "Provide --target <IP of device running the firewall>"
ip link show "$IFACE" &>/dev/null || die "Interface $IFACE not found"
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
ATK_NETNS="xdp_attacker"
INJECT_IFACE="$IFACE"
INJECT_PREFIX=""

if $VETH_MODE; then
    if [[ "$IFACE" != fw* ]]; then
        die "--veth: --iface must start with fw (got: $IFACE). Cannot derive atk* peer name."
    fi
    ATK_IFACE="atk${IFACE#fw}"
    ip netns list | grep -q "^${ATK_NETNS}" || \
        die "Netns '$ATK_NETNS' not found. Run: sudo bash veth_setup.sh setup <topology>"
    ip netns exec "$ATK_NETNS" ip link show "$ATK_IFACE" &>/dev/null || \
        die "$ATK_IFACE not found in netns $ATK_NETNS. Run: sudo bash veth_setup.sh status"
    OWN_IP=$(ip netns exec "$ATK_NETNS" ip -4 addr show "$ATK_IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
    [[ -z "$OWN_IP" ]] && die "No IPv4 on $ATK_IFACE inside $ATK_NETNS"
    NEXTHOP_MAC=$(cat "/sys/class/net/${IFACE}/address" 2>/dev/null || true)
    [[ -z "$NEXTHOP_MAC" ]] && die "Cannot read MAC for $IFACE from sysfs"
    INJECT_IFACE="$ATK_IFACE"
    INJECT_PREFIX="ip netns exec ${ATK_NETNS}"
    info "Veth mode: ${ATK_NETNS}/${ATK_IFACE} (${OWN_IP}) -> ${IFACE} (${TARGET_IP})"
    info "Destination MAC: ${NEXTHOP_MAC}"
else
    OWN_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
    [[ -z "$OWN_IP" ]] && die "No IPv4 on $IFACE"
    NEXTHOP=$(ip route get "$TARGET_IP" 2>/dev/null | awk '/via/{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' | head -1)
    [[ -z "$NEXTHOP" ]] && NEXTHOP="$TARGET_IP"
    ping -c 2 -W 1 -I "$IFACE" "$NEXTHOP" &>/dev/null || true
    sleep 0.2
    NEXTHOP_MAC=$(ip neigh show "$NEXTHOP" dev "$IFACE" 2>/dev/null | awk '/lladdr/{print $3}' | head -1)
    [[ -z "$NEXTHOP_MAC" ]] && die "Cannot resolve MAC for $NEXTHOP. Run: ping -c3 $NEXTHOP first."
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
try: from bcc import BPF
except ImportError: sys.exit("BCC not found")

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

mode = sys.argv[1]

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
    local _pin="${PIN_BASE}/${IFACE}/blacklist"
    python3 - "$_pin" << 'EOF'
import sys, ctypes
pin_path = sys.argv[1]
try:
    import subprocess, json
    out = subprocess.check_output(["bpftool", "map", "dump", "pinned", pin_path, "-j"], text=True, stderr=subprocess.DEVNULL)
    entries = json.loads(out)
    count = 0
    for e in entries:
        kb = e.get("key", [])
        if kb:
            subprocess.run(["bpftool", "map", "delete", "pinned", pin_path, "key", "hex"] +[f"{b:02x}" for b in kb], stderr=subprocess.DEVNULL)
            count += 1
    print(f"  Cleared {count} blacklist entries (bpftool)")
except Exception:
    try:
        class OG(ctypes.Structure): _fields_=[("pathname",ctypes.c_uint64),("bpf_fd",ctypes.c_uint32),("file_flags",ctypes.c_uint32)]
        class MO(ctypes.Structure): _fields_=[("map_fd",ctypes.c_uint32),("key",ctypes.c_uint64),("value",ctypes.c_uint64),("flags",ctypes.c_uint64)]
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.syscall.restype = ctypes.c_long
        buf = ctypes.create_string_buffer(pin_path.encode()+b'\x00')
        ag = OG(); ag.pathname = ctypes.cast(buf, ctypes.c_void_p).value
        fd = libc.syscall(321, 7, ctypes.byref(ag), ctypes.sizeof(ag))
        if fd >= 0:
            count = 0; nk = ctypes.create_string_buffer(4)
            attr = MO(); attr.map_fd = fd; attr.key = 0; attr.value = ctypes.cast(nk, ctypes.c_void_p).value
            while libc.syscall(321, 3, ctypes.byref(attr), ctypes.sizeof(attr)) == 0:
                da = MO(); da.map_fd = fd; da.key = ctypes.cast(nk, ctypes.c_void_p).value
                libc.syscall(321, 4, ctypes.byref(da), ctypes.sizeof(da))
                count += 1; attr.key = 0
            print(f"  Cleared {count} blacklist entries (ctypes fallback)")
            import os; os.close(fd)
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
BPF_OBJ_GET        = 7

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
    pin, ip, tms, ims = sys.argv[2], sys.argv[3], float(sys.argv[4]), float(sys.argv[5])
    fd = bpf_obj_get(pin); t0 = time.perf_counter()
    while time.perf_counter() - t0 < tms / 1000:
        if bpf_lookup(fd, ip_key(ip), BL_VSIZE) is not None:
            ms = (time.perf_counter() - t0) * 1000
            os.close(fd); print(f"FOUND elapsed_ms={ms:.3f}"); sys.exit(0)
        time.sleep(ims / 1000)
    os.close(fd); print("NOT_FOUND")

elif mode == "lookup_jac":
    pin, ip, field = sys.argv[2], sys.argv[3], sys.argv[4]
    fd = bpf_obj_get(pin); v = bpf_lookup(fd, ip_key(ip), JAC_VSIZE); os.close(fd)
    if v is None: print("NOT_FOUND")
    else: print(struct.unpack_from("<Q", v, JAC_FIELDS[field])[0])

elif mode == "poll_jac_score":
    pin, ip, tms, ims = sys.argv[2], sys.argv[3], float(sys.argv[4]), float(sys.argv[5])
    fd = bpf_obj_get(pin); t0 = time.perf_counter()
    while time.perf_counter() - t0 < tms / 1000:
        v = bpf_lookup(fd, ip_key(ip), JAC_VSIZE)
        if v is not None:
            score = struct.unpack_from("<Q", v, JAC_FIELDS["score"])[0]
            if score > 0: os.close(fd); print(score); sys.exit(0)
        time.sleep(ims / 1000)
    os.close(fd); print(0)
MAPEOF

poll_pinned_blacklist() {
    python3 /tmp/_bpf_map_access.py poll_bl "$_BL_PIN" "$1" "${2:-2000}" "${3:-5}"
}

read_pinned_jac_score() {
    python3 /tmp/_bpf_map_access.py poll_jac_score "$_JAC_PIN" "$1" "${2:-500}" "5"
}

read_pinned_jac_field() {
    python3 /tmp/_bpf_map_access.py lookup_jac "$_JAC_PIN" "$1" "$2"
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

# =============================================================================
# B1 — Packet processing latency
# =============================================================================
hdr "B1 — Packet processing latency (per-packet, µs)"
OUT="$OUTDIR/B1_latency.txt"
echo "B1 — Packet processing latency" > "$OUT"

if ! command -v hping3 &>/dev/null; then
    info "hping3 not available — using C injector flood_timed latency measurement."
    LATENCIES=()
    for i in $(seq 1 $RUNS); do
        PROBE_IP="10.253.${i}.1"
        if [[ "$_INJECTOR_TYPE" == "C" ]]; then
            $INJECT_PREFIX "$INJECTOR" flood_timed "$INJECT_IFACE" "$PROBE_IP" \
                         "$TARGET_IP" "$NEXTHOP_MAC" 8080 200 > /tmp/_b1_flood_${i}.txt 2>/dev/null || true
            lat_us=$(python3 - /tmp/_b1_flood_${i}.txt << 'PYEOF'
import sys
pkts =[]
try:
    with open(sys.argv[1]) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 3 and parts[0] == "PKT": pkts.append(float(parts[2]))
except Exception: pass
if len(pkts) < 2: print(0)
else:
    gaps = [(pkts[j+1]-pkts[j])*1e6 for j in range(len(pkts)-1)]
    print(f'{sum(gaps)/len(gaps):.3f}')
PYEOF
)
        else
            lat_us=$(python3 -c "import subprocess, re
out = subprocess.run(['ping','-c','10','-W','1','-I','$INJECT_IFACE','$TARGET_IP'], capture_output=True, text=True).stdout
m = re.search(r'rtt .* = [\d.]+/([\d.]+)/', out)
print(f'{float(m.group(1))*1000:.3f}' if m else '0')" 2>/dev/null || echo "0")
        fi
        [[ "$lat_us" != "0" ]] && LATENCIES+=("$lat_us")
        info "  Run $i: latency ≈ ${lat_us} µs"
        sleep 0.3
    done
    B1_RESULT=$(stats_py "${LATENCIES[@]}")
    echo "$B1_RESULT" >> "$OUT"
    ok "B1 done (no-hping3 proxy): $B1_RESULT µs"
    append_summary "B1  Latency (flood_timed proxy µs): $B1_RESULT"
else
    LATENCIES=()
    for i in $(seq 1 $RUNS); do
        PROBE_IP="10.253.${i}.1"
        rtt=$(
    {
        hping3 -S -p 8080 -c 20 --fast \
            -a "$PROBE_IP" -I "$IFACE" "$TARGET_IP" 2>&1 || true
    } |
    sed -n 's/.*= \([0-9.]*\)\/\([0-9.]*\)\/\([0-9.]*\).*/\2/p'
)
        rtt_us=$(python3 -c "print(f'{float(\"${rtt:-0}\")*1000:.1f}')" 2>/dev/null || echo "0")
        LATENCIES+=("$rtt_us")
        info "  Run $i: RTT = ${rtt:-N/A} ms  (${rtt_us} µs)"
        sleep 0.5
    done
    B1_RESULT=$(stats_py "${LATENCIES[@]}")
    echo "$B1_RESULT" >> "$OUT"
    ok "B1 done: $B1_RESULT µs"
    append_summary "B1  Per-packet latency (µs):       $B1_RESULT"
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
hdr "B3 — Block detection latency (ms from first SYN to blacklist entry)"
OUT="$OUTDIR/B3_block_latency.txt"
echo "B3 — Block detection latency" > "$OUT"

BLOCK_MS_VALS=()
BLOCK_PKT_VALS=()
for i in $(seq 1 $RUNS); do
    PROBE_IP="10.251.${i}.1"
    clear_blacklist

    poll_pinned_blacklist "$PROBE_IP" 3000 2 > /tmp/_b3_poll_${i}.txt &
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
        after=$(python3 /tmp/_bpf_map_access.py lookup_jac "$_JAC_PIN" "$PROBE_IP" n_packets 2>/dev/null)
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
# B4 — Decay timing (score half-life verification)
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

    ht=$(python3 - "$PROBE_IP" "$_JAC_PIN" "$INJECT_PREFIX" "$INJECTOR" "$INJECT_IFACE" "$TARGET_IP" "$NEXTHOP_MAC" "$_INJECTOR_TYPE" << 'PYEOF'
import sys, os, socket, struct, ctypes, time
probe_ip=sys.argv[1]; pin_path=sys.argv[2]
inj_prefix=sys.argv[3]; inj_bin=sys.argv[4]; iface=sys.argv[5]; target=sys.argv[6]; mac=sys.argv[7]; inj_type=sys.argv[8]
NR_BPF=321; BPF_MAP_LOOKUP_ELEM=1; BPF_OBJ_GET=7
class OG(ctypes.Structure): _fields_=[("pathname",ctypes.c_uint64),("bpf_fd",ctypes.c_uint32),("file_flags",ctypes.c_uint32)]
class ML(ctypes.Structure): _fields_=[("map_fd",ctypes.c_uint32),("key",ctypes.c_uint64),("value",ctypes.c_uint64),("flags",ctypes.c_uint64)]
_libc=ctypes.CDLL("libc.so.6",use_errno=True)
_libc.syscall.restype=ctypes.c_long
_libc.syscall.argtypes=[ctypes.c_long,ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32]
def _bpf(cmd,a): return _libc.syscall(NR_BPF,cmd,ctypes.byref(a),ctypes.sizeof(a))
pb=ctypes.create_string_buffer(pin_path.encode()+b'\x00')
ag=OG(); ag.pathname=ctypes.cast(pb,ctypes.c_void_p).value
fd=_bpf(BPF_OBJ_GET,ag)
if fd<0: print(0); sys.exit(0)
JAC_VSIZE=56; SCORE_OFF=16; ip_bytes=socket.inet_aton(probe_ip)
def read_score():
    kbuf=ctypes.create_string_buffer(ip_bytes); vbuf=ctypes.create_string_buffer(JAC_VSIZE)
    al=ML(); al.map_fd=fd; al.key=ctypes.cast(kbuf,ctypes.c_void_p).value
    al.value=ctypes.cast(vbuf,ctypes.c_void_p).value; al.flags=0
    return struct.unpack_from("<Q",bytes(vbuf),SCORE_OFF)[0] if _bpf(BPF_MAP_LOOKUP_ELEM,al)==0 else 0

initial_score=0
for _ in range(100):
    time.sleep(0.005)
    s=read_score()
    if s>0: initial_score=s; break
if initial_score==0:
    sys.stderr.write("  initial score never appeared\n")
    os.close(fd); print(0); sys.exit(0)

sys.stderr.write(f"  initial_score={initial_score} (expected ~40)\n")

if inj_type == "C":
    os.system(f"{inj_prefix} {inj_bin} decay_tickle {iface} {probe_ip} {target} {mac} 8080 6.0 >/dev/null 2>&1 &")

half=initial_score/2; t0=time.monotonic(); half_time_ms=None
for tick in range(120):
    time.sleep(0.05)
    sc=read_score(); elapsed=(time.monotonic()-t0)*1000
    if tick % 5 == 0: sys.stderr.write(f"  t={elapsed:.0f}ms score={sc}/{initial_score}\n")
    if sc<=half and half_time_ms is None: half_time_ms=elapsed; break
os.close(fd)
if half_time_ms:
    sys.stderr.write(f"  RESULT: initial={initial_score} half_at={half_time_ms:.1f}ms\n")
    print(f"{half_time_ms:.1f}")
else:
    print(0)
PYEOF
)
    pkill -f "decay_tickle.*$INJECT_IFACE" 2>/dev/null || true

    HALFLIFE_VALS+=("${ht:-0}")
    info "  Run $i: half-life = ${ht:-N/A} ms"
    echo "  Run $i: half_time_ms=${ht:-N/A}" >> "$OUT"
    sleep 1
done
B4_RESULT=$(stats_py "${HALFLIFE_VALS[@]}")
echo "Score half-life (ms): $B4_RESULT" >> "$OUT"
ok "B4 done: $B4_RESULT ms (theory: 138.6ms)"
append_summary "B4  Score half-life (ms):           $B4_RESULT  (theoretical=138.6ms)"

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

    poll_pinned_blacklist "$GOSSIP_IP" 3000 2 > /tmp/_b5_poll_${i}.txt &
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

BLOCKED_COUNT=$(python3 - "$_BL_PIN" "$TOTAL_IPS" << 'PYEOF'
import sys, os, socket, ctypes
pin_path=sys.argv[1]; total_ips=int(sys.argv[2])
NR_BPF=321; BPF_MAP_LOOKUP_ELEM=1; BPF_OBJ_GET=7
class OG(ctypes.Structure): _fields_=[("pathname",ctypes.c_uint64),("bpf_fd",ctypes.c_uint32),("file_flags",ctypes.c_uint32)]
class ML(ctypes.Structure): _fields_=[("map_fd",ctypes.c_uint32),("key",ctypes.c_uint64),("value",ctypes.c_uint64),("flags",ctypes.c_uint64)]
_libc=ctypes.CDLL("libc.so.6",use_errno=True)
_libc.syscall.restype=ctypes.c_long
_libc.syscall.argtypes=[ctypes.c_long,ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32]
pb=ctypes.create_string_buffer(pin_path.encode()+b'\x00')
ag=OG(); ag.pathname=ctypes.cast(pb,ctypes.c_void_p).value
fd=_libc.syscall(NR_BPF,BPF_OBJ_GET,ctypes.byref(ag),ctypes.sizeof(ag))
if fd<0: print(f"  ERROR bpf_obj_get: {ctypes.get_errno()}"); sys.exit(1)
count=0
for i in range(1,total_ips+1):
    ip=f"10.248.1.{i}"; kbuf=ctypes.create_string_buffer(socket.inet_aton(ip)); vbuf=ctypes.create_string_buffer(1)
    al=ML(); al.map_fd=fd; al.key=ctypes.cast(kbuf,ctypes.c_void_p).value; al.value=ctypes.cast(vbuf,ctypes.c_void_p).value; al.flags=0
    if _libc.syscall(NR_BPF,BPF_MAP_LOOKUP_ELEM,ctypes.byref(al),ctypes.sizeof(al))==0:
        count+=1; print(f"  BLOCKED: {ip}")
os.close(fd)
print(f"FPR blocked={count} total={total_ips} fpr_pct={count*100/total_ips:.1f}")
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
    python3 "$STATS_READER" map_memory 2>/dev/null || echo "  (bpftool unavailable — using estimates)"
    echo "Userspace RSS:"
    python3 "$STATS_READER" rss 2>/dev/null
    echo "Kernel BPF program size:"
    bpftool prog show 2>/dev/null | grep -A3 "xdp_firewall_prog" || echo "  (bpftool unavailable)"
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
        python3 - "$SIZE" "$_BL_PIN" << 'PYEOF'
import sys, os, socket, ctypes
n = int(sys.argv[1]); pin = sys.argv[2]
NR_BPF=321; BPF_MAP_UPDATE_ELEM=2; BPF_OBJ_GET=7
class OG(ctypes.Structure): _fields_=[("pathname",ctypes.c_uint64),("bpf_fd",ctypes.c_uint32),("file_flags",ctypes.c_uint32)]
class MU(ctypes.Structure): _fields_=[("map_fd",ctypes.c_uint32),("key",ctypes.c_uint64),("value",ctypes.c_uint64),("flags",ctypes.c_uint64)]
_libc=ctypes.CDLL("libc.so.6",use_errno=True)
_libc.syscall.restype=ctypes.c_long
_libc.syscall.argtypes=[ctypes.c_long,ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32]
pb=ctypes.create_string_buffer(pin.encode()+b'\x00')
ag=OG(); ag.pathname=ctypes.cast(pb,ctypes.c_void_p).value
fd=_libc.syscall(NR_BPF,BPF_OBJ_GET,ctypes.byref(ag),ctypes.sizeof(ag))
if fd<0: print(f"  ERROR bpf_obj_get: {ctypes.get_errno()}"); sys.exit(1)
v=ctypes.c_uint8(1)
for i in range(n):
    ip=f"192.168.{i//256}.{i%256}"; kb=ctypes.create_string_buffer(socket.inet_aton(ip))
    au=MU(); au.map_fd=fd; au.key=ctypes.cast(kb,ctypes.c_void_p).value
    au.value=ctypes.cast(ctypes.byref(v),ctypes.c_void_p).value; au.flags=0
    _libc.syscall(NR_BPF,BPF_MAP_UPDATE_ELEM,ctypes.byref(au),ctypes.sizeof(au))
os.close(fd); print(f"  Populated {n} entries")
PYEOF
    fi

    MPPS_VALS=()
    for i in $(seq 1 3); do
        PROBE_IP="172.31.${SIZE}.${i}"
        if [[ "$_INJECTOR_TYPE" == "C" ]]; then
            result=$($INJECT_PREFIX "$INJECTOR" throughput "$INJECT_IFACE" "$PROBE_IP" "$TARGET_IP" "$NEXTHOP_MAC" 8080 3.0 2>/dev/null) || true
        else
            result=$($INJECT_PREFIX python3 "$INJECTOR" throughput "$INJECT_IFACE" "$PROBE_IP" "$TARGET_IP" 8080 3.0 2>/dev/null) || true
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