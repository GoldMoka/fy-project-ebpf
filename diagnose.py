#!/usr/bin/env python3
"""
diagnose.py — Run this on device 1 alongside the firewall.
Attaches a second XDP probe that prints every TCP packet it sees,
so you can confirm what (if anything) is reaching the XDP layer.

Usage:  sudo python3 diagnose.py --iface eno1 [--filter-src 172.16.44.78]
"""
import sys, socket, struct, signal, argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--iface",      default="eno1")
parser.add_argument("--filter-src", default="",
                    help="Only print packets from this source IP")
args = parser.parse_args()

try:
    from bcc import BPF
except ImportError:
    sys.exit("[✗] BCC not found. Run install_and_run.sh first.")

FILTER_INT = 0
if args.filter_src:
    FILTER_INT = struct.unpack("I", socket.inet_aton(args.filter_src))[0]

BPF_SRC = r"""
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/in.h>

struct pkt_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  flags;   /* SYN=0x02 ACK=0x10 RST=0x04 FIN=0x01 */
};

BPF_PERF_OUTPUT(pkts);

int xdp_diagnose(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth+1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(0x0800)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth+1);
    if ((void *)(ip+1) > data_end) return XDP_PASS;

    /* Pass non-TCP through silently */
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = (void *)(ip+1);
    if ((void *)(tcp+1) > data_end) return XDP_PASS;

    FILTER_CHECK

    struct pkt_t p = {};
    p.saddr = ip->saddr;
    p.daddr = ip->daddr;
    p.sport = bpf_ntohs(tcp->source);
    p.dport = bpf_ntohs(tcp->dest);
    p.flags = (tcp->syn  ? 0x02 : 0)
            | (tcp->ack  ? 0x10 : 0)
            | (tcp->rst  ? 0x04 : 0)
            | (tcp->fin  ? 0x01 : 0);
    pkts.perf_submit(ctx, &p, sizeof(p));
    return XDP_PASS;
}
"""

# Inject optional source-IP filter
if FILTER_INT:
    check = f"if (ip->saddr != {FILTER_INT}U) return XDP_PASS;"
else:
    check = "/* no filter */"
BPF_SRC = BPF_SRC.replace("FILTER_CHECK", check)

print(f"[*] Compiling diagnostic XDP probe...")
b = BPF(text=BPF_SRC, cflags=["-w"])
fn = b.load_func("xdp_diagnose", BPF.XDP)

print(f"[*] Attaching to {args.iface} in GENERIC mode...")
try:
    b.attach_xdp(args.iface, fn, BPF.XDP_FLAGS_SKB_MODE)
except Exception as e:
    print(f"[!] Attach failed: {e}")
    print(f"    If the firewall is already attached in generic mode, detach it first")
    print(f"    or run the firewall with --xdp-mode native and this in generic.")
    sys.exit(1)

filter_msg = f" (filtering src={args.filter_src})" if args.filter_src else " (all TCP)"
print(f"[+] Listening for TCP packets on {args.iface}{filter_msg}")
print(f"    Columns: SRC_IP:PORT → DST_IP:PORT  FLAGS  (S=SYN A=ACK R=RST F=FIN)")
print(f"    Press Ctrl+C to stop.\n")

pkt_count = 0

def flag_str(f):
    s = ""
    if f & 0x02: s += "S"
    if f & 0x10: s += "A"
    if f & 0x04: s += "R"
    if f & 0x01: s += "F"
    return s or "?"

def handle(cpu, data, size):
    global pkt_count
    p = b["pkts"].event(data)
    src = socket.inet_ntoa(struct.pack("I", p.saddr))
    dst = socket.inet_ntoa(struct.pack("I", p.daddr))
    fl  = flag_str(p.flags)
    pkt_count += 1
    print(f"  #{pkt_count:4d}  {src:15s}:{p.sport:<5d}  →  {dst:15s}:{p.dport:<5d}  [{fl}]")

b["pkts"].open_perf_buffer(handle)

def shutdown(s, f):
    print(f"\n[+] Detaching... ({pkt_count} packets seen)")
    b.remove_xdp(args.iface, 0)
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)

while True:
    b.perf_buffer_poll(timeout=200)
