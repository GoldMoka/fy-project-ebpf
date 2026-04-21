#!/usr/bin/env python3
import sys, socket, struct, time, random, threading, os

NEXTHOP_MAC = bytes(int(x,16) for x in "be:46:ff:cc:d9:8c".split(':'))

def cksum(data):
    if len(data) % 2: data += b'\x00'
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xffff)
    return (~(s + (s >> 16))) & 0xffff

def tcp_pkt(src_ip, dst_ip, sport, dport, flags, seq=None):
    fb = (0x02 if 'S' in flags else 0) | (0x10 if 'A' in flags else 0)        | (0x04 if 'R' in flags else 0) | (0x01 if 'F' in flags else 0)
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
        return b'\x00'*6

def raw_sock(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    s.bind((iface, 0))
    return s

def eth_hdr(iface):
    return NEXTHOP_MAC + src_mac(iface) + b'\x08\x00'

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
