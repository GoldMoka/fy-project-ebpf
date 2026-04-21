/*
 * _bench_inject.c — High-performance raw-socket packet injector
 *
 * Uses sendmmsg(2) to batch 64 frames per syscall, removing the Python
 * interpreter overhead that capped _bench_inject.py at ~200k pps.
 * On a single core over a veth pair this reliably reaches 1–3 Mpps.
 *
 * Usage:
 *   _bench_inject <mode> <iface> <src_ip> <dst_ip> <dst_mac> <dport> [extra]
 *
 * Modes:
 *   throughput <iface> <src> <dst> <dst_mac> <dport> <duration_s>
 *       Blast SYNs as fast as possible for duration_s seconds.
 *       Prints: THROUGHPUT packets_sent=N elapsed_s=F mpps=F
 *
 *   flood_timed <iface> <src> <dst> <dst_mac> <dport> <count>
 *       Send exactly count SYNs, print timestamps for latency analysis.
 *
 *   balanced <iface> <src> <dst> <dst_mac> <dport> <duration_s>
 *       Alternates 2 SYNs + 3 ACKs per burst (score stays below threshold).
 *       Used for B8 CPU overhead and B10 EWMA convergence tests.
 *
 *   false_pos <iface> <src> <dst> <dst_mac> <dport> <bursts> <burst_size> <gap_ms>
 *       Send <bursts> rounds of <burst_size> SYNs then <burst_size> ACKs.
 *       <gap_ms> gap between bursts. Net score stays well below FLOOR_THRESHOLD.
 *       Always exits 0. Used for B6 (false positive rate).
 *
 *   burst_syn <iface> <src> <dst> <dst_mac> <dport> <count>
 *       Send exactly count SYNs in one sendmmsg batch (single syscall).
 *       Near-simultaneous delivery minimises inter-packet decay. Used by B4.
 *
 *   decay_tickle <iface> <src> <dst> <dst_mac> <dport> <duration_s>
 *       Send one SYN+ACK every 20ms for duration_s seconds.
 *       Triggers XDP Stage 3 decay without changing the score (Stage 5).
 *       Used by B4 alongside benchmark.sh's jac_map polling loop.
 *
 * Build:
 *   gcc -O2 -o _bench_inject _bench_inject.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define BATCH_SIZE   64
#define FRAME_SIZE   64

static uint16_t cksum(const void *buf, int len) {
    const uint16_t *p = buf;
    uint32_t s = 0;
    while (len > 1) { s += *p++; len -= 2; }
    if (len) s += *(uint8_t *)p;
    s = (s >> 16) + (s & 0xffff);
    s += (s >> 16);
    return (uint16_t)~s;
}

static uint16_t tcp_cksum(uint32_t saddr, uint32_t daddr, const void *tcp_hdr, int tcp_len) {
    struct { uint32_t s, d; uint8_t z, proto; uint16_t len; } ph;
    ph.s = saddr; ph.d = daddr; ph.z = 0; ph.proto = IPPROTO_TCP; ph.len = htons(tcp_len);
    uint8_t buf[1500];
    memcpy(buf, &ph, sizeof ph);
    memcpy(buf + sizeof ph, tcp_hdr, tcp_len);
    return cksum(buf, sizeof ph + tcp_len);
}

static int build_frame(uint8_t *frame, const uint8_t *src_mac, const uint8_t *dst_mac,
                        uint32_t src_ip, uint32_t dst_ip, uint16_t sport, uint16_t dport,
                        uint8_t flags, uint32_t seq) {
    struct ethhdr *eth = (struct ethhdr *)frame;
    memcpy(eth->h_dest, dst_mac, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_IP);

    struct iphdr *ip = (struct iphdr *)(frame + 14);
    ip->ihl = 5; ip->version = 4; ip->tot_len = htons(40);
    ip->id = htons(rand()); ip->frag_off = 0; ip->ttl = 64;
    ip->protocol = IPPROTO_TCP; ip->saddr = src_ip; ip->daddr = dst_ip;
    ip->check = 0; ip->check = cksum(ip, 20);

    struct tcphdr *tcp = (struct tcphdr *)(frame + 34);
    tcp->source = htons(sport); tcp->dest = htons(dport);
    tcp->seq = htonl(seq); tcp->doff = 5; tcp->th_flags = flags;
    tcp->window = htons(65535); tcp->check = 0;
    tcp->check = tcp_cksum(src_ip, dst_ip, tcp, 20);
    return 54;
}

/* send one packet reusing msgs[0]/iovs[0]/frames[0] */
static void send_one(int sock,
                     struct mmsghdr *msgs, struct iovec *iovs, uint8_t (*frames)[64],
                     const uint8_t *smac, const uint8_t *dmac,
                     uint32_t src_ip, uint32_t dst_ip,
                     uint16_t sport, uint16_t dport, uint8_t flags) {
    int len = build_frame(frames[0], smac, dmac, src_ip, dst_ip,
                          sport, dport, flags, (uint32_t)rand());
    iovs[0].iov_base = frames[0]; iovs[0].iov_len = len;
    msgs[0].msg_hdr.msg_iov = &iovs[0]; msgs[0].msg_hdr.msg_iovlen = 1;
    sendmmsg(sock, msgs, 1, 0);
}

int main(int argc, char **argv) {
    if (argc < 8) {
        fprintf(stderr,
            "Usage: %s <mode> <iface> <src_ip> <dst_ip> <dst_mac> <dport> <extra>\n"
            "Modes: throughput flood_timed balanced false_pos burst_syn decay_tickle\n", argv[0]);
        return 1;
    }
    const char *mode = argv[1];
    const char *iface = argv[2];
    uint32_t src_ip = inet_addr(argv[3]);
    uint32_t dst_ip = inet_addr(argv[4]);
    uint8_t dmac[6], smac[6];
    sscanf(argv[5], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &dmac[0],&dmac[1],&dmac[2],&dmac[3],&dmac[4],&dmac[5]);
    uint16_t dport = (uint16_t)atoi(argv[6]);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return 1; }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return 1; }
    int ifindex = ifr.ifr_ifindex;
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); return 1; }
    memcpy(smac, ifr.ifr_hwaddr.sa_data, 6);

    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_ifindex  = ifindex,
        .sll_protocol = htons(ETH_P_IP)
    };
    bind(sock, (struct sockaddr *)&sll, sizeof(sll));

    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec   iovs[BATCH_SIZE];
    uint8_t        frames[BATCH_SIZE][64];
    memset(msgs, 0, sizeof(msgs));

    /* ── throughput ── */
    if (strcmp(mode, "throughput") == 0) {
        double duration = atof(argv[7]);
        for (int i = 0; i < BATCH_SIZE; i++) {
            int len = build_frame(frames[i], smac, dmac, src_ip, dst_ip,
                                  (uint16_t)(10000+i), dport, 0x02, rand());
            iovs[i].iov_base = frames[i]; iovs[i].iov_len = len;
            msgs[i].msg_hdr.msg_iov = &iovs[i]; msgs[i].msg_hdr.msg_iovlen = 1;
        }
        long long sent = 0;
        struct timespec start, now;
        clock_gettime(CLOCK_MONOTONIC, &start);
        while (1) {
            sendmmsg(sock, msgs, BATCH_SIZE, 0);
            sent += BATCH_SIZE;
            clock_gettime(CLOCK_MONOTONIC, &now);
            double e = (now.tv_sec-start.tv_sec)+(now.tv_nsec-start.tv_nsec)*1e-9;
            if (e >= duration) break;
        }
        double elapsed = (now.tv_sec-start.tv_sec)+(now.tv_nsec-start.tv_nsec)*1e-9;
        printf("THROUGHPUT packets_sent=%lld elapsed_s=%.4f mpps=%.4f\n",
               sent, elapsed, sent/elapsed/1e6);

    /* ── flood_timed ── */
    } else if (strcmp(mode, "flood_timed") == 0) {
        int count = atoi(argv[7]);
        uint16_t sport = 31337;
        for (int i = 0; i < count; i++) {
            int len = build_frame(frames[0], smac, dmac, src_ip, dst_ip,
                                  sport, dport, 0x02, rand());
            iovs[0].iov_base = frames[0]; iovs[0].iov_len = len;
            msgs[0].msg_hdr.msg_iov = &iovs[0]; msgs[0].msg_hdr.msg_iovlen = 1;
            sendmmsg(sock, msgs, 1, 0);
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            printf("PKT %d %lld.%09ld\n", i, (long long)ts.tv_sec, ts.tv_nsec);
        }
        fflush(stdout);

    /* ── balanced ── */
    } else if (strcmp(mode, "balanced") == 0) {
        double duration = atof(argv[7]);
        uint16_t sport = (uint16_t)(rand() % 50000 + 10000);
        uint8_t burst[5][64];
        struct iovec b_iovs[5];
        struct mmsghdr b_msgs[5];
        memset(b_msgs, 0, sizeof(b_msgs));
        for (int j = 0; j < 2; j++) {
            int len = build_frame(burst[j], smac, dmac, src_ip, dst_ip,
                                  sport, dport, 0x02, rand());
            b_iovs[j].iov_base = burst[j]; b_iovs[j].iov_len = len;
            b_msgs[j].msg_hdr.msg_iov = &b_iovs[j]; b_msgs[j].msg_hdr.msg_iovlen = 1;
        }
        for (int j = 2; j < 5; j++) {
            int len = build_frame(burst[j], smac, dmac, src_ip, dst_ip,
                                  sport, dport, 0x10, rand());
            b_iovs[j].iov_base = burst[j]; b_iovs[j].iov_len = len;
            b_msgs[j].msg_hdr.msg_iov = &b_iovs[j]; b_msgs[j].msg_hdr.msg_iovlen = 1;
        }
        struct timespec start, now;
        clock_gettime(CLOCK_MONOTONIC, &start);
        while (1) {
            sendmmsg(sock, b_msgs, 5, 0);
            struct timespec gap = {0, 100000};
            nanosleep(&gap, NULL);
            clock_gettime(CLOCK_MONOTONIC, &now);
            double e = (now.tv_sec-start.tv_sec)+(now.tv_nsec-start.tv_nsec)*1e-9;
            if (e >= duration) break;
        }

    /* ── false_pos ──────────────────────────────────────────────────────────────
     *
     * benchmark.sh call (line 1171-1172):
     *   $INJECT_PREFIX "$INJECTOR" false_pos "$INJECT_IFACE" "$FP_IP" \
     *       "$TARGET_IP" "$NEXTHOP_MAC" 8080 1 4 200
     *
     * argv positions:
     *   [1]=false_pos [2]=iface [3]=src [4]=dst [5]=dst_mac [6]=dport(8080)
     *   [7]=bursts(1) [8]=burst_size(4) [9]=gap_ms(200)
     *
     * Score math: 4 SYNs * +10 = +40, then 4 ACKs * -2 = -8 → net 32
     * 32 < FLOOR_THRESHOLD(50) → no block → correct FPR=0 result
     * ── */
    } else if (strcmp(mode, "false_pos") == 0) {
        if (argc < 10) {
            fprintf(stderr, "false_pos needs <bursts> <burst_size> <gap_ms>\n");
            return 1;
        }
        int bursts     = atoi(argv[7]);
        int burst_size = atoi(argv[8]);
        int gap_ms     = atoi(argv[9]);
        uint16_t sport = (uint16_t)(rand() % 50000 + 10000);

        for (int b = 0; b < bursts; b++) {
            /* SYN burst */
            for (int j = 0; j < burst_size; j++)
                send_one(sock, msgs, iovs, frames, smac, dmac,
                         src_ip, dst_ip, sport, dport, 0x02);
            /* 10ms gap between SYN and ACK phases */
            struct timespec sa_gap = {0, 10000000L};
            nanosleep(&sa_gap, NULL);
            /* ACK burst */
            for (int j = 0; j < burst_size; j++)
                send_one(sock, msgs, iovs, frames, smac, dmac,
                         src_ip, dst_ip, sport, dport, 0x10);
            /* inter-burst gap */
            if (b < bursts - 1 && gap_ms > 0) {
                struct timespec ig = {
                    .tv_sec  = gap_ms / 1000,
                    .tv_nsec = (long)(gap_ms % 1000) * 1000000L
                };
                nanosleep(&ig, NULL);
            }
        }
        /* always exit 0 — benchmark.sh checks blacklist externally */

    /* ── burst_syn ───────────────────────────────────────────────────────────────
     *
     * Send exactly <count> SYN packets from <src_ip> in a single sendmmsg batch
     * (one syscall). Because all frames are submitted together the inter-packet
     * time seen by XDP is sub-microsecond, so Stage 3 decay between consecutive
     * SYNs is negligible and the resulting jac_map score is close to count*W_SYN.
     *
     * Used by B4 to replace the old Python _b4_inject.py loop which had
     * multi-millisecond inter-packet gaps that pre-decayed the score.
     *
     * argv: burst_syn [2]=iface [3]=src [4]=dst [5]=dst_mac [6]=dport [7]=count
     * ── */
    } else if (strcmp(mode, "burst_syn") == 0) {
        int count = atoi(argv[7]);
        if (count < 1 || count > BATCH_SIZE) count = 4;
        uint16_t sport = (uint16_t)(rand() % 50000 + 10000);
        for (int i = 0; i < count; i++) {
            int len = build_frame(frames[i], smac, dmac, src_ip, dst_ip,
                                  sport, dport, 0x02 /* SYN */, rand());
            iovs[i].iov_base = frames[i]; iovs[i].iov_len = len;
            msgs[i].msg_hdr.msg_iov = &iovs[i]; msgs[i].msg_hdr.msg_iovlen = 1;
        }
        sendmmsg(sock, msgs, count, 0);

    /* ── decay_tickle ────────────────────────────────────────────────────────────
     *
     * benchmark.sh B4 section injects 4 SYNs via the C injector burst_syn mode,
     * then polls jac_map score every 50ms waiting for it to halve. But xdp_fw.c
     * only applies decay when a packet arrives (Stage 3). Without more packets
     * the map value is frozen forever — passive polling never sees it drop.
     *
     * This mode sends one SYN+ACK (flags=0x12) every 20ms, forcing XDP to run
     * Stage 3 (decay) WITHOUT touching the score in Stage 5.
     *
     * Why SYN+ACK and NOT plain ACK:
     *   xdp_fw.c Stage 5 checks:
     *     if (syn && !ack)  -> score += W_SYN   (+10 or +20)
     *     if (ack && !syn)  -> score -= W_ACK   (-2 or -1)   ← plain ACK hits this
     *     if (rst)          -> score += W_RST   (+5)
     *   SYN+ACK (syn=1, ack=1) satisfies NEITHER the first NOR the second branch,
     *   so the score is untouched. Only Stage 3 exponential decay fires.
     *   This gives a clean measurement of the decay curve alone.
     *
     * argv: decay_tickle [2]=iface [3]=src [4]=dst [5]=dst_mac [6]=dport [7]=duration_s
     * ── */
    } else if (strcmp(mode, "decay_tickle") == 0) {
        double duration = atof(argv[7]);
        uint16_t sport = (uint16_t)(rand() % 50000 + 10000);
        struct timespec tickle_interval = {0, 20000000L}; /* 20ms */
        struct timespec start, now;
        clock_gettime(CLOCK_MONOTONIC, &start);
        while (1) {
            send_one(sock, msgs, iovs, frames, smac, dmac,
                     src_ip, dst_ip, sport, dport, 0x12 /* SYN+ACK: triggers decay only, no score delta */);
            nanosleep(&tickle_interval, NULL);
            clock_gettime(CLOCK_MONOTONIC, &now);
            double e = (now.tv_sec-start.tv_sec)+(now.tv_nsec-start.tv_nsec)*1e-9;
            if (e >= duration) break;
        }

    } else {
        fprintf(stderr, "Unknown mode: %s\n", mode);
        fprintf(stderr, "Modes: throughput flood_timed balanced false_pos burst_syn decay_tickle\n");
        return 1;
    }

    close(sock);
    return 0;
}
