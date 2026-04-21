/*
 * xdp_fw.c — Adaptive XDP Firewall
 *
 * Architecture:
 *   - score     : raw accumulator. SYN=+10, ACK=-2, RST=+5. Time-decays.
 *   - EWMA      : tracks the SCORE PEAK per observation window.
 *                 "What scores does this IP normally reach?" — not the
 *                 instantaneous score, which decays between checks.
 *   - threshold : SRTT + 4*RTTVAR applied to the score peak SAMPLE.
 *                 Floor ensures a fresh IP can still be blocked fast.
 *
 * Bug fixes vs original:
 *   FIX 1 (CRITICAL) — check-then-update ordering
 *     Original checked peak > threshold AFTER updating EWMA with that same
 *     peak. The threshold always rose at least as fast as the peak, so a
 *     sustained sub-floor attack (score < 50) could ride the EWMA upward
 *     indefinitely and never trigger the adaptive path.
 *     Fix: snapshot prev_srtt/prev_rttvar/prev_peak before the EWMA update,
 *     then evaluate the threshold against the PREVIOUS window's values.
 *
 *   FIX 2 (MEDIUM) — rttvar minimum floor in fixed-point space
 *     Original floored rttvar at 1 FP unit (= 0.01 raw score).
 *     4 * 1 / 100 = 0 in integer division, so the K*RTTVAR safety margin
 *     vanished entirely once rttvar converged near-zero.
 *     Fix: floor rttvar at FP/4 (= 25 FP units = 0.25 raw), ensuring
 *     K*rttvar always contributes at least 4*25/100 = 1 to the raw threshold.
 *
 *   FIX 3 (MINOR) — window_start not reset on floor-path block
 *     Original only reset window_start in the adaptive-path block, not the
 *     floor-path block. A manually-unblocked IP reconnecting within the same
 *     500ms window could trigger an immediate EWMA evaluation with only a
 *     few packets of history.
 *     Fix: reset window_start = 0 in the floor path as well.
 *
 * BPF verifier: ALL division is u64/u64. No signed division anywhere.
 */

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/in.h>

/* ── Tuning ── */
#define JACOBSON_ALPHA_RECIP  8ULL    /* α = 1/8  */
#define JACOBSON_BETA_RECIP   4ULL    /* β = 1/4  */
#define JACOBSON_K            4ULL    /* threshold = SRTT + 4*RTTVAR */
#define WARMUP_PACKETS        5ULL    /* packets before adaptive mode */
#define FLOOR_THRESHOLD       50ULL   /* raw score floor — always block above this */
#define DECAY_LAMBDA          5ULL    /* score decay: half-life ~140ms silence */
#define W_SYN_BASE            10ULL
#define W_ACK_BASE            2ULL
#define W_RST                 5ULL
#define ELEVATED_SRTT         200ULL  /* raw srtt above which weights tighten */
#define W_SYN_ELEVATED        20ULL
#define W_ACK_ELEVATED        1ULL
#define SCORE_CEIL            10000ULL
#define FP                    100ULL  /* fixed-point scale for SRTT/RTTVAR */
#define EWMA_WINDOW_NS        500000000ULL  /* 500ms EWMA sample window */
/* FIX 2: rttvar minimum in FP units. 4*25/100 = 1 raw-unit K*rttvar floor. */
#define RTTVAR_MIN_FP         (FP / 4ULL)   /* 25 FP units = 0.25 raw score */

struct jacobson_t {
    u64 srtt;           /* smoothed score-peak ×FP */
    u64 rttvar;         /* mean deviation ×FP */
    u64 score;          /* current raw score (decays) */
    u64 peak;           /* max score seen in current window */
    u64 last_ts_ns;     /* last packet time */
    u64 window_start;   /* start of current EWMA sample window */
    u64 n_packets;      /* total packets (warmup counter) */
};

struct event_data_t {
    u32 saddr;
    u64 score;
    u64 threshold;
    u64 srtt;
    u64 rttvar;
};

BPF_HASH(blacklist, u32, u8);
BPF_HASH(jac_map,   u32, struct jacobson_t);
BPF_PERF_OUTPUT(events);

/* Per-CPU packet counters — read by monitor.py at 1 Hz for live pps display.
 * Using BPF_PERCPU_ARRAY avoids any atomic contention; the reader sums CPUs.
 * Index 0 = total packets seen, index 1 = packets dropped (XDP_DROP). */
enum { CTR_TOTAL = 0, CTR_DROP = 1, CTR_COUNT = 2 };
BPF_PERCPU_ARRAY(pkt_counters, u64, CTR_COUNT);

static __always_inline int parse_ip_tcp(
    struct xdp_md *ctx, struct iphdr **ip, struct tcphdr **tcp)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth+1) > data_end)        return 0;
    if (eth->h_proto != bpf_htons(0x0800)) return 0;
    *ip = (void *)(eth+1);
    if ((void *)(*ip+1) > data_end)        return 0;
    if ((*ip)->protocol != IPPROTO_TCP)    return 0;
    *tcp = (void *)(*ip+1);
    if ((void *)(*tcp+1) > data_end)       return 0;
    return 1;
}

static __always_inline u64 uclamp(u64 v, u64 lo, u64 hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}
static __always_inline u64 udiff(u64 a, u64 b) {
    return a >= b ? a - b : b - a;
}

int xdp_firewall_prog(struct xdp_md *ctx)
{
    struct iphdr  *iph;
    struct tcphdr *tcp;
    if (!parse_ip_tcp(ctx, &iph, &tcp)) return XDP_PASS;

    /* Count every TCP packet that enters the scoring pipeline */
    u32 ctr_idx = CTR_TOTAL;
    u64 *ctr = pkt_counters.lookup(&ctr_idx);
    if (ctr) (*ctr)++;

    u32 saddr = iph->saddr;

    /* Stage 1: blacklist — count the drop for pps stats */
    u8 *blocked = blacklist.lookup(&saddr);
    if (blocked) {
        u32 bl_drop = CTR_DROP;
        u64 *bdctr = pkt_counters.lookup(&bl_drop);
        if (bdctr) (*bdctr)++;
        return XDP_DROP;
    }

    /* Stage 2: get/init state */
    struct jacobson_t *j, zero = {};
    j = jac_map.lookup_or_try_init(&saddr, &zero);
    if (!j) return XDP_PASS;

    u64 now = bpf_ktime_get_ns();

    /* Stage 3: time-decay on score
     * score(t) ≈ score(t0) × (1000 - λ×Δt_ms) / 1000
     * All u64 — no signed division.
     */
    if (j->last_ts_ns > 0 && now > j->last_ts_ns) {
        u64 dt_ms = (now - j->last_ts_ns) / 1000000ULL;
        if (dt_ms > 1000) dt_ms = 1000;
        u64 df = dt_ms * DECAY_LAMBDA;
        if (df > 1000) df = 1000;
        j->score = (j->score * (1000ULL - df)) / 1000ULL;
    }
    j->last_ts_ns = now;
    j->n_packets++;

    /* Stage 4: adaptive weights */
    u64 w_syn = (j->srtt / FP > ELEVATED_SRTT) ? W_SYN_ELEVATED : W_SYN_BASE;
    u64 w_ack = (j->srtt / FP > ELEVATED_SRTT) ? W_ACK_ELEVATED : W_ACK_BASE;

    /* Stage 5: score update */
    if (tcp->syn && !tcp->ack) {
        j->score += w_syn;
    } else if (tcp->ack && !tcp->syn) {
        j->score = (j->score >= w_ack) ? j->score - w_ack : 0;
    } else if (tcp->rst) {
        j->score += W_RST;
    }
    j->score = uclamp(j->score, 0, SCORE_CEIL);

    /* Stage 6: fast-path hard floor block (no warmup needed)
     * Catches fresh IPs doing a large burst before EWMA calibrates.
     *
     * FIX 3: also reset window_start here so a manually-unblocked IP
     * starts a clean 500ms window rather than inheriting an already-
     * elapsed one that could fire an immediate EWMA eval.
     */
    if (j->score > FLOOR_THRESHOLD) {
        struct event_data_t evt = {};
        evt.saddr     = saddr;
        evt.score     = j->score;
        evt.threshold = FLOOR_THRESHOLD;
        evt.srtt      = j->srtt / FP;
        evt.rttvar    = j->rttvar / FP;
        events.perf_submit(ctx, &evt, sizeof(evt));
        u8 one = 1;
        blacklist.update(&saddr, &one);
        j->score        = 0;
        j->peak         = 0;
        j->window_start = 0;   /* FIX 3: was missing in original */
        u32 drop_idx0 = CTR_DROP;
        u64 *dctr0 = pkt_counters.lookup(&drop_idx0);
        if (dctr0) (*dctr0)++;
        return XDP_DROP;
    }

    /* Stage 7: EWMA window update
     *
     * Every EWMA_WINDOW_NS (500ms), take the peak score of that window
     * as the sample and feed it into Jacobson EWMA.
     *
     * FIX 1: check-then-update ordering.
     *
     * Original order:
     *   1. update EWMA(srtt, rttvar) using current_peak
     *   2. compute threshold from NEW srtt/rttvar
     *   3. check current_peak > threshold
     *
     * Problem: threshold is computed from the EWMA that just absorbed
     * current_peak. For a sustained constant-rate attack the threshold
     * chases the peak and the check NEVER fires.
     *
     * Fixed order:
     *   1. snapshot prev_srtt, prev_rttvar, prev_peak (last window)
     *   2. update EWMA(srtt, rttvar) using current_peak
     *   3. compute threshold from PREV srtt/rttvar (before absorption)
     *   4. check prev_peak > threshold
     *
     * Now the threshold reflects the baseline BEFORE the attack window,
     * so an anomalous burst is always evaluated against the calm baseline.
     */
    if (j->score > j->peak) j->peak = j->score;

    if (j->window_start == 0) j->window_start = now;

    if (now - j->window_start >= EWMA_WINDOW_NS && j->n_packets > WARMUP_PACKETS) {
        u64 sample = j->peak * FP;   /* ×FP, u64 */

        /* Snapshot PREVIOUS window's EWMA state for the threshold check */
        u64 prev_srtt   = j->srtt;
        u64 prev_rttvar = j->rttvar;
        u64 prev_peak   = j->peak;

        /* Update EWMA with this window's sample */
        if (j->srtt == 0) {
            j->srtt   = sample;
            j->rttvar = sample / 2ULL;
            /* FIX 2: floor rttvar at RTTVAR_MIN_FP, not 1 */
            if (j->rttvar < RTTVAR_MIN_FP) j->rttvar = RTTVAR_MIN_FP;
        } else {
            u64 diff  = udiff(j->srtt, sample);
            j->rttvar = j->rttvar - j->rttvar / JACOBSON_BETA_RECIP
                      + diff      / JACOBSON_BETA_RECIP;
            j->srtt   = j->srtt   - j->srtt   / JACOBSON_ALPHA_RECIP
                      + sample    / JACOBSON_ALPHA_RECIP;
            /* FIX 2: raise rttvar floor to guarantee K*rttvar > 0 after /FP */
            if (j->rttvar < RTTVAR_MIN_FP) j->rttvar = RTTVAR_MIN_FP;
        }

        j->srtt   = uclamp(j->srtt,   0,            SCORE_CEIL * FP);
        j->rttvar = uclamp(j->rttvar, RTTVAR_MIN_FP, SCORE_CEIL * FP);

        /* FIX 1: evaluate against PREVIOUS window's baseline.
         *
         * Cold-start case (prev_srtt == 0): we have no baseline yet —
         * the very first EWMA observation is used to initialise, not to judge.
         * Skip the check; let the floor handle any burst on the first window.
         */
        if (prev_srtt > 0) {
            /* Compute threshold from prev window's EWMA (before absorption) */
            u64 threshold_fp = prev_srtt + JACOBSON_K * prev_rttvar;
            u64 threshold    = threshold_fp / FP;

            if (prev_peak > threshold && threshold > 0) {
                struct event_data_t evt = {};
                evt.saddr     = saddr;
                evt.score     = prev_peak;
                evt.threshold = threshold;
                evt.srtt      = prev_srtt   / FP;
                evt.rttvar    = prev_rttvar / FP;
                events.perf_submit(ctx, &evt, sizeof(evt));
                u8 one = 1;
                blacklist.update(&saddr, &one);
                j->score        = 0;
                j->peak         = 0;
                j->window_start = now;
                u32 drop_idx1 = CTR_DROP;
                u64 *dctr1 = pkt_counters.lookup(&drop_idx1);
                if (dctr1) (*dctr1)++;
                return XDP_DROP;
            }
        }

        /* Reset window for next sample */
        j->window_start = now;
        j->peak = 0;
    }

    return XDP_PASS;
}
