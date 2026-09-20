#pragma once

// Fixed-base scalar multiplication for the vanity search: the precomputed
// table (layout and generation), signed fixed-window multiplication, and the
// per-thread batched derivation of public keys from seeds. Shared by the
// search backend and the unit tests.

#include <cstddef>
#include <cstdint>

#include "ed25519.cuh"

// Width in bits of the fixed-base comb window. Each key costs one point
// addition per window position; the precomputed table has 2^(W-1) + 1 entries
// per position, so a larger window trades memory (and cache footprint) for
// fewer additions.
#ifndef VANISSH_CUDA_WINDOW
#define VANISSH_CUDA_WINDOW 18
#endif

// Keys derived per thread between inversions. One field inversion (~265
// multiplications) is shared by kBatch keys at a cost of three extra
// multiplications per key (Montgomery's trick), with the per-key points parked
// in local memory meanwhile.
#ifndef VANISSH_CUDA_BATCH
#define VANISSH_CUDA_BATCH 32
#endif

namespace ed25519 {

constexpr int kWindow = VANISSH_CUDA_WINDOW;
static_assert(kWindow >= 4 && kWindow <= 20, "unsupported window size");
// A clamped scalar is 2^254 + 8*u, with 0 <= u < 2^251. Recode u
// instead of the whole scalar, reserving one bit for the signed-digit carry.
// Fold the fixed 2^254*B point into the last position's table entries.
constexpr int kPositions = (252 + kWindow - 1) / kWindow;
constexpr int kPositionBases = kPositions + 1;  // includes the fixed high-bit point
constexpr uint32_t kHalf = 1u << (kWindow - 1);
constexpr uint32_t kStride = kHalf + 1;  // magnitudes 0..kHalf
constexpr size_t kTableEntries = static_cast<size_t>(kPositions) * kStride;
constexpr int kBatch = VANISSH_CUDA_BATCH;
static_assert(kBatch >= 1 && kBatch <= 256, "unsupported batch size");

// Precomputed affine point in limb form, padded to 128 bytes so every entry
// is exactly four 32-byte sectors. (Packing the coordinates into 3 x 32 bytes
// was measured slower: the lookups are latency-bound, not bandwidth-bound.)
struct NielsEntry {
    uint32_t yplusx[10];
    uint32_t yminusx[10];
    uint32_t xy2d[10];
    uint32_t pad[2];
};
static_assert(sizeof(NielsEntry) == 128, "NielsEntry must be 128 bytes");

__device__ __forceinline__ void store_niels(NielsEntry* dst, const ge_niels& q) {
#pragma unroll
    for (int i = 0; i < 10; ++i) {
        dst->yplusx[i] = q.yplusx.v[i];
        dst->yminusx[i] = q.yminusx.v[i];
        dst->xy2d[i] = q.xy2d.v[i];
    }
    dst->pad[0] = 0;
    dst->pad[1] = 0;
}

__device__ __forceinline__ void
load_niels(const NielsEntry* __restrict__ entry, bool negate, ge_niels& q) {
    const uint4* p = reinterpret_cast<const uint4*>(entry);
    uint32_t w[32];
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        const uint4 v = __ldg(p + i);
        w[4 * i] = v.x;
        w[4 * i + 1] = v.y;
        w[4 * i + 2] = v.z;
        w[4 * i + 3] = v.w;
    }
    fe yplusx, yminusx, xy2d;
#pragma unroll
    for (int i = 0; i < 10; ++i) {
        yplusx.v[i] = w[i];
        yminusx.v[i] = w[10 + i];
        xy2d.v[i] = w[20 + i];
    }
    // Negating a point swaps y+x with y-x and negates 2dxy.
    fe neg;
    fe_neg(neg, xy2d);
#pragma unroll
    for (int i = 0; i < 10; ++i) {
        q.yplusx.v[i] = negate ? yminusx.v[i] : yplusx.v[i];
        q.yminusx.v[i] = negate ? yplusx.v[i] : yminusx.v[i];
        q.xy2d.v[i] = negate ? neg.v[i] : xy2d.v[i];
    }
}

// ---------------------------------------------------------------------------
// Table generation (wrapped in kernels by the including translation unit)
// ---------------------------------------------------------------------------

// bases[i] = 2^(3 + W*i) * B; bases[kPositions] = 2^254 * B.
// The caller launches kPositions threads and allocates kPositionBases entries.
__device__ inline void generate_position_base(int i, NielsEntry* bases) {
    ge_p3 p;
    ge_base_point(p);
    for (int k = 0; k < 3 + kWindow * i; ++k) {
        ge_dbl(p, p);
    }
    ge_niels q;
    ge_to_niels(q, p);
    store_niels(bases + i, q);
    if (i == kPositions - 1) {
        for (int bit = 3 + kWindow * i; bit < 254; ++bit) {
            ge_dbl(p, p);
        }
        ge_to_niels(q, p);
        store_niels(bases + kPositions, q);
    }
}

// table[i][j] = j * bases[i], plus 2^254*B at the last position.
__device__ inline void
generate_table_entry(size_t id, const NielsEntry* __restrict__ bases, NielsEntry* table) {
    const int i = static_cast<int>(id / kStride);
    const uint32_t j = static_cast<uint32_t>(id % kStride);

    ge_niels q;
    if (j == 0) {
        fe_1(q.yplusx);
        fe_1(q.yminusx);
        fe_0(q.xy2d);
    } else {
        ge_niels base;
        load_niels(bases + i, false, base);
        ge_p3 p;
        ge_identity(p);
        for (int b = kWindow - 1; b >= 0; --b) {
            ge_dbl(p, p);
            if ((j >> b) & 1u) {
                ge_nielsadd(p, p, base);
            }
        }
        ge_to_niels(q, p);
    }
    if (i == kPositions - 1) {
        ge_p3 p;
        ge_from_niels(p, q);
        ge_niels offset;
        load_niels(bases + kPositions, false, offset);
        ge_nielsadd(p, p, offset);
        ge_to_niels(q, p);
    }
    store_niels(table + id, q);
}

// ---------------------------------------------------------------------------
// Scalar multiplication and key derivation
// ---------------------------------------------------------------------------

// Selects s[word], with the fixed high bit removed, for a warp-uniform,
// loop-variant index without spilling s to local memory.
__device__ __forceinline__ uint32_t scalar_word(const uint32_t s[8], int word) {
    uint32_t v = 0;
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        v = (word == i) ? (i == 7 ? s[i] & 0x3fffffffu : s[i]) : v;
    }
    return v;
}

// r = s * B for an Ed25519-clamped scalar: low three bits zero, bit 254
// set, bit 255 clear. Other scalars are not supported by this table.
__device__ __forceinline__ void
scalarmult_clamped_base(const uint32_t s[8], const NielsEntry* __restrict__ table, ge_p3& r) {
    // Digits are recoded into [-kHalf + 1, kHalf] so the table only needs
    // positive entries. They are produced on the fly, in order (the recoding
    // carry ripples upwards), straight from the scalar registers: a digit array
    // in local memory would put an LDL on the critical path of every table
    // load, which measured 40% slower.
    uint32_t carry = 0;
    const auto digit_at = [&](int i) -> int32_t {
        const int bit = 3 + kWindow * i;
        const int word = bit >> 5;
        const int shift = bit & 31;
        const uint32_t lo = scalar_word(s, word);
        const uint32_t hi = scalar_word(s, word + 1);  // 0 past the last word
        const uint32_t d = (__funnelshift_r(lo, hi, shift) & ((1u << kWindow) - 1)) + carry;
        const bool negate = d > kHalf;
        carry = negate ? 1u : 0u;
        return negate ? -static_cast<int32_t>((1u << kWindow) - d) : static_cast<int32_t>(d);
    };
    const auto entry = [&](int i, int32_t d) {
        return table + static_cast<size_t>(i) * kStride + static_cast<uint32_t>(d < 0 ? -d : d);
    };
    // Fetching the next position's entry into L2 while the current addition
    // runs hides most of the DRAM latency of the random table accesses.
    const auto prefetch = [&](const NielsEntry* e) {
        asm volatile("prefetch.global.L2 [%0];" ::"l"(e));
    };

    // The digit of the next position is carried in a register so the next
    // iteration's load address never waits on anything but arithmetic.
    int32_t d_cur = digit_at(0);
    int32_t d_next = digit_at(1);

    ge_niels q;
    load_niels(entry(0, d_cur), d_cur < 0, q);
    prefetch(entry(1, d_next));
    ge_from_niels(r, q);
#pragma unroll 1
    for (int i = 1; i < kPositions - 1; ++i) {
        d_cur = d_next;
        d_next = digit_at(i + 1);
        load_niels(entry(i, d_cur), d_cur < 0, q);
        prefetch(entry(i + 1, d_next));
        ge_nielsadd(r, r, q);
    }
    // The top digit (including carry) is at most kHalf, so it is never
    // negated: the fixed high-bit point folded into this entry keeps its sign.
    // The last addition does not need the T coordinate.
    load_niels(entry(kPositions - 1, d_next), d_next < 0, q);
    ge_nielsadd<false>(r, r, q);
}

// Derives kBatch public keys per thread. make_seed(k, seed) must fill the seed
// for key k; on_key(k, pk) receives the resulting public key as little-endian
// words. All kBatch inversions are folded into a single one.
template <typename SeedFn, typename KeyFn>
__device__ __forceinline__ void
derive_public_keys(const NielsEntry* __restrict__ table, SeedFn make_seed, KeyFn on_key) {
    fe xs[kBatch], ys[kBatch], zs[kBatch], prods[kBatch];

#pragma unroll 1
    for (int k = 0; k < kBatch; ++k) {
        uint32_t seed[8], s[8];
        make_seed(k, seed);
        sha512_seed_to_scalar(seed, s);

        ge_p3 p;
        scalarmult_clamped_base(s, table, p);
        fe_copy(xs[k], p.X);
        fe_copy(ys[k], p.Y);
        fe_copy(zs[k], p.Z);
        if (k == 0) {
            fe_copy(prods[0], p.Z);
        } else {
            fe_mul(prods[k], prods[k - 1], p.Z);
        }
    }

    fe acc;
    fe_invert(acc, prods[kBatch - 1]);

#pragma unroll 1
    for (int k = kBatch - 1; k >= 0; --k) {
        fe zinv;
        if (k > 0) {
            fe_mul(zinv, prods[k - 1], acc);
            fe_mul(acc, acc, zs[k]);
        } else {
            fe_copy(zinv, acc);
        }
        fe x, y;
        fe_mul(x, xs[k], zinv);
        fe_mul(y, ys[k], zinv);

        uint32_t xb[8], pk[8];
        fe_tobytes(xb, x);
        fe_tobytes(pk, y);
        pk[7] |= (xb[0] & 1u) << 31;
        on_key(k, pk);
    }
}

}  // namespace ed25519
