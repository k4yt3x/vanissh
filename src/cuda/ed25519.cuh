#pragma once

// Ed25519 primitives for the CUDA backend.
//
// Field elements mod p = 2^255 - 19 use ten unsigned limbs in radix 2^25.5
// (26, 25, 26, 25, ... bits), the layout used by ref10/ed25519-donna. Products
// of two limbs are accumulated in 64-bit column sums, which nvcc compiles to a
// single IMAD.WIDE.U32 per term.
//
// Limb-size conventions used to keep everything inside 32/64-bit ranges:
//   "reduced": limbs < 2^26 (even) / 2^25 (odd) plus a tiny slack. Produced by
//              mul, sq, sub and add_reduce.
//   "loose":   limbs < 2^27 / 2^26. Produced by add and neg.
// mul, sq and sub accept reduced or loose inputs; everything they produce is
// reduced. Only tobytes() needs (and performs) full canonical reduction.

#include <cstdint>

namespace ed25519 {

struct fe {
    uint32_t v[10];
};

constexpr uint32_t kMask26 = (1u << 26) - 1;
constexpr uint32_t kMask25 = (1u << 25) - 1;

// 2p and 4p expressed limb-wise; added as a bias so subtraction never underflows.
constexpr uint32_t kTwoP0 = 2 * ((1u << 26) - 19);
constexpr uint32_t kTwoPOdd = 2 * ((1u << 25) - 1);
constexpr uint32_t kTwoPEven = 2 * ((1u << 26) - 1);
constexpr uint32_t kFourP0 = 4 * ((1u << 26) - 19);
constexpr uint32_t kFourPOdd = 4 * ((1u << 25) - 1);
constexpr uint32_t kFourPEven = 4 * ((1u << 26) - 1);

__device__ __forceinline__ void fe_0(fe& r) {
#pragma unroll
    for (int i = 0; i < 10; ++i) {
        r.v[i] = 0;
    }
}

__device__ __forceinline__ void fe_1(fe& r) {
    fe_0(r);
    r.v[0] = 1;
}

__device__ __forceinline__ void fe_copy(fe& r, const fe& a) {
#pragma unroll
    for (int i = 0; i < 10; ++i) {
        r.v[i] = a.v[i];
    }
}

// r = a + b without carry propagation. Inputs reduced, output loose.
__device__ __forceinline__ void fe_add(fe& r, const fe& a, const fe& b) {
#pragma unroll
    for (int i = 0; i < 10; ++i) {
        r.v[i] = a.v[i] + b.v[i];
    }
}

// r = a + b with carry propagation. Inputs reduced or loose, output reduced.
__device__ __forceinline__ void fe_add_reduce(fe& r, const fe& a, const fe& b) {
    uint32_t c;
    uint32_t t0 = a.v[0] + b.v[0];
    c = t0 >> 26;
    t0 &= kMask26;
    uint32_t t1 = a.v[1] + b.v[1] + c;
    c = t1 >> 25;
    t1 &= kMask25;
    uint32_t t2 = a.v[2] + b.v[2] + c;
    c = t2 >> 26;
    t2 &= kMask26;
    uint32_t t3 = a.v[3] + b.v[3] + c;
    c = t3 >> 25;
    t3 &= kMask25;
    uint32_t t4 = a.v[4] + b.v[4] + c;
    c = t4 >> 26;
    t4 &= kMask26;
    uint32_t t5 = a.v[5] + b.v[5] + c;
    c = t5 >> 25;
    t5 &= kMask25;
    uint32_t t6 = a.v[6] + b.v[6] + c;
    c = t6 >> 26;
    t6 &= kMask26;
    uint32_t t7 = a.v[7] + b.v[7] + c;
    c = t7 >> 25;
    t7 &= kMask25;
    uint32_t t8 = a.v[8] + b.v[8] + c;
    c = t8 >> 26;
    t8 &= kMask26;
    uint32_t t9 = a.v[9] + b.v[9] + c;
    c = t9 >> 25;
    t9 &= kMask25;
    t0 += 19 * c;
    r.v[0] = t0;
    r.v[1] = t1;
    r.v[2] = t2;
    r.v[3] = t3;
    r.v[4] = t4;
    r.v[5] = t5;
    r.v[6] = t6;
    r.v[7] = t7;
    r.v[8] = t8;
    r.v[9] = t9;
}

// r = a - b. Inputs reduced or loose, output reduced.
__device__ __forceinline__ void fe_sub(fe& r, const fe& a, const fe& b) {
    uint32_t c;
    uint32_t t0 = kFourP0 + a.v[0] - b.v[0];
    c = t0 >> 26;
    t0 &= kMask26;
    uint32_t t1 = kFourPOdd + a.v[1] - b.v[1] + c;
    c = t1 >> 25;
    t1 &= kMask25;
    uint32_t t2 = kFourPEven + a.v[2] - b.v[2] + c;
    c = t2 >> 26;
    t2 &= kMask26;
    uint32_t t3 = kFourPOdd + a.v[3] - b.v[3] + c;
    c = t3 >> 25;
    t3 &= kMask25;
    uint32_t t4 = kFourPEven + a.v[4] - b.v[4] + c;
    c = t4 >> 26;
    t4 &= kMask26;
    uint32_t t5 = kFourPOdd + a.v[5] - b.v[5] + c;
    c = t5 >> 25;
    t5 &= kMask25;
    uint32_t t6 = kFourPEven + a.v[6] - b.v[6] + c;
    c = t6 >> 26;
    t6 &= kMask26;
    uint32_t t7 = kFourPOdd + a.v[7] - b.v[7] + c;
    c = t7 >> 25;
    t7 &= kMask25;
    uint32_t t8 = kFourPEven + a.v[8] - b.v[8] + c;
    c = t8 >> 26;
    t8 &= kMask26;
    uint32_t t9 = kFourPOdd + a.v[9] - b.v[9] + c;
    c = t9 >> 25;
    t9 &= kMask25;
    t0 += 19 * c;
    r.v[0] = t0;
    r.v[1] = t1;
    r.v[2] = t2;
    r.v[3] = t3;
    r.v[4] = t4;
    r.v[5] = t5;
    r.v[6] = t6;
    r.v[7] = t7;
    r.v[8] = t8;
    r.v[9] = t9;
}

// r = a - b without carry propagation (as a + 2p - b, limb-wise). Inputs must
// be reduced; output limbs are < 2^27.6 / 2^26.6, which fe_mul still accepts
// as either operand (see the bounds in fe_mul).
__device__ __forceinline__ void fe_sub_loose(fe& r, const fe& a, const fe& b) {
    r.v[0] = kTwoP0 + a.v[0] - b.v[0];
#pragma unroll
    for (int i = 1; i < 10; ++i) {
        r.v[i] = ((i & 1) ? kTwoPOdd : kTwoPEven) + a.v[i] - b.v[i];
    }
}

// r = -a (as 2p - a, limb-wise). Input reduced, output loose.
__device__ __forceinline__ void fe_neg(fe& r, const fe& a) {
    r.v[0] = kTwoP0 - a.v[0];
#pragma unroll
    for (int i = 1; i < 10; ++i) {
        r.v[i] = ((i & 1) ? kTwoPOdd : kTwoPEven) - a.v[i];
    }
}

// Common tail of mul/sq: propagate carries through the ten 64-bit column sums.
__device__ __forceinline__ void fe_carry_columns(
    fe& r,
    uint64_t h0,
    uint64_t h1,
    uint64_t h2,
    uint64_t h3,
    uint64_t h4,
    uint64_t h5,
    uint64_t h6,
    uint64_t h7,
    uint64_t h8,
    uint64_t h9
) {
    uint64_t c;
    c = h0 >> 26;
    uint32_t r0 = static_cast<uint32_t>(h0) & kMask26;
    h1 += c;
    c = h1 >> 25;
    uint32_t r1 = static_cast<uint32_t>(h1) & kMask25;
    h2 += c;
    c = h2 >> 26;
    uint32_t r2 = static_cast<uint32_t>(h2) & kMask26;
    h3 += c;
    c = h3 >> 25;
    uint32_t r3 = static_cast<uint32_t>(h3) & kMask25;
    h4 += c;
    c = h4 >> 26;
    uint32_t r4 = static_cast<uint32_t>(h4) & kMask26;
    h5 += c;
    c = h5 >> 25;
    uint32_t r5 = static_cast<uint32_t>(h5) & kMask25;
    h6 += c;
    c = h6 >> 26;
    uint32_t r6 = static_cast<uint32_t>(h6) & kMask26;
    h7 += c;
    c = h7 >> 25;
    uint32_t r7 = static_cast<uint32_t>(h7) & kMask25;
    h8 += c;
    c = h8 >> 26;
    uint32_t r8 = static_cast<uint32_t>(h8) & kMask26;
    h9 += c;
    c = h9 >> 25;
    uint32_t r9 = static_cast<uint32_t>(h9) & kMask25;
    // 2^255 == 19 (mod p); c < 2^38 so this needs 64 bits.
    uint64_t t = static_cast<uint64_t>(r0) + c * 19;
    r0 = static_cast<uint32_t>(t) & kMask26;
    r1 += static_cast<uint32_t>(t >> 26);
    r.v[0] = r0;
    r.v[1] = r1;
    r.v[2] = r2;
    r.v[3] = r3;
    r.v[4] = r4;
    r.v[5] = r5;
    r.v[6] = r6;
    r.v[7] = r7;
    r.v[8] = r8;
    r.v[9] = r9;
}

// r = f * g. Output reduced.
//
// Limb i sits at bit offset ceil(25.5 * i), so a product f_i * g_j lands at
// offset_i + offset_j: one bit high when both i and j are odd (hence the *2),
// and 2^255 == 19 folds everything past limb 9 back down (hence the *19).
//
// Operand bounds: g limbs must stay below 2^32 / 19 (< 2^27.75) so 19 * g_j
// fits 32 bits; f limbs may be up to 2^28. Odd f limbs are doubled, and at
// most five of the ten products in a column involve a doubled limb, so a
// column sums to less than 5 * 2^29 * 2^31.75 + 5 * 2^28 * 2^31.75 < 2^63.7
// and the uint64_t accumulators cannot overflow. Reduced and loose values
// satisfy both bounds, as do the outputs of fe_sub_loose; a plain fe_add of
// two loose values is only safe as the f operand.
__device__ __forceinline__ void fe_mul(fe& r, const fe& f, const fe& g) {
    const uint32_t f0 = f.v[0], f1 = f.v[1], f2 = f.v[2], f3 = f.v[3], f4 = f.v[4];
    const uint32_t f5 = f.v[5], f6 = f.v[6], f7 = f.v[7], f8 = f.v[8], f9 = f.v[9];
    const uint32_t g0 = g.v[0], g1 = g.v[1], g2 = g.v[2], g3 = g.v[3], g4 = g.v[4];
    const uint32_t g5 = g.v[5], g6 = g.v[6], g7 = g.v[7], g8 = g.v[8], g9 = g.v[9];
    const uint32_t f1_2 = 2 * f1, f3_2 = 2 * f3, f5_2 = 2 * f5, f7_2 = 2 * f7, f9_2 = 2 * f9;
    const uint32_t g1_19 = 19 * g1, g2_19 = 19 * g2, g3_19 = 19 * g3, g4_19 = 19 * g4,
                   g5_19 = 19 * g5, g6_19 = 19 * g6, g7_19 = 19 * g7, g8_19 = 19 * g8,
                   g9_19 = 19 * g9;
    // clang-format off
    uint64_t h0 = (uint64_t)f0 * g0 + (uint64_t)f1_2 * g9_19 + (uint64_t)f2 * g8_19 + (uint64_t)f3_2 * g7_19 + (uint64_t)f4 * g6_19 + (uint64_t)f5_2 * g5_19 + (uint64_t)f6 * g4_19 + (uint64_t)f7_2 * g3_19 + (uint64_t)f8 * g2_19 + (uint64_t)f9_2 * g1_19;
    uint64_t h1 = (uint64_t)f0 * g1 + (uint64_t)f1 * g0 + (uint64_t)f2 * g9_19 + (uint64_t)f3 * g8_19 + (uint64_t)f4 * g7_19 + (uint64_t)f5 * g6_19 + (uint64_t)f6 * g5_19 + (uint64_t)f7 * g4_19 + (uint64_t)f8 * g3_19 + (uint64_t)f9 * g2_19;
    uint64_t h2 = (uint64_t)f0 * g2 + (uint64_t)f1_2 * g1 + (uint64_t)f2 * g0 + (uint64_t)f3_2 * g9_19 + (uint64_t)f4 * g8_19 + (uint64_t)f5_2 * g7_19 + (uint64_t)f6 * g6_19 + (uint64_t)f7_2 * g5_19 + (uint64_t)f8 * g4_19 + (uint64_t)f9_2 * g3_19;
    uint64_t h3 = (uint64_t)f0 * g3 + (uint64_t)f1 * g2 + (uint64_t)f2 * g1 + (uint64_t)f3 * g0 + (uint64_t)f4 * g9_19 + (uint64_t)f5 * g8_19 + (uint64_t)f6 * g7_19 + (uint64_t)f7 * g6_19 + (uint64_t)f8 * g5_19 + (uint64_t)f9 * g4_19;
    uint64_t h4 = (uint64_t)f0 * g4 + (uint64_t)f1_2 * g3 + (uint64_t)f2 * g2 + (uint64_t)f3_2 * g1 + (uint64_t)f4 * g0 + (uint64_t)f5_2 * g9_19 + (uint64_t)f6 * g8_19 + (uint64_t)f7_2 * g7_19 + (uint64_t)f8 * g6_19 + (uint64_t)f9_2 * g5_19;
    uint64_t h5 = (uint64_t)f0 * g5 + (uint64_t)f1 * g4 + (uint64_t)f2 * g3 + (uint64_t)f3 * g2 + (uint64_t)f4 * g1 + (uint64_t)f5 * g0 + (uint64_t)f6 * g9_19 + (uint64_t)f7 * g8_19 + (uint64_t)f8 * g7_19 + (uint64_t)f9 * g6_19;
    uint64_t h6 = (uint64_t)f0 * g6 + (uint64_t)f1_2 * g5 + (uint64_t)f2 * g4 + (uint64_t)f3_2 * g3 + (uint64_t)f4 * g2 + (uint64_t)f5_2 * g1 + (uint64_t)f6 * g0 + (uint64_t)f7_2 * g9_19 + (uint64_t)f8 * g8_19 + (uint64_t)f9_2 * g7_19;
    uint64_t h7 = (uint64_t)f0 * g7 + (uint64_t)f1 * g6 + (uint64_t)f2 * g5 + (uint64_t)f3 * g4 + (uint64_t)f4 * g3 + (uint64_t)f5 * g2 + (uint64_t)f6 * g1 + (uint64_t)f7 * g0 + (uint64_t)f8 * g9_19 + (uint64_t)f9 * g8_19;
    uint64_t h8 = (uint64_t)f0 * g8 + (uint64_t)f1_2 * g7 + (uint64_t)f2 * g6 + (uint64_t)f3_2 * g5 + (uint64_t)f4 * g4 + (uint64_t)f5_2 * g3 + (uint64_t)f6 * g2 + (uint64_t)f7_2 * g1 + (uint64_t)f8 * g0 + (uint64_t)f9_2 * g9_19;
    uint64_t h9 = (uint64_t)f0 * g9 + (uint64_t)f1 * g8 + (uint64_t)f2 * g7 + (uint64_t)f3 * g6 + (uint64_t)f4 * g5 + (uint64_t)f5 * g4 + (uint64_t)f6 * g3 + (uint64_t)f7 * g2 + (uint64_t)f8 * g1 + (uint64_t)f9 * g0;
    // clang-format on
    fe_carry_columns(r, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
}

// r = f^2. Same conventions as fe_mul; symmetric terms are merged.
__device__ __forceinline__ void fe_sq(fe& r, const fe& f) {
    const uint32_t f0 = f.v[0], f1 = f.v[1], f2 = f.v[2], f3 = f.v[3], f4 = f.v[4];
    const uint32_t f5 = f.v[5], f6 = f.v[6], f7 = f.v[7], f8 = f.v[8], f9 = f.v[9];
    const uint32_t f0_2 = 2 * f0, f1_2 = 2 * f1, f2_2 = 2 * f2, f3_2 = 2 * f3, f4_2 = 2 * f4,
                   f5_2 = 2 * f5, f6_2 = 2 * f6, f7_2 = 2 * f7, f8_2 = 2 * f8, f9_2 = 2 * f9;
    const uint32_t f1_4 = 4 * f1, f3_4 = 4 * f3, f5_4 = 4 * f5, f7_4 = 4 * f7;
    const uint32_t f5_19 = 19 * f5, f6_19 = 19 * f6, f7_19 = 19 * f7, f8_19 = 19 * f8,
                   f9_19 = 19 * f9;
    // clang-format off
    uint64_t h0 = (uint64_t)f0 * f0 + (uint64_t)f1_4 * f9_19 + (uint64_t)f2_2 * f8_19 + (uint64_t)f3_4 * f7_19 + (uint64_t)f4_2 * f6_19 + (uint64_t)f5_2 * f5_19;
    uint64_t h1 = (uint64_t)f0_2 * f1 + (uint64_t)f2_2 * f9_19 + (uint64_t)f3_2 * f8_19 + (uint64_t)f4_2 * f7_19 + (uint64_t)f5_2 * f6_19;
    uint64_t h2 = (uint64_t)f0_2 * f2 + (uint64_t)f1_2 * f1 + (uint64_t)f3_4 * f9_19 + (uint64_t)f4_2 * f8_19 + (uint64_t)f5_4 * f7_19 + (uint64_t)f6 * f6_19;
    uint64_t h3 = (uint64_t)f0_2 * f3 + (uint64_t)f1_2 * f2 + (uint64_t)f4_2 * f9_19 + (uint64_t)f5_2 * f8_19 + (uint64_t)f6_2 * f7_19;
    uint64_t h4 = (uint64_t)f0_2 * f4 + (uint64_t)f1_4 * f3 + (uint64_t)f2 * f2 + (uint64_t)f5_4 * f9_19 + (uint64_t)f6_2 * f8_19 + (uint64_t)f7_2 * f7_19;
    uint64_t h5 = (uint64_t)f0_2 * f5 + (uint64_t)f1_2 * f4 + (uint64_t)f2_2 * f3 + (uint64_t)f6_2 * f9_19 + (uint64_t)f7_2 * f8_19;
    uint64_t h6 = (uint64_t)f0_2 * f6 + (uint64_t)f1_4 * f5 + (uint64_t)f2_2 * f4 + (uint64_t)f3_2 * f3 + (uint64_t)f7_4 * f9_19 + (uint64_t)f8 * f8_19;
    uint64_t h7 = (uint64_t)f0_2 * f7 + (uint64_t)f1_2 * f6 + (uint64_t)f2_2 * f5 + (uint64_t)f3_2 * f4 + (uint64_t)f8_2 * f9_19;
    uint64_t h8 = (uint64_t)f0_2 * f8 + (uint64_t)f1_4 * f7 + (uint64_t)f2_2 * f6 + (uint64_t)f3_4 * f5 + (uint64_t)f4 * f4 + (uint64_t)f9_2 * f9_19;
    uint64_t h9 = (uint64_t)f0_2 * f9 + (uint64_t)f1_2 * f8 + (uint64_t)f2_2 * f7 + (uint64_t)f3_2 * f6 + (uint64_t)f4_2 * f5;
    // clang-format on
    fe_carry_columns(r, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
}

// r = a^(2^n)
__device__ __forceinline__ void fe_sq_n(fe& r, const fe& a, int n) {
    fe_sq(r, a);
#pragma unroll 1
    for (int i = 1; i < n; ++i) {
        fe_sq(r, r);
    }
}

// r = z^(p - 2) = z^-1, 254 squarings + 11 multiplications.
__device__ __forceinline__ void fe_invert(fe& r, const fe& z) {
    fe z2, z9, z11, z_5_0, z_10_0, z_20_0, z_50_0, z_100_0, t;
    fe_sq(z2, z);          // z^2
    fe_sq_n(t, z2, 2);     // z^8
    fe_mul(z9, t, z);      // z^9
    fe_mul(z11, z9, z2);   // z^11
    fe_sq(t, z11);         // z^22
    fe_mul(z_5_0, t, z9);  // z^(2^5 - 1)
    fe_sq_n(t, z_5_0, 5);
    fe_mul(z_10_0, t, z_5_0);  // z^(2^10 - 1)
    fe_sq_n(t, z_10_0, 10);
    fe_mul(z_20_0, t, z_10_0);  // z^(2^20 - 1)
    fe_sq_n(t, z_20_0, 20);
    fe_mul(t, t, z_20_0);  // z^(2^40 - 1)
    fe_sq_n(t, t, 10);
    fe_mul(z_50_0, t, z_10_0);  // z^(2^50 - 1)
    fe_sq_n(t, z_50_0, 50);
    fe_mul(z_100_0, t, z_50_0);  // z^(2^100 - 1)
    fe_sq_n(t, z_100_0, 100);
    fe_mul(t, t, z_100_0);  // z^(2^200 - 1)
    fe_sq_n(t, t, 50);
    fe_mul(t, t, z_50_0);  // z^(2^250 - 1)
    fe_sq_n(t, t, 5);
    fe_mul(r, t, z11);  // z^(2^255 - 21) = z^(p - 2)
}

// Canonical little-endian 32-byte encoding, as eight 32-bit words.
__device__ __forceinline__ void fe_tobytes(uint32_t out[8], const fe& a) {
    uint32_t f0 = a.v[0], f1 = a.v[1], f2 = a.v[2], f3 = a.v[3], f4 = a.v[4];
    uint32_t f5 = a.v[5], f6 = a.v[6], f7 = a.v[7], f8 = a.v[8], f9 = a.v[9];

    // Two full carry passes bring every limb into canonical range and the
    // value below 2^255.
#pragma unroll
    for (int pass = 0; pass < 2; ++pass) {
        f1 += f0 >> 26;
        f0 &= kMask26;
        f2 += f1 >> 25;
        f1 &= kMask25;
        f3 += f2 >> 26;
        f2 &= kMask26;
        f4 += f3 >> 25;
        f3 &= kMask25;
        f5 += f4 >> 26;
        f4 &= kMask26;
        f6 += f5 >> 25;
        f5 &= kMask25;
        f7 += f6 >> 26;
        f6 &= kMask26;
        f8 += f7 >> 25;
        f7 &= kMask25;
        f9 += f8 >> 26;
        f8 &= kMask26;
        f0 += 19 * (f9 >> 25);
        f9 &= kMask25;
    }

    // Now 0 <= f < 2^255. If f >= p then f + 19 >= 2^255; in that case the
    // low 255 bits of f + 19 are exactly f - p.
    uint32_t g0 = f0 + 19;
    uint32_t g1 = f1 + (g0 >> 26);
    g0 &= kMask26;
    uint32_t g2 = f2 + (g1 >> 25);
    g1 &= kMask25;
    uint32_t g3 = f3 + (g2 >> 26);
    g2 &= kMask26;
    uint32_t g4 = f4 + (g3 >> 25);
    g3 &= kMask25;
    uint32_t g5 = f5 + (g4 >> 26);
    g4 &= kMask26;
    uint32_t g6 = f6 + (g5 >> 25);
    g5 &= kMask25;
    uint32_t g7 = f7 + (g6 >> 26);
    g6 &= kMask26;
    uint32_t g8 = f8 + (g7 >> 25);
    g7 &= kMask25;
    uint32_t g9 = f9 + (g8 >> 26);
    g8 &= kMask26;
    const bool ge_p = (g9 >> 25) != 0;
    g9 &= kMask25;
    if (ge_p) {
        f0 = g0;
        f1 = g1;
        f2 = g2;
        f3 = g3;
        f4 = g4;
        f5 = g5;
        f6 = g6;
        f7 = g7;
        f8 = g8;
        f9 = g9;
    }

    out[0] = f0 | (f1 << 26);
    out[1] = (f1 >> 6) | (f2 << 19);
    out[2] = (f2 >> 13) | (f3 << 13);
    out[3] = (f3 >> 19) | (f4 << 6);
    out[4] = f5 | (f6 << 25);
    out[5] = (f6 >> 7) | (f7 << 19);
    out[6] = (f7 >> 13) | (f8 << 12);
    out[7] = (f8 >> 20) | (f9 << 6);
}

// Inverse of fe_tobytes for values below 2^255 (used for constants only).
__device__ __forceinline__ void fe_frombytes(fe& r, const uint32_t w[8]) {
    r.v[0] = w[0] & kMask26;
    r.v[1] = ((w[0] >> 26) | (w[1] << 6)) & kMask25;
    r.v[2] = ((w[1] >> 19) | (w[2] << 13)) & kMask26;
    r.v[3] = ((w[2] >> 13) | (w[3] << 19)) & kMask25;
    r.v[4] = w[3] >> 6;
    r.v[5] = w[4] & kMask25;
    r.v[6] = ((w[4] >> 25) | (w[5] << 7)) & kMask26;
    r.v[7] = ((w[5] >> 19) | (w[6] << 13)) & kMask25;
    r.v[8] = ((w[6] >> 12) | (w[7] << 20)) & kMask26;
    r.v[9] = (w[7] >> 6) & kMask25;
}

// ---------------------------------------------------------------------------
// Group operations (twisted Edwards curve -x^2 + y^2 = 1 + d x^2 y^2)
// ---------------------------------------------------------------------------

// Extended coordinates: x = X/Z, y = Y/Z, X*Y = Z*T.
struct ge_p3 {
    fe X, Y, Z, T;
};

// Precomputed affine point in "Niels" form: (y + x, y - x, 2 d x y).
struct ge_niels {
    fe yplusx, yminusx, xy2d;
};

// Base point B and 2d as little-endian words.
__constant__ uint32_t kBaseX[8] = {
    0x8f25d51a,
    0xc9562d60,
    0x9525a7b2,
    0x692cc760,
    0xfdd6dc5c,
    0xc0a4e231,
    0xcd6e53fe,
    0x216936d3
};
__constant__ uint32_t kBaseY[8] = {
    0x66666658,
    0x66666666,
    0x66666666,
    0x66666666,
    0x66666666,
    0x66666666,
    0x66666666,
    0x66666666
};
__constant__ uint32_t kTwoD[8] = {
    0x26b2f159,
    0xebd69b94,
    0x8283b156,
    0x00e0149a,
    0xeef3d130,
    0x198e80f2,
    0x56dffce7,
    0x2406d9dc
};

__device__ __forceinline__ void ge_identity(ge_p3& r) {
    fe_0(r.X);
    fe_1(r.Y);
    fe_1(r.Z);
    fe_0(r.T);
}

__device__ __forceinline__ void ge_base_point(ge_p3& r) {
    fe_frombytes(r.X, kBaseX);
    fe_frombytes(r.Y, kBaseY);
    fe_1(r.Z);
    fe_mul(r.T, r.X, r.Y);
}

// r = p + q (7 multiplications, 6 when the T coordinate is not needed).
// p.X, p.Y, p.Z and p.T must be reduced (as produced by this function itself
// or by ge_from_niels).
template <bool kWithT = true>
__device__ __forceinline__ void ge_nielsadd(ge_p3& r, const ge_p3& p, const ge_niels& q) {
    fe ypx, ymx, a, b, c, d, e, f, g, h;
    fe_add(ypx, p.Y, p.X);
    fe_sub_loose(ymx, p.Y, p.X);
    fe_mul(a, ypx, q.yplusx);
    fe_mul(b, ymx, q.yminusx);
    fe_mul(c, q.xy2d, p.T);
    fe_add(d, p.Z, p.Z);
    fe_sub_loose(e, a, b);
    // d is loose, so f is below 2^28 and may only be used as the f operand.
    fe_sub_loose(f, d, c);
    fe_add(g, d, c);
    fe_add(h, a, b);
    fe_mul(r.X, f, e);
    fe_mul(r.Y, h, g);
    fe_mul(r.Z, f, g);
    if constexpr (kWithT) {
        fe_mul(r.T, e, h);
    }
}

// r = 2p (4 squarings + 4 multiplications).
__device__ __forceinline__ void ge_dbl(ge_p3& r, const ge_p3& p) {
    fe xx, yy, zz2, a, aa, e, f, g, h;
    fe_sq(xx, p.X);
    fe_sq(yy, p.Y);
    fe_sq(zz2, p.Z);
    fe_add_reduce(zz2, zz2, zz2);
    fe_add(a, p.X, p.Y);
    fe_sq(aa, a);
    fe_add(h, yy, xx);
    fe_sub(g, yy, xx);
    fe_sub(e, aa, h);
    fe_sub(f, zz2, g);
    fe_mul(r.X, e, f);
    fe_mul(r.Y, h, g);
    fe_mul(r.Z, g, f);
    fe_mul(r.T, e, h);
}

// Convert to affine Niels form (one inversion).
__device__ __forceinline__ void ge_to_niels(ge_niels& r, const ge_p3& p) {
    fe zinv, x, y, xy, two_d;
    fe_invert(zinv, p.Z);
    fe_mul(x, p.X, zinv);
    fe_mul(y, p.Y, zinv);
    fe_add_reduce(r.yplusx, y, x);
    fe_sub(r.yminusx, y, x);
    fe_mul(xy, x, y);
    fe_frombytes(two_d, kTwoD);
    fe_mul(r.xy2d, xy, two_d);
}

// Initialize an extended point directly from a Niels entry, avoiding a full
// addition to the identity: with e = 2x and h = 2y, (4x : 4y : 4 : 4xy).
__device__ __forceinline__ void ge_from_niels(ge_p3& r, const ge_niels& q) {
    fe e, h;
    fe_sub(e, q.yplusx, q.yminusx);
    fe_add(h, q.yplusx, q.yminusx);
    fe_add_reduce(r.X, e, e);
    fe_add_reduce(r.Y, h, h);
    fe_0(r.Z);
    r.Z.v[0] = 4;
    fe_mul(r.T, e, h);
}

// ---------------------------------------------------------------------------
// SHA-512 of a 32-byte seed (single block), returning the clamped scalar.
// ---------------------------------------------------------------------------

__constant__ uint64_t kSha512K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

template <int N>
__device__ __forceinline__ uint64_t rotr64(uint64_t x) {
    const uint32_t lo = static_cast<uint32_t>(x);
    const uint32_t hi = static_cast<uint32_t>(x >> 32);
    uint32_t nlo, nhi;
    if constexpr (N < 32) {
        nlo = __funnelshift_r(lo, hi, N);
        nhi = __funnelshift_r(hi, lo, N);
    } else {
        nlo = __funnelshift_r(hi, lo, N - 32);
        nhi = __funnelshift_r(lo, hi, N - 32);
    }
    return (static_cast<uint64_t>(nhi) << 32) | nlo;
}

__device__ __forceinline__ uint32_t bswap32(uint32_t x) {
    return __byte_perm(x, 0, 0x0123);
}

// seed: 32 bytes as little-endian words. s: clamped scalar as little-endian words.
//
// The 80 rounds run as five 16-round blocks in a rolled loop: unrolling all of
// them measurably hurts because the kernel then no longer fits the instruction
// cache. 16 rounds is a multiple of the 8-variable rotation, so the working
// variables map to the same registers at the top of every block.
__device__ __forceinline__ void sha512_seed_to_scalar(const uint32_t seed[8], uint32_t s[8]) {
    uint64_t w[16];
#pragma unroll
    for (int i = 0; i < 4; ++i) {
        w[i] = (static_cast<uint64_t>(bswap32(seed[2 * i])) << 32) | bswap32(seed[2 * i + 1]);
    }
    w[4] = 0x8000000000000000ULL;
#pragma unroll
    for (int i = 5; i < 15; ++i) {
        w[i] = 0;
    }
    w[15] = 256;  // message length in bits

    uint64_t a = 0x6a09e667f3bcc908ULL, b = 0xbb67ae8584caa73bULL, c = 0x3c6ef372fe94f82bULL,
             d = 0xa54ff53a5f1d36f1ULL, e = 0x510e527fade682d1ULL, f = 0x9b05688c2b3e6c1fULL,
             g = 0x1f83d9abfb41bd6bULL, h = 0x5be0cd19137e2179ULL;

#pragma unroll 1
    for (int block = 0; block < 5; ++block) {
        if (block > 0) {
            // w[i] here holds W[t-16] for t = 16*block + i; W[t-15], W[t-7] and
            // W[t-2] are at (i+1), (i+9) and (i+14) mod 16, the latter two
            // already updated in this pass.
#pragma unroll
            for (int i = 0; i < 16; ++i) {
                const uint64_t w15 = w[(i + 1) & 15];
                const uint64_t w2 = w[(i + 14) & 15];
                const uint64_t s0 = rotr64<1>(w15) ^ rotr64<8>(w15) ^ (w15 >> 7);
                const uint64_t s1 = rotr64<19>(w2) ^ rotr64<61>(w2) ^ (w2 >> 6);
                w[i] = w[i] + s0 + w[(i + 9) & 15] + s1;
            }
        }
#pragma unroll
        for (int i = 0; i < 16; ++i) {
            const uint64_t big_s1 = rotr64<14>(e) ^ rotr64<18>(e) ^ rotr64<41>(e);
            const uint64_t ch = (e & f) ^ (~e & g);
            const uint64_t t1 = h + big_s1 + ch + kSha512K[16 * block + i] + w[i];
            const uint64_t big_s0 = rotr64<28>(a) ^ rotr64<34>(a) ^ rotr64<39>(a);
            const uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint64_t t2 = big_s0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
    }

    const uint64_t h0 = a + 0x6a09e667f3bcc908ULL;
    const uint64_t h1 = b + 0xbb67ae8584caa73bULL;
    const uint64_t h2 = c + 0x3c6ef372fe94f82bULL;
    const uint64_t h3 = d + 0xa54ff53a5f1d36f1ULL;

    // First 32 digest bytes (big-endian words) reinterpreted little-endian.
    s[0] = bswap32(static_cast<uint32_t>(h0 >> 32));
    s[1] = bswap32(static_cast<uint32_t>(h0));
    s[2] = bswap32(static_cast<uint32_t>(h1 >> 32));
    s[3] = bswap32(static_cast<uint32_t>(h1));
    s[4] = bswap32(static_cast<uint32_t>(h2 >> 32));
    s[5] = bswap32(static_cast<uint32_t>(h2));
    s[6] = bswap32(static_cast<uint32_t>(h3 >> 32));
    s[7] = bswap32(static_cast<uint32_t>(h3));

    // Clamp: clear the low 3 bits and bit 255, set bit 254.
    s[0] &= ~7u;
    s[7] = (s[7] & 0x7fffffffu) | 0x40000000u;
}

}  // namespace ed25519
