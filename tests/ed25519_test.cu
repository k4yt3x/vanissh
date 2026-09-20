// Unit tests for the device-side Ed25519 code, checked against OpenSSL.
//
// - Field operations are compared with BIGNUM arithmetic on the largest limb
//   magnitudes each operation is documented to accept, on values around p and
//   on random inputs; output limbs are also checked against the bounds the
//   callers rely on.
// - SHA-512 seed hashing and the SHA-256 fingerprint of the public key blob
//   are compared with OpenSSL.
// - The clamped fixed-base scalar multiplication is compared with an affine Edwards
//   implementation on BIGNUM (itself validated against OpenSSL's Ed25519 key
//   derivation) for scalars that exercise every path of the digit recoding.
// - The batched seed-to-key derivation used by the search is compared with
//   OpenSSL for random seeds.
// - The device pattern matcher is compared with an independent string-based
//   reference for random criteria over the public key and fingerprint strings
//   of random and adversarial keys.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include <cuda_runtime.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include "cuda/matcher.cuh"
#include "cuda/scalarmult.cuh"
#include "reference_matcher.h"

using namespace ed25519;

namespace {

// ---------------------------------------------------------------------------
// Device side
// ---------------------------------------------------------------------------

enum FieldOp : int {
    kOpMul,
    kOpSq,
    kOpAdd,
    kOpAddReduce,
    kOpSub,
    kOpSubLoose,
    kOpNeg,
    kOpInvert,
    kOpToBytes,
};

struct FieldCase {
    fe a;
    fe b;
    int op;
};

struct FieldResult {
    fe raw;
    uint32_t bytes[8];
};

__global__ void field_op_kernel(const FieldCase* cases, FieldResult* results, int count) {
    const int i = static_cast<int>(blockIdx.x * blockDim.x + threadIdx.x);
    if (i >= count) {
        return;
    }
    const fe a = cases[i].a;
    const fe b = cases[i].b;
    fe r;
    switch (cases[i].op) {
        case kOpMul:
            fe_mul(r, a, b);
            break;
        case kOpSq:
            fe_sq(r, a);
            break;
        case kOpAdd:
            fe_add(r, a, b);
            break;
        case kOpAddReduce:
            fe_add_reduce(r, a, b);
            break;
        case kOpSub:
            fe_sub(r, a, b);
            break;
        case kOpSubLoose:
            fe_sub_loose(r, a, b);
            break;
        case kOpNeg:
            fe_neg(r, a);
            break;
        case kOpInvert:
            fe_invert(r, a);
            break;
        default:
            fe_copy(r, a);
            break;
    }
    results[i].raw = r;
    fe_tobytes(results[i].bytes, r);
}

__global__ void sha_kernel(const uint32_t* seeds, uint32_t* scalars, int count) {
    const int i = static_cast<int>(blockIdx.x * blockDim.x + threadIdx.x);
    if (i >= count) {
        return;
    }
    sha512_seed_to_scalar(seeds + 8 * i, scalars + 8 * i);
}

__global__ void sha256_kernel(const uint32_t* pks, uint32_t* digests, int count) {
    const int i = static_cast<int>(blockIdx.x * blockDim.x + threadIdx.x);
    if (i >= count) {
        return;
    }
    sha256_pubkey_blob(pks + 8 * i, digests + 8 * i);
}

__global__ void match_kernel(const uint32_t* pks, uint8_t* out, int count) {
    const int i = static_cast<int>(blockIdx.x * blockDim.x + threadIdx.x);
    if (i >= count) {
        return;
    }
    out[i] = matches_criteria(pks + 8 * i) ? 1 : 0;
}

__global__ void gen_positions_kernel(NielsEntry* bases) {
    if (threadIdx.x < kPositions) {
        generate_position_base(static_cast<int>(threadIdx.x), bases);
    }
}

__global__ void gen_table_kernel(const NielsEntry* __restrict__ bases, NielsEntry* table) {
    const size_t id = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (id < kTableEntries) {
        generate_table_entry(id, bases, table);
    }
}

// Clamped s * B encoded like a public key, with a plain per-thread inversion
__global__ void scalarmult_kernel(
    const NielsEntry* __restrict__ table,
    const uint32_t* scalars,
    uint32_t* out,
    int count
) {
    const int i = static_cast<int>(blockIdx.x * blockDim.x + threadIdx.x);
    if (i >= count) {
        return;
    }
    ge_p3 p;
    scalarmult_clamped_base(scalars + 8 * i, table, p);
    fe zinv, x, y;
    fe_invert(zinv, p.Z);
    fe_mul(x, p.X, zinv);
    fe_mul(y, p.Y, zinv);
    uint32_t xb[8];
    fe_tobytes(xb, x);
    fe_tobytes(out + 8 * i, y);
    out[8 * i + 7] |= (xb[0] & 1u) << 31;
}

// The batched derivation used by the search; count must be a multiple of kBatch
__global__ void derive_kernel(
    const NielsEntry* __restrict__ table,
    const uint32_t* seeds,
    uint32_t* out,
    int count
) {
    const int first = static_cast<int>(blockIdx.x * blockDim.x + threadIdx.x) * kBatch;
    if (first >= count) {
        return;
    }
    derive_public_keys(
        table,
        [&](int k, uint32_t* seed) {
            for (int j = 0; j < 8; ++j) {
                seed[j] = seeds[(first + k) * 8 + j];
            }
        },
        [&](int k, const uint32_t* pk) {
            for (int j = 0; j < 8; ++j) {
                out[(first + k) * 8 + j] = pk[j];
            }
        }
    );
}

// ---------------------------------------------------------------------------
// Host side: BIGNUM reference arithmetic
// ---------------------------------------------------------------------------

#define CUDA_CHECK(call)                                                                         \
    do {                                                                                         \
        const cudaError_t err = (call);                                                          \
        if (err != cudaSuccess) {                                                                \
            std::fprintf(                                                                        \
                stderr, "CUDA error at %s:%d: %s\n", __FILE__, __LINE__, cudaGetErrorString(err) \
            );                                                                                   \
            std::exit(2);                                                                        \
        }                                                                                        \
    } while (0)

class Big {
   public:
    Big() : n_(BN_new()) {}
    explicit Big(uint64_t value) : Big() { BN_set_word(n_, value); }
    explicit Big(const char* hex) : Big() {
        BIGNUM* tmp = n_;
        BN_hex2bn(&tmp, hex);
    }
    Big(const Big& other) : n_(BN_dup(other.n_)) {}
    Big& operator=(const Big& other) {
        BN_copy(n_, other.n_);
        return *this;
    }
    ~Big() { BN_free(n_); }
    BIGNUM* get() { return n_; }
    const BIGNUM* get() const { return n_; }

   private:
    BIGNUM* n_;
};

struct Field {
    BN_CTX* ctx = BN_CTX_new();
    Big p;

    Field() {
        BN_set_bit(p.get(), 255);
        BN_sub_word(p.get(), 19);
    }
    ~Field() { BN_CTX_free(ctx); }

    Big reduce(const Big& a) const {
        Big r;
        BN_nnmod(r.get(), a.get(), p.get(), ctx);
        return r;
    }
    Big mul(const Big& a, const Big& b) const {
        Big r;
        BN_mod_mul(r.get(), a.get(), b.get(), p.get(), ctx);
        return r;
    }
    Big add(const Big& a, const Big& b) const {
        Big r;
        BN_mod_add(r.get(), a.get(), b.get(), p.get(), ctx);
        return r;
    }
    Big sub(const Big& a, const Big& b) const {
        Big r;
        BN_mod_sub(r.get(), a.get(), b.get(), p.get(), ctx);
        return r;
    }
    Big inv(const Big& a) const {
        Big r;
        if (BN_is_zero(a.get())) {
            return r;  // x^(p-2) with x = 0, matching the device implementation
        }
        BN_mod_inverse(r.get(), a.get(), p.get(), ctx);
        return r;
    }
    std::array<uint8_t, 32> to_bytes(const Big& a) const {
        std::array<uint8_t, 32> out{};
        BN_bn2lebinpad(reduce(a).get(), out.data(), 32);
        return out;
    }
};

constexpr int kLimbOffsets[10] = {0, 26, 51, 77, 102, 128, 153, 179, 204, 230};

Big value_of(const fe& f) {
    Big v(static_cast<uint64_t>(0));
    for (int i = 0; i < 10; ++i) {
        Big limb(static_cast<uint64_t>(f.v[i]));
        BN_lshift(limb.get(), limb.get(), kLimbOffsets[i]);
        BN_add(v.get(), v.get(), limb.get());
    }
    return v;
}

// Canonical limb form of a value below 2^255 (same split as fe_frombytes)
fe limbs_of(const Field& field, const Big& value) {
    const auto bytes = field.to_bytes(value);
    uint32_t w[8];
    std::memcpy(w, bytes.data(), 32);
    fe f;
    f.v[0] = w[0] & kMask26;
    f.v[1] = ((w[0] >> 26) | (w[1] << 6)) & kMask25;
    f.v[2] = ((w[1] >> 19) | (w[2] << 13)) & kMask26;
    f.v[3] = ((w[2] >> 13) | (w[3] << 19)) & kMask25;
    f.v[4] = w[3] >> 6;
    f.v[5] = w[4] & kMask25;
    f.v[6] = ((w[4] >> 25) | (w[5] << 7)) & kMask26;
    f.v[7] = ((w[5] >> 19) | (w[6] << 13)) & kMask25;
    f.v[8] = ((w[6] >> 12) | (w[7] << 20)) & kMask26;
    f.v[9] = (w[7] >> 6) & kMask25;
    return f;
}

fe uniform_limbs(uint32_t even, uint32_t odd) {
    fe f;
    for (int i = 0; i < 10; ++i) {
        f.v[i] = (i & 1) ? odd : even;
    }
    return f;
}

std::string hex(const uint8_t* bytes, size_t size) {
    static const char digits[] = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < size; ++i) {
        s += digits[bytes[i] >> 4];
        s += digits[bytes[i] & 15];
    }
    return s;
}

std::string limbs_str(const fe& f) {
    std::string s = "[";
    for (int i = 0; i < 10; ++i) {
        s += (i ? ", " : "") + std::to_string(f.v[i]);
    }
    return s + "]";
}

int g_failures = 0;
int g_checks = 0;

void fail(const std::string& message) {
    ++g_failures;
    if (g_failures <= 20) {
        std::fprintf(stderr, "FAIL: %s\n", message.c_str());
    }
}

// ---------------------------------------------------------------------------
// Field operation tests
// ---------------------------------------------------------------------------

// Largest limb values each class of input may carry (see ed25519.cuh)
struct LimbBounds {
    uint32_t limb0, even, odd, limb1;
};
// Outputs of mul/sq/sub/add_reduce/invert
const LimbBounds kReducedBounds = {(1u << 26) + 128, 1u << 26, 1u << 25, (1u << 25) + (1u << 17)};
// Outputs of add and neg (and the inputs mul/sq/sub/add_reduce/invert accept):
// twice the reduced bounds, including the slack on limbs 0 and 1
const LimbBounds kLooseBounds =
    {(1u << 27) + 256, 1u << 27, (1u << 26) + (1u << 18), (1u << 26) + (1u << 18)};
// Outputs of sub_loose
const LimbBounds kSubLooseBounds = {
    (1u << 26) + 128 + kTwoP0,
    (1u << 26) + kTwoPEven,
    (1u << 25) + kTwoPOdd,
    (1u << 25) + (1u << 17) + kTwoPOdd
};

bool within(const fe& f, const LimbBounds& b) {
    for (int i = 0; i < 10; ++i) {
        const uint32_t limit = i == 0 ? b.limb0 : i == 1 ? b.limb1 : (i & 1) ? b.odd : b.even;
        if (f.v[i] >= limit) {
            return false;
        }
    }
    return true;
}

struct FieldInputs {
    std::vector<fe> reduced;  // satisfy the "reduced" contract
    std::vector<fe> loose;    // satisfy only the "loose" contract
    fe f_max;                 // largest f operand fe_mul accepts
    fe g_max;                 // largest g operand fe_mul accepts
};

FieldInputs make_field_inputs(const Field& field, std::mt19937_64& rng) {
    FieldInputs in;
    in.reduced.push_back(uniform_limbs(0, 0));
    in.reduced.push_back(limbs_of(field, Big(static_cast<uint64_t>(1))));
    in.reduced.push_back(limbs_of(field, Big(static_cast<uint64_t>(19))));
    // Maximum reduced magnitudes, including the slack limb 1 may carry
    fe reduced_max = uniform_limbs((1u << 26) - 1, (1u << 25) - 1);
    in.reduced.push_back(reduced_max);
    reduced_max.v[1] = (1u << 25) + (1u << 17) - 1;
    reduced_max.v[0] = (1u << 26) + 127;
    in.reduced.push_back(reduced_max);
    // Values around p in canonical limb form, exercising the final subtraction
    Big two255(static_cast<uint64_t>(0));
    BN_set_bit(two255.get(), 255);
    for (int delta : {-20, -19, -18, -1, 0, 1, 18, 19, 20}) {
        Big v = field.p;
        if (delta < 0) {
            BN_sub_word(v.get(), static_cast<BN_ULONG>(-delta));
        } else {
            BN_add_word(v.get(), static_cast<BN_ULONG>(delta));
        }
        if (BN_cmp(v.get(), two255.get()) >= 0) {
            continue;
        }
        // Canonical limb form of the value itself, not reduced mod p
        uint8_t bytes[32] = {};
        BN_bn2lebinpad(v.get(), bytes, 32);
        uint32_t w[8];
        std::memcpy(w, bytes, 32);
        fe f;
        f.v[0] = w[0] & kMask26;
        f.v[1] = ((w[0] >> 26) | (w[1] << 6)) & kMask25;
        f.v[2] = ((w[1] >> 19) | (w[2] << 13)) & kMask26;
        f.v[3] = ((w[2] >> 13) | (w[3] << 19)) & kMask25;
        f.v[4] = w[3] >> 6;
        f.v[5] = w[4] & kMask25;
        f.v[6] = ((w[4] >> 25) | (w[5] << 7)) & kMask26;
        f.v[7] = ((w[5] >> 19) | (w[6] << 13)) & kMask25;
        f.v[8] = ((w[6] >> 12) | (w[7] << 20)) & kMask26;
        f.v[9] = (w[7] >> 6) & kMask25;
        in.reduced.push_back(f);
    }
    // Single maximal limbs
    for (int i = 0; i < 10; ++i) {
        fe f = uniform_limbs(0, 0);
        f.v[i] = (i & 1) ? (1u << 25) - 1 : (1u << 26) - 1;
        in.reduced.push_back(f);
    }
    for (int n = 0; n < 200; ++n) {
        fe f;
        for (int i = 0; i < 10; ++i) {
            f.v[i] = static_cast<uint32_t>(rng() % ((i & 1) ? (1u << 25) : (1u << 26)));
        }
        in.reduced.push_back(f);
    }

    in.loose.push_back(uniform_limbs((1u << 27) - 1, (1u << 26) + (1u << 18) - 1));
    for (int n = 0; n < 200; ++n) {
        fe f;
        for (int i = 0; i < 10; ++i) {
            f.v[i] =
                static_cast<uint32_t>(rng() % ((i & 1) ? (1u << 26) + (1u << 18) : (1u << 27)));
        }
        in.loose.push_back(f);
    }

    in.f_max = uniform_limbs((1u << 28) - 1, (1u << 28) - 1);
    in.g_max = uniform_limbs(226050910u, 226050910u);  // floor(2^32 / 19)
    return in;
}

void test_field_ops(const Field& field, std::mt19937_64& rng) {
    const FieldInputs in = make_field_inputs(field, rng);
    std::vector<fe> reduced_or_loose = in.reduced;
    reduced_or_loose.insert(reduced_or_loose.end(), in.loose.begin(), in.loose.end());

    std::vector<FieldCase> cases;
    const auto add_case = [&](int op, const fe& a, const fe& b) { cases.push_back({a, b, op}); };
    // Binary operations over all admissible pairs (sampled for the big sets)
    const auto pairs = [&](int op, const std::vector<fe>& as, const std::vector<fe>& bs) {
        for (size_t i = 0; i < as.size(); ++i) {
            for (size_t j = 0; j < bs.size(); ++j) {
                if (i < 40 || j < 40 || rng() % 8 == 0) {
                    add_case(op, as[i], bs[j]);
                }
            }
        }
    };
    pairs(kOpMul, reduced_or_loose, reduced_or_loose);
    for (const fe& g : reduced_or_loose) {
        add_case(kOpMul, in.f_max, g);
    }
    add_case(kOpMul, in.f_max, in.g_max);
    for (const fe& f : reduced_or_loose) {
        add_case(kOpMul, f, in.g_max);
    }
    for (const fe& a : reduced_or_loose) {
        add_case(kOpSq, a, a);
        add_case(kOpInvert, a, a);
    }
    pairs(kOpAdd, in.reduced, in.reduced);
    pairs(kOpAddReduce, reduced_or_loose, reduced_or_loose);
    pairs(kOpSub, reduced_or_loose, reduced_or_loose);
    pairs(kOpSubLoose, in.reduced, in.reduced);
    for (const fe& a : in.reduced) {
        add_case(kOpNeg, a, a);
        add_case(kOpToBytes, a, a);
    }

    FieldCase* d_cases = nullptr;
    FieldResult* d_results = nullptr;
    const int count = static_cast<int>(cases.size());
    CUDA_CHECK(cudaMalloc(&d_cases, cases.size() * sizeof(FieldCase)));
    CUDA_CHECK(cudaMalloc(&d_results, cases.size() * sizeof(FieldResult)));
    CUDA_CHECK(
        cudaMemcpy(d_cases, cases.data(), cases.size() * sizeof(FieldCase), cudaMemcpyHostToDevice)
    );
    field_op_kernel<<<(count + 255) / 256, 256>>>(d_cases, d_results, count);
    CUDA_CHECK(cudaGetLastError());
    std::vector<FieldResult> results(cases.size());
    CUDA_CHECK(cudaMemcpy(
        results.data(), d_results, cases.size() * sizeof(FieldResult), cudaMemcpyDeviceToHost
    ));
    cudaFree(d_cases);
    cudaFree(d_results);

    static const char* const names[] = {
        "mul", "sq", "add", "add_reduce", "sub", "sub_loose", "neg", "invert", "tobytes"
    };
    for (size_t i = 0; i < cases.size(); ++i) {
        const FieldCase& c = cases[i];
        const Big a = value_of(c.a);
        const Big b = value_of(c.b);
        Big expected;
        const LimbBounds* bounds = &kReducedBounds;
        switch (c.op) {
            case kOpMul:
                expected = field.mul(a, b);
                break;
            case kOpSq:
                expected = field.mul(a, a);
                break;
            case kOpAdd:
                expected = field.add(a, b);
                bounds = &kLooseBounds;
                break;
            case kOpAddReduce:
                expected = field.add(a, b);
                break;
            case kOpSub:
                expected = field.sub(a, b);
                break;
            case kOpSubLoose:
                expected = field.sub(a, b);
                bounds = &kSubLooseBounds;
                break;
            case kOpNeg:
                expected = field.sub(Big(static_cast<uint64_t>(0)), a);
                bounds = &kLooseBounds;
                break;
            case kOpInvert:
                expected = field.inv(a);
                break;
            default:
                expected = field.reduce(a);
                bounds = nullptr;
                break;
        }
        ++g_checks;
        const auto want = field.to_bytes(expected);
        if (std::memcmp(want.data(), results[i].bytes, 32) != 0) {
            fail(
                std::string("fe_") + names[c.op] + " wrong value for a=" + limbs_str(c.a) +
                " b=" + limbs_str(c.b) + ": got " +
                hex(reinterpret_cast<const uint8_t*>(results[i].bytes), 32) + " want " +
                hex(want.data(), 32)
            );
        }
        if (bounds != nullptr && !within(results[i].raw, *bounds)) {
            fail(
                std::string("fe_") + names[c.op] + " output limbs out of bounds for a=" +
                limbs_str(c.a) + " b=" + limbs_str(c.b) + ": " + limbs_str(results[i].raw)
            );
        }
    }
    std::printf("field operations: %zu cases\n", cases.size());
}

// ---------------------------------------------------------------------------
// SHA-512 and OpenSSL key derivation helpers
// ---------------------------------------------------------------------------

using Bytes32 = std::array<uint8_t, 32>;

Bytes32 random_bytes(std::mt19937_64& rng) {
    Bytes32 b;
    for (auto& x : b) {
        x = static_cast<uint8_t>(rng());
    }
    return b;
}

// SHA-512(seed)[0..32) clamped, as OpenSSL computes it
Bytes32 openssl_scalar(const Bytes32& seed) {
    uint8_t digest[64];
    unsigned int length = 0;
    EVP_Digest(seed.data(), seed.size(), digest, &length, EVP_sha512(), nullptr);
    Bytes32 s;
    std::memcpy(s.data(), digest, 32);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    return s;
}

Bytes32 openssl_public_key(const Bytes32& seed) {
    EVP_PKEY* key =
        EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
    Bytes32 pk{};
    size_t length = pk.size();
    if (key == nullptr || EVP_PKEY_get_raw_public_key(key, pk.data(), &length) != 1) {
        std::fprintf(stderr, "OpenSSL key derivation failed\n");
        std::exit(2);
    }
    EVP_PKEY_free(key);
    return pk;
}

void test_sha512(std::mt19937_64& rng) {
    const int count = 4096;
    std::vector<uint32_t> seeds(count * 8), scalars(count * 8);
    std::vector<Bytes32> seed_bytes(count);
    for (int i = 0; i < count; ++i) {
        seed_bytes[i] = random_bytes(rng);
        std::memcpy(&seeds[i * 8], seed_bytes[i].data(), 32);
    }
    uint32_t* d_seeds = nullptr;
    uint32_t* d_scalars = nullptr;
    CUDA_CHECK(cudaMalloc(&d_seeds, seeds.size() * 4));
    CUDA_CHECK(cudaMalloc(&d_scalars, scalars.size() * 4));
    CUDA_CHECK(cudaMemcpy(d_seeds, seeds.data(), seeds.size() * 4, cudaMemcpyHostToDevice));
    sha_kernel<<<(count + 255) / 256, 256>>>(d_seeds, d_scalars, count);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaMemcpy(scalars.data(), d_scalars, scalars.size() * 4, cudaMemcpyDeviceToHost));
    cudaFree(d_seeds);
    cudaFree(d_scalars);

    for (int i = 0; i < count; ++i) {
        ++g_checks;
        const Bytes32 want = openssl_scalar(seed_bytes[i]);
        if (std::memcmp(want.data(), &scalars[i * 8], 32) != 0) {
            fail("sha512 scalar mismatch for seed " + hex(seed_bytes[i].data(), 32));
        }
    }
    std::printf("sha512: %d seeds\n", count);
}

// SHA-256 of the ssh-ed25519 public key blob of pk, as OpenSSL computes it
Bytes32 openssl_fingerprint(const Bytes32& pk) {
    uint8_t blob[51] = {
        0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 32
    };
    std::memcpy(blob + 19, pk.data(), pk.size());
    Bytes32 digest{};
    unsigned int length = 0;
    EVP_Digest(blob, sizeof(blob), digest.data(), &length, EVP_sha256(), nullptr);
    return digest;
}

void test_sha256(std::mt19937_64& rng) {
    const int count = 4096;
    std::vector<uint32_t> pks(count * 8), digests(count * 8);
    std::vector<Bytes32> pk_bytes(count);
    for (int i = 0; i < count; ++i) {
        pk_bytes[i] = random_bytes(rng);
        std::memcpy(&pks[i * 8], pk_bytes[i].data(), 32);
    }
    uint32_t* d_pks = nullptr;
    uint32_t* d_digests = nullptr;
    CUDA_CHECK(cudaMalloc(&d_pks, pks.size() * 4));
    CUDA_CHECK(cudaMalloc(&d_digests, digests.size() * 4));
    CUDA_CHECK(cudaMemcpy(d_pks, pks.data(), pks.size() * 4, cudaMemcpyHostToDevice));
    sha256_kernel<<<(count + 255) / 256, 256>>>(d_pks, d_digests, count);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaMemcpy(digests.data(), d_digests, digests.size() * 4, cudaMemcpyDeviceToHost));
    cudaFree(d_pks);
    cudaFree(d_digests);

    for (int i = 0; i < count; ++i) {
        ++g_checks;
        const Bytes32 want = openssl_fingerprint(pk_bytes[i]);
        Bytes32 got{};
        for (size_t j = 0; j < got.size(); ++j) {
            // The device returns big-endian words
            got[j] = static_cast<uint8_t>(digests[i * 8 + j / 4] >> (24 - 8 * (j % 4)));
        }
        if (want != got) {
            fail("sha256 fingerprint mismatch for key " + hex(pk_bytes[i].data(), 32));
        }
    }
    std::printf("sha256: %d keys\n", count);
}

void test_matcher(std::mt19937_64& rng) {
    const int count = 1024;
    const int trials = 400;
    std::vector<Bytes32> keys(count);
    for (auto& key : keys) {
        key = random_bytes(rng);
    }
    // Adversarial keys: all bits clear or set, and extreme values in the bytes
    // that share base64 groups with the constant key length byte
    keys[0].fill(0);
    keys[1].fill(0xff);
    keys[2].fill(0x55);
    keys[3].fill(0xaa);
    keys[4][0] = 0;
    keys[5][0] = 0xff;
    keys[6][31] = 0xff;
    keys[7][31] = 0;

    std::vector<std::string> key_strings(count), fingerprints(count);
    std::vector<uint32_t> pks(count * 8);
    for (int i = 0; i < count; ++i) {
        key_strings[i] = reference::key_string(keys[i].data());
        fingerprints[i] = reference::fingerprint_string(keys[i].data());
        std::memcpy(&pks[i * 8], keys[i].data(), 32);
    }
    uint32_t* d_pks = nullptr;
    uint8_t* d_out = nullptr;
    CUDA_CHECK(cudaMalloc(&d_pks, pks.size() * 4));
    CUDA_CHECK(cudaMalloc(&d_out, count));
    CUDA_CHECK(cudaMemcpy(d_pks, pks.data(), pks.size() * 4, cudaMemcpyHostToDevice));

    std::vector<uint8_t> out(count);
    int positives = 0;
    for (int t = 0; t < trials; ++t) {
        const int j = static_cast<int>(rng() % count);
        VanityCriteria criteria = reference::random_criteria(rng, key_strings[j], fingerprints[j]);
        if (t == 0) {
            criteria = VanityCriteria{};  // empty criteria match everything
        }
        upload_criteria(criteria);
        match_kernel<<<(count + 255) / 256, 256>>>(d_pks, d_out, count);
        CUDA_CHECK(cudaGetLastError());
        CUDA_CHECK(cudaMemcpy(out.data(), d_out, count, cudaMemcpyDeviceToHost));
        for (int i = 0; i < count; ++i) {
            ++g_checks;
            const bool expected = reference::matches(key_strings[i], fingerprints[i], criteria);
            positives += expected ? 1 : 0;
            if ((out[i] != 0) != expected) {
                fail(
                    std::string("device matcher ") + (expected ? "rejected " : "accepted ") +
                    reference::describe(criteria) + " for " + key_strings[i] + " / " +
                    fingerprints[i]
                );
            }
        }
    }
    cudaFree(d_pks);
    cudaFree(d_out);
    std::printf("matcher: %d criteria x %d keys, %d expected matches\n", trials, count, positives);
}

// ---------------------------------------------------------------------------
// Affine Edwards reference and scalar multiplication tests
// ---------------------------------------------------------------------------

struct Point {
    Big x, y;
};

struct Curve {
    const Field& field;
    Big d;
    Point base;

    explicit Curve(const Field& f)
        : field(f),
          base{
              Big("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a"),
              Big("6666666666666666666666666666666666666666666666666666666666666658")
          } {
        // d = -121665 / 121666
        d = field.mul(
            field.sub(Big(static_cast<uint64_t>(0)), Big(static_cast<uint64_t>(121665))),
            field.inv(Big(static_cast<uint64_t>(121666)))
        );
    }

    // Unified affine addition on -x^2 + y^2 = 1 + d x^2 y^2
    Point add(const Point& p, const Point& q) const {
        const Big x1x2 = field.mul(p.x, q.x);
        const Big y1y2 = field.mul(p.y, q.y);
        const Big t = field.mul(d, field.mul(x1x2, y1y2));
        const Big one(static_cast<uint64_t>(1));
        Point r;
        r.x = field.mul(
            field.add(field.mul(p.x, q.y), field.mul(p.y, q.x)), field.inv(field.add(one, t))
        );
        r.y = field.mul(field.add(y1y2, x1x2), field.inv(field.sub(one, t)));
        return r;
    }

    Point mul(const Big& scalar) const {
        Point r{Big(static_cast<uint64_t>(0)), Big(static_cast<uint64_t>(1))};
        for (int bit = 255; bit >= 0; --bit) {
            r = add(r, r);
            if (BN_is_bit_set(scalar.get(), bit)) {
                r = add(r, base);
            }
        }
        return r;
    }

    Bytes32 encode(const Point& p) const {
        Bytes32 out = field.to_bytes(p.y);
        if (BN_is_odd(field.reduce(p.x).get())) {
            out[31] |= 0x80;
        }
        return out;
    }
};

Big big_from_le(const Bytes32& bytes) {
    Big v;
    BN_lebin2bn(bytes.data(), 32, v.get());
    return v;
}

void test_scalarmult(
    const Field& field,
    const Curve& curve,
    const NielsEntry* d_table,
    std::mt19937_64& rng
) {
    // The reference itself must agree with OpenSSL
    for (int i = 0; i < 8; ++i) {
        const Bytes32 seed = random_bytes(rng);
        ++g_checks;
        if (curve.encode(curve.mul(big_from_le(openssl_scalar(seed)))) !=
            openssl_public_key(seed)) {
            fail("the BIGNUM Edwards reference disagrees with OpenSSL");
            return;
        }
    }

    std::vector<Big> scalars;
    const auto from_words = [](const std::vector<uint32_t>& words) {
        Bytes32 b{};
        std::memcpy(b.data(), words.data(), 32);
        return big_from_le(b);
    };
    const uint64_t small_scalars[] = {
        0,
        1,
        2,
        7,
        8,
        kHalf - 1,
        kHalf,
        kHalf + 1,
        (1ull << kWindow) - 1,
        1ull << kWindow,
    };
    for (const uint64_t v : small_scalars) {
        // Boundary digits belong to u in s = 2^254 + 8*u.
        scalars.emplace_back(v << 3);
    }
    {
        Big v(static_cast<uint64_t>(0));
        BN_set_bit(v.get(), 254);
        scalars.push_back(v);  // smallest clamped scalar
        Big w(static_cast<uint64_t>(0));
        BN_set_bit(w.get(), 255);
        BN_sub_word(w.get(), 8);
        scalars.push_back(w);  // largest clamped scalar
        BN_add_word(w.get(), 7);
        scalars.push_back(w);  // exercises clearing the low bits below
    }
    // Every window holding the same digit: the boundary digit kHalf, the first
    // negated digit kHalf + 1 (carry into every position), all ones, and
    // alternating patterns
    for (uint32_t digit : {kHalf, kHalf + 1, (1u << kWindow) - 1, 1u, (1u << kWindow) - 2}) {
        for (int pattern = 0; pattern < 3; ++pattern) {
            Big v(static_cast<uint64_t>(0));
            for (int i = 0; i < kPositions; ++i) {
                const uint32_t value = (pattern == 0 || (i % 2 == pattern - 1)) ? digit : 0;
                for (int b = 0; b < kWindow; ++b) {
                    if (((value >> b) & 1u) != 0 && 3 + kWindow * i + b < 254) {
                        BN_set_bit(v.get(), 3 + kWindow * i + b);
                    }
                }
            }
            scalars.push_back(v);
        }
    }
    for (int n = 0; n < 256; ++n) {
        std::vector<uint32_t> words(8);
        for (auto& w : words) {
            w = static_cast<uint32_t>(rng());
        }
        words[7] &= 0x7fffffffu;
        scalars.push_back(from_words(words));
        scalars.push_back(big_from_le(openssl_scalar(random_bytes(rng))));
    }

    const int count = static_cast<int>(scalars.size());
    std::vector<uint32_t> h_scalars(count * 8), h_out(count * 8);
    for (int i = 0; i < count; ++i) {
        // This table specializes in clamped scalars, including the minimum,
        // maximum and recoding boundaries constructed above.
        for (int bit : {0, 1, 2, 255}) {
            BN_clear_bit(scalars[i].get(), bit);
        }
        BN_set_bit(scalars[i].get(), 254);
        uint8_t bytes[32] = {};
        BN_bn2lebinpad(scalars[i].get(), bytes, 32);
        std::memcpy(&h_scalars[i * 8], bytes, 32);
    }
    uint32_t* d_scalars = nullptr;
    uint32_t* d_out = nullptr;
    CUDA_CHECK(cudaMalloc(&d_scalars, h_scalars.size() * 4));
    CUDA_CHECK(cudaMalloc(&d_out, h_out.size() * 4));
    CUDA_CHECK(
        cudaMemcpy(d_scalars, h_scalars.data(), h_scalars.size() * 4, cudaMemcpyHostToDevice)
    );
    scalarmult_kernel<<<(count + 255) / 256, 256>>>(d_table, d_scalars, d_out, count);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaMemcpy(h_out.data(), d_out, h_out.size() * 4, cudaMemcpyDeviceToHost));
    cudaFree(d_scalars);
    cudaFree(d_out);

    for (int i = 0; i < count; ++i) {
        ++g_checks;
        const Bytes32 want = curve.encode(curve.mul(scalars[i]));
        if (std::memcmp(want.data(), &h_out[i * 8], 32) != 0) {
            char* hex_scalar = BN_bn2hex(scalars[i].get());
            fail(
                std::string("scalarmult_clamped_base wrong for scalar 0x") + hex_scalar + ": got " +
                hex(reinterpret_cast<const uint8_t*>(&h_out[i * 8]), 32) + " want " +
                hex(want.data(), 32)
            );
            OPENSSL_free(hex_scalar);
        }
    }
    std::printf("scalar multiplication: %d scalars\n", count);
}

void test_batched_derivation(const NielsEntry* d_table, std::mt19937_64& rng) {
    const int count = kBatch * 64;
    std::vector<Bytes32> seeds(count);
    std::vector<uint32_t> h_seeds(count * 8), h_out(count * 8);
    for (int i = 0; i < count; ++i) {
        seeds[i] = random_bytes(rng);
        std::memcpy(&h_seeds[i * 8], seeds[i].data(), 32);
    }
    uint32_t* d_seeds = nullptr;
    uint32_t* d_out = nullptr;
    CUDA_CHECK(cudaMalloc(&d_seeds, h_seeds.size() * 4));
    CUDA_CHECK(cudaMalloc(&d_out, h_out.size() * 4));
    CUDA_CHECK(cudaMemcpy(d_seeds, h_seeds.data(), h_seeds.size() * 4, cudaMemcpyHostToDevice));
    derive_kernel<<<(count / kBatch + 255) / 256, 256>>>(d_table, d_seeds, d_out, count);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaMemcpy(h_out.data(), d_out, h_out.size() * 4, cudaMemcpyDeviceToHost));
    cudaFree(d_seeds);
    cudaFree(d_out);

    for (int i = 0; i < count; ++i) {
        ++g_checks;
        const Bytes32 want = openssl_public_key(seeds[i]);
        if (std::memcmp(want.data(), &h_out[i * 8], 32) != 0) {
            fail("batched derivation wrong for seed " + hex(seeds[i].data(), 32));
        }
    }
    std::printf("batched derivation: %d seeds\n", count);
}

}  // namespace

int main() {
    std::mt19937_64 rng(20260915);
    const Field field;
    const Curve curve(field);

    test_field_ops(field, rng);
    test_sha512(rng);
    test_sha256(rng);
    test_matcher(rng);

    NielsEntry* d_bases = nullptr;
    NielsEntry* d_table = nullptr;
    CUDA_CHECK(cudaMalloc(&d_bases, kPositionBases * sizeof(NielsEntry)));
    CUDA_CHECK(cudaMalloc(&d_table, kTableEntries * sizeof(NielsEntry)));
    gen_positions_kernel<<<1, kPositions>>>(d_bases);
    CUDA_CHECK(cudaGetLastError());
    gen_table_kernel<<<static_cast<unsigned int>((kTableEntries + 255) / 256), 256>>>(
        d_bases, d_table
    );
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    test_scalarmult(field, curve, d_table, rng);
    test_batched_derivation(d_table, rng);
    cudaFree(d_bases);
    cudaFree(d_table);

    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
