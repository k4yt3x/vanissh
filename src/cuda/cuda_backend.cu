#include "cuda_backend.h"

#include <cstring>
#include <stdexcept>
#include <string>

#include <cuda_runtime.h>

#include "scalarmult.cuh"

// Minimum number of resident blocks per SM the key kernels are compiled for.
// This caps register usage at 65536 / (kBlockSize * kMinBlocksPerSm) and thus
// fixes the occupancy, instead of leaving it to ptxas heuristics.
#ifndef VANISSH_CUDA_MIN_BLOCKS
#define VANISSH_CUDA_MIN_BLOCKS 2
#endif

namespace {

using namespace ed25519;

constexpr int kBlockSize = 256;
constexpr int kMinBlocksPerSm = VANISSH_CUDA_MIN_BLOCKS;

constexpr int kKeyChars = 68;    // base64 length of an ssh-ed25519 public key blob
constexpr int kFixedChars = 25;  // "AAAAC3NzaC1lZDI1NTE5AAAAI" is constant
constexpr int kMaxPatternLen = kKeyChars;
constexpr char kBase64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

struct DeviceResult {
    unsigned int found;
    uint32_t seed[8];
    uint32_t pubkey[8];
};

__constant__ uint32_t c_base_seed[8];
// Sextet codes of the 24 base64 characters that only depend on the fixed header.
__constant__ uint8_t c_fixed_sextets[24];
// Patterns as base64 sextet codes, [kind][variant][i]. Variant 1 holds the
// alternate-case code for case-insensitive matching (same as variant 0 otherwise).
__constant__ uint8_t c_pattern[3][2][kMaxPatternLen];
__constant__ int c_pattern_len[3];

// ---------------------------------------------------------------------------
// Device code
// ---------------------------------------------------------------------------

__device__ __forceinline__ bool sextet_matches(uint8_t v, int kind, int i) {
    return v == c_pattern[kind][0][i] || v == c_pattern[kind][1][i];
}

// Checks the base64 form of the public key blob against the configured pattern.
__device__ bool matches_pattern(const uint32_t pk[8]) {
    // Sextets of the 68-character base64 string. The blob is 51 bytes; the
    // first 18 are constant and the 19th (0x20, the key length) shares a
    // base64 group with the first two key bytes.
    uint8_t sx[kKeyChars];
#pragma unroll
    for (int i = 0; i < 24; ++i) {
        sx[i] = c_fixed_sextets[i];
    }
    uint8_t bytes[33];
    bytes[0] = 0x20;
#pragma unroll
    for (int i = 0; i < 32; ++i) {
        bytes[1 + i] = static_cast<uint8_t>(pk[i >> 2] >> (8 * (i & 3)));
    }
#pragma unroll
    for (int t = 0; t < 11; ++t) {
        const uint32_t b0 = bytes[3 * t], b1 = bytes[3 * t + 1], b2 = bytes[3 * t + 2];
        sx[24 + 4 * t] = static_cast<uint8_t>(b0 >> 2);
        sx[24 + 4 * t + 1] = static_cast<uint8_t>(((b0 & 3) << 4) | (b1 >> 4));
        sx[24 + 4 * t + 2] = static_cast<uint8_t>(((b1 & 15) << 2) | (b2 >> 6));
        sx[24 + 4 * t + 3] = static_cast<uint8_t>(b2 & 63);
    }

    const int prefix_len = c_pattern_len[0];
    for (int i = 0; i < prefix_len; ++i) {
        if (!sextet_matches(sx[kFixedChars + i], 0, i)) {
            return false;
        }
    }

    const int suffix_len = c_pattern_len[1];
    for (int i = 0; i < suffix_len; ++i) {
        if (!sextet_matches(sx[kKeyChars - suffix_len + i], 1, i)) {
            return false;
        }
    }

    const int contains_len = c_pattern_len[2];
    if (contains_len > 0) {
        bool found = false;
        for (int pos = 0; pos + contains_len <= kKeyChars && !found; ++pos) {
            bool ok = true;
            for (int i = 0; i < contains_len && ok; ++i) {
                ok = sextet_matches(sx[pos + i], 2, i);
            }
            found = ok;
        }
        if (!found) {
            return false;
        }
    }

    return true;
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

// Each thread derives kBatch consecutive seeds; count must be a multiple of kBatch.
__global__ void __launch_bounds__(kBlockSize, kMinBlocksPerSm) pubkey_kernel(
    const NielsEntry* __restrict__ table,
    const uint32_t* __restrict__ seeds,
    uint32_t* __restrict__ out,
    uint32_t count
) {
    const uint32_t first = (blockIdx.x * blockDim.x + threadIdx.x) * kBatch;
    if (first >= count) {
        return;
    }
    derive_public_keys(
        table,
        [&](int k, uint32_t* seed) {
#pragma unroll
            for (int i = 0; i < 8; ++i) {
                seed[i] = seeds[(first + static_cast<uint32_t>(k)) * 8 + i];
            }
        },
        [&](int k, const uint32_t* pk) {
#pragma unroll
            for (int i = 0; i < 8; ++i) {
                out[(first + static_cast<uint32_t>(k)) * 8 + i] = pk[i];
            }
        }
    );
}

__global__ void __launch_bounds__(
    kBlockSize,
    kMinBlocksPerSm
) vanity_kernel(const NielsEntry* __restrict__ table, uint32_t batches, DeviceResult* result) {
    const uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t nthreads = gridDim.x * blockDim.x;

    // Seeds are unique per (launch, thread, key); the base seed is fresh CSPRNG
    // output for every launch.
    const auto make_seed = [&](uint64_t counter, uint32_t* seed) {
#pragma unroll
        for (int i = 0; i < 8; ++i) {
            seed[i] = c_base_seed[i];
        }
        seed[0] ^= static_cast<uint32_t>(counter);
        seed[1] ^= static_cast<uint32_t>(counter >> 32);
    };

    for (uint32_t b = 0; b < batches; ++b) {
        const uint64_t base_counter = static_cast<uint64_t>(b) * kBatch * nthreads + tid;
        derive_public_keys(
            table,
            [&](int k, uint32_t* seed) {
                make_seed(base_counter + static_cast<uint64_t>(k) * nthreads, seed);
            },
            [&](int k, const uint32_t* pk) {
                if (matches_pattern(pk)) {
                    if (atomicCAS(&result->found, 0u, 1u) == 0u) {
                        uint32_t seed[8];
                        make_seed(base_counter + static_cast<uint64_t>(k) * nthreads, seed);
#pragma unroll
                        for (int i = 0; i < 8; ++i) {
                            result->seed[i] = seed[i];
                            result->pubkey[i] = pk[i];
                        }
                    }
                }
            }
        );
    }
}

// ---------------------------------------------------------------------------
// Host helpers
// ---------------------------------------------------------------------------

void check(cudaError_t err, const char* what) {
    if (err != cudaSuccess) {
        throw std::runtime_error(
            std::string("CUDA error (") + what + "): " + cudaGetErrorString(err)
        );
    }
}

uint8_t base64_index(char c) {
    const char* pos = std::strchr(kBase64Alphabet, c);
    if (c == '\0' || pos == nullptr) {
        throw std::runtime_error(std::string("invalid base64 character '") + c + "'");
    }
    return static_cast<uint8_t>(pos - kBase64Alphabet);
}

}  // namespace

struct CudaBackend::Impl {
    int device = 0;
    cudaDeviceProp prop{};
    NielsEntry* d_table = nullptr;
    DeviceResult* d_result = nullptr;
    int grid_blocks = 0;

    ~Impl() {
        cudaFree(d_table);
        cudaFree(d_result);
    }
};

int CudaBackend::device_count() {
    int count = 0;
    if (cudaGetDeviceCount(&count) != cudaSuccess) {
        return 0;
    }
    return count;
}

CudaBackend::CudaBackend(int device) : impl_(std::make_unique<Impl>()) {
    impl_->device = device;
    check(cudaSetDevice(device), "cudaSetDevice");
    check(cudaGetDeviceProperties(&impl_->prop, device), "cudaGetDeviceProperties");

    // Precompute the fixed-base table on the device itself.
    check(cudaMalloc(&impl_->d_table, kTableEntries * sizeof(NielsEntry)), "cudaMalloc table");
    NielsEntry* d_bases = nullptr;
    check(cudaMalloc(&d_bases, kPositions * sizeof(NielsEntry)), "cudaMalloc bases");
    gen_positions_kernel<<<1, kPositions>>>(d_bases);
    check(cudaGetLastError(), "gen_positions_kernel");
    const unsigned int table_blocks = static_cast<unsigned int>((kTableEntries + 255) / 256);
    gen_table_kernel<<<table_blocks, 256>>>(d_bases, impl_->d_table);
    check(cudaGetLastError(), "gen_table_kernel");
    check(cudaDeviceSynchronize(), "table generation");
    cudaFree(d_bases);

    // Sextets of the constant part of the base64 string.
    const uint8_t header[18] = {
        0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0
    };
    uint8_t fixed[24];
    for (int t = 0; t < 6; ++t) {
        const uint32_t b0 = header[3 * t], b1 = header[3 * t + 1], b2 = header[3 * t + 2];
        fixed[4 * t] = static_cast<uint8_t>(b0 >> 2);
        fixed[4 * t + 1] = static_cast<uint8_t>(((b0 & 3) << 4) | (b1 >> 4));
        fixed[4 * t + 2] = static_cast<uint8_t>(((b1 & 15) << 2) | (b2 >> 6));
        fixed[4 * t + 3] = static_cast<uint8_t>(b2 & 63);
    }
    check(cudaMemcpyToSymbol(c_fixed_sextets, fixed, sizeof(fixed)), "cudaMemcpyToSymbol fixed");

    check(cudaMalloc(&impl_->d_result, sizeof(DeviceResult)), "cudaMalloc result");

    int blocks_per_sm = 0;
    check(
        cudaOccupancyMaxActiveBlocksPerMultiprocessor(&blocks_per_sm, vanity_kernel, kBlockSize, 0),
        "cudaOccupancyMaxActiveBlocksPerMultiprocessor"
    );
    if (blocks_per_sm < 1) {
        blocks_per_sm = 1;
    }
    impl_->grid_blocks = blocks_per_sm * impl_->prop.multiProcessorCount;
}

CudaBackend::~CudaBackend() = default;

std::string CudaBackend::device_name() const {
    return impl_->prop.name;
}

std::string CudaBackend::config_summary() const {
    const size_t table_bytes = kTableEntries * sizeof(NielsEntry);
    return "window " + std::to_string(kWindow) + " bits, " + std::to_string(kPositions) +
           " point additions/key, table " + std::to_string(table_bytes / (1024 * 1024)) + " MiB, " +
           std::to_string(impl_->grid_blocks) + "x" + std::to_string(kBlockSize) + " threads x " +
           std::to_string(kBatch) + " keys/inversion";
}

uint64_t CudaBackend::keys_per_launch(uint32_t batches) const {
    return static_cast<uint64_t>(impl_->grid_blocks) * kBlockSize * kBatch * batches;
}

void CudaBackend::set_pattern(const VanityPattern& pattern) {
    check(cudaSetDevice(impl_->device), "cudaSetDevice");
    uint8_t codes[3][2][kMaxPatternLen] = {};
    int lengths[3] = {};
    const std::string* parts[3] = {&pattern.prefix, &pattern.suffix, &pattern.contains};
    for (int kind = 0; kind < 3; ++kind) {
        const std::string& part = *parts[kind];
        if (part.size() > static_cast<size_t>(kMaxPatternLen)) {
            throw std::runtime_error("pattern is longer than the public key");
        }
        lengths[kind] = static_cast<int>(part.size());
        for (size_t i = 0; i < part.size(); ++i) {
            const char c = part[i];
            char alt = c;
            if (pattern.case_insensitive) {
                if (c >= 'a' && c <= 'z') {
                    alt = static_cast<char>(c - 'a' + 'A');
                } else if (c >= 'A' && c <= 'Z') {
                    alt = static_cast<char>(c - 'A' + 'a');
                }
            }
            codes[kind][0][i] = base64_index(c);
            codes[kind][1][i] = base64_index(alt);
        }
    }
    check(cudaMemcpyToSymbol(c_pattern, codes, sizeof(codes)), "cudaMemcpyToSymbol pattern");
    check(
        cudaMemcpyToSymbol(c_pattern_len, lengths, sizeof(lengths)), "cudaMemcpyToSymbol lengths"
    );
}

std::vector<Bytes32> CudaBackend::compute_public_keys(const std::vector<Bytes32>& seeds) {
    check(cudaSetDevice(impl_->device), "cudaSetDevice");
    // Every thread derives kBatch keys, so pad to a multiple of the batch size.
    const size_t padded = (seeds.size() + kBatch - 1) / kBatch * kBatch;
    std::vector<uint32_t> h_seeds(padded * 8, 0);
    for (size_t i = 0; i < seeds.size(); ++i) {
        std::memcpy(&h_seeds[i * 8], seeds[i].data(), 32);
    }

    uint32_t* d_seeds = nullptr;
    uint32_t* d_out = nullptr;
    check(cudaMalloc(&d_seeds, padded * 32), "cudaMalloc seeds");
    check(cudaMalloc(&d_out, padded * 32), "cudaMalloc pubkeys");
    check(cudaMemcpy(d_seeds, h_seeds.data(), padded * 32, cudaMemcpyHostToDevice), "upload seeds");

    const size_t threads = padded / kBatch;
    const unsigned int blocks = static_cast<unsigned int>((threads + kBlockSize - 1) / kBlockSize);
    pubkey_kernel<<<blocks, kBlockSize>>>(
        impl_->d_table, d_seeds, d_out, static_cast<uint32_t>(padded)
    );
    check(cudaGetLastError(), "pubkey_kernel");

    std::vector<uint32_t> h_out(padded * 8);
    check(cudaMemcpy(h_out.data(), d_out, padded * 32, cudaMemcpyDeviceToHost), "download pubkeys");
    cudaFree(d_seeds);
    cudaFree(d_out);

    std::vector<Bytes32> result(seeds.size());
    for (size_t i = 0; i < seeds.size(); ++i) {
        std::memcpy(result[i].data(), &h_out[i * 8], 32);
    }
    return result;
}

CudaLaunchResult CudaBackend::launch(const Bytes32& base_seed, uint32_t batches) {
    check(cudaSetDevice(impl_->device), "cudaSetDevice");
    check(
        cudaMemcpyToSymbol(c_base_seed, base_seed.data(), base_seed.size()),
        "cudaMemcpyToSymbol base seed"
    );
    check(cudaMemsetAsync(impl_->d_result, 0, sizeof(unsigned int)), "reset result");

    vanity_kernel<<<impl_->grid_blocks, kBlockSize>>>(impl_->d_table, batches, impl_->d_result);
    check(cudaGetLastError(), "vanity_kernel");

    DeviceResult host{};
    check(
        cudaMemcpy(&host, impl_->d_result, sizeof(host), cudaMemcpyDeviceToHost), "download result"
    );

    CudaLaunchResult result;
    result.found = host.found != 0;
    if (result.found) {
        std::memcpy(result.seed.data(), host.seed, 32);
        std::memcpy(result.public_key.data(), host.pubkey, 32);
    }
    return result;
}
