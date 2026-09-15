#include "cuda_backend.h"

#include <cstring>
#include <stdexcept>
#include <string>

#include <cuda_runtime.h>

#include "matcher.cuh"
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

struct DeviceResult {
    unsigned int found;
    uint32_t seed[8];
    uint32_t pubkey[8];
};

__constant__ uint32_t c_base_seed[8];

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
                if (matches_criteria(pk)) {
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

void CudaBackend::set_criteria(const VanityCriteria& criteria) {
    check(cudaSetDevice(impl_->device), "cudaSetDevice");
    upload_criteria(criteria);
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
