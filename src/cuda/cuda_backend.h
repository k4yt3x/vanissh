#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "vanity_pattern.h"

using Bytes32 = std::array<uint8_t, 32>;

struct CudaLaunchResult {
    bool found = false;
    Bytes32 seed{};
    Bytes32 public_key{};
};

// Thin wrapper around the CUDA kernels. Every method throws std::runtime_error
// on CUDA errors. Must be used from the thread that constructed it.
class CudaBackend {
   public:
    static int device_count();

    explicit CudaBackend(int device);
    ~CudaBackend();
    CudaBackend(const CudaBackend&) = delete;
    CudaBackend& operator=(const CudaBackend&) = delete;

    [[nodiscard]] std::string device_name() const;
    // Human-readable description of the kernel configuration
    [[nodiscard]] std::string config_summary() const;
    [[nodiscard]] uint64_t keys_per_launch(uint32_t batches) const;

    void set_pattern(const VanityPattern& pattern);

    // Derive the Ed25519 public keys of the given seeds on the GPU
    std::vector<Bytes32> compute_public_keys(const std::vector<Bytes32>& seeds);

    // Run one synchronous search launch. Every thread derives `batches`
    // batches of keys from seeds obtained by mixing a unique counter into
    // base_seed.
    CudaLaunchResult launch(const Bytes32& base_seed, uint32_t batches);

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
