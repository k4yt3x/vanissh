#pragma once

#include <atomic>
#include <cstddef>
#include <string>
#include <vector>

#include "cuda/cuda_backend.h"
#include "ssh_key_generator.h"
#include "vanity_pattern.h"

struct CudaDeviceInfo {
    int index;
    std::string name;
    std::string config;
};

// Independent searches on distinct GPUs, stopped by the first verified match.
// Every candidate is re-derived with OpenSSL on the host before acceptance.
class CudaVanityGenerator {
   public:
    // An empty selection uses all visible CUDA devices. Duplicates are rejected.
    explicit CudaVanityGenerator(std::vector<int> devices);

    [[nodiscard]] const std::vector<CudaDeviceInfo>& devices() const { return devices_; }

    // Derive `count` random seeds on each GPU and OpenSSL and compare.
    // Throws std::runtime_error on any mismatch.
    void self_test(size_t count);

    VanityResult generate(
        const VanityCriteria& criteria,
        std::atomic<bool>* stop_flag,
        std::atomic<uint64_t>* total_attempts
    );

   private:
    std::vector<std::unique_ptr<CudaBackend>> backends_;
    std::vector<CudaDeviceInfo> devices_;
};
