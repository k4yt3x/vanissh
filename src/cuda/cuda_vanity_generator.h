#pragma once

#include <atomic>
#include <cstddef>
#include <string>

#include "cuda/cuda_backend.h"
#include "ssh_key_generator.h"
#include "vanity_pattern.h"

// GPU vanity key search. The GPU only searches; every candidate it reports is
// re-derived with OpenSSL on the host before it is accepted.
class CudaVanityGenerator {
   public:
    explicit CudaVanityGenerator(int device);

    [[nodiscard]] std::string device_name() const;
    [[nodiscard]] std::string config_summary() const;

    // Derive `count` random seeds on both the GPU and OpenSSL and compare.
    // Throws std::runtime_error on any mismatch.
    void self_test(size_t count);

    VanityResult generate(
        const VanityCriteria& criteria,
        std::atomic<bool>* stop_flag,
        std::atomic<uint64_t>* total_attempts
    );

   private:
    CudaBackend backend_;
};
