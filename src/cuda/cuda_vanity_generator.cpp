#include "cuda/cuda_vanity_generator.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <format>
#include <stdexcept>
#include <vector>

#include <openssl/rand.h>

namespace {

// Keep launches short enough that Ctrl-C and the progress display stay
// responsive, but long enough that launch overhead is negligible.
constexpr double kTargetLaunchSeconds = 0.05;
constexpr uint32_t kMaxIterations = 1u << 16;

// Same private DRBG that OpenSSL uses for its own key generation
Bytes32 random_bytes() {
    Bytes32 bytes;
    if (RAND_priv_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw std::runtime_error("RAND_priv_bytes failed");
    }
    return bytes;
}

}  // namespace

CudaVanityGenerator::CudaVanityGenerator(int device) : backend_(device) {}

std::string CudaVanityGenerator::device_name() const {
    return backend_.device_name();
}

std::string CudaVanityGenerator::config_summary() const {
    return backend_.config_summary();
}

void CudaVanityGenerator::self_test(size_t count) {
    std::vector<Bytes32> seeds(count);
    for (auto& seed : seeds) {
        seed = random_bytes();
    }

    const std::vector<Bytes32> gpu_keys = backend_.compute_public_keys(seeds);

    SSHKeyGenerator generator;
    for (size_t i = 0; i < count; ++i) {
        Bytes32 expected{};
        if (!generator.load_from_seed(seeds[i]) || !generator.get_raw_public_key(expected)) {
            throw std::runtime_error("OpenSSL failed to derive a key during the GPU self-test");
        }
        if (expected != gpu_keys[i]) {
            throw std::runtime_error(
                std::format("GPU self-test failed: public key mismatch for seed {}", i)
            );
        }
    }
}

VanityResult CudaVanityGenerator::generate(
    const VanityCriteria& criteria,
    std::atomic<bool>* stop_flag,
    std::atomic<uint64_t>* total_attempts
) {
    backend_.set_criteria(criteria);
    // SSHKeyGenerator::matches expects lower-cased patterns for case-insensitive matching
    const VanityCriteria check_criteria =
        criteria.case_insensitive ? criteria.lowercased() : criteria;

    VanityResult result;

    uint32_t iterations = 1;
    while (!stop_flag->load(std::memory_order_relaxed)) {
        const auto start = std::chrono::steady_clock::now();
        const CudaLaunchResult launch = backend_.launch(random_bytes(), iterations);
        const std::chrono::duration<double> elapsed = std::chrono::steady_clock::now() - start;

        total_attempts->fetch_add(backend_.keys_per_launch(iterations), std::memory_order_relaxed);

        if (launch.found) {
            SSHKeyGenerator generator;
            Bytes32 host_key{};
            if (!generator.load_from_seed(launch.seed) || !generator.get_raw_public_key(host_key)) {
                throw std::runtime_error("OpenSSL rejected the seed found by the GPU");
            }
            if (host_key != launch.public_key || !generator.matches(check_criteria)) {
                throw std::runtime_error(
                    "the key found by the GPU failed host verification; this is a bug"
                );
            }
            result.found = true;
            result.public_key_ssh = generator.get_public_key_ssh();
            result.fingerprint_sha256 = generator.get_fingerprint_sha256();
            result.private_key_openssh = generator.get_private_key_openssh();
            break;
        }

        // Scale the per-launch work towards the target launch duration
        const double ratio = kTargetLaunchSeconds / std::max(elapsed.count(), 1e-4);
        if (ratio < 0.8 || ratio > 1.25) {
            const double next =
                std::clamp(iterations * ratio, 1.0, static_cast<double>(kMaxIterations));
            iterations = static_cast<uint32_t>(next);
        }
    }

    result.attempts = total_attempts->load();
    return result;
}
