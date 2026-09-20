#include "cuda/cuda_vanity_generator.h"

#include <algorithm>
#include <chrono>
#include <exception>
#include <format>
#include <mutex>
#include <numeric>
#include <stdexcept>
#include <thread>
#include <utility>
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

void self_test_device(CudaBackend& backend, size_t count) {
    std::vector<Bytes32> seeds(count);
    for (auto& seed : seeds) {
        seed = random_bytes();
    }

    const std::vector<Bytes32> gpu_keys = backend.compute_public_keys(seeds);

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

VanityResult search_device(
    CudaBackend& backend,
    const VanityCriteria& criteria,
    const VanityCriteria& check_criteria,
    std::atomic<bool>* stop_flag,
    const std::atomic<bool>& finished,
    std::atomic<uint64_t>* total_attempts
) {
    backend.set_criteria(criteria);

    VanityResult result;

    uint32_t iterations = 1;
    while (!stop_flag->load(std::memory_order_relaxed) &&
           !finished.load(std::memory_order_relaxed)) {
        const auto start = std::chrono::steady_clock::now();
        const CudaLaunchResult launch = backend.launch(random_bytes(), iterations);
        const std::chrono::duration<double> elapsed = std::chrono::steady_clock::now() - start;

        total_attempts->fetch_add(backend.keys_per_launch(iterations), std::memory_order_relaxed);

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
            if (result.private_key_openssh.empty()) {
                throw std::runtime_error("failed to serialize the key found by the GPU");
            }
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

    return result;
}

}  // namespace

CudaVanityGenerator::CudaVanityGenerator(std::vector<int> devices) {
    const int count = CudaBackend::device_count();
    if (count == 0) {
        throw std::runtime_error("no CUDA devices are available");
    }
    if (devices.empty()) {
        devices.resize(static_cast<size_t>(count));
        std::iota(devices.begin(), devices.end(), 0);
    }
    // Validate the entire selection before allocating any GPU resources.
    for (size_t i = 0; i < devices.size(); ++i) {
        if (devices[i] < 0 || devices[i] >= count) {
            throw std::runtime_error(std::format("CUDA device {} is not available", devices[i]));
        }
        if (std::find(
                devices.begin(), devices.begin() + static_cast<std::ptrdiff_t>(i), devices[i]
            ) != devices.begin() + static_cast<std::ptrdiff_t>(i)) {
            throw std::runtime_error(
                std::format("CUDA device {} was selected more than once", devices[i])
            );
        }
    }
    for (const int device : devices) {
        try {
            auto backend = std::make_unique<CudaBackend>(device);
            devices_.push_back({device, backend->device_name(), backend->config_summary()});
            backends_.push_back(std::move(backend));
        } catch (const std::exception& e) {
            throw std::runtime_error(std::format("CUDA device {}: {}", device, e.what()));
        }
    }
}

void CudaVanityGenerator::self_test(size_t count) {
    for (size_t i = 0; i < backends_.size(); ++i) {
        try {
            self_test_device(*backends_[i], count);
        } catch (const std::exception& e) {
            throw std::runtime_error(
                std::format("CUDA device {}: {}", devices_[i].index, e.what())
            );
        }
    }
}

VanityResult CudaVanityGenerator::generate(
    const VanityCriteria& criteria,
    std::atomic<bool>* stop_flag,
    std::atomic<uint64_t>* total_attempts
) {
    const VanityCriteria check_criteria =
        criteria.case_insensitive ? criteria.lowercased() : criteria;
    // Separate from the caller's interrupt flag: success is not an interruption.
    std::atomic<bool> finished(false);
    std::mutex mutex;
    VanityResult result;
    std::exception_ptr error;
    int failed_device = -1;
    std::vector<std::jthread> workers;
    workers.reserve(backends_.size());
    try {
        for (size_t i = 0; i < backends_.size(); ++i) {
            workers.emplace_back([&, i] {
                try {
                    VanityResult candidate = search_device(
                        *backends_[i], criteria, check_criteria, stop_flag, finished, total_attempts
                    );
                    if (candidate.found) {
                        std::lock_guard lock(mutex);
                        if (!finished.load(std::memory_order_relaxed)) {
                            result = std::move(candidate);
                            finished.store(true, std::memory_order_relaxed);
                        }
                    }
                } catch (...) {
                    std::lock_guard lock(mutex);
                    if (!error) {
                        error = std::current_exception();
                        failed_device = devices_[i].index;
                    }
                    finished.store(true, std::memory_order_relaxed);
                }
            });
        }
    } catch (...) {
        // jthread destruction joins workers even if creating a later thread fails.
        finished.store(true, std::memory_order_relaxed);
        throw;
    }
    for (auto& worker : workers) {
        worker.join();
    }
    if (error) {
        // A worker failure is fatal even if another worker found a valid key.
        try {
            std::rethrow_exception(error);
        } catch (const std::exception& e) {
            throw std::runtime_error(std::format("CUDA device {}: {}", failed_device, e.what()));
        }
    }
    // Include work completed by other devices while the winner was being verified.
    result.attempts = total_attempts->load(std::memory_order_relaxed);
    return result;
}
