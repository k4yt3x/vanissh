// Exercise the real multi-GPU coordinator with a simulated CudaBackend. No
// CUDA runtime is linked, so races, cancellation and failures can be tested
// on machines with one GPU or no GPUs. Key verification still uses OpenSSL.
#include <array>
#include <atomic>
#include <barrier>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "cuda/cuda_vanity_generator.h"

namespace {

enum class Mode {
    BothWin,
    OneWins,
    Cancel,
    LaunchError,
    WinAndError,
    BadKey,
    BadMatch,
    InitError,
    EnumerationError,
    SelfTestError
};

struct Scenario {
    Mode mode = Mode::BothWin;
    int available = 2;
    int winner = 0;
    int live = 0;
    std::array<int, 2> self_tests{};
    std::array<std::atomic<int>, 2> launches{};
    std::array<Bytes32, 2> first_seeds{};
    std::array<Bytes32, 2> result_seeds{};
    std::atomic<uint64_t> attempts{0};
    std::atomic<bool>* stop = nullptr;
    std::barrier<> first_launch;

    explicit Scenario(int participants = 2) : first_launch(participants) {}
};

Scenario* scenario = nullptr;
int checks = 0;

void check(bool value, const char* message) {
    ++checks;
    if (!value) {
        throw std::runtime_error(message);
    }
}

Bytes32 public_key(const Bytes32& seed) {
    SSHKeyGenerator generator;
    Bytes32 key{};
    if (!generator.load_from_seed(seed) || !generator.get_raw_public_key(key)) {
        throw std::runtime_error("OpenSSL derivation failed in test backend");
    }
    return key;
}

VanityCriteria always_matches() {
    VanityCriteria criteria;
    criteria.key.contains = "aaaac3nzac1lzdi1nte5aaaai";
    criteria.case_insensitive = true;
    return criteria;
}

template <typename Fn>
void expect_error(Fn fn, const std::string& text) {
    try {
        fn();
    } catch (const std::exception& e) {
        check(std::string(e.what()).contains(text), "unexpected error message");
        return;
    }
    check(false, "expected an exception");
}

void check_result(const VanityResult& result, const Scenario& state, size_t devices) {
    check(result.found, "search failed to return a winner");
    check(result.attempts == state.attempts.load(), "in-flight attempts were lost");
    check(!result.private_key_openssh.empty(), "winner has no private key");
    bool valid = false;
    for (size_t i = 0; i < devices; ++i) {
        SSHKeyGenerator generator;
        check(generator.load_from_seed(state.result_seeds[i]), "winner seed import failed");
        valid |= result.public_key_ssh == generator.get_public_key_ssh() &&
                 result.fingerprint_sha256 == generator.get_fingerprint_sha256();
    }
    check(valid, "public key and fingerprint came from different winners");
}

void test_selection() {
    Scenario state;
    scenario = &state;
    {
        CudaVanityGenerator generator({});
        check(generator.devices().size() == 2, "default selection must use every GPU");
        check(
            generator.devices()[0].index == 0 && generator.devices()[1].index == 1,
            "wrong default devices"
        );
        generator.self_test(4);
        check(
            state.self_tests[0] == 1 && state.self_tests[1] == 1, "each GPU must pass the self-test"
        );
    }
    check(state.live == 0, "GPU resources leaked");
    expect_error([] { CudaVanityGenerator generator({0, 0}); }, "more than once");
    expect_error([] { CudaVanityGenerator generator({0, 2}); }, "not available");
    expect_error([] { CudaVanityGenerator generator({-1}); }, "not available");
    check(state.live == 0, "invalid selection allocated a GPU");
    state.available = 0;
    expect_error([] { CudaVanityGenerator generator({}); }, "no CUDA devices");
    state.available = 2;
    state.mode = Mode::EnumerationError;
    expect_error([] { CudaVanityGenerator generator({}); }, "simulated driver failure");
    check(state.live == 0, "device enumeration failure allocated a GPU");
    state.mode = Mode::InitError;
    expect_error(
        [] { CudaVanityGenerator generator({}); }, "CUDA device 1: simulated init failure"
    );
    check(state.live == 0, "partial initialization leaked the first GPU");
    state.mode = Mode::SelfTestError;
    CudaVanityGenerator generator({});
    expect_error([&] { generator.self_test(4); }, "CUDA device 1: GPU self-test failed");
}

void test_winners(Mode mode, int winner) {
    Scenario state;
    state.mode = mode;
    state.winner = winner;
    scenario = &state;
    std::atomic<bool> stop(false);
    std::atomic<uint64_t> attempts(0);
    CudaVanityGenerator generator({});
    const VanityResult result = generator.generate(always_matches(), &stop, &attempts);
    check_result(result, state, 2);
    check(!stop.load(), "success must not change the interrupt flag");
    check(state.launches[0] > 0 && state.launches[1] > 0, "both GPUs must participate");
    check(state.first_seeds[0] != state.first_seeds[1], "GPUs reused a base seed");
    check(attempts.load() == result.attempts, "shared attempt counter is inconsistent");
}

void test_selected_device() {
    Scenario state(1);
    scenario = &state;
    std::atomic<bool> stop(false);
    std::atomic<uint64_t> attempts(0);
    CudaVanityGenerator generator({1});
    check(
        generator.devices().size() == 1 && generator.devices()[0].index == 1,
        "explicit device selection ignored"
    );
    const auto result = generator.generate(always_matches(), &stop, &attempts);
    check_result(result, state, 2);
    check(state.launches[0] == 0 && state.launches[1] == 1, "unselected GPU was used");
}

void test_cancellation() {
    Scenario state;
    state.mode = Mode::Cancel;
    scenario = &state;
    std::atomic<bool> stop(false);
    state.stop = &stop;
    std::atomic<uint64_t> attempts(0);
    CudaVanityGenerator generator({});
    const auto result = generator.generate(always_matches(), &stop, &attempts);
    check(!result.found && stop.load(), "interruption should return without a key");
    check(result.attempts == state.attempts.load(), "cancelled search lost completed work");
    const auto previous_attempts = attempts.load();
    const auto stopped = generator.generate(always_matches(), &stop, &attempts);
    check(
        !stopped.found && stopped.attempts == previous_attempts,
        "already interrupted search launched more work"
    );
}

void test_failure(Mode mode) {
    Scenario state;
    state.mode = mode;
    scenario = &state;
    std::atomic<bool> stop(false);
    std::atomic<uint64_t> attempts(0);
    CudaVanityGenerator generator({});
    auto criteria = always_matches();
    if (mode == Mode::BadMatch) {
        Bytes32 seed{};
        SSHKeyGenerator key;
        check(key.load_from_seed(seed), "bad-match fixture failed");
        criteria = {};
        criteria.key.suffix = key.get_public_key_ssh().back() == 'A' ? "B" : "A";
    }
    expect_error([&] { generator.generate(criteria, &stop, &attempts); }, "CUDA device 0:");
    check(state.launches[1] > 0, "failure did not exercise another running worker");
    check(!stop.load(), "worker failure changed the caller's interrupt flag");
}

}  // namespace

struct CudaBackend::Impl {
    int device;
    explicit Impl(int index) : device(index) { ++scenario->live; }
    ~Impl() { --scenario->live; }
};

int CudaBackend::device_count() {
    if (scenario->mode == Mode::EnumerationError) {
        throw std::runtime_error("simulated driver failure");
    }
    return scenario->available;
}

CudaBackend::CudaBackend(int device) {
    if (scenario->mode == Mode::InitError && device == 1) {
        throw std::runtime_error("simulated init failure");
    }
    impl_ = std::make_unique<Impl>(device);
}

CudaBackend::~CudaBackend() = default;
std::string CudaBackend::device_name() const {
    return "simulated GPU";
}
std::string CudaBackend::config_summary() const {
    return "simulated configuration";
}
void CudaBackend::set_criteria(const VanityCriteria&) {}

uint64_t CudaBackend::keys_per_launch(uint32_t batches) const {
    // Different rates help catch accidental counting with another GPU's configuration.
    return static_cast<uint64_t>(impl_->device + 1) * 32 * batches;
}

std::vector<Bytes32> CudaBackend::compute_public_keys(const std::vector<Bytes32>& seeds) {
    ++scenario->self_tests[static_cast<size_t>(impl_->device)];
    std::vector<Bytes32> keys;
    for (const auto& seed : seeds) {
        keys.push_back(public_key(seed));
    }
    if (scenario->mode == Mode::SelfTestError && impl_->device == 1 && !keys.empty()) {
        keys[0][0] ^= 1;
    }
    return keys;
}

CudaLaunchResult CudaBackend::launch(const Bytes32& base_seed, uint32_t batches) {
    const int device = impl_->device;
    const size_t index = static_cast<size_t>(device);
    const int launch = ++scenario->launches[index];
    if (launch == 1) {
        scenario->first_seeds[index] = base_seed;
        scenario->first_launch.arrive_and_wait();
    }
    if ((scenario->mode == Mode::LaunchError || scenario->mode == Mode::WinAndError) &&
        device == 0) {
        throw std::runtime_error("simulated launch failure");
    }
    scenario->attempts.fetch_add(keys_per_launch(batches));
    if (scenario->mode == Mode::Cancel) {
        scenario->stop->store(true);
        return {};
    }
    const bool wins =
        scenario->mode == Mode::BothWin || (scenario->mode == Mode::WinAndError && device == 1) ||
        (scenario->mode == Mode::OneWins && device == scenario->winner) ||
        ((scenario->mode == Mode::BadKey || scenario->mode == Mode::BadMatch) && device == 0);
    if (!wins) {
        std::this_thread::yield();
        return {};
    }
    CudaLaunchResult result;
    result.found = true;
    result.seed = scenario->mode == Mode::BadMatch ? Bytes32{} : base_seed;
    result.public_key = public_key(result.seed);
    scenario->result_seeds[index] = result.seed;
    if (scenario->mode == Mode::BadKey) {
        result.public_key[0] ^= 1;
    }
    return result;
}

int main() try {
    test_selection();
    // Repeat the simultaneous-winner race without depending on thread ordering.
    for (int i = 0; i < 25; ++i) {
        test_winners(Mode::BothWin, 0);
        test_failure(Mode::WinAndError);
    }
    test_winners(Mode::OneWins, 0);
    test_winners(Mode::OneWins, 1);
    test_selected_device();
    test_cancellation();
    test_failure(Mode::LaunchError);
    test_failure(Mode::BadKey);
    test_failure(Mode::BadMatch);
    std::printf("%d multi-GPU coordination checks passed\n", checks);
    return 0;
} catch (const std::exception& e) {
    std::fprintf(stderr, "FAIL: %s\n", e.what());
    return 1;
}
