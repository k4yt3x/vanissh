#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>

#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>

#include "ssh_key_generator.h"
#include "vanity_pattern.h"

#ifdef VANISSH_CUDA
#include "cuda/cuda_vanity_generator.h"
#endif

#ifndef VANISSH_VERSION
#define VANISSH_VERSION "unknown"
#endif

namespace {

constexpr std::string_view kVersion = VANISSH_VERSION;
constexpr std::string_view kBase64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr int64_t kProgressRefreshIntervalSec = 1;
// Length of the base64 form of an ssh-ed25519 public key, and of its constant prefix
constexpr size_t kKeyBase64Length = 68;
constexpr size_t kFixedPrefixLength = 25;
#ifdef VANISSH_CUDA
constexpr size_t kGpuSelfTestKeys = 4096;
#endif

// Set by the signal handler, checked by the search loops and the progress thread
std::atomic<bool> g_stop_flag(false);
std::atomic<uint64_t> g_total_attempts(0);

struct Options {
    VanityPattern pattern;
    std::string output_file;
    int num_threads = 0;
    bool use_gpu = false;
    int gpu_device = 0;
};

// Only async-signal-safe operations are allowed here: write(2), _exit(2) and
// lock-free atomics. The progress thread may be inside std::print at any time.
void signal_handler(int /*signal*/) {
    static_assert(std::atomic<bool>::is_always_lock_free);
    if (g_stop_flag.load()) {
        constexpr std::string_view message = "\nForce exiting...\n";
        std::ignore = write(STDERR_FILENO, message.data(), message.size());
        _exit(1);
    }
    constexpr std::string_view message = "\nReceived interrupt signal. Stopping generation...\n";
    std::ignore = write(STDOUT_FILENO, message.data(), message.size());
    g_stop_flag.store(true);
}

void print_usage() {
    std::print(
        "Usage: vanissh [OPTIONS]\n\n"
        "Generate vanity SSH public keys that start/end with specified strings.\n\n"
        "Options:\n"
        "  -p, --prefix PREFIX    Desired prefix for the base64 public key\n"
        "  -s, --suffix SUFFIX    Desired suffix for the base64 public key\n"
        "  -c, --contains STRING  String that must appear anywhere in the base64 public key\n"
        "  -j, --threads NUM      Number of threads to use (default: auto)\n"
#ifdef VANISSH_CUDA
        "  -g, --gpu              Search on the GPU with CUDA instead of the CPU\n"
        "  -d, --device NUM       CUDA device index to use; implies --gpu (default: 0)\n"
#endif
        "  -o, --output FILE      Output private key to file (default: stdout)\n"
        "  -i, --ignore-case      Case-insensitive matching\n"
        "  -h, --help             Show this help message\n\n"
        "Notes:\n"
        "  - At least one of --prefix, --suffix, or --contains must be specified.\n"
        "  - Ed25519 public keys will always start with 'AAAAC3NzaC1lZDI1NTE5AAAAI',\n"
        "      which will be skipped when matching prefixes.\n"
        "  - The first character after that prefix is always one of A-P.\n\n"
        "Examples:\n"
        "  vanissh -s TEST\n"
        "  vanissh -c 1337 -i\n"
        "  vanissh -p abc -i -o id_ed25519\n"
#ifdef VANISSH_CUDA
        "  vanissh -g -s TEST -o id_ed25519\n"
#endif
    );
}

std::optional<int> parse_int(std::string_view text) {
    int value = 0;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc() || end != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

// Returns false if the program should exit with exit_code
bool parse_options(int argc, char* argv[], Options& options, int& exit_code) {
    static const option long_options[] = {
        {"prefix", required_argument, nullptr, 'p'},
        {"suffix", required_argument, nullptr, 's'},
        {"contains", required_argument, nullptr, 'c'},
        {"threads", required_argument, nullptr, 'j'},
        {"gpu", no_argument, nullptr, 'g'},
        {"device", required_argument, nullptr, 'd'},
        {"output", required_argument, nullptr, 'o'},
        {"ignore-case", no_argument, nullptr, 'i'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };

    exit_code = 1;
    int c = 0;
    while ((c = getopt_long(argc, argv, "p:s:c:j:gd:o:ih", long_options, nullptr)) != -1) {
        switch (c) {
            case 'p':
                options.pattern.prefix = optarg;
                break;
            case 's':
                options.pattern.suffix = optarg;
                break;
            case 'c':
                options.pattern.contains = optarg;
                break;
            case 'j': {
                const auto threads = parse_int(optarg);
                if (!threads || *threads <= 0) {
                    std::println(stderr, "Error: Number of threads must be a positive integer");
                    return false;
                }
                options.num_threads = *threads;
                break;
            }
            case 'g':
                options.use_gpu = true;
                break;
            case 'd': {
                const auto device = parse_int(optarg);
                if (!device || *device < 0) {
                    std::println(stderr, "Error: Device index must be a non-negative integer");
                    return false;
                }
                options.gpu_device = *device;
                options.use_gpu = true;
                break;
            }
            case 'o':
                options.output_file = optarg;
                break;
            case 'i':
                options.pattern.case_insensitive = true;
                break;
            case 'h':
                print_usage();
                exit_code = 0;
                return false;
            default:
                return false;
        }
    }

    if (options.pattern.empty()) {
        std::println(
            stderr, "Error: At least one of --prefix, --suffix, or --contains must be specified"
        );
        print_usage();
        return false;
    }
    return true;
}

// Returns a message if the pattern is malformed or can never match a key
std::optional<std::string> validate_pattern(const VanityPattern& pattern) {
    const std::tuple<std::string_view, const std::string&, size_t> parts[] = {
        {"Prefix", pattern.prefix, kKeyBase64Length - kFixedPrefixLength},
        {"Suffix", pattern.suffix, kKeyBase64Length},
        {"Contains string", pattern.contains, kKeyBase64Length},
    };
    for (const auto& [name, value, max_length] : parts) {
        for (const char c : value) {
            if (!kBase64Chars.contains(c)) {
                return std::format(
                    "{} contains invalid base64 character: '{}'\nValid characters: {}",
                    name,
                    c,
                    kBase64Chars
                );
            }
        }
        if (value.size() > max_length) {
            return std::format("{} is longer than {} characters", name, max_length);
        }
    }

    // The first variable character shares a base64 group with the constant key
    // length byte, so only its low four bits vary: 'A' to 'P'.
    if (!pattern.prefix.empty()) {
        const char first = pattern.prefix.front();
        const bool possible = (first >= 'A' && first <= 'P') ||
                              (pattern.case_insensitive && first >= 'a' && first <= 'p');
        if (!possible) {
            return std::format(
                "Prefix cannot start with '{}': the first character after the fixed prefix is "
                "always one of A-P",
                first
            );
        }
    }
    return std::nullopt;
}

void print_progress() {
    const auto start_time = std::chrono::steady_clock::now();
    uint64_t last_attempts = 0;

    while (!g_stop_flag.load()) {
        const uint64_t current_attempts = g_total_attempts.load();
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start_time
        );

        const uint64_t attempts_per_second = current_attempts - last_attempts;
        const uint64_t average_rate =
            elapsed.count() > 0 ? current_attempts / static_cast<uint64_t>(elapsed.count()) : 0;

        std::print(
            "\rAttempts: {} | Rate: {}/s | Avg: {}/s | Elapsed: {}s",
            current_attempts,
            attempts_per_second,
            average_rate,
            elapsed.count()
        );
        std::cout.flush();

        last_attempts = current_attempts;
        std::this_thread::sleep_for(std::chrono::seconds(kProgressRefreshIntervalSec));
    }
    std::println();
}

// Writes the private key readable by the owner only, never overwriting an existing file
bool write_private_key(const std::string& path, const std::string& contents, std::string& error) {
    const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        error = std::strerror(errno);
        return false;
    }

    size_t written = 0;
    while (written < contents.size()) {
        const ssize_t n = write(fd, contents.data() + written, contents.size() - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            error = std::strerror(errno);
            close(fd);
            return false;
        }
        written += static_cast<size_t>(n);
    }

    if (close(fd) != 0) {
        error = std::strerror(errno);
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char* argv[]) {
    Options options;
    int exit_code = 0;
    if (!parse_options(argc, argv, options, exit_code)) {
        return exit_code;
    }

    if (const auto error = validate_pattern(options.pattern)) {
        std::println(stderr, "Error: {}", *error);
        return 1;
    }

#ifndef VANISSH_CUDA
    if (options.use_gpu) {
        std::println(stderr, "Error: This build of vanissh does not include CUDA support");
        return 1;
    }
#endif

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

#ifdef VANISSH_CUDA
    // Initialize the GPU backend and verify its key derivation against OpenSSL
    std::unique_ptr<CudaVanityGenerator> gpu;
    if (options.use_gpu) {
        try {
            gpu = std::make_unique<CudaVanityGenerator>(options.gpu_device);
            gpu->self_test(kGpuSelfTestKeys);
        } catch (const std::exception& e) {
            std::println(stderr, "Error: CUDA device {}: {}", options.gpu_device, e.what());
            return 1;
        }
    }
#endif

    // Display configuration
    std::println("VaniSSH Version {}\n", kVersion);
    std::println("Key generation parameters:");
    std::println("==========================");
    if (!options.pattern.prefix.empty()) {
        std::println("Prefix: {}", options.pattern.prefix);
    }
    if (!options.pattern.suffix.empty()) {
        std::println("Suffix: {}", options.pattern.suffix);
    }
    if (!options.pattern.contains.empty()) {
        std::println("Contains: {}", options.pattern.contains);
    }
    if (options.pattern.case_insensitive) {
        std::println("Case-insensitive: yes");
    }
#ifdef VANISSH_CUDA
    if (gpu) {
        std::println("Backend: CUDA device {} ({})", options.gpu_device, gpu->device_name());
        std::println("Kernel: {}", gpu->config_summary());
        std::println("Self-test: {} keys verified against OpenSSL", kGpuSelfTestKeys);
    } else
#endif
    {
        std::println(
            "Threads: {}", options.num_threads > 0 ? std::to_string(options.num_threads) : "auto"
        );
    }
    if (!options.output_file.empty()) {
        std::println("Output: {}", options.output_file);
    }
    std::println();

    std::thread progress_thread(print_progress);
    const auto start_time = std::chrono::steady_clock::now();

    VanityResult result;
    std::optional<std::string> error;
    try {
#ifdef VANISSH_CUDA
        if (gpu) {
            result = gpu->generate(options.pattern, &g_stop_flag, &g_total_attempts);
        } else
#endif
        {
            result = SSHKeyGenerator::generate_vanity_key(
                options.pattern, options.num_threads, &g_stop_flag, &g_total_attempts
            );
        }
    } catch (const std::exception& e) {
        error = e.what();
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time
    );
    const bool interrupted = g_stop_flag.load();
    g_stop_flag.store(true);
    progress_thread.join();

    if (error) {
        std::println(stderr, "Error: {}", *error);
        return 1;
    }
    if (!result.found) {
        if (interrupted) {
            std::println("Generation interrupted.");
            return 130;
        }
        std::println(stderr, "Error: Failed to generate vanity key");
        return 1;
    }

    // Display results
    std::println("\nSuccess! Generated vanity SSH key:");
    std::println("==================================");
    std::println("Attempts: {}", result.attempts);
    std::println("Time: {} ms", elapsed.count());
    std::println(
        "Rate: {} keys/sec",
        elapsed.count() > 0 ? result.attempts * 1000 / static_cast<uint64_t>(elapsed.count()) : 0
    );
    std::println();

    std::println("Public key:");
    std::println("{}", result.public_key_ssh);
    std::println();

    if (!options.output_file.empty()) {
        std::string write_error;
        if (write_private_key(options.output_file, result.private_key_openssh, write_error)) {
            std::println("Private key written to: {}", options.output_file);
            return 0;
        }
        std::fflush(stdout);  // keep the error after the results when both go to one pipe
        std::println(stderr, "Error: Could not write {}: {}", options.output_file, write_error);
    }
    std::print("Private key:\n{}", result.private_key_openssh);
    return 0;
}
