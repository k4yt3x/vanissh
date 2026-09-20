#include <algorithm>
#include <atomic>
#include <cctype>
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
#include <utility>
#include <vector>

#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>

#include "number_format.h"
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
// The first variable character of a key shares a base64 group with the
// constant key length byte, so only its low four bits vary
constexpr std::string_view kKeyFirstChars = "ABCDEFGHIJKLMNOP";
// The last fingerprint character encodes the final four digest bits followed
// by two zero bits
constexpr std::string_view kFingerprintLastChars = "AEIMQUYcgkosw048";
#ifdef VANISSH_CUDA
constexpr size_t kGpuSelfTestKeys = 4096;
#endif

// Set by the signal handler, checked by the search loops and the progress thread
std::atomic<bool> g_stop_flag(false);
std::atomic<uint64_t> g_total_attempts(0);

struct Options {
    VanityCriteria criteria;
    std::string output_file;
    int num_threads = 0;
    bool use_gpu = false;
    std::vector<int> gpu_devices;
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
        "Generate Ed25519 SSH keys whose public key or SHA-256 fingerprint starts with,\n"
        "ends with, or contains the strings you choose.\n\n"
        "Options:\n"
        "  -p, --prefix PREFIX                Desired prefix of the base64 public key\n"
        "  -s, --suffix SUFFIX                Desired suffix of the base64 public key\n"
        "  -c, --contains STRING              String that must appear anywhere in the\n"
        "                                       base64 public key\n"
        "  -P, --fingerprint-prefix PREFIX    Desired prefix of the SHA-256 fingerprint\n"
        "  -S, --fingerprint-suffix SUFFIX    Desired suffix of the SHA-256 fingerprint\n"
        "  -C, --fingerprint-contains STRING  String that must appear anywhere in the\n"
        "                                       SHA-256 fingerprint\n"
        "  -j, --threads NUM                  Number of threads to use (default: auto)\n"
#ifdef VANISSH_CUDA
        "  -g, --gpus DEVICES                 CUDA GPUs to use: 'all' or comma-separated\n"
        "                                       indices (e.g. 0,2); default: CPU\n"
#endif
        "  -o, --output FILE                  Output private key to file (default: stdout)\n"
        "  -i, --ignore-case                  Case-insensitive matching\n"
        "  -h, --help                         Show this help message\n\n"
        "Notes:\n"
        "  - At least one pattern must be specified; all given patterns must match.\n"
        "  - Ed25519 public keys always start with 'AAAAC3NzaC1lZDI1NTE5AAAAI', which is\n"
        "      skipped when matching prefixes. The character after it is one of A-P.\n"
        "  - Fingerprint patterns apply to the 43 characters after 'SHA256:', the last\n"
        "      of which is one of A E I M Q U Y c g k o s w 0 4 8.\n\n"
        "Examples:\n"
        "  vanissh -s TEST\n"
        "  vanissh -c 1337 -i\n"
        "  vanissh -p abc -i -o id_ed25519\n"
        "  vanissh -S cafe -i\n"
#ifdef VANISSH_CUDA
        "  vanissh -g all -s TEST -o id_ed25519\n"
        "  vanissh -g 0,2 -s TEST\n"
#endif
    );
}

// Fingerprints are usually pasted as "SHA256:<base64>"; the constant part is
// not part of the matched string
std::string without_fingerprint_prefix(std::string_view pattern) {
    if (pattern.starts_with(kFingerprintSha256Prefix)) {
        pattern.remove_prefix(kFingerprintSha256Prefix.size());
    }
    return std::string(pattern);
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
        {"fingerprint-prefix", required_argument, nullptr, 'P'},
        {"fingerprint-suffix", required_argument, nullptr, 'S'},
        {"fingerprint-contains", required_argument, nullptr, 'C'},
        {"threads", required_argument, nullptr, 'j'},
        {"gpus", required_argument, nullptr, 'g'},
        {"output", required_argument, nullptr, 'o'},
        {"ignore-case", no_argument, nullptr, 'i'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };

    exit_code = 1;
    int c = 0;
    while ((c = getopt_long(argc, argv, "p:s:c:P:S:C:j:g:o:ih", long_options, nullptr)) != -1) {
        switch (c) {
            case 'p':
                options.criteria.key.prefix = optarg;
                break;
            case 's':
                options.criteria.key.suffix = optarg;
                break;
            case 'c':
                options.criteria.key.contains = optarg;
                break;
            case 'P':
                options.criteria.fingerprint.prefix = without_fingerprint_prefix(optarg);
                break;
            case 'S':
                options.criteria.fingerprint.suffix = without_fingerprint_prefix(optarg);
                break;
            case 'C':
                options.criteria.fingerprint.contains = without_fingerprint_prefix(optarg);
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
            case 'g': {
                options.use_gpu = true;
                // Like the pattern options, the last supplied selector wins.
                options.gpu_devices.clear();
                std::string_view devices(optarg);
                if (devices == "all") {
                    break;
                }
                for (;;) {
                    const size_t comma = devices.find(',');
                    const auto device = parse_int(devices.substr(0, comma));
                    if (!device || *device < 0) {
                        std::println(
                            stderr,
                            "Error: GPUs must be 'all' or a comma-separated list of non-negative indices"
                        );
                        return false;
                    }
                    if (std::find(
                            options.gpu_devices.begin(), options.gpu_devices.end(), *device
                        ) != options.gpu_devices.end()) {
                        std::println(
                            stderr, "Error: CUDA device {} was selected more than once", *device
                        );
                        return false;
                    }
                    options.gpu_devices.push_back(*device);
                    if (comma == std::string_view::npos) {
                        break;
                    }
                    devices.remove_prefix(comma + 1);
                }
                break;
            }
            case 'o':
                options.output_file = optarg;
                break;
            case 'i':
                options.criteria.case_insensitive = true;
                break;
            case 'h':
                print_usage();
                exit_code = 0;
                return false;
            default:
                return false;
        }
    }

    if (optind < argc) {
        std::println(stderr, "Error: Unexpected argument: {}", argv[optind]);
        return false;
    }
    if (options.criteria.empty()) {
        std::println(stderr, "Error: At least one pattern must be specified");
        print_usage();
        return false;
    }
    return true;
}

// Whether c, or its other-case form when case_insensitive, is one of chars
bool can_occur(char c, std::string_view chars, bool case_insensitive) {
    if (chars.contains(c)) {
        return true;
    }
    if (!case_insensitive) {
        return false;
    }
    const auto uc = static_cast<unsigned char>(c);
    const char other = std::isupper(uc) ? static_cast<char>(std::tolower(uc))
                                        : static_cast<char>(std::toupper(uc));
    return chars.contains(other);
}

// Returns a message if a part of the pattern is malformed or too long for its target
std::optional<std::string>
validate_pattern(std::string_view name, const VanityPattern& pattern, const VanityTarget& target) {
    const std::tuple<std::string_view, const std::string&, size_t> parts[] = {
        {"prefix", pattern.prefix, target.length - target.prefix_offset},
        {"suffix", pattern.suffix, target.length},
        {"contains string", pattern.contains, target.length},
    };
    for (const auto& [part, value, max_length] : parts) {
        for (const char c : value) {
            if (!kBase64Chars.contains(c)) {
                return std::format(
                    "{} {} contains invalid base64 character: '{}'\nValid characters: {}",
                    name,
                    part,
                    c,
                    kBase64Chars
                );
            }
        }
        if (value.size() > max_length) {
            return std::format("{} {} is longer than {} characters", name, part, max_length);
        }
    }
    return std::nullopt;
}

// Returns a message if the criteria are malformed or can never match a key
std::optional<std::string> validate_criteria(const VanityCriteria& criteria) {
    if (auto error = validate_pattern("Public key", criteria.key, kKeyTarget)) {
        return error;
    }
    if (auto error = validate_pattern("Fingerprint", criteria.fingerprint, kFingerprintTarget)) {
        return error;
    }

    const bool case_insensitive = criteria.case_insensitive;
    if (!criteria.key.prefix.empty() &&
        !can_occur(criteria.key.prefix.front(), kKeyFirstChars, case_insensitive)) {
        return std::format(
            "Public key prefix cannot start with '{}': the first character after the fixed "
            "prefix is always one of A-P",
            criteria.key.prefix.front()
        );
    }

    // A suffix, or a contains string as long as the fingerprint, ends on the
    // last fingerprint character
    const VanityPattern& fingerprint = criteria.fingerprint;
    const bool contains_all = fingerprint.contains.size() == kFingerprintTarget.length;
    const std::pair<std::string_view, std::string_view> ends[] = {
        {"suffix", fingerprint.suffix},
        {"contains string", contains_all ? std::string_view(fingerprint.contains) : ""},
    };
    for (const auto& [part, value] : ends) {
        if (!value.empty() && !can_occur(value.back(), kFingerprintLastChars, case_insensitive)) {
            return std::format(
                "Fingerprint {} cannot end with '{}': the last fingerprint character is always "
                "one of {}",
                part,
                value.back(),
                kFingerprintLastChars
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
            format_number(current_attempts),
            format_number(attempts_per_second),
            format_number(average_rate),
            format_number(static_cast<uint64_t>(elapsed.count()))
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

    if (const auto error = validate_criteria(options.criteria)) {
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
    // Initialize each selected GPU and verify its key derivation against OpenSSL.
    std::unique_ptr<CudaVanityGenerator> gpu;
    if (options.use_gpu) {
        try {
            gpu = std::make_unique<CudaVanityGenerator>(options.gpu_devices);
            gpu->self_test(kGpuSelfTestKeys);
        } catch (const std::exception& e) {
            std::println(stderr, "Error: {}", e.what());
            return 1;
        }
    }
#endif

    // Display configuration
    std::println("VaniSSH Version {}\n", kVersion);
    std::println("Key generation parameters:");
    std::println("==========================");
    const std::tuple<std::string_view, std::string_view, const std::string&> patterns[] = {
        {"Public key", "prefix", options.criteria.key.prefix},
        {"Public key", "suffix", options.criteria.key.suffix},
        {"Public key", "contains", options.criteria.key.contains},
        {"Fingerprint", "prefix", options.criteria.fingerprint.prefix},
        {"Fingerprint", "suffix", options.criteria.fingerprint.suffix},
        {"Fingerprint", "contains", options.criteria.fingerprint.contains},
    };
    for (const auto& [target, part, value] : patterns) {
        if (!value.empty()) {
            std::println("{} {}: {}", target, part, value);
        }
    }
    if (options.criteria.case_insensitive) {
        std::println("Case-insensitive: yes");
    }
#ifdef VANISSH_CUDA
    if (gpu) {
        for (const auto& device : gpu->devices()) {
            std::println("Backend: CUDA device {} ({})", device.index, device.name);
            std::println("Kernel: {}", device.config);
        }
        std::println(
            "Self-test: {} keys per GPU verified against OpenSSL", format_number(kGpuSelfTestKeys)
        );
    } else
#endif
    {
        std::println(
            "Threads: {}",
            options.num_threads > 0 ? format_number(static_cast<uint64_t>(options.num_threads))
                                    : "auto"
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
            result = gpu->generate(options.criteria, &g_stop_flag, &g_total_attempts);
        } else
#endif
        {
            result = SSHKeyGenerator::generate_vanity_key(
                options.criteria, options.num_threads, &g_stop_flag, &g_total_attempts
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
    if (result.private_key_openssh.empty()) {
        std::println(stderr, "Error: Failed to serialize the private key");
        return 1;
    }

    // Display results
    std::println("\nSuccess! Generated vanity SSH key:");
    std::println("==================================");
    std::println("Attempts: {}", format_number(result.attempts));
    std::println("Time: {} ms", format_number(static_cast<uint64_t>(elapsed.count())));
    std::println(
        "Rate: {} keys/sec",
        format_number(
            elapsed.count() > 0 ? result.attempts * 1000 / static_cast<uint64_t>(elapsed.count())
                                : 0
        )
    );
    std::println();

    std::println("Public key:");
    std::println("{}", result.public_key_ssh);
    std::println();

    std::println("Fingerprint:");
    std::println("{}", result.fingerprint_sha256);
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
