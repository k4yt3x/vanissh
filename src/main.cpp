#include "ssh_key_generator.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <print>
#include <string>
#include <thread>

#include <getopt.h>

constexpr std::string_view kVersion = "1.0.0";
constexpr int64_t kProgressRefreshIntervalSec = 1;
constexpr std::string_view kBase64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Global flag for signal handling
std::atomic<bool> g_stop_flag(false);
std::atomic<uint64_t> g_total_attempts(0);

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        // Force stop on second signal
        if (g_stop_flag.load()) {
            std::println("\nForce exiting...");
            std::exit(1);
        }

        std::println("\nReceived interrupt signal. Stopping generation...");
        g_stop_flag.store(true);
    }
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
        "  -o, --output FILE      Output private key to file (default: stdout)\n"
        "  -i, --ignore-case      Case-insensitive matching\n"
        "  -f, --fingerprint      Match against SHA256 fingerprint instead of public key\n"
        "  -h, --help             Show this help message\n\n"
        "Notes:\n"
        "  - At least one of --prefix, --suffix, or --contains must be specified.\n"
        "  - Ed25519 public keys will always start with 'AAAAC3NzaC1lZDI1NTE5AAAAI',\n"
        "      which will be skipped when matching prefixes (unless --fingerprint is used).\n"
        "  - The prefixes have a limited character set; not all characters are possible.\n"
        "  - When using --fingerprint, matches are done against the base64-encoded SHA256\n"
        "      fingerprint instead of the public key.\n\n"
        "Examples:\n"
        "  vanissh -s TEST\n"
        "  vanissh -c 1337 -i\n"
        "  vanissh -p abc -i -o id_ed25519\n"
        "  vanissh -p AAAA -f\n"
    );
}

void print_progress(std::atomic<bool>* stop_flag, std::atomic<uint64_t>* attempts) {
    auto start_time = std::chrono::steady_clock::now();
    uint64_t last_attempts = 0;

    while (!stop_flag->load()) {
        uint64_t current_attempts = attempts->load();
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time);

        uint64_t attempts_per_second = current_attempts - last_attempts;
        double total_rate = elapsed.count() > 0 ? static_cast<double>(current_attempts) /
                                                      static_cast<double>(elapsed.count())
                                                : 0;

        std::print(
            "\rAttempts: {} | Rate: {}/s | Avg: {}/s | Elapsed: {}s",
            current_attempts,
            attempts_per_second,
            static_cast<uint64_t>(total_rate),
            elapsed.count()
        );
        std::cout.flush();

        last_attempts = current_attempts;

        // Update every second
        std::this_thread::sleep_for(std::chrono::seconds(kProgressRefreshIntervalSec));
    }
    std::println();
}

int main(int argc, char* argv[]) {
    std::string prefix;
    std::string suffix;
    std::string contains;
    std::string output_file;
    int num_threads = 0;
    bool case_insensitive = false;
    bool use_fingerprint = false;

    static struct option long_options[] = {
        {"prefix", required_argument, nullptr, 'p'},
        {"suffix", required_argument, nullptr, 's'},
        {"contains", required_argument, nullptr, 'c'},
        {"threads", required_argument, nullptr, 'j'},
        {"output", required_argument, nullptr, 'o'},
        {"ignore-case", no_argument, nullptr, 'i'},
        {"fingerprint", no_argument, nullptr, 'f'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };

    int option_index = 0;
    int c;

    while ((c = getopt_long(argc, argv, "p:s:c:j:o:ifh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'p':
                prefix = optarg;
                break;
            case 's':
                suffix = optarg;
                break;
            case 'c':
                contains = optarg;
                break;
            case 'j':
                num_threads = std::atoi(optarg);
                if (num_threads <= 0) {
                    std::println(stderr, "Error: Number of threads must be positive");
                    return 1;
                }
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'i':
                case_insensitive = true;
                break;
            case 'f':
                use_fingerprint = true;
                break;
            case 'h':
                print_usage();
                return 0;
            case '?':
                return 1;
            default:
                std::println(stderr, "Error: Unknown option");
                return 1;
        }
    }

    // Validate arguments
    if (prefix.empty() && suffix.empty() && contains.empty()) {
        std::println(
            stderr, "Error: At least one of --prefix, --suffix, or --contains must be specified"
        );
        print_usage();
        return 1;
    }

    // Validate base64 characters in prefix and suffix
    auto validate_base64 = [](const std::string& str, const std::string& name) {
        for (char c : str) {
            if (kBase64Chars.find(c) == std::string::npos) {
                std::println(stderr, "Error: {} contains invalid base64 character: '{}'", name, c);
                std::println(stderr, "Valid characters: {}", kBase64Chars);
                return false;
            }
        }
        return true;
    };

    if (!prefix.empty() && !validate_base64(prefix, "Prefix")) {
        return 1;
    }
    if (!suffix.empty() && !validate_base64(suffix, "Suffix")) {
        return 1;
    }
    if (!contains.empty() && !validate_base64(contains, "Contains string")) {
        return 1;
    }

    // Set up signal handlers
    std::signal(SIGINT, signal_handler);

    // Display configuration
    std::println("VaniSSH Version {}\n", kVersion);
    std::println("Key generation parameters:");
    std::println("==========================");
    if (!prefix.empty()) {
        std::println("Prefix: {}", prefix);
    }
    if (!suffix.empty()) {
        std::println("Suffix: {}", suffix);
    }
    if (!contains.empty()) {
        std::println("Contains: {}", contains);
    }
    if (case_insensitive) {
        std::println("Case-insensitive: yes");
    }
    if (use_fingerprint) {
        std::println("Match target: SHA256 fingerprint");
    }
    std::println("Threads: {}", (num_threads > 0 ? std::to_string(num_threads) : "auto"));
    if (!output_file.empty()) {
        std::println("Output: {}", output_file);
    }
    std::println();

    // Start progress thread if verbose
    std::thread progress_thread;
    progress_thread = std::thread(print_progress, &g_stop_flag, &g_total_attempts);

    auto start_time = std::chrono::steady_clock::now();

    // Generate vanity SSH key
    VanityResult result = SSHKeyGenerator::generate_vanity_key(
        prefix, suffix, contains, num_threads, case_insensitive, use_fingerprint, &g_stop_flag, &g_total_attempts
    );

    auto end_time = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    // Stop progress thread
    if (progress_thread.joinable()) {
        g_stop_flag.store(true);
        progress_thread.join();
    }

    if (g_stop_flag.load() && result.private_key_pem.empty()) {
        std::println("Generation interrupted.");
        return 130;
    }

    if (result.private_key_pem.empty()) {
        std::println(stderr, "Failed to generate vanity key");
        return 1;
    }

    // Display results
    std::println("\nSuccess! Generated vanity SSH key:");
    std::println("==================================");
    std::println("Attempts: {}", result.attempts);
    std::println("Time: {} ms", elapsed.count());
    std::println(
        "Rate: {} keys/sec",
        (elapsed.count() > 0 ? result.attempts * 1000 / static_cast<uint64_t>(elapsed.count()) : 0)
    );
    std::println();

    std::println("Public key:");
    std::println("{}", result.public_key_ssh);
    std::println();

    std::println("Public key fingerprint (SHA256):");
    std::println("SHA256:{}", result.public_key_fingerprint);
    std::println();

    // Output private key
    if (!output_file.empty()) {
        std::ofstream file(output_file);
        if (file.is_open()) {
            file << result.private_key_openssh;
            file.close();
            std::println("Private key written to: {}", output_file);
        } else {
            std::println(stderr, "Error: Could not write to file: {}", output_file);
            std::print("Private key:\n{}", result.private_key_openssh);
        }
    } else {
        std::print("Private key:\n{}", result.private_key_openssh);
    }

    return 0;
}
