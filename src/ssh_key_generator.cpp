#include "ssh_key_generator.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string_view>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <libssh/libssh.h>

#include "base64_encoder.h"

constexpr std::string_view kEd25519AlgorithmName = "ssh-ed25519";
constexpr size_t kEd25519AlgorithmNameLen = kEd25519AlgorithmName.size();

constexpr std::string_view kEd25519WireFormatPrefix = "AAAAC3NzaC1lZDI1NTE5AAAAI";
constexpr size_t kEd25519WireFormatPrefixLen = kEd25519WireFormatPrefix.size();

constexpr size_t kEd25519KeySize = 32;
constexpr size_t kEd25519BufferSize = 256;
constexpr size_t kSearchBufferSize = 512;
constexpr size_t kPubkeyCharsPerLine = 70;

SSHKeyGenerator::SSHKeyGenerator() : private_key_(nullptr), cache_valid_(false) {}

SSHKeyGenerator::~SSHKeyGenerator() {
    if (private_key_) {
        EVP_PKEY_free(private_key_);
    }
}

bool SSHKeyGenerator::generate_ed25519_key() {
    clear_cache();

    if (private_key_ != nullptr) [[unlikely]] {
        EVP_PKEY_free(private_key_);
        private_key_ = nullptr;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) {
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    private_key_ = pkey;
    EVP_PKEY_CTX_free(ctx);
    return true;
}

const std::string& SSHKeyGenerator::get_public_key_ssh() const {
    if (!cache_valid_) [[unlikely]] {
        cached_public_key_ssh_ = public_key_to_ssh();
        cache_valid_ = true;
    }
    return cached_public_key_ssh_;
}

std::string SSHKeyGenerator::get_private_key_pem() const {
    if (cached_private_key_pem_.empty()) {
        cached_private_key_pem_ = private_key_to_pem();
    }
    return cached_private_key_pem_;
}

std::string SSHKeyGenerator::get_private_key_openssh() const {
    if (cached_private_key_openssh_.empty()) {
        cached_private_key_openssh_ = private_key_to_openssh();
    }
    return cached_private_key_openssh_;
}

std::string SSHKeyGenerator::get_public_key_fingerprint() const {
    if (!cached_public_key_fingerprint_.empty()) {
        return cached_public_key_fingerprint_;
    }

    // Get the SSH public key
    const std::string& ssh_key = get_public_key_ssh();
    if (ssh_key.empty()) {
        return "";
    }

    // Extract the base64 part (second field after space)
    size_t space_pos = ssh_key.find(' ');
    if (space_pos == std::string::npos) {
        return "";
    }

    std::string base64_part = ssh_key.substr(space_pos + 1);

    // Decode the base64 data
    std::vector<unsigned char> decoded = Base64Encoder::decode_data(base64_part);
    if (decoded.empty()) {
        return "";
    }

    // Compute SHA256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(decoded.data(), decoded.size(), hash);

    // Encode hash as base64
    std::string fingerprint = Base64Encoder::encode_data(hash, SHA256_DIGEST_LENGTH);

    // Remove padding characters
    fingerprint.erase(
        std::remove(fingerprint.begin(), fingerprint.end(), '='),
        fingerprint.end()
    );

    cached_public_key_fingerprint_ = fingerprint;
    return cached_public_key_fingerprint_;
}

std::string SSHKeyGenerator::public_key_to_ssh() const {
    if (!private_key_) {
        return "";
    }

    // Ed25519 SSH format; optimized with pre-allocated buffer
    unsigned char ssh_key_data[kEd25519BufferSize];  // Stack allocation for speed
    size_t offset = 0;

    // Algorithm name length (4 bytes big-endian)
    uint32_t alg_len = htonl(kEd25519AlgorithmNameLen);
    std::memcpy(ssh_key_data + offset, &alg_len, 4);
    offset += 4;

    // Algorithm name
    std::memcpy(ssh_key_data + offset, kEd25519AlgorithmName.data(), kEd25519AlgorithmNameLen);
    offset += kEd25519AlgorithmNameLen;

    // Public key data
    size_t pub_len = kEd25519KeySize;
    unsigned char pub_key[kEd25519KeySize];
    if (EVP_PKEY_get_raw_public_key(private_key_, pub_key, &pub_len) == 1) {
        uint32_t key_len = htonl(kEd25519KeySize);
        std::memcpy(ssh_key_data + offset, &key_len, 4);
        offset += 4;
        std::memcpy(ssh_key_data + offset, pub_key, kEd25519KeySize);
        offset += kEd25519KeySize;
    }

    return std::string(kEd25519AlgorithmName) + " " +
           Base64Encoder::encode_data(ssh_key_data, offset);
}

std::string SSHKeyGenerator::private_key_to_pem() const {
    if (!private_key_) {
        return "";
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return "";
    }

    if (PEM_write_bio_PrivateKey(bio, private_key_, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(bio);
        return "";
    }

    char* pem_data = nullptr;
    long pem_len = BIO_get_mem_data(bio, &pem_data);

    std::string result(pem_data, static_cast<size_t>(pem_len));
    BIO_free(bio);
    return result;
}

std::string SSHKeyGenerator::private_key_to_openssh() const {
    if (!private_key_) {
        return "";
    }

    // Create a libssh key structure
    ssh_key ssh_key_obj = nullptr;

    // Get PEM format first
    std::string pem_content = private_key_to_pem();
    if (pem_content.empty()) {
        return "";
    }

    // Import the private key from PEM format
    int rc =
        ssh_pki_import_privkey_base64(pem_content.c_str(), nullptr, nullptr, nullptr, &ssh_key_obj);
    if (rc != SSH_OK) {
        return "";
    }

    // Export to OpenSSH format
    char* openssh_key = nullptr;
    rc = ssh_pki_export_privkey_base64(ssh_key_obj, nullptr, nullptr, nullptr, &openssh_key);

    std::string result;
    if (rc == SSH_OK && openssh_key) {
        std::string raw_key = openssh_key;
        ssh_string_free_char(openssh_key);

        // Find the header and footer to identify the base64 content
        const std::string header = "-----BEGIN OPENSSH PRIVATE KEY-----";
        const std::string footer = "-----END OPENSSH PRIVATE KEY-----";

        size_t header_pos = raw_key.find(header);
        size_t footer_pos = raw_key.find(footer);

        if (header_pos != std::string::npos && footer_pos != std::string::npos) {
            // Extract the base64 content between header and footer
            size_t content_start = header_pos + header.length();
            while (content_start < footer_pos &&
                   (raw_key[content_start] == '\n' || raw_key[content_start] == '\r')) {
                content_start++;
            }

            size_t content_end = footer_pos;
            while (content_end > content_start &&
                   (raw_key[content_end - 1] == '\n' || raw_key[content_end - 1] == '\r' ||
                    raw_key[content_end - 1] == ' ')) {
                content_end--;
            }

            std::string base64_content = raw_key.substr(content_start, content_end - content_start);

            // Remove any existing whitespace from base64 content
            base64_content.erase(
                std::remove_if(
                    base64_content.begin(),
                    base64_content.end(),
                    [](char c) { return std::isspace(c); }
                ),
                base64_content.end()
            );

            // Rebuild the key with proper line wrapping
            std::ostringstream formatted_key;
            formatted_key << header << "\n";

            for (size_t i = 0; i < base64_content.length(); i += kPubkeyCharsPerLine) {
                size_t line_length = std::min(kPubkeyCharsPerLine, base64_content.length() - i);
                formatted_key << base64_content.substr(i, line_length) << "\n";
            }

            formatted_key << footer << "\n";
            result = formatted_key.str();
        } else {
            result = raw_key;
        }
    }

    ssh_key_free(ssh_key_obj);
    return result;
}

bool SSHKeyGenerator::matches_pattern(
    const std::string& base64_str,
    size_t prefix_offset,
    const std::string& prefix,
    const std::string& suffix,
    const std::string& contains,
    bool case_insensitive
) const {
    const char* base64_start = base64_str.c_str();
    size_t base64_len = base64_str.length();

    // Check if the prefix matches
    if (!prefix.empty()) [[likely]] {
        // Skip the prefix offset (for public key, skip the fixed Ed25519 wire format prefix)
        if (base64_len < prefix_offset + prefix.length()) [[unlikely]] {
            return false;
        }

        const char* variable_part = base64_start + prefix_offset;

        if (case_insensitive) [[unlikely]] {
            for (size_t i = 0; i < prefix.length(); ++i) {
                if (std::tolower(variable_part[i]) != prefix[i]) [[unlikely]] {
                    return false;
                }
            }
        } else {
            if (std::memcmp(variable_part, prefix.c_str(), prefix.length()) != 0) [[likely]] {
                return false;
            }
        }
    }

    // Check if the suffix matches
    if (!suffix.empty()) [[unlikely]] {
        if (base64_len < suffix.length()) [[unlikely]] {
            return false;
        }

        const char* suffix_start = base64_start + base64_len - suffix.length();

        if (case_insensitive) [[unlikely]] {
            for (size_t i = 0; i < suffix.length(); ++i) {
                if (std::tolower(suffix_start[i]) != suffix[i]) [[unlikely]] {
                    return false;
                }
            }
        } else {
            if (std::memcmp(suffix_start, suffix.c_str(), suffix.length()) != 0) [[likely]] {
                return false;
            }
        }
    }

    // Check contains anywhere in the base64 part
    if (!contains.empty()) [[unlikely]] {
        if (case_insensitive) {
            // Use stack buffer for case-insensitive search
            thread_local static char search_buffer[kSearchBufferSize];
            if (base64_len < sizeof(search_buffer)) {
                for (size_t i = 0; i < base64_len; ++i) {
                    search_buffer[i] = static_cast<char>(std::tolower(base64_start[i]));
                }
                search_buffer[base64_len] = '\0';

                // Simple substring search on null-terminated buffer
                if (!strstr(search_buffer, contains.c_str())) {
                    return false;
                }
            } else {
                // Base64 part too long for buffer
                return false;
            }
        } else {
            // Direct memory search for case-sensitive using manual search
            const char* needle = contains.c_str();
            size_t needle_len = contains.length();
            bool found = false;

            for (size_t i = 0; i <= base64_len - needle_len; ++i) {
                if (memcmp(base64_start + i, needle, needle_len) == 0) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                return false;
            }
        }
    }

    return true;
}

bool SSHKeyGenerator::matches_vanity(
    const std::string& prefix,
    const std::string& suffix,
    const std::string& contains,
    bool case_insensitive,
    bool use_fingerprint
) const {
    if (use_fingerprint) {
        // Use fingerprint
        const std::string& fingerprint = get_public_key_fingerprint();
        if (fingerprint.empty()) [[unlikely]] {
            return false;
        }

        // For fingerprint, no offset needed - match from the start
        return matches_pattern(
            fingerprint,
            0,
            prefix,
            suffix,
            contains,
            case_insensitive
        );
    } else {
        // Fast path: generate SSH key string only once and reuse
        if (!cache_valid_) [[unlikely]] {
            cached_public_key_ssh_ = get_public_key_ssh();
            cache_valid_ = true;
        }

        const std::string& ssh_key = cached_public_key_ssh_;
        if (ssh_key.empty()) [[unlikely]] {
            return false;
        }

        // Extract base64 part and skip algorithm prefix
        size_t space_pos = ssh_key.find(' ');
        if (space_pos == std::string::npos) [[unlikely]] {
            return false;
        }

        std::string base64_part = ssh_key.substr(space_pos + 1);

        // For public key, skip the fixed "AAAAC3NzaC1lZDI1NTE5AAAAI" prefix
        return matches_pattern(
            base64_part,
            kEd25519WireFormatPrefixLen,
            prefix,
            suffix,
            contains,
            case_insensitive
        );
    }
}

void SSHKeyGenerator::clear_cache() {
    cached_public_key_ssh_.clear();
    cached_private_key_pem_.clear();
    cached_private_key_openssh_.clear();
    cached_public_key_fingerprint_.clear();
    cache_valid_ = false;
}

VanityResult SSHKeyGenerator::generate_vanity_key(
    const std::string& prefix,
    const std::string& suffix,
    const std::string& contains,
    int num_threads,
    bool case_insensitive,
    bool use_fingerprint,
    std::atomic<bool>* stop_flag,
    std::atomic<uint64_t>* total_attempts
) {
    if (num_threads <= 0) {
        num_threads = static_cast<int>(std::thread::hardware_concurrency());
        if (num_threads <= 0) {
            num_threads = 4;
        }
    }

    std::atomic<bool> found(false);
    std::atomic<bool> local_stop_flag(false);
    std::atomic<uint64_t> local_attempts(0);

    if (!stop_flag) {
        stop_flag = &local_stop_flag;
    }
    if (!total_attempts) {
        total_attempts = &local_attempts;
    }

    VanityResult result;
    result.attempts = 0;

    std::vector<std::thread> threads;
    threads.reserve(static_cast<size_t>(num_threads));

    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([=, &found, &result]() {
            // Set CPU affinity to reduce context switching
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(
                static_cast<unsigned int>(
                    static_cast<unsigned int>(i) % std::thread::hardware_concurrency()
                ),
                &cpuset
            );
            pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

            worker_thread(
                prefix,
                suffix,
                contains,
                case_insensitive,
                use_fingerprint,
                &found,
                stop_flag,
                total_attempts,
                &result
            );
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    result.attempts = total_attempts->load();
    return result;
}

void SSHKeyGenerator::worker_thread(
    const std::string& prefix,
    const std::string& suffix,
    const std::string& contains,
    bool case_insensitive,
    bool use_fingerprint,
    std::atomic<bool>* found,
    std::atomic<bool>* stop_flag,
    std::atomic<uint64_t>* total_attempts,
    VanityResult* result
) {
    SSHKeyGenerator generator;
    uint64_t local_attempts = 0;

    // Pre-convert search patterns to avoid doing it every iteration
    std::string search_prefix = prefix;
    std::string search_suffix = suffix;
    std::string search_contains = contains;

    if (case_insensitive) {
        std::transform(
            search_prefix.begin(), search_prefix.end(), search_prefix.begin(), ::tolower
        );
        std::transform(
            search_suffix.begin(), search_suffix.end(), search_suffix.begin(), ::tolower
        );
        std::transform(
            search_contains.begin(), search_contains.end(), search_contains.begin(), ::tolower
        );
    }

    // Check found/stop flags less frequently to reduce atomic overhead
    const uint64_t kCheckInterval = 5000;

    while (true) {
        // Batch check of atomic flags to reduce overhead
        if (local_attempts % kCheckInterval == 0) [[unlikely]] {
            if (found->load(std::memory_order_relaxed) ||
                stop_flag->load(std::memory_order_relaxed)) [[unlikely]] {
                break;
            }
            // Update global counter less frequently to reduce contention
            total_attempts->fetch_add(kCheckInterval, std::memory_order_relaxed);
            local_attempts = 0;
        }

        if (!generator.generate_ed25519_key()) [[unlikely]] {
            continue;
        }

        ++local_attempts;

        // Fast path: do direct pattern matching without expensive string operations
        if (generator.matches_vanity(
                search_prefix, search_suffix, search_contains, case_insensitive, use_fingerprint
            )) [[unlikely]] {
            bool expected = false;
            if (found->compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                // We're the first to find a match; now do expensive operations
                result->private_key_pem = generator.get_private_key_pem();
                result->private_key_openssh = generator.get_private_key_openssh();
                result->public_key_ssh = generator.get_public_key_ssh();
                result->public_key_fingerprint = generator.get_public_key_fingerprint();
            }
            break;
        }
    }

    // Add any remaining attempts
    total_attempts->fetch_add(local_attempts, std::memory_order_relaxed);
}
