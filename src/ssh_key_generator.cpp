#include "ssh_key_generator.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <string_view>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <pthread.h>
#include <sched.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "base64_encoder.h"

namespace {

constexpr std::string_view kEd25519AlgorithmName = "ssh-ed25519";
constexpr std::string_view kEd25519WireFormatPrefix = "AAAAC3NzaC1lZDI1NTE5AAAAI";
constexpr size_t kPrivateKeyCharsPerLine = 70;
constexpr std::string_view kOpenSshKeyMagic = "openssh-key-v1";  // followed by a NUL
constexpr size_t kOpenSshNoneCipherBlockSize = 8;

// Keys generated per thread between updates of the shared counter and flags
constexpr uint64_t kCheckInterval = 5000;

// RFC 4251 encodings used by the SSH key formats
void put_uint32(std::string& out, uint32_t value) {
    const uint32_t big_endian = htonl(value);
    out.append(reinterpret_cast<const char*>(&big_endian), sizeof(big_endian));
}

void put_string(std::string& out, std::span<const unsigned char> data) {
    put_uint32(out, static_cast<uint32_t>(data.size()));
    out.append(reinterpret_cast<const char*>(data.data()), data.size());
}

void put_string(std::string& out, std::string_view data) {
    put_uint32(out, static_cast<uint32_t>(data.size()));
    out.append(data);
}

std::span<const unsigned char> as_bytes(std::string_view s) {
    return {reinterpret_cast<const unsigned char*>(s.data()), s.size()};
}

}  // namespace

SSHKeyGenerator::~SSHKeyGenerator() {
    EVP_PKEY_free(private_key_);
    EVP_PKEY_CTX_free(keygen_ctx_);
}

void SSHKeyGenerator::reset_key(EVP_PKEY* key) {
    EVP_PKEY_free(private_key_);
    private_key_ = key;
    cached_public_key_ssh_.clear();
    cached_private_key_openssh_.clear();
}

bool SSHKeyGenerator::generate_ed25519_key() {
    // The context is reusable, so it is created once per generator
    if (keygen_ctx_ == nullptr) [[unlikely]] {
        keygen_ctx_ = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        if (keygen_ctx_ == nullptr || EVP_PKEY_keygen_init(keygen_ctx_) <= 0) {
            EVP_PKEY_CTX_free(keygen_ctx_);
            keygen_ctx_ = nullptr;
            return false;
        }
    }

    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(keygen_ctx_, &key) <= 0) [[unlikely]] {
        return false;
    }
    reset_key(key);
    return true;
}

bool SSHKeyGenerator::load_from_seed(std::span<const unsigned char, kEd25519KeySize> seed) {
    EVP_PKEY* key =
        EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
    if (key == nullptr) {
        return false;
    }
    reset_key(key);
    return true;
}

bool SSHKeyGenerator::get_raw_public_key(std::span<unsigned char, kEd25519KeySize> out) const {
    if (private_key_ == nullptr) {
        return false;
    }
    size_t length = out.size();
    return EVP_PKEY_get_raw_public_key(private_key_, out.data(), &length) == 1 &&
           length == out.size();
}

const std::string& SSHKeyGenerator::get_public_key_ssh() const {
    if (cached_public_key_ssh_.empty()) [[unlikely]] {
        cached_public_key_ssh_ = public_key_to_ssh();
    }
    return cached_public_key_ssh_;
}

const std::string& SSHKeyGenerator::get_private_key_openssh() const {
    if (cached_private_key_openssh_.empty()) {
        cached_private_key_openssh_ = private_key_to_openssh();
    }
    return cached_private_key_openssh_;
}

std::string SSHKeyGenerator::public_key_to_ssh() const {
    std::array<unsigned char, kEd25519KeySize> public_key{};
    if (!get_raw_public_key(public_key)) {
        return "";
    }

    // RFC 4253 wire format: string "ssh-ed25519", string <32 key bytes>
    std::string blob;
    put_string(blob, kEd25519AlgorithmName);
    put_string(blob, public_key);

    return std::string(kEd25519AlgorithmName) + ' ' + base64::encode(as_bytes(blob));
}

// Serializes the key in OpenSSH's own private key format (PROTOCOL.key in the
// OpenSSH sources), unencrypted, as ssh-keygen would write it.
std::string SSHKeyGenerator::private_key_to_openssh() const {
    std::array<unsigned char, kEd25519KeySize> seed{};
    std::array<unsigned char, kEd25519KeySize> public_key{};
    size_t seed_length = seed.size();
    if (private_key_ == nullptr ||
        EVP_PKEY_get_raw_private_key(private_key_, seed.data(), &seed_length) != 1 ||
        seed_length != seed.size() || !get_raw_public_key(public_key)) {
        return "";
    }

    // Both copies of the check value must match for the key to be accepted
    uint32_t check = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&check), sizeof(check)) != 1) {
        return "";
    }

    std::string public_blob;
    put_string(public_blob, kEd25519AlgorithmName);
    put_string(public_blob, public_key);

    // OpenSSH stores the Ed25519 private key as the 64 bytes seed || public key
    std::array<unsigned char, 2 * kEd25519KeySize> secret{};
    std::copy(seed.begin(), seed.end(), secret.begin());
    std::copy(public_key.begin(), public_key.end(), secret.begin() + kEd25519KeySize);

    std::string private_section;
    put_uint32(private_section, check);
    put_uint32(private_section, check);
    put_string(private_section, kEd25519AlgorithmName);
    put_string(private_section, public_key);
    put_string(private_section, secret);
    put_string(private_section, std::string_view());  // comment
    for (unsigned char pad = 1; private_section.size() % kOpenSshNoneCipherBlockSize != 0; ++pad) {
        private_section += static_cast<char>(pad);
    }

    std::string blob(kOpenSshKeyMagic);
    blob += '\0';
    put_string(blob, "none");              // cipher
    put_string(blob, "none");              // kdf
    put_string(blob, std::string_view());  // kdf options
    put_uint32(blob, 1);                   // number of keys
    put_string(blob, public_blob);
    put_string(blob, private_section);

    OPENSSL_cleanse(seed.data(), seed.size());
    OPENSSL_cleanse(secret.data(), secret.size());

    const std::string body = base64::encode(as_bytes(blob));
    std::string result = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
    for (size_t i = 0; i < body.size(); i += kPrivateKeyCharsPerLine) {
        result.append(body, i, kPrivateKeyCharsPerLine).append("\n");
    }
    result += "-----END OPENSSH PRIVATE KEY-----\n";
    return result;
}

bool SSHKeyGenerator::matches_vanity(const VanityPattern& pattern) const {
    const std::string& ssh_key = get_public_key_ssh();
    const size_t space_pos = ssh_key.find(' ');
    if (space_pos == std::string::npos) [[unlikely]] {
        return false;
    }
    const std::string_view key = std::string_view(ssh_key).substr(space_pos + 1);

    const bool case_insensitive = pattern.case_insensitive;
    const auto equals = [case_insensitive](std::string_view text, std::string_view wanted) {
        if (!case_insensitive) {
            return text == wanted;
        }
        for (size_t i = 0; i < wanted.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(text[i])) != wanted[i]) {
                return false;
            }
        }
        return true;
    };

    if (!pattern.prefix.empty()) [[likely]] {
        // The variable part starts after the constant wire-format prefix
        if (key.size() < kEd25519WireFormatPrefix.size() + pattern.prefix.size()) [[unlikely]] {
            return false;
        }
        if (!equals(
                key.substr(kEd25519WireFormatPrefix.size(), pattern.prefix.size()), pattern.prefix
            )) [[likely]] {
            return false;
        }
    }

    if (!pattern.suffix.empty()) {
        if (key.size() < pattern.suffix.size()) [[unlikely]] {
            return false;
        }
        if (!equals(key.substr(key.size() - pattern.suffix.size()), pattern.suffix)) [[likely]] {
            return false;
        }
    }

    if (!pattern.contains.empty()) {
        if (!case_insensitive) {
            return key.contains(pattern.contains);
        }
        // Reused per thread so the common miss path does not allocate
        thread_local std::string lowered;
        lowered.resize(key.size());
        std::transform(key.begin(), key.end(), lowered.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return lowered.contains(pattern.contains);
    }

    return true;
}

VanityResult SSHKeyGenerator::generate_vanity_key(
    const VanityPattern& pattern,
    int num_threads,
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
    if (stop_flag == nullptr) {
        stop_flag = &local_stop_flag;
    }
    if (total_attempts == nullptr) {
        total_attempts = &local_attempts;
    }

    // Converted once here rather than in every match
    const VanityPattern search_pattern = pattern.case_insensitive ? pattern.lowercased() : pattern;

    VanityResult result;
    std::vector<std::thread> threads;
    threads.reserve(static_cast<size_t>(num_threads));

    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([=, &search_pattern, &found, &result]() {
            // Pin each worker to a core to reduce context switching; failure is harmless
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(static_cast<unsigned int>(i) % std::thread::hardware_concurrency(), &cpuset);
            pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

            worker_thread(search_pattern, &found, stop_flag, total_attempts, &result);
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    result.attempts = total_attempts->load();
    return result;
}

void SSHKeyGenerator::worker_thread(
    const VanityPattern& pattern,
    std::atomic<bool>* found,
    std::atomic<bool>* stop_flag,
    std::atomic<uint64_t>* total_attempts,
    VanityResult* result
) {
    SSHKeyGenerator generator;
    bool done = false;

    while (!done && !found->load(std::memory_order_relaxed) &&
           !stop_flag->load(std::memory_order_relaxed)) {
        // The shared counter and flags are only touched once per batch
        uint64_t attempts = 0;
        for (uint64_t i = 0; i < kCheckInterval && !done; ++i) {
            if (!generator.generate_ed25519_key()) [[unlikely]] {
                continue;
            }
            ++attempts;

            if (generator.matches_vanity(pattern)) [[unlikely]] {
                bool expected = false;
                if (found->compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                    // First to find a match: the expensive encodings happen only here
                    result->found = true;
                    result->public_key_ssh = generator.get_public_key_ssh();
                    result->private_key_openssh = generator.get_private_key_openssh();
                }
                done = true;
            }
        }
        total_attempts->fetch_add(attempts, std::memory_order_relaxed);
    }
}
