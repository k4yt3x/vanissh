#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "vanity_pattern.h"

// Forward declarations keep the OpenSSL headers out of this header
struct evp_pkey_st;
using EVP_PKEY = evp_pkey_st;
struct evp_pkey_ctx_st;
using EVP_PKEY_CTX = evp_pkey_ctx_st;

inline constexpr size_t kEd25519KeySize = 32;
// Constant start of an SHA-256 fingerprint, as printed by ssh-keygen -l
inline constexpr std::string_view kFingerprintSha256Prefix = "SHA256:";

struct VanityResult {
    bool found = false;
    std::string public_key_ssh;
    std::string fingerprint_sha256;
    std::string private_key_openssh;
    uint64_t attempts = 0;
};

// An Ed25519 key pair with lazily cached SSH encodings
class SSHKeyGenerator {
   public:
    SSHKeyGenerator() = default;
    ~SSHKeyGenerator();
    SSHKeyGenerator(const SSHKeyGenerator&) = delete;
    SSHKeyGenerator& operator=(const SSHKeyGenerator&) = delete;

    // Generate a fresh random key pair
    [[gnu::hot]] bool generate_ed25519_key();

    // Load a key pair from a raw Ed25519 seed
    bool load_from_seed(std::span<const unsigned char, kEd25519KeySize> seed);

    // Copy the raw Ed25519 public key into out
    [[nodiscard]] bool get_raw_public_key(std::span<unsigned char, kEd25519KeySize> out) const;

    // Public key as "ssh-ed25519 <base64>"
    [[gnu::hot, nodiscard]] const std::string& get_public_key_ssh() const;

    // Fingerprint of the public key as "SHA256:<unpadded base64>"
    [[gnu::hot, nodiscard]] const std::string& get_fingerprint_sha256() const;

    // Private key in OpenSSH format; empty if the key could not be serialized
    [[nodiscard]] const std::string& get_private_key_openssh() const;

    // Check whether the public key and its fingerprint match the criteria. For
    // case-insensitive matching the criteria must be lower-cased
    // (VanityCriteria::lowercased).
    [[gnu::hot, nodiscard]] bool matches(const VanityCriteria& criteria) const;

    // Multi-threaded vanity search; num_threads <= 0 uses the hardware concurrency
    static VanityResult generate_vanity_key(
        const VanityCriteria& criteria,
        int num_threads = 0,
        std::atomic<bool>* stop_flag = nullptr,
        std::atomic<uint64_t>* total_attempts = nullptr
    );

   private:
    EVP_PKEY* private_key_ = nullptr;
    EVP_PKEY_CTX* keygen_ctx_ = nullptr;
    mutable std::string cached_public_key_ssh_;
    mutable std::string cached_fingerprint_sha256_;
    mutable std::string cached_private_key_openssh_;

    // Take ownership of key, replacing the current one
    void reset_key(EVP_PKEY* key);

    // RFC 4253 public key blob: string "ssh-ed25519", string <32 key bytes>;
    // empty on failure
    std::string public_key_blob() const;
    std::string public_key_to_ssh() const;
    std::string fingerprint_to_sha256() const;
    std::string private_key_to_openssh() const;

    // Search loop of one thread; the criteria must already be in matcher form
    static void worker_thread(
        const VanityCriteria& criteria,
        std::atomic<bool>* found,
        std::atomic<bool>* stop_flag,
        std::atomic<uint64_t>* total_attempts,
        VanityResult* result
    );
};
