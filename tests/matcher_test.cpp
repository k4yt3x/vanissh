// Unit tests for the CPU side of the search, checked against an independent
// reference (tests/reference_matcher.h) and OpenSSL:
//
// - the base64 encoder, padded and unpadded, for every input length up to 80;
// - the public key line and SHA-256 fingerprint of SSHKeyGenerator;
// - SSHKeyGenerator::matches for random criteria drawn from the strings of
//   random keys (exact, near-miss and random patterns, both case modes) and
//   for hand-picked edge cases.

#include <array>
#include <cstdint>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

#include "base64_encoder.h"
#include "reference_matcher.h"
#include "ssh_key_generator.h"
#include "vanity_pattern.h"

namespace {

int g_checks = 0;
int g_failures = 0;

void fail(const std::string& message) {
    ++g_failures;
    if (g_failures <= 20) {
        std::printf("FAIL: %s\n", message.c_str());
    }
}

void check(bool ok, const std::string& message) {
    ++g_checks;
    if (!ok) {
        fail(message);
    }
}

void test_base64(std::mt19937_64& rng) {
    for (size_t length = 0; length <= 80; ++length) {
        std::vector<unsigned char> data(length);
        for (auto& b : data) {
            b = static_cast<unsigned char>(rng());
        }
        check(
            base64::encode(data) == reference::base64(data.data(), length, true),
            "base64 padded, length " + std::to_string(length)
        );
        check(
            base64::encode_unpadded(data) == reference::base64(data.data(), length, false),
            "base64 unpadded, length " + std::to_string(length)
        );
    }
    std::printf("base64: 81 lengths\n");
}

void test_lowercased() {
    VanityCriteria c;
    c.key = {"AbC+/1", "XyZ", "Qq"};
    c.fingerprint = {"MiXeD", "09", "+A/"};
    c.case_insensitive = true;
    const VanityCriteria l = c.lowercased();
    check(
        l.key.prefix == "abc+/1" && l.key.suffix == "xyz" && l.key.contains == "qq",
        "lowercased key"
    );
    check(
        l.fingerprint.prefix == "mixed" && l.fingerprint.suffix == "09" &&
            l.fingerprint.contains == "+a/",
        "lowercased fingerprint"
    );
    check(l.case_insensitive && !l.empty(), "lowercased flags");
    check(VanityCriteria{}.empty() && VanityPattern{}.empty(), "empty criteria");
    std::printf("lowercased: ok\n");
}

// Runs the generator's matcher the way the search does and compares with the reference
void check_criteria(
    const SSHKeyGenerator& generator,
    const std::string& key,
    const std::string& fingerprint,
    const VanityCriteria& criteria,
    int& positives
) {
    const bool expected = reference::matches(key, fingerprint, criteria);
    const bool actual =
        generator.matches(criteria.case_insensitive ? criteria.lowercased() : criteria);
    positives += expected ? 1 : 0;
    check(
        actual == expected,
        std::string("matches ") + (expected ? "should accept " : "should reject ") +
            reference::describe(criteria) + " for " + key + " / " + fingerprint
    );
}

void test_matcher(std::mt19937_64& rng) {
    const int keys = 200;
    const int criteria_per_key = 500;
    int positives = 0;
    for (int k = 0; k < keys; ++k) {
        SSHKeyGenerator generator;
        if (!generator.generate_ed25519_key()) {
            std::printf("OpenSSL key generation failed\n");
            std::exit(2);
        }
        std::array<unsigned char, 32> pk{};
        if (!generator.get_raw_public_key(pk)) {
            std::printf("get_raw_public_key failed\n");
            std::exit(2);
        }
        const std::string key = reference::key_string(pk.data());
        const std::string fingerprint = reference::fingerprint_string(pk.data());
        check(generator.get_public_key_ssh() == "ssh-ed25519 " + key, "public key line");
        check(
            generator.get_fingerprint_sha256() == "SHA256:" + fingerprint,
            "fingerprint " + generator.get_fingerprint_sha256() + " vs SHA256:" + fingerprint
        );

        for (int t = 0; t < criteria_per_key; ++t) {
            check_criteria(
                generator,
                key,
                fingerprint,
                reference::random_criteria(rng, key, fingerprint),
                positives
            );
        }

        // Edge cases: whole strings, the constant part of the key, empty criteria
        VanityCriteria c;
        check_criteria(generator, key, fingerprint, c, positives);
        c.key = {key.substr(25), key, key};
        c.fingerprint = {fingerprint, fingerprint, fingerprint};
        check_criteria(generator, key, fingerprint, c, positives);
        c.case_insensitive = true;
        check_criteria(generator, key, fingerprint, c, positives);
        c = {};
        c.key.contains = "AAAAC3NzaC1lZDI1NTE5AAAAI";
        check_criteria(generator, key, fingerprint, c, positives);
        c.key.contains = "AAAAC3NzaC1lZDI1NTE5AAAAI" + key.substr(25, 1);
        check_criteria(generator, key, fingerprint, c, positives);
        c = {};
        c.key.prefix = key.substr(25) + "A";  // longer than the variable part
        check_criteria(generator, key, fingerprint, c, positives);
        c = {};
        c.fingerprint.suffix = "A" + fingerprint;  // longer than the fingerprint
        check_criteria(generator, key, fingerprint, c, positives);
    }
    std::printf(
        "matcher: %d keys x %d criteria, %d expected matches\n", keys, criteria_per_key, positives
    );
}

}  // namespace

int main() {
    std::mt19937_64 rng(20260915);
    test_base64(rng);
    test_lowercased();
    test_matcher(rng);
    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
