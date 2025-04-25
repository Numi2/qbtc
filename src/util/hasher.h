// src/util/hasher.h

#ifndef QUBITCOIN_UTIL_HASHER_H
#define QUBITCOIN_UTIL_HASHER_H
// src/util/hasher.hpp
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <span.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <crypto/blake3.h>

/** Utility hashing functors for QuBitcoin (BLAKE3-based, quantum-safe). */
namespace qubitcoin::util {

/** BLAKE3-keyed hasher for txids. */
class SaltedTxidHasher {
    std::array<uint8_t, 32> key_;
public:
    SaltedTxidHasher() noexcept {
        std::random_device rd;
        for (auto& b : key_) b = rd();
    }
    size_t operator()(const uint256& txid) const noexcept {
        blake3_hasher h;
        blake3_hasher_init_keyed(&h, key_.data());
        blake3_hasher_update(&h, txid.begin(), txid.size());
        uint64_t out;
        blake3_hasher_finalize(&h, reinterpret_cast<uint8_t*>(&out), sizeof(out));
        return static_cast<size_t>(out);
    }
};

/** BLAKE3-keyed hasher for outpoints. */
class SaltedOutpointHasher {
    std::array<uint8_t, 32> key_;
public:
    explicit SaltedOutpointHasher(bool deterministic = false) noexcept {
        if (deterministic) {
            key_.fill(0);
        } else {
            std::random_device rd;
            for (auto& b : key_) b = rd();
        }
    }
    size_t operator()(const COutPoint& out) const noexcept {
        blake3_hasher h;
        blake3_hasher_init_keyed(&h, key_.data());
        blake3_hasher_update(&h, out.hash.begin(), out.hash.size());
        uint64_t n = out.n;
        blake3_hasher_update(&h, reinterpret_cast<const uint8_t*>(&n), sizeof(n));
        uint64_t out64;
        blake3_hasher_finalize(&h, reinterpret_cast<uint8_t*>(&out64), sizeof(out64));
        return static_cast<size_t>(out64);
    }
};

/** Simple 64-bit hasher: first 8 bytes of a BLAKE3 hash. */
struct FilterHeaderHasher {
    size_t operator()(const uint256& h) const noexcept {
        return ReadLE64(h.begin());
    }
};

/** Map a 256-bit key into 32-bit via 4-byte slice. */
class SignatureCacheHasher {
public:
    template <uint8_t I>
    uint32_t operator()(const uint256& k) const noexcept {
        static_assert(I < 8, "Index out of range");
        uint32_t v;
        std::memcpy(&v, k.begin() + I * 4, 4);
        return v;
    }
};

/** Same as FilterHeaderHasher for block hashes. */
struct BlockHasher {
    size_t operator()(const uint256& h) const noexcept {
        return ReadLE64(h.begin());
    }
};

/** BLAKE3-keyed hasher for arbitrary scripts. */
class SaltedScriptHasher {
    std::array<uint8_t, 32> key_;
public:
    SaltedScriptHasher() noexcept {
        std::random_device rd;
        for (auto& b : key_) b = rd();
    }
    size_t operator()(std::span<const std::byte> script) const noexcept {
        blake3_hasher h;
        blake3_hasher_init_keyed(&h, key_.data());
        blake3_hasher_update(
            &h,
            reinterpret_cast<const uint8_t*>(script.data()),
            script.size()
        );
        uint64_t out;
        blake3_hasher_finalize(&h, reinterpret_cast<uint8_t*>(&out), sizeof(out));
        return static_cast<size_t>(out);
    }
};

} // namespace qubitcoin::util

#endif // QUBITCOIN_UTIL_HASHER_H
