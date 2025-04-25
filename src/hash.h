
// src/hash.h

#ifndef QUBITCOIN_HASH_H
#define QUBITCOIN_HASH_H
Refactored for clarity, safety and full BLAKE3-based quantum-safe hashing. Key changes:
	•	#pragma once
	•	Doxygen comments
	•	noexcept on trivial methods
	•	std::byte everywhere
	•	static_assert on output sizes
	•	unified templated CBlake3 wrapper
	•	clear aliasing and strong typing
	•	full BLAKE3→RIPEMD160 for 160-bit

// src/hash.hpp
#pragma once

#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <serialize.h>
#include <uint160.h>
#include <uint256.h>
#include <crypto/blake3.h>
#include <crypto/ripemd160.h>

namespace qubitcoin {
namespace crypto {

/** Generic BLAKE3 hasher template. */
template<std::size_t OUT_LEN>
class CBlake3 {
    blake3_hasher ctx_;
public:
    static constexpr std::size_t OUTPUT_SIZE = OUT_LEN;
    static_assert(OUTPUT_SIZE > 0, "Output size must be positive");

    CBlake3() noexcept { reset(); }
    CBlake3(const CBlake3&) = delete;
    CBlake3& operator=(const CBlake3&) = delete;

    /** Reset to initial state. */
    CBlake3& reset() noexcept {
        blake3_hasher_init(&ctx_);
        return *this;
    }

    /** Absorb data. */
    CBlake3& write(std::span<const std::byte> data) noexcept {
        blake3_hasher_update(&ctx_,
            reinterpret_cast<const uint8_t*>(data.data()),
            data.size());
        return *this;
    }

    /** Finalize and write exactly OUTPUT_SIZE bytes to out. */
    void finalize(std::span<std::byte> out) noexcept {
        assert(out.size() == OUTPUT_SIZE);
        blake3_hasher_finalize(&ctx_,
            reinterpret_cast<uint8_t*>(out.data()),
            OUTPUT_SIZE);
    }
};

/** 256-bit BLAKE3 hasher. */
using CHash256 = CBlake3<BLAKE3_OUT_LEN>;

/** 160-bit: BLAKE3 → RIPEMD160 quantum-safe hybrid. */
class CHash160 {
    CBlake3<BLAKE3_OUT_LEN> ctx_;
public:
    static constexpr std::size_t OUTPUT_SIZE = CRIPEMD160::OUTPUT_SIZE;
    static_assert(OUTPUT_SIZE == 20, "RIPEMD160 output must be 20 bytes");

    CHash160() noexcept { reset(); }
    CHash160(const CHash160&) = delete;
    CHash160& operator=(const CHash160&) = delete;

    /** Reset BLAKE3 state. */
    CHash160& reset() noexcept {
        ctx_.reset();
        return *this;
    }

    /** Absorb data. */
    CHash160& write(std::span<const std::byte> data) noexcept {
        ctx_.write(data);
        return *this;
    }

    /** Finalize: BLAKE3 → RIPEMD160. */
    void finalize(std::span<std::byte> out) noexcept {
        assert(out.size() == OUTPUT_SIZE);
        std::array<std::byte, BLAKE3_OUT_LEN> tmp;
        ctx_.finalize(tmp);
        CRIPEMD160()
            .Write(reinterpret_cast<const uint8_t*>(tmp.data()), tmp.size())
            .Finalize(reinterpret_cast<uint8_t*>(out.data()));
    }
};

/** Compute 256-bit hash of any serializable obj. */
template<typename T>
inline uint256 Hash256(const T& obj) {
    std::array<std::byte, CHash256::OUTPUT_SIZE> buf;
    CHash256().write(MakeSpan(obj)).finalize(buf);
    return uint256{buf};
}

/** Compute 256-bit of two concatenated objects. */
template<typename A, typename B>
inline uint256 Hash256(const A& a, const B& b) {
    std::array<std::byte, CHash256::OUTPUT_SIZE> buf;
    CHash256()
        .write(MakeSpan(a))
        .write(MakeSpan(b))
        .finalize(buf);
    return uint256{buf};
}

/** Compute 160-bit hash of any serializable obj. */
template<typename T>
inline uint160 Hash160(const T& obj) {
    std::array<std::byte, CHash160::OUTPUT_SIZE> buf;
    CHash160().write(MakeSpan(obj)).finalize(buf);
    return uint160{buf};
}

/** Stream writer that hashes all data (BLAKE3-256). */
class HashWriter {
    CHash256 ctx_;
public:
    HashWriter() noexcept = default;

    /** Feed raw bytes. */
    void write(std::span<const std::byte> data) noexcept {
        ctx_.write(data);
    }

    /** Serialize and hash. */
    template<typename T>
    HashWriter& operator<<(const T& obj) {
        Serialize(*this, obj);
        return *this;
    }

    /** Finalize to 256-bit hash. */
    uint256 getHash() {
        std::array<std::byte, CHash256::OUTPUT_SIZE> buf;
        ctx_.finalize(buf);
        return uint256{buf};
    }

    /** Alias for getHash(). */
    uint256 getSHA256() {
        return getHash();
    }

    /** First 64 bits of hash, little-endian. */
    uint64_t getCheapHash() {
        return ReadLE64(getHash().begin());
    }
};

/** Wrap an input stream: reading + hashing. */
template<typename Source>
class HashVerifier : public HashWriter {
    Source& src_;
public:
    explicit HashVerifier(Source& s) noexcept : src_(s) {}

    void read(std::span<std::byte> dst) {
        src_.read(dst);
        write(dst);
    }

    void ignore(std::size_t n) {
        std::array<std::byte, 1024> buf;
        while (n) {
            auto chunk = std::min(n, buf.size());
            read({buf.data(), chunk});
            n -= chunk;
        }
    }

    template<typename T>
    HashVerifier& operator>>(T& obj) {
        Unserialize(*this, obj);
        return *this;
    }
};

/** Wrap an output sink: writing + hashing. */
template<typename Sink>
class HashedSinkWriter : public HashWriter {
    Sink& sink_;
public:
    explicit HashedSinkWriter(Sink& s) noexcept : sink_(s) {}

    void write(std::span<const std::byte> data) noexcept {
        sink_.write(data);
        HashWriter::write(data);
    }

    template<typename T>
    HashedSinkWriter& operator<<(const T& obj) {
        Serialize(*this, obj);
        return *this;
    }
};



} // namespace crypto
} // namespace qubitcoin

#endif // QUBITCOIN_HASH_H
