// 
//   2009-present 
//    
//  

#ifndef BITCOIN_HASH_H
#define BITCOIN_HASH_H

#include <attributes.h>
#include <crypto/common.h>
#include <crypto/ripemd160.h>
#include <crypto/sha256.h>
#include <crypto/blake3.h>
#include <prevector.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>
#include <array>

#include <string>
#include <vector>

typedef uint256 ChainCode;

/** A hasher class for Bitcoin's 256-bit hash (single BLAKE3). */
class CHash256 {
private:
    blake3_hasher hasher;
public:
    static const size_t OUTPUT_SIZE = BLAKE3_OUT_LEN;

    CHash256() {
        blake3_hasher_init(&hasher);
    }

    void Finalize(std::span<unsigned char> output) {
        assert(output.size() == OUTPUT_SIZE);
        blake3_hasher_finalize(&hasher, output.data(), OUTPUT_SIZE);
    }

    CHash256& Write(std::span<const unsigned char> input) {
        blake3_hasher_update(&hasher, input.data(), input.size());
        return *this;
    }

    CHash256& Reset() {
        blake3_hasher_init(&hasher);
        return *this;
    }
};

/** A hasher class for Bitcoin's 160-bit hash (BLAKE3 + RIPEMD-160). */
class CHash160 {
private:
    blake3_hasher hasher;
public:
    static const size_t OUTPUT_SIZE = CRIPEMD160::OUTPUT_SIZE;

    CHash160() {
        blake3_hasher_init(&hasher);
    }

    void Finalize(std::span<unsigned char> output) {
        assert(output.size() == OUTPUT_SIZE);
        // First compute BLAKE3 digest
        std::array<unsigned char, BLAKE3_OUT_LEN> buf;
        blake3_hasher_finalize(&hasher, buf.data(), BLAKE3_OUT_LEN);
        // Then SHA-160: RIPEMD-160 over BLAKE3 output
        CRIPEMD160().Write(buf.data(), BLAKE3_OUT_LEN).Finalize(output.data());
    }

    CHash160& Write(std::span<const unsigned char> input) {
        blake3_hasher_update(&hasher, input.data(), input.size());
        return *this;
    }

    CHash160& Reset() {
        blake3_hasher_init(&hasher);
        return *this;
    }
};

/** Compute the 256-bit hash of an object. */
template<typename T>
inline uint256 Hash(const T& in1)
{
    uint256 result;
    CHash256().Write(MakeUCharSpan(in1)).Finalize(result);
    return result;
}

/** Compute the 256-bit hash of the concatenation of two objects. */
template<typename T1, typename T2>
inline uint256 Hash(const T1& in1, const T2& in2) {
    uint256 result;
    CHash256().Write(MakeUCharSpan(in1)).Write(MakeUCharSpan(in2)).Finalize(result);
    return result;
}

/** Compute the 160-bit hash an object. */
template<typename T1>
inline uint160 Hash160(const T1& in1)
{
    uint160 result;
    CHash160().Write(MakeUCharSpan(in1)).Finalize(result);
    return result;
}

/** A writer stream (for serialization) that computes a 256-bit hash. */
/**
 * A writer stream (for serialization) that computes a 256-bit hash (BLAKE3) over the data.
 */
class HashWriter
{
private:
    blake3_hasher hasher;

public:
    HashWriter() {
        blake3_hasher_init(&hasher);
    }
    void write(std::span<const std::byte> src)
    {
        blake3_hasher_update(&hasher, reinterpret_cast<const unsigned char*>(src.data()), src.size());
    }

    /** Compute the double-SHA256 hash of all data written to this object.
     *
     * Invalidates this object.
     */
    /**
     * Compute the BLAKE3-256 hash of all data written to this object.
     * Invalidates this object.
     */
    uint256 GetHash() {
        uint256 result;
        blake3_hasher_finalize(&hasher, result.begin(), CHash256::OUTPUT_SIZE);
        return result;
    }

    /** Compute the SHA256 hash of all data written to this object.
     *
     * Invalidates this object.
     */
    /**
     * Alias for GetHash().
     */
    uint256 GetSHA256() {
        return GetHash();
    }

    /**
     * Returns the first 64 bits from the resulting hash.
     */
    inline uint64_t GetCheapHash() {
        uint256 result = GetHash();
        return ReadLE64(result.begin());
    }

    template <typename T>
    HashWriter& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return *this;
    }
};

/** Reads data from an underlying stream, while hashing the read data. */
template <typename Source>
class HashVerifier : public HashWriter
{
private:
    Source& m_source;

public:
    explicit HashVerifier(Source& source LIFETIMEBOUND) : m_source{source} {}

    void read(std::span<std::byte> dst)
    {
        m_source.read(dst);
        this->write(dst);
    }

    void ignore(size_t num_bytes)
    {
        std::byte data[1024];
        while (num_bytes > 0) {
            size_t now = std::min<size_t>(num_bytes, 1024);
            read({data, now});
            num_bytes -= now;
        }
    }

    template <typename T>
    HashVerifier<Source>& operator>>(T&& obj)
    {
        ::Unserialize(*this, obj);
        return *this;
    }
};

/** Writes data to an underlying source stream, while hashing the written data. */
template <typename Source>
class HashedSourceWriter : public HashWriter
{
private:
    Source& m_source;

public:
    explicit HashedSourceWriter(Source& source LIFETIMEBOUND) : HashWriter{}, m_source{source} {}

    void write(std::span<const std::byte> src)
    {
        m_source.write(src);
        HashWriter::write(src);
    }

    template <typename T>
    HashedSourceWriter& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return *this;
    }
};

/** Single-SHA256 a 32-byte input (represented as uint256). */
[[nodiscard]] uint256 SHA256Uint256(const uint256& input);

unsigned int MurmurHash3(unsigned int nHashSeed, std::span<const unsigned char> vDataToHash);

void BIP32Hash(const ChainCode &chainCode, unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64]);

/** Return a HashWriter primed for tagged hashes (as specified in BIP 340).
 *
 * The returned object will have SHA256(tag) written to it twice (= 64 bytes).
 * A tagged hash can be computed by feeding the message into this object, and
 * then calling HashWriter::GetSHA256().
 */
HashWriter TaggedHash(const std::string& tag);

/** Compute the 160-bit RIPEMD-160 hash of an array. */
inline uint160 RIPEMD160(std::span<const unsigned char> data)
{
    uint160 result;
    CRIPEMD160().Write(data.data(), data.size()).Finalize(result.begin());
    return result;
}

#endif // BITCOIN_HASH_H
