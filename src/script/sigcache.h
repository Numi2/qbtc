// src/script/sigcache.h

#ifndef QUBITCOIN_SCRIPT_SIGCACHE_H
#define QUBITCOIN_SCRIPT_SIGCACHE_H

#include <consensus/amount.h>
#include <crypto/sha256.h>
#include <cuckoocache.h>
#include <script/interpreter.h>
#include <span.h>
#include <uint256.h>
#include <util/hasher.h>

#include <cstddef>
#include <shared_mutex>
#include <vector>

class CPubKey;
class CTransaction;
class XOnlyPubKey;

// DoS prevention: limit cache size to 32MiB (over 1000000 entries on 64-bit
// systems). Due to how we count cache size, actual memory usage is slightly
// more (~32.25 MiB)
static constexpr size_t DEFAULT_VALIDATION_CACHE_BYTES{32 << 20};
static constexpr size_t DEFAULT_SIGNATURE_CACHE_BYTES{DEFAULT_VALIDATION_CACHE_BYTES / 2};
static constexpr size_t DEFAULT_SCRIPT_EXECUTION_CACHE_BYTES{DEFAULT_VALIDATION_CACHE_BYTES / 2};
static_assert(DEFAULT_VALIDATION_CACHE_BYTES == DEFAULT_SIGNATURE_CACHE_BYTES + DEFAULT_SCRIPT_EXECUTION_CACHE_BYTES);

/**
 * Valid signature cache, to avoid doing expensive ECDSA signature checking
 * twice for every transaction (once when accepted into memory pool, and
 * again when accepted into the block chain)
 */
class SignatureCache
{
private:
    //! Entries are SHA256(nonce || 'D' or 'S' || padding || sighash || pubkey || signature):
    CSHA256 m_salted_hasher_schnorr;
    CSHA256 m_salted_hasher_dilithium;
    typedef CuckooCache::cache<uint256, SignatureCacheHasher> map_type;
    map_type setValid;
    std::shared_mutex cs_sigcache;

public:
    SignatureCache(size_t max_size_bytes);

    SignatureCache(const SignatureCache&) = delete;
    SignatureCache& operator=(const SignatureCache&) = delete;

    void ComputeEntrySchnorr(uint256& entry, const uint256 &hash, std::span<const unsigned char> sig, const XOnlyPubKey& pubkey) const;

    void ComputeEntryDilithium(uint256& entry, const uint256 &hash, std::span<const unsigned char> sig, std::span<const unsigned char> pubkey) const;

    bool Get(const uint256& entry, const bool erase);

    void Set(const uint256& entry);
};

class CachingTransactionSignatureChecker : public TransactionSignatureChecker
{
private:
    bool store;
    SignatureCache& m_signature_cache;

public:
    CachingTransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, bool storeIn, SignatureCache& signature_cache, PrecomputedTransactionData& txdataIn) : TransactionSignatureChecker(txToIn, nInIn, amountIn, txdataIn, MissingDataBehavior::ASSERT_FAIL), store(storeIn), m_signature_cache(signature_cache)  {}

    bool VerifySchnorrSignature(std::span<const unsigned char> sig, const XOnlyPubKey& pubkey, const uint256& sighash) const override;

    bool CheckDilithiumSignature(std::span<const unsigned char> sig, std::span<const unsigned char> pubkey, const uint256& sighash) const override;
};

#endif // QUBITCOIN_SCRIPT_SIGCACHE_H
