// 
//   2009-present 
//    
//  

#include <script/sigcache.h>

#include <crypto/sha256.h>
#include <logging.h>
#include <pubkey.h>
#include <random.h>
#include <script/interpreter.h>
#include <span.h>
#include <uint256.h>

#include <mutex>
#include <shared_mutex>
#include <vector>

SignatureCache::SignatureCache(const size_t max_size_bytes)
{
    uint256 nonce = GetRandHash();
    // We want the nonce to be 64 bytes long to force the hasher to process
    // this chunk, which makes later hash computations more efficient. We
    // just write our 32-byte entropy, and then pad with 'S' for Schnorr
    // and 'D' for Dilithium (followed by 0 bytes).
    static constexpr unsigned char PADDING_SCHNORR[32] = {'S'};
    static constexpr unsigned char PADDING_DILITHIUM[32] = {'D'};
    m_salted_hasher_schnorr.Write(nonce.begin(), 32);
    m_salted_hasher_schnorr.Write(PADDING_SCHNORR, 32);
    m_salted_hasher_dilithium.Write(nonce.begin(), 32);
    m_salted_hasher_dilithium.Write(PADDING_DILITHIUM, 32);

    const auto [num_elems, approx_size_bytes] = setValid.setup_bytes(max_size_bytes);
    LogPrintf("Using %zu MiB out of %zu MiB requested for signature cache, able to store %zu elements\n",
              approx_size_bytes >> 20, max_size_bytes >> 20, num_elems);
}

void SignatureCache::ComputeEntrySchnorr(uint256& entry, const uint256& hash, std::span<const unsigned char> sig, const XOnlyPubKey& pubkey) const
{
    CSHA256 hasher = m_salted_hasher_schnorr;
    hasher.Write(hash.begin(), 32).Write(pubkey.data(), pubkey.size()).Write(sig.data(), sig.size()).Finalize(entry.begin());
}

void SignatureCache::ComputeEntryDilithium(uint256& entry, const uint256& hash, std::span<const unsigned char> sig, std::span<const unsigned char> pubkey) const
{
    CSHA256 hasher = m_salted_hasher_dilithium;
    hasher.Write(hash.begin(), 32).Write(pubkey.data(), pubkey.size()).Write(sig.data(), sig.size()).Finalize(entry.begin());
}

bool SignatureCache::Get(const uint256& entry, const bool erase)
{
    std::shared_lock<std::shared_mutex> lock(cs_sigcache);
    return setValid.contains(entry, erase);
}

void SignatureCache::Set(const uint256& entry)
{
    std::unique_lock<std::shared_mutex> lock(cs_sigcache);
    setValid.insert(entry);
}

bool CachingTransactionSignatureChecker::VerifySchnorrSignature(std::span<const unsigned char> sig, const XOnlyPubKey& pubkey, const uint256& sighash) const
{
    uint256 entry;
    m_signature_cache.ComputeEntrySchnorr(entry, sighash, sig, pubkey);
    if (m_signature_cache.Get(entry, !store)) return true;
    if (!TransactionSignatureChecker::VerifySchnorrSignature(sig, pubkey, sighash)) return false;
    if (store) m_signature_cache.Set(entry);
    return true;
}

bool CachingTransactionSignatureChecker::CheckDilithiumSignature(std::span<const unsigned char> sig, std::span<const unsigned char> pubkey, const uint256& sighash) const
{
    uint256 entry;
    m_signature_cache.ComputeEntryDilithium(entry, sighash, sig, pubkey);
    if (m_signature_cache.Get(entry, !store))
        return true;
    if (!TransactionSignatureChecker::CheckDilithiumSignature(sig, pubkey, sighash))
        return false;
    if (store)
        m_signature_cache.Set(entry);
    return true;
}
