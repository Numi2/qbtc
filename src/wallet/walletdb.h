 
// src/wallet/walletdb.h

#ifndef QUBITCOIN_WALLET_WALLETDB_H
#define QUBITCOIN_WALLET_WALLETDB_H
// src/wallet/walletdb.hpp
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>
#include <memory>

#include <serialize.h>
#include <uint160.h>
#include <uint256.h>

#include <wallet/db.h>
#include <wallet/walletutil.h>
#include <common/bloom.h>
#include <primitives/block.h>

#include <crypto/blake3.h>
#include <crypto/dilithium.h>  // new Dilithium PQC API

namespace qubitcoin {
namespace wallet {

// Aliases for quantum‐safe keys
using DPublicKey  = qubitcoin::crypto::Dilithium::PublicKey;
using DPrivateKey = qubitcoin::crypto::Dilithium::PrivateKey;

// Metadata for each Dilithium key
struct DKeyMetadata
{
    static constexpr int CURRENT_VERSION = 1;
    int            nVersion;
    int64_t        nCreateTime;   // epoch secs
    std::string    keyOrigin;     // path/fingerprint

    DKeyMetadata() { SetNull(); }
    void SetNull() {
        nVersion     = CURRENT_VERSION;
        nCreateTime  = 0;
        keyOrigin.clear();
    }

    SERIALIZE_METHODS(DKeyMetadata, obj) {
        READWRITE(obj.nVersion, obj.nCreateTime, obj.keyOrigin);
    }
};

// Simple HD chain counters for Dilithium/BLAKE3 derivation
class CHDChain
{
public:
    static constexpr int VERSION_HD_BASE = 1;
    static constexpr int CURRENT_VERSION = VERSION_HD_BASE;

    uint32_t nExternalIndex;      // next external derivation index
    uint32_t nInternalIndex;      // next internal (change) index
    qubitcoin::uint160 seed_id;   // BLAKE3-160 of master Dilithium pubkey

    CHDChain() { SetNull(); }

    void SetNull() {
        nExternalIndex = 0;
        nInternalIndex = 0;
        seed_id.SetNull();
    }

    SERIALIZE_METHODS(CHDChain, obj) {
        READWRITE(obj.nExternalIndex, obj.nInternalIndex, obj.seed_id);
    }
};

// DB error codes
enum class DBErrors : int {
    LOAD_OK = 0,
    NEED_RESCAN,
    NEED_REWRITE,
    EXTERNAL_SIGNER_REQUIRED,
    NONCRITICAL_ERROR,
    TOO_NEW,
    UNKNOWN_DESCRIPTOR,
    LOAD_FAIL,
    CORRUPT,
};

// DB keys for PQC items (defined in walletdb.cpp)
namespace DBKeys {
extern const std::string PQCSEED;   // master Dilithium seed
extern const std::string PQCKEY;    // per-index Dilithium private key
extern const std::string PQCINDEX;  // next derivation index
extern const std::unordered_set<std::string> LEGACY_TYPES;
}

// Transaction listener
struct DbTxnListener {
    std::function<void()> on_commit;
    std::function<void()> on_abort;
};

/**
 * Abstract batch for atomic DB updates.
 * All methods use BLAKE3 for indexing and Dilithium for signing.
 */
class WalletBatch
{
private:
    std::unique_ptr<DatabaseBatch> m_batch;
    WalletDatabase&                m_database;
    std::vector<DbTxnListener>     m_txn_listeners;

    // internal write+auto‐flush
    template<typename K, typename T>
    bool WriteIC(const K& key, const T& value, bool overwrite = true)
    {
        if (!m_batch->Write(key, value, overwrite)) return false;
        m_database.IncrementUpdateCounter();
        if (m_database.nUpdateCounter % 1000 == 0) m_batch->Flush();
        return true;
    }
    template<typename K>
    bool EraseIC(const K& key)
    {
        if (!m_batch->Erase(key)) return false;
        m_database.IncrementUpdateCounter();
        if (m_database.nUpdateCounter % 1000 == 0) m_batch->Flush();
        return true;
    }

public:
    explicit WalletBatch(WalletDatabase& db, bool flushOnClose = true) :
        m_batch(db.MakeBatch(flushOnClose)), m_database(db) {}
    WalletBatch(const WalletBatch&) = delete;
    WalletBatch& operator=(const WalletBatch&) = delete;

    // — Master seed for HD Dilithium keys
    bool WritePQCSeed(const DPublicKey& pubkey, const std::vector<uint8_t>& seed);
    bool ReadPQCSeed(DPublicKey& pubkey, std::vector<uint8_t>& seed_out);

    // — Per‐index private keys
    bool WritePQCKey(const DPublicKey& pubkey, const DPrivateKey& privkey, const DKeyMetadata& meta);
    bool ErasePQCKey(const DPublicKey& pubkey);

    // — HD chain counter
    bool WriteHDChain(const CHDChain& chain);
    bool ReadHDChain(CHDChain& chain_out);

    // — transactions
    bool WriteTx(const CWalletTx& wtx);
    bool EraseTx(const qubitcoin::uint256& hash);

    // — wallet descriptors (unchanged except PQC pubkey support)
    bool WriteDescriptor(const qubitcoin::uint256& desc_id, const WalletDescriptor& desc);
    bool WriteDescriptorKey(const qubitcoin::uint256& desc_id, const DPublicKey& pubkey, const DPrivateKey& privkey);
    bool EraseDescriptorKey(const qubitcoin::uint256& desc_id);

    // — address book
    bool WriteName(const std::string& addr, const std::string& name);
    bool EraseName(const std::string& addr);

    // — best block marker
    bool WriteBestBlock(const CBlockLocator& loc);
    bool ReadBestBlock(CBlockLocator& loc_out);

    // — txn listeners
    void RegisterTxnListener(const DbTxnListener& l) { m_txn_listeners.push_back(l); }

    // — transactions control
    bool TxnBegin()  { return m_batch->TxnBegin(); }
    bool TxnCommit() { 
        bool ok = m_batch->TxnCommit();
        if (ok) for (auto& l : m_txn_listeners) if (l.on_commit) l.on_commit();
        m_txn_listeners.clear();
        return ok;
    }
    bool TxnAbort()  {
        bool ok = m_batch->TxnAbort();
        if (ok) for (auto& l : m_txn_listeners) if (l.on_abort) l.on_abort();
        m_txn_listeners.clear();
        return ok;
    }
    bool HasActiveTxn() const { return m_batch->HasActiveTxn(); }
};

/**
 * Run a series of DB ops atomically.
 * Rolls back if func() returns false or throws.
 */
bool RunWithinTxn(
    WalletDatabase& db,
    std::string_view desc,
    const std::function<bool(WalletBatch&)>& func
);

// Compact DB if needed
void MaybeCompactWalletDB(WalletContext& ctx);

// Legacy loaders (for backward compatibility; these fail if any LEGACY_TYPES are present)
bool HasLegacyRecords(CWallet& wallet);
bool HasLegacyRecords(CWallet& wallet, DatabaseBatch& batch);

} // namespace wallet
} // namespace qubitcoin

#endif // QUBITCOIN_WALLET_WALLETDB_H
