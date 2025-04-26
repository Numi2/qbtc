// src/wallet/wallet.h

#ifndef QUBITCOIN_WALLET_WALLET_H
#define QUBITCOIN_WALLET_WALLET_H

#pragma once
#include <wallet/pqckeystore.h>
#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <serialize.h>
#include <uint160.h>
#include <uint256.h>

#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <common/bloom.h>
#include <primitives/block.h>
#include <primitives/transaction.h>

#include <crypto/blake3.h>
#include <crypto/dilithium.h>
#include <wallet/db.h>
#include <wallet/walletutil.h>
#include <util/result.h>

namespace qubitcoin {
namespace wallet {

// Aliases
using DPubKey  = crypto::Dilithium::PublicKey;
using DPrivKey = crypto::Dilithium::PrivateKey;
using uint160  = qubitcoin::uint160;
using uint256  = qubitcoin::uint256;
using ChainPtr = std::shared_ptr<interfaces::Chain>;

/** Wallet context passed to creation/load calls. */
struct WalletContext { /*...*/ };

/** High-level wallet interface. */
class CWallet : public interfaces::Chain::Notifications
{
public:
    /** Create or load a wallet. */
    static std::unique_ptr<CWallet> Create(WalletContext& ctx, std::string_view name);

    ~CWallet();

    /** Return wallet name. */
    const std::string& GetName() const { return m_name; }

    /** Master PQC seed exists? */
    bool HasPqcSeed() const;

    /** Set & persist master PQC seed (for HD Dilithium). */
    void SetPqcSeed(std::vector<uint8_t> seed);

    /** Get master PQC seed. */
    const std::vector<uint8_t>& GetPqcSeed() const;

    /** Derive new Dilithium keypair. */
    std::pair<DPubKey,DPrivKey> DeriveNextKey();

    /** Sign a transaction with all available keys. */
    util::Result<bool> SignTransaction(CMutableTransaction& tx);

    /** Create, commit & broadcast a tx. */
    util::Result<uint256> CommitTransaction(CMutableTransaction&& tx);

    /** Get balance for wallet. */
    CAmount GetBalance() const;

    /** Rescan chain for wallet-relevant txs. */
    void RescanChain(std::optional<int64_t> fromTime = std::nullopt);

    /** Notifications from chain. */
    void blockConnected(const interfaces::BlockInfo& info) override;
    void blockDisconnected(const interfaces::BlockInfo& info) override;
    void updatedBlockTip() override;

    /** Expose DB for batch writes. */
    WalletDatabase& GetDB();

    // Set the model used for spending PQC coins
    void SetSpendingPQCModel(bool spend_pqc) { m_spend_pqc = spend_pqc; }
    
    // Get the model used for spending P2WPQC outputs
    bool GetSpendingPQCModel() const { return m_spend_pqc; }
    
    // Access the PQC keystore
    const PQCKeyStore& GetPQCKeyStore() const { return *m_pqc_keystore; }
    PQCKeyStore& GetPQCKeyStore() { return *m_pqc_keystore; }
    
    /** Sign a P2WPQC (witness version 2) transaction input with Dilithium */
    bool SignP2WPQCTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int nIn, const CScript& scriptPubKey, CAmount amount) const;
    
    /** Get the public key for a P2WPQC address */
    bool GetPubKeyForP2WPQC(const CScript& scriptPubKey, std::vector<unsigned char>& pubkey) const;

private:
    explicit CWallet(WalletContext& ctx, std::string name, ChainPtr chain);

    std::string                    m_name;
    ChainPtr                       m_chain;
    std::unique_ptr<WalletDatabase> m_db;

    // HD PQC seed & key‐derivation
    std::vector<uint8_t>           m_pqc_seed;
    uint32_t                       m_next_index{0};

    // In-memory utxo & tx map
    std::map<uint256, CWalletTx>   m_wallet_tx;
    mutable std::atomic<CAmount>   m_cached_balance{0};

    // Sync state
    mutable std::atomic<int64_t>   m_last_block_time{0};
    mutable std::atomic<bool>      m_rescanning{false};

    mutable RecursiveMutex         cs_wallet;

    // PQC model
    bool                           m_spend_pqc{false};
    std::unique_ptr<PQCKeyStore>   m_pqc_keystore;

    /** Load existing seed & next index from DB. */
    void LoadPqcState();

    /** Persist seed & index. */
    void WritePqcState();

    /** Internal: scan blocks for matches. */
    void ScanBlock(const interfaces::BlockInfo& info);

    /** Internal: update cached balance. */
    void UpdateBalance();

    /** Internal: add or update a wallet tx. */
    void AddToWallet(const CTransactionRef& tx);

    /** Broadcast helper. */
    void BroadcastTx(const CWalletTx& wtx);
};

} // namespace wallet
} // namespace qubitcoin

#endif // QUBITCOIN_WALLET_WALLET_H
