// Qubitcoin: HD key store for post-quantum Dilithium3 key derivation
#ifndef QUBITCOIN_WALLET_PQCKEYSTORE_H
#define QUBITCOIN_WALLET_PQCKEYSTORE_H


#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <vector>

#include <wallet/wallet.hpp>      // for CWallet, CTxDestination
#include <wallet/db.h>            // for WalletBatch
#include <crypto/blake3.h>        // for BLAKE3-PRF
#include <crypto/dilithium.h>     // for Dilithium keypair APIs

namespace qubitcoin::wallet {

/**
 * PQC key store for HD Dilithium3.
 * Derives per-index keypairs from a master seed via BLAKE3-PRF,
 * persists index and private keys in the wallet DB, and loads them on demand.
 */
class PQCKeyStore {
public:
    /** Construct with owning wallet. */
    explicit PQCKeyStore(CWallet* wallet) noexcept;

    /** Load `next_index` from the wallet database. */
    bool Load(WalletBatch& batch) noexcept;

    /** Derive and persist next Dilithium3 keypair. 
     *  Returns (address, pubkey, privkey). */
    std::tuple<CTxDestination, crypto::Dilithium::PublicKey, crypto::Dilithium::PrivateKey>
    DeriveNextKey(WalletBatch& batch);

    /** Import an externally-generated keypair under a given address. */
    bool ImportKey(const CTxDestination& addr,
                   const crypto::Dilithium::PublicKey&  pub,
                   const crypto::Dilithium::PrivateKey& priv,
                   WalletBatch& batch) noexcept;

    /** Sign an arbitrary message with the private key for `addr`. */
    bool SignMessage(const CTxDestination& addr,
                     std::string_view message,
                     std::vector<uint8_t>& signature) const noexcept;

    /** Sign a transaction input with Dilithium key, using BLAKE3-tagged sighash. */
    bool SignTransaction(const CTransaction& txTo, 
                        std::vector<unsigned char>& signature,
                        int nIn,
                        const CAmount& amount,
                        const CScript& scriptPubKey) const;

private:
    CWallet* wallet_;                           // owning wallet
    uint32_t  next_index_;                      // next HD derivation index
    std::unordered_map<CTxDestination,
        crypto::Dilithium::PrivateKey> keys_;   // in-memory privkeys

    /** Persist updated `next_index_` to DB. */
    void PersistIndex(WalletBatch& batch) const;

    /** Persist a single private key to DB. */
    void PersistKey(const CTxDestination& addr,
                    const crypto::Dilithium::PrivateKey& priv,
                    WalletBatch& batch) const;

    /** BLAKE3-PRF: derive 64 bytes from seed+index. */
    static std::array<uint8_t, 64> Blake3Prf(std::span<const uint8_t> seed, uint32_t index) noexcept;
};

} // namespace qubitcoin::wallet
#endif // QUBITCOIN_WALLET_PQCKEYSTORE_H