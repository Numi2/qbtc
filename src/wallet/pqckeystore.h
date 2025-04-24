// Qubitcoin: HD key store for post-quantum Dilithium3 key derivation
#ifndef BITCOIN_WALLET_PQCKEYSTORE_H
#define BITCOIN_WALLET_PQCKEYSTORE_H

#include <string>
#include <vector>
#include <tuple>

class CWallet;
struct CTxDestination;
class WalletBatch;

/**
 * CPQCKeyStore: derives per-index Dilithium3 keypairs from master PQC seed using BLAKE3-PRF,
 * persists keypairs and index in wallet database, and imports them into the wallet.
 */
class CPQCKeyStore {
private:
    CWallet* wallet;
    uint32_t next_index;
public:
    explicit CPQCKeyStore(CWallet* _wallet);
    /** Load persisted PQC keystore state (next index) */
    bool Load(WalletBatch& batch);
    /** Derive a new keypair/address: returns {address, pubkey_b64, privkey_b64} */
    std::tuple<std::string,std::string,std::string> GetNewPQCAddress();
    /** Import an existing PQC address + keypair (base64 SPKI/PKCS8) */
    bool ImportPQCAddress(const std::string& address, const std::string& pubkey_b64, const std::string& privkey_b64);
};

#endif // BITCOIN_WALLET_PQCKEYSTORE_H