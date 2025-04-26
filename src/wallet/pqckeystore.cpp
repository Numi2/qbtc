// Qubitcoin: HD key store for post-quantum Dilithium3 key derivation
#include <wallet/pqckeystore.h>
#include <key_io.h>
#include <crypto/pqc_keys.h>
#include <util/hash.h>
#include <wallet/walletdb.h>
#include <util/strencodings.h>
#include <vector>
#include <util/time.h>
#include <script/interpreter.h>
#include <chainparams.h>
#include <span>

CPQCKeyStore::CPQCKeyStore(CWallet* _wallet) : wallet(_wallet), next_index(0) {}

bool CPQCKeyStore::Load(WalletBatch& batch)
{
    // Load next index for HD PQC key derivation (if stored)
    uint32_t idx = 0;
    try {
        batch.Read(DBKeys::PQCINDEX, idx);
        next_index = idx;
    } catch (...) {
        next_index = 0;
    }
    // Load persisted PQC private keys and build address->privkey map
    for (uint32_t i = 0; i < next_index; ++i) {
        std::vector<unsigned char> priv_der;
        if (batch.ReadIC(std::make_pair(DBKeys::PQCKEY, i), priv_der)) {
            EVP_PKEY* pkey = nullptr;
            try {
                pkey = LoadDilithium3PrivateKey(priv_der.data(), priv_der.size());
                std::vector<unsigned char> pub_der = ExportDilithium3PublicKey(pkey);
                uint256 h = Blake3(std::span{pub_der.data(), pub_der.size()});
                std::vector<unsigned char> program(h.begin(), h.end());
                CTxDestination dest = WitnessUnknown{1, program};
                std::string addr = EncodeDestination(dest);
                m_address_priv_map[addr] = priv_der;
            } catch (...) {
                // skip invalid
            }
            if (pkey) EVP_PKEY_free(pkey);
        }
    }
    return true;
}
// Sign a plain message with the PQC private key for a given address
bool CPQCKeyStore::SignMessage(const std::string& address, const std::string& message, std::string& signature) const
{
    auto it = m_address_priv_map.find(address);
    if (it == m_address_priv_map.end()) return false;
    // Load private key
    EVP_PKEY* pkey = nullptr;
    try {
        pkey = LoadDilithium3PrivateKey(it->second.data(), it->second.size());
        auto sig = SignDilithium3(pkey,
            reinterpret_cast<const unsigned char*>(message.data()), message.size());
        signature = EncodeBase64(sig);
    } catch (...) {
        if (pkey) EVP_PKEY_free(pkey);
        return false;
    }
    EVP_PKEY_free(pkey);
    return true;
}

std::tuple<std::string, std::string, std::string> CPQCKeyStore::GetNewPQCAddress()
{
    // Derive new Dilithium3 keypair via HD (BLAKE3-PRF(master_seed, index))
    std::vector<unsigned char> seed = wallet->GetPqcSeed();
    if (seed.empty()) throw std::runtime_error("PQC seed not set");
    // Compute PRF output
    blake3_hasher hasher;
    blake3_hasher_init_keyed(&hasher, seed.data());
    uint32_t idx = next_index;
    uint32_t idx_be = htobe32(idx);
    blake3_hasher_update(&hasher, reinterpret_cast<const uint8_t*>(&idx_be), sizeof(idx_be));
    uint8_t out[BLAKE3_KEY_LEN];
    blake3_hasher_finalize(&hasher, out, BLAKE3_KEY_LEN);
    // Seed OpenSSL RNG for deterministic keygen
    RAND_seed(out, BLAKE3_KEY_LEN);
    EVP_PKEY* pkey = GenerateDilithium3Key();
    std::vector<unsigned char> pub_der = ExportDilithium3PublicKey(pkey);
    std::vector<unsigned char> priv_der = ExportDilithium3PrivateKey(pkey);
    std::string pub_b64 = EncodeBase64(pub_der);
    std::string priv_b64 = EncodeBase64(priv_der);

    // Compute Bech32m v2 address from public key hash
    uint256 h = Blake3(std::span{pub_der.data(), pub_der.size()});
    std::vector<unsigned char> program(h.begin(), h.end());
    CTxDestination dest = WitnessUnknown{1, program};
    std::string address = EncodeDestination(dest);

    // Persist this keypair and bump index
    {
        WalletBatch batch(wallet->GetDatabase());
        batch.WriteIC(std::make_pair(DBKeys::PQCKEY, next_index), priv_der);
        batch.WriteIC(DBKeys::PQCINDEX, next_index + 1);
        next_index++;
    }

    EVP_PKEY_free(pkey);
    return {address, pub_b64, priv_b64};
}

bool CPQCKeyStore::ImportPQCAddress(const std::string& address, const std::string& pubkey_b64, const std::string& privkey_b64)
{
    // Decode base64-encoded keys
    std::vector<unsigned char> pub_der = DecodeBase64(pubkey_b64);
    std::vector<unsigned char> priv_der = DecodeBase64(privkey_b64);
    // Load private key
    EVP_PKEY* pkey = nullptr;
    try {
        pkey = LoadDilithium3PrivateKey(priv_der.data(), priv_der.size());
    } catch (...) {
        return false;
    }
    // Persist this keypair: store private key in wallet DB and update in-memory map
    {
        // Use current next_index to assign this imported key
        WalletBatch batch(wallet->GetDatabase());
        // Persist raw private key bytes under PQCKEY at next_index
        batch.WriteIC(std::make_pair(DBKeys::PQCKEY, next_index), priv_der);
        // Bump stored PQCINDEX to include this new key
        batch.WriteIC(DBKeys::PQCINDEX, next_index + 1);
        // Update in-memory index and map
        m_address_priv_map[address] = priv_der;
        next_index++;
    }

    // Import address script to wallet
    std::string err;
    CTxDestination dest = DecodeDestination(address, Params(), err, nullptr);
    if (!IsValidDestination(dest)) {
        EVP_PKEY_free(pkey);
        return false;
    }
    CScript script = GetScriptForDestination(dest);
    WalletBatch batch(wallet->GetDatabase());
    auto spk_man = wallet->GetOrCreateScriptPubKeyMan(batch, dest);
    LOCK(spk_man->cs_KeyStore);
    spk_man->ImportScripts({script}, /*have_solving_data=*/true, /*timestamp=*/GetTime());
    EVP_PKEY_free(pkey);
    return true;
}