// Post-Quantum Cryptography key management (Dilithium3) using OpenSSL 3.x EVP + Provider API
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <stdexcept>
#include <string>
#include <vector>
#include "pqc_keys.h"

// Static provider handle for OQS
static OSSL_PROVIDER* oqs_provider = nullptr;

void LoadOQSProvider() {
    if (oqs_provider == nullptr) {
        oqs_provider = OSSL_PROVIDER_load(nullptr, "oqs");
        if (!oqs_provider) {
            unsigned long err_code = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            throw std::runtime_error(std::string("pqc_keys: failed to load OQS provider: ") + err_buf);
        }
    }
}

EVP_PKEY* GenerateDilithium3Key() {
    LoadOQSProvider();
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DILITHIUM3, nullptr);
    if (!pctx) {
        unsigned long err_code = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        throw std::runtime_error(std::string("pqc_keys: EVP_PKEY_CTX_new_id failed: ") + err_buf);
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        unsigned long err_code = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        throw std::runtime_error(std::string("pqc_keys: EVP_PKEY_keygen_init failed: ") + err_buf);
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        unsigned long err_code = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        throw std::runtime_error(std::string("pqc_keys: EVP_PKEY_keygen failed: ") + err_buf);
    }
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

std::vector<unsigned char> ExportDilithium3PublicKey(EVP_PKEY* pkey) {
    int len = i2d_PUBKEY(pkey, nullptr);
    if (len <= 0) {
        unsigned long err_code = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        throw std::runtime_error(std::string("pqc_keys: i2d_PUBKEY length error: ") + err_buf);
    }
    std::vector<unsigned char> buf(len);
    unsigned char* p = buf.data();
    if (i2d_PUBKEY(pkey, &p) != len) {
        unsigned long err_code = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        throw std::runtime_error(std::string("pqc_keys: i2d_PUBKEY failed: ") + err_buf);
    }
    return buf;
}

std::vector<unsigned char> ExportDilithium3PrivateKey(EVP_PKEY* pkey) {
    int len = i2d_PrivateKey(pkey, nullptr);
    if (len <= 0) {
        unsigned long err_code = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        throw std::runtime_error(std::string("pqc_keys: i2d_PrivateKey length error: ") + err_buf);
    }
    std::vector<unsigned char> buf(len);
    unsigned char* p = buf.data();
    if (i2d_PrivateKey(pkey, &p) != len) {
        unsigned long err_code = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        throw std::runtime_error(std::string("pqc_keys: i2d_PrivateKey failed: ") + err_buf);
    }
    return buf;
}

EVP_PKEY* LoadDilithium3PublicKey(const unsigned char* data, std::size_t len) {
    LoadOQSProvider();
    const unsigned char* p = data;
    EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, len);
    if (!pkey) {
        unsigned long err_code = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        throw std::runtime_error(std::string("pqc_keys: d2i_PUBKEY failed: ") + err_buf);
    }
    if (EVP_PKEY_id(pkey) != EVP_PKEY_DILITHIUM3) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("pqc_keys: loaded key is not Dilithium3");
    }
    return pkey;
}

EVP_PKEY* LoadDilithium3PrivateKey(const unsigned char* data, std::size_t len) {
    LoadOQSProvider();
    const unsigned char* p = data;
    EVP_PKEY* pkey = d2i_PrivateKey(EVP_PKEY_DILITHIUM3, nullptr, &p, len);
    if (!pkey) {
        unsigned long err_code = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        throw std::runtime_error(std::string("pqc_keys: d2i_PrivateKey failed: ") + err_buf);
    }
    return pkey;
}
// Sign data using Dilithium3 private key (BLAKE3 digest under the hood)
std::vector<unsigned char> SignDilithium3(EVP_PKEY* pkey, const unsigned char* msg, std::size_t msglen) {
    LoadOQSProvider();
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) throw std::runtime_error("pqc_keys: EVP_MD_CTX_new failed");
    if (EVP_DigestSignInit(mdctx, nullptr, EVP_blake3(), nullptr, pkey) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("pqc_keys: DigestSignInit failed");
    }
    if (EVP_DigestSignUpdate(mdctx, msg, msglen) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("pqc_keys: DigestSignUpdate failed");
    }
    size_t siglen = 0;
    if (EVP_DigestSignFinal(mdctx, nullptr, &siglen) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("pqc_keys: DigestSignFinal (get length) failed");
    }
    std::vector<unsigned char> sig(siglen);
    if (EVP_DigestSignFinal(mdctx, sig.data(), &siglen) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("pqc_keys: DigestSignFinal failed");
    }
    EVP_MD_CTX_free(mdctx);
    sig.resize(siglen);
    return sig;
}

// Verify Dilithium3 signature over data (BLAKE3 digest)
// Verify a Dilithium-3 signature using the raw EVP API
// Returns true if signature is valid, false on bad signature or error
bool VerifyDilithium3(EVP_PKEY* pkey,
                      const unsigned char* sig, std::size_t siglen,
                      const unsigned char* msg, std::size_t msglen) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
    if (!ctx) return false;
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    int ret = EVP_PKEY_verify(ctx, sig, siglen, msg, msglen);
    EVP_PKEY_CTX_free(ctx);
    return ret == 1;
}