// Post-Quantum Cryptography key management (Dilithium3) using OpenSSL 3.x EVP + Provider API
#ifndef BITCOIN_CRYPTO_PQC_KEYS_H
#define BITCOIN_CRYPTO_PQC_KEYS_H

#include <openssl/evp.h>
#include <cstddef>
#include <vector>

/**
 * Load the OpenQuantumSafe provider (OQS) for PQC algorithms.
 * Throws std::runtime_error on failure.
 */
void LoadOQSProvider();

/**
 * Generate a new Dilithium3 key pair.
 * Returns a newly allocated EVP_PKEY*, or throws std::runtime_error.
 * Caller is responsible for EVP_PKEY_free().
 */
EVP_PKEY* GenerateDilithium3Key();

/**
 * Export the Dilithium3 public key to DER-encoded SubjectPublicKeyInfo.
 * Returns the DER bytes, or throws std::runtime_error.
 */
std::vector<unsigned char> ExportDilithium3PublicKey(EVP_PKEY* pkey);

/**
 * Export the Dilithium3 private key to DER-encoded PKCS8.
 * Returns the DER bytes, or throws std::runtime_error.
 */
std::vector<unsigned char> ExportDilithium3PrivateKey(EVP_PKEY* pkey);

/**
 * Load a Dilithium3 public key from DER-encoded SubjectPublicKeyInfo.
 * Returns a newly allocated EVP_PKEY*, or throws std::runtime_error.
 * Caller is responsible for EVP_PKEY_free().
 */
EVP_PKEY* LoadDilithium3PublicKey(const unsigned char* data, std::size_t len);

/**
 * Load a Dilithium3 private key from DER-encoded PKCS8.
 * Returns a newly allocated EVP_PKEY*, or throws std::runtime_error.
 * Caller is responsible for EVP_PKEY_free().
 */
EVP_PKEY* LoadDilithium3PrivateKey(const unsigned char* data, std::size_t len);
/**
 * Create a Dilithium3 signature over data using the private key.
 * Returns the signature bytes, or throws std::runtime_error.
 */
std::vector<unsigned char> SignDilithium3(EVP_PKEY* pkey, const unsigned char* msg, std::size_t msglen);

/**
 * Verify a Dilithium3 signature over data using the public key.
 * Returns true if the signature is valid, false or throws on error.
 */
bool VerifyDilithium3(EVP_PKEY* pkey, const unsigned char* sig, std::size_t siglen, const unsigned char* msg, std::size_t msglen);

#endif // BITCOIN_CRYPTO_PQC_KEYS_H