#ifndef QUBITCOIN_CRYPTO_KYBER_H
#define QUBITCOIN_CRYPTO_KYBER_H

#pragma once

#include <span>
#include <vector>
#include <cstdint>
#include <memory>

// Forward declarations to avoid OpenSSL dependency in header
typedef struct evp_pkey_st EVP_PKEY;

namespace qubitcoin {
namespace crypto {
namespace kyber {

// Size constants for Kyber768
static constexpr size_t PUBLIC_KEY_SIZE = 1184;
static constexpr size_t SECRET_KEY_SIZE = 2400;
static constexpr size_t CIPHERTEXT_SIZE = 1088;
static constexpr size_t SHARED_SECRET_SIZE = 32;

/**
 * Kyber768 Post-Quantum Key Encapsulation Mechanism
 * 
 * Provides a C++ wrapper for liboqs/OpenSSL Kyber768 implementation with the 
 * following operations:
 * - Key generation
 * - Encapsulation (generate shared secret and ciphertext)
 * - Decapsulation (recover shared secret from ciphertext)
 */
class Kyber768KEM {
public:
    /** Generate a new Kyber768 key pair */
    static EVP_PKEY* GenerateKeypair();
    
    /** Export public key in binary format */
    static std::vector<uint8_t> ExportPublicKey(EVP_PKEY* key);
    
    /** Export private key in binary format */
    static std::vector<uint8_t> ExportPrivateKey(EVP_PKEY* key);
    
    /** Load public key from binary format */
    static EVP_PKEY* LoadPublicKey(std::span<const uint8_t> key_data);
    
    /** Load private key from binary format */
    static EVP_PKEY* LoadPrivateKey(std::span<const uint8_t> key_data);
    
    /** 
     * Encapsulate: Create a shared secret and ciphertext using recipient's public key 
     * @returns pair of (shared_secret, ciphertext)
     */
    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> 
    Encapsulate(EVP_PKEY* public_key);
    
    /**
     * Decapsulate: Recover shared secret from ciphertext using private key
     * @returns shared secret
     */
    static std::vector<uint8_t> Decapsulate(
        EVP_PKEY* private_key, 
        std::span<const uint8_t> ciphertext);
};

} // namespace kyber
} // namespace crypto
} // namespace qubitcoin

#endif // QUBITCOIN_CRYPTO_KYBER_H 